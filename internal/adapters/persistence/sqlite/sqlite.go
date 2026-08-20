// Package sqlite is the SQLite-backed persistence adapter implementing the
// repository ports. SQL is parameterised (no concatenation) and every business
// query is scoped by tenant_id (threats P1/P2). The adapter is swappable: cmd
// wiring chooses it without the domain/use-cases knowing (see ../inmemory).
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	// Pure-Go SQLite driver (no cgo) for simple, portable CI builds.
	_ "modernc.org/sqlite"

	"github.com/ia-dev-sindireceita/payment/internal/domain/account"
	"github.com/ia-dev-sindireceita/payment/internal/domain/billing"
	"github.com/ia-dev-sindireceita/payment/internal/domain/invoice"
	"github.com/ia-dev-sindireceita/payment/internal/domain/payment"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

const tsLayout = time.RFC3339Nano

// busyTimeout is how long a statement waits for a write lock before giving up.
//
// SQLite permite UM escritor por vez. Sem espera, a segunda escrita concorrente falha
// NA HORA com SQLITE_BUSY — e "na hora" aqui significa em microssegundos, por uma
// disputa que teria acabado sozinha em milissegundos.
const busyTimeout = 5 * time.Second

// Open opens a SQLite database at dsn (e.g. a file path or ":memory:") with foreign
// keys enabled and a busy timeout. The returned *sql.DB is owned by the caller.
//
// A concorrência é deliberada e apertada, por causa de um pagamento real (SIN-69368).
// Um cartão de R$ 15,00 foi pago, o C6 avisou, e o aviso foi RECUSADO com 500:
//
//	mark processed: database is locked (5) (SQLITE_BUSY)
//
// A gravação da marca de anti-replay é a primeira coisa dentro da transação de
// liquidação, e ela esbarrou no trabalhador de entrega de saída, que escreve a cada
// DOIS segundos. Nenhuma das duas estava errada; o banco é que não tinha instrução para
// esperar. O pagamento só não se perdeu porque o C6 repetiu o aviso sozinho — sorte,
// não desenho, e a marca não gravada significava que a repetição seria reprocessada do
// zero, sem a proteção de anti-replay valer para nada.
//
// A correção é o busy_timeout: a escrita ESPERA o lock em vez de desistir. Cinco
// segundos é ordens de grandeza acima de qualquer transação daqui, então na prática só
// um travamento de verdade estoura o prazo — e aí falhar é o certo.
//
// O pragma vai no DSN, não num Exec: assim vale para TODA conexão que o driver abrir,
// inclusive uma reaberta depois de a anterior morrer. Um Exec valeria só para a conexão
// que por acaso o atendeu.
//
// NÃO serializamos com SetMaxOpenConns(1), que seria o remédio óbvio. Tentei, e ele
// TRAVA este código: ListInvoices consulta invoice_items dentro do rows ainda aberto de
// invoices, e com uma conexão só a consulta de dentro espera para sempre a que a de
// fora está segurando. Uma conexão única transformaria um erro barulhento numa
// requisição pendurada, que é troca ruim. Serializar só depois de eliminar as consultas
// aninhadas — e aí o busy_timeout continua valendo, de graça.
func Open(dsn string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", withBusyTimeout(dsn))
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if _, err := db.Exec("PRAGMA foreign_keys = ON;"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("enable foreign keys: %w", err)
	}
	return db, nil
}

// withBusyTimeout adds the busy-timeout pragma to a modernc sqlite DSN, preserving any
// parameters the caller already set. A DSN that already names busy_timeout is left
// alone — quem foi explícito tem a última palavra.
func withBusyTimeout(dsn string) string {
	if strings.Contains(dsn, "busy_timeout") {
		return dsn
	}
	pragma := fmt.Sprintf("_pragma=busy_timeout(%d)", busyTimeout.Milliseconds())
	if strings.Contains(dsn, "?") {
		return dsn + "&" + pragma
	}
	return dsn + "?" + pragma
}

// Migrate applies every *.up.sql file from the given filesystem in lexical order,
// each exactly once, recording applied files in a schema_migrations ledger.
//
// The ledger is what makes Migrate safe to call on every boot. Earlier migrations
// were all CREATE ... IF NOT EXISTS (re-runnable), but additive migrations such as
// ALTER TABLE ... ADD COLUMN are NOT idempotent in SQLite (it has no ADD COLUMN IF
// NOT EXISTS) — re-running one crashes with "duplicate column". The ledger skips a
// file once applied, so any migration shape is safe across restarts (SIN-66044).
//
// Backward compatible: on an existing database whose tables were created by the
// previous ledger-less runner, the ledger starts empty, so 0001/0002 are re-applied
// once — harmlessly, since they are IF NOT EXISTS — then recorded and skipped
// thereafter. Each file's apply and its ledger insert share one transaction, so a
// failure leaves neither the schema half-changed nor the file marked applied.
func Migrate(ctx context.Context, db *sql.DB, fsys fs.FS) error {
	if _, err := db.ExecContext(ctx,
		`CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		return fmt.Errorf("ensure schema_migrations: %w", err)
	}
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return fmt.Errorf("read migrations: %w", err)
	}
	var ups []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".up.sql") {
			ups = append(ups, e.Name())
		}
	}
	sort.Strings(ups)
	for _, name := range ups {
		var applied bool
		if err := db.QueryRowContext(ctx,
			`SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE name = ?)`, name).Scan(&applied); err != nil {
			return fmt.Errorf("check migration %s: %w", name, err)
		}
		if applied {
			continue
		}
		b, err := fs.ReadFile(fsys, name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin migration %s: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx, string(b)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("apply migration %s: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO schema_migrations (name, applied_at) VALUES (?, ?)`,
			name, time.Now().UTC().Format(tsLayout)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record migration %s: %w", name, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %s: %w", name, err)
		}
	}
	return nil
}

// dbtx is the subset of *sql.DB / *sql.Tx the queries use, so the same query code
// runs both autocommitted (on the pool) and inside a transaction.
type dbtx interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// repo holds the SQL implementing the repository ports over a dbtx.
type repo struct{ q dbtx }

// Store implements the repository ports and the unit-of-work port over a *sql.DB.
// Its repository methods run autocommitted on the connection pool; WithinTx runs
// them inside a single transaction.
type Store struct {
	db *sql.DB
	repo
}

// NewStore wraps a database handle.
func NewStore(db *sql.DB) *Store { return &Store{db: db, repo: repo{q: db}} }

// Compile-time checks that the adapter satisfies the persistence ports.
var (
	_ ports.PaymentRepository   = (*Store)(nil)
	_ ports.TenantRepository    = (*Store)(nil)
	_ ports.AccountRepository   = (*Store)(nil)
	_ ports.PricingRepository   = (*Store)(nil)
	_ ports.LedgerRepository    = (*Store)(nil)
	_ ports.ProcessedEventStore = (*Store)(nil)
	_ ports.Repository          = (*Store)(nil)
	_ ports.UnitOfWork          = (*Store)(nil)
	_ ports.Repository          = repo{}
)

// WithinTx runs fn inside a single BEGIN/COMMIT transaction. All writes through
// the supplied Repository commit together when fn returns nil and roll back when
// it returns an error. This is the transactional boundary the multi-write
// use-cases rely on for financial integrity (SIN-64719).
func (s *Store) WithinTx(ctx context.Context, fn func(ports.Repository) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	if err := fn(repo{q: tx}); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// --- Tenants ---

// SaveTenant inserts or updates a tenant. account_id is written on INSERT but is
// deliberately NOT in the DO UPDATE SET clause: the owning account is IMMUTABLE
// once assigned (ADR-0009 §3.2), so an admin activate/suspend upsert must never
// clobber a backfilled owner. An empty AccountID persists as SQL NULL — the
// NULL-safe "self-account" legacy semantics (ADR-0009 §4).
func (r repo) SaveTenant(ctx context.Context, t *tenant.Tenant) error {
	_, err := r.q.ExecContext(ctx,
		`INSERT INTO tenants (id, name, active, created_at, account_id) VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET name = excluded.name, active = excluded.active`,
		t.ID(), t.Name(), boolToInt(t.Active()), t.CreatedAt().Format(tsLayout), nullIfEmpty(t.AccountID()))
	if err != nil {
		return fmt.Errorf("save tenant: %w", err)
	}
	return nil
}

// FindTenantByID returns a tenant or ErrNotFound. A NULL account_id (legacy
// self-account) reads back as an empty owner.
func (r repo) FindTenantByID(ctx context.Context, id string) (*tenant.Tenant, error) {
	row := r.q.QueryRowContext(ctx, `SELECT id, name, active, created_at, account_id FROM tenants WHERE id = ?`, id)
	var gotID, name, createdAt string
	var accountID sql.NullString
	var active int
	if err := row.Scan(&gotID, &name, &active, &createdAt, &accountID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, fmt.Errorf("scan tenant: %w", err)
	}
	return tenant.RehydrateWithAccount(gotID, name, active != 0, parseTime(createdAt), accountID.String), nil
}

// ListTenants returns every tenant, newest-first (created_at desc, id desc as a
// deterministic tie-break). Used by the admin console listing.
func (s *Store) ListTenants(ctx context.Context) ([]*tenant.Tenant, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, active, created_at, account_id FROM tenants ORDER BY created_at DESC, id DESC`)
	if err != nil {
		return nil, fmt.Errorf("query tenants: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*tenant.Tenant
	for rows.Next() {
		var id, name, createdAt string
		var accountID sql.NullString
		var active int
		if err := rows.Scan(&id, &name, &active, &createdAt, &accountID); err != nil {
			return nil, fmt.Errorf("scan tenant: %w", err)
		}
		out = append(out, tenant.RehydrateWithAccount(id, name, active != 0, parseTime(createdAt), accountID.String))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tenants: %w", err)
	}
	return out, nil
}

// --- Accounts (two-level tenancy, ADR-0009) ---

// SaveAccount inserts or updates an account (the API user / reseller that owns
// tenants). Upsert on id so admin rename/activate is retry-safe, mirroring
// SaveTenant. An account holds no bank credential and no money.
func (r repo) SaveAccount(ctx context.Context, a *account.Account) error {
	_, err := r.q.ExecContext(ctx,
		`INSERT INTO accounts (id, name, active, created_at) VALUES (?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET name = excluded.name, active = excluded.active`,
		a.ID(), a.Name(), boolToInt(a.Active()), a.CreatedAt().Format(tsLayout))
	if err != nil {
		return fmt.Errorf("save account: %w", err)
	}
	return nil
}

// FindAccountByID returns an account or ErrNotFound.
func (r repo) FindAccountByID(ctx context.Context, id string) (*account.Account, error) {
	row := r.q.QueryRowContext(ctx, `SELECT id, name, active, created_at FROM accounts WHERE id = ?`, id)
	var gotID, name, createdAt string
	var active int
	if err := row.Scan(&gotID, &name, &active, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, fmt.Errorf("scan account: %w", err)
	}
	return account.Rehydrate(gotID, name, active != 0, parseTime(createdAt)), nil
}

// ListAccounts returns every account, newest-first (created_at desc, id desc as a
// deterministic tie-break), mirroring ListTenants. Used by the admin console Contas
// listing (SIN-69157). The per-tenant self-accounts backfilled by migration 0007 are
// returned too; the app layer filters them out by default.
func (s *Store) ListAccounts(ctx context.Context) ([]*account.Account, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, active, created_at FROM accounts ORDER BY created_at DESC, id DESC`)
	if err != nil {
		return nil, fmt.Errorf("query accounts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*account.Account
	for rows.Next() {
		var id, name, createdAt string
		var active int
		if err := rows.Scan(&id, &name, &active, &createdAt); err != nil {
			return nil, fmt.Errorf("scan account: %w", err)
		}
		out = append(out, account.Rehydrate(id, name, active != 0, parseTime(createdAt)))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate accounts: %w", err)
	}
	return out, nil
}

// --- Payments (tenant-scoped) ---

// SavePayment inserts or updates a payment. A second payment reusing a tenant's
// idempotency key violates ux_payments_tenant_idempotency and surfaces as
// shared.ErrConflict so the use-case can resolve the race (no double charge).
func (r repo) SavePayment(ctx context.Context, p *payment.Payment) error {
	_, err := r.q.ExecContext(ctx,
		`INSERT INTO payments (id, tenant_id, endpoint, amount_cents, currency, status, tx_id, idempotency_key, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET status = excluded.status, tx_id = excluded.tx_id, updated_at = excluded.updated_at`,
		p.ID(), p.TenantID(), p.Endpoint(), p.Amount().Cents(), p.Amount().Currency(),
		string(p.Status()), p.TxID(), p.IdempotencyKey(), p.CreatedAt().Format(tsLayout), p.UpdatedAt().Format(tsLayout))
	if err != nil {
		if isUniqueViolation(err) {
			return shared.ErrConflict
		}
		return fmt.Errorf("save payment: %w", err)
	}
	return nil
}

// FindPaymentByID returns a tenant-scoped payment or ErrNotFound.
func (r repo) FindPaymentByID(ctx context.Context, tenantID, id string) (*payment.Payment, error) {
	return r.queryPayment(ctx,
		`SELECT id, tenant_id, endpoint, amount_cents, currency, status, tx_id, idempotency_key, created_at, updated_at
		 FROM payments WHERE tenant_id = ? AND id = ?`, tenantID, id)
}

// FindPaymentByIdempotencyKey returns a tenant-scoped payment by idempotency key.
func (r repo) FindPaymentByIdempotencyKey(ctx context.Context, tenantID, key string) (*payment.Payment, error) {
	return r.queryPayment(ctx,
		`SELECT id, tenant_id, endpoint, amount_cents, currency, status, tx_id, idempotency_key, created_at, updated_at
		 FROM payments WHERE tenant_id = ? AND idempotency_key = ?`, tenantID, key)
}

// FindPaymentByTxID returns a tenant-scoped payment by bank tx id.
func (r repo) FindPaymentByTxID(ctx context.Context, tenantID, txID string) (*payment.Payment, error) {
	return r.queryPayment(ctx,
		`SELECT id, tenant_id, endpoint, amount_cents, currency, status, tx_id, idempotency_key, created_at, updated_at
		 FROM payments WHERE tenant_id = ? AND tx_id = ?`, tenantID, txID)
}

func (r repo) queryPayment(ctx context.Context, query string, args ...any) (*payment.Payment, error) {
	row := r.q.QueryRowContext(ctx, query, args...)
	var id, tenantID, endpoint, currency, status, txID, idemKey, createdAt, updatedAt string
	var cents int64
	if err := row.Scan(&id, &tenantID, &endpoint, &cents, &currency, &status, &txID, &idemKey, &createdAt, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, fmt.Errorf("scan payment: %w", err)
	}
	money, err := shared.NewMoney(cents, currency)
	if err != nil {
		return nil, fmt.Errorf("rehydrate money: %w", err)
	}
	return payment.Rehydrate(id, tenantID, endpoint, idemKey, txID, money, payment.Status(status), parseTime(createdAt), parseTime(updatedAt)), nil
}

// --- Pricing ---

// GetEndpointPrice returns the price for a tenant × endpoint or ErrNotFound.
func (r repo) GetEndpointPrice(ctx context.Context, tenantID, endpoint string) (billing.EndpointPricing, error) {
	row := r.q.QueryRowContext(ctx,
		`SELECT tenant_id, endpoint, price_cents FROM endpoint_pricing WHERE tenant_id = ? AND endpoint = ?`,
		tenantID, endpoint)
	var gotTenant, gotEndpoint string
	var price int64
	if err := row.Scan(&gotTenant, &gotEndpoint, &price); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return billing.EndpointPricing{}, shared.ErrNotFound
		}
		return billing.EndpointPricing{}, fmt.Errorf("scan price: %w", err)
	}
	return billing.NewEndpointPricing(gotTenant, gotEndpoint, price)
}

// UpsertEndpointPrice inserts or updates a pricing rule.
func (r repo) UpsertEndpointPrice(ctx context.Context, p billing.EndpointPricing) error {
	_, err := r.q.ExecContext(ctx,
		`INSERT INTO endpoint_pricing (tenant_id, endpoint, price_cents) VALUES (?, ?, ?)
		 ON CONFLICT(tenant_id, endpoint) DO UPDATE SET price_cents = excluded.price_cents`,
		p.TenantID(), p.Endpoint(), p.PriceCents())
	if err != nil {
		return fmt.Errorf("upsert price: %w", err)
	}
	return nil
}

// ListEndpointPrices returns a tenant's pricing rules ordered by endpoint.
func (s *Store) ListEndpointPrices(ctx context.Context, tenantID string) ([]billing.EndpointPricing, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT tenant_id, endpoint, price_cents FROM endpoint_pricing WHERE tenant_id = ? ORDER BY endpoint ASC`,
		tenantID)
	if err != nil {
		return nil, fmt.Errorf("query prices: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []billing.EndpointPricing
	for rows.Next() {
		var gotTenant, endpoint string
		var price int64
		if err := rows.Scan(&gotTenant, &endpoint, &price); err != nil {
			return nil, fmt.Errorf("scan price: %w", err)
		}
		p, err := billing.NewEndpointPricing(gotTenant, endpoint, price)
		if err != nil {
			return nil, fmt.Errorf("rehydrate price: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate prices: %w", err)
	}
	return out, nil
}

// --- Ledger ---

// AppendLedgerEntry appends a billable event (append-only). account_id carries the
// charged tenant's owning account (two-level tenancy metering, SIN-69127); a
// self-account is stored as NULL (NULL-safe, matching migration 0007's backfill).
func (r repo) AppendLedgerEntry(ctx context.Context, e billing.LedgerEntry) error {
	_, err := r.q.ExecContext(ctx,
		`INSERT INTO billing_ledger (id, tenant_id, endpoint, price_cents, reference, at, account_id) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		e.ID(), e.TenantID(), e.Endpoint(), e.PriceCents(), e.Reference(), e.At().Format(tsLayout), nullIfEmpty(e.AccountID()))
	if err != nil {
		return fmt.Errorf("append ledger: %w", err)
	}
	return nil
}

// ListLedgerEntries returns one tenant's ledger entries, newest-first (at desc,
// id desc tie-break). Tenant-scoped (threat P1).
func (s *Store) ListLedgerEntries(ctx context.Context, tenantID string) ([]billing.LedgerEntry, error) {
	return s.scanLedger(ctx,
		`SELECT id, tenant_id, endpoint, price_cents, reference, at, account_id FROM billing_ledger
		 WHERE tenant_id = ? ORDER BY at DESC, id DESC`, tenantID)
}

// ListLedgerEntriesByAccount returns every ledger entry owned by one account,
// across all of its tenants, newest-first. It is the read side of the
// account→tenant→endpoint metering rollup (SIN-69127) — the app layer groups the
// returned entries by tenant then endpoint. The scan is served by the
// ix_ledger_account_at index (migration 0007). Account-scoped: an account only
// ever sees its own tenants' entries.
func (s *Store) ListLedgerEntriesByAccount(ctx context.Context, accountID string) ([]billing.LedgerEntry, error) {
	return s.scanLedger(ctx,
		`SELECT id, tenant_id, endpoint, price_cents, reference, at, account_id FROM billing_ledger
		 WHERE account_id = ? ORDER BY at DESC, id DESC`, accountID)
}

// scanLedger runs a ledger SELECT (whose column order is id, tenant_id, endpoint,
// price_cents, reference, at, account_id) and rehydrates each row into a
// billing.LedgerEntry. A NULL account_id (a self-account, or a row written before
// the account dimension existed) rehydrates to the empty account — NULL-safe.
func (s *Store) scanLedger(ctx context.Context, query string, args ...any) ([]billing.LedgerEntry, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query ledger: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []billing.LedgerEntry
	for rows.Next() {
		var id, gotTenant, endpoint, reference, at string
		var account sql.NullString
		var price int64
		if err := rows.Scan(&id, &gotTenant, &endpoint, &price, &reference, &at, &account); err != nil {
			return nil, fmt.Errorf("scan ledger: %w", err)
		}
		e, err := billing.NewLedgerEntry(id, gotTenant, endpoint, reference, price, parseTime(at),
			billing.WithAccount(account.String))
		if err != nil {
			return nil, fmt.Errorf("rehydrate ledger: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate ledger: %w", err)
	}
	return out, nil
}

// --- Processed events (idempotency) ---

// MarkProcessed atomically records an event key for a tenant. Returns false if
// the key was already present (duplicate/replay).
func (r repo) MarkProcessed(ctx context.Context, tenantID, eventKey string) (bool, error) {
	res, err := r.q.ExecContext(ctx,
		`INSERT INTO processed_events (tenant_id, event_key, processed_at) VALUES (?, ?, ?)
		 ON CONFLICT(tenant_id, event_key) DO NOTHING`,
		tenantID, eventKey, time.Now().UTC().Format(tsLayout))
	if err != nil {
		return false, fmt.Errorf("mark processed: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("rows affected: %w", err)
	}
	return n > 0, nil
}

// isUniqueViolation reports whether err is a SQLite UNIQUE constraint failure.
// On the payments table the only such constraint reachable from an INSERT (the
// primary key is absorbed by ON CONFLICT(id) DO UPDATE) is the per-tenant
// idempotency-key index, so the use-case can treat it as an idempotency conflict.
func isUniqueViolation(err error) bool {
	return strings.Contains(err.Error(), "UNIQUE constraint failed")
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// nullIfEmpty maps an empty string to a SQL NULL and any other value to itself,
// so an unset optional column (e.g. a self-account tenant's account_id) is stored
// as NULL rather than ” — preserving the NULL-safe semantics of migration 0007.
func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func parseTime(s string) time.Time {
	t, err := time.Parse(tsLayout, s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// --- Invoices (Faturas, SIN-69121) ---

// SaveInvoice persists a generated invoice append-only: the header and its line
// items are written together in ONE transaction so a reader never sees a header
// without its body (and a mid-write failure leaves nothing behind). There is no
// UPDATE/DELETE path — regenerating a period inserts a new invoice id.
func (s *Store) SaveInvoice(ctx context.Context, inv invoice.Invoice) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin invoice tx: %w", err)
	}
	// Roll back on any early return; the successful path commits and this is a no-op.
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO invoices (id, tenant_id, account_id, period_start, period_end, total_calls, total_cents, generated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		inv.ID(), inv.TenantID(), inv.AccountID(),
		inv.PeriodStart().UTC().Format(tsLayout), inv.PeriodEnd().UTC().Format(tsLayout),
		inv.TotalCalls(), inv.TotalCents(), inv.GeneratedAt().UTC().Format(tsLayout)); err != nil {
		return fmt.Errorf("insert invoice: %w", err)
	}
	for i, l := range inv.Lines() {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO invoice_items (invoice_id, seq, endpoint, calls, subtotal_cents) VALUES (?, ?, ?, ?, ?)`,
			inv.ID(), i, l.Endpoint(), l.Calls(), l.SubtotalCents()); err != nil {
			return fmt.Errorf("insert invoice item: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit invoice tx: %w", err)
	}
	return nil
}

// FindInvoiceByID returns one invoice with its line items, tenant-scoped (threat
// P1: the tenant comes from the authenticated console session, never client
// input). Returns shared.ErrNotFound when the id is unknown for the tenant.
func (s *Store) FindInvoiceByID(ctx context.Context, tenantID, id string) (invoice.Invoice, error) {
	var accountID, ps, pe, gen string
	var totalCalls int
	var totalCents int64
	err := s.db.QueryRowContext(ctx,
		`SELECT account_id, period_start, period_end, total_calls, total_cents, generated_at
		 FROM invoices WHERE tenant_id = ? AND id = ?`, tenantID, id).
		Scan(&accountID, &ps, &pe, &totalCalls, &totalCents, &gen)
	if errors.Is(err, sql.ErrNoRows) {
		return invoice.Invoice{}, shared.ErrNotFound
	}
	if err != nil {
		return invoice.Invoice{}, fmt.Errorf("query invoice: %w", err)
	}
	lines, err := s.invoiceItems(ctx, id)
	if err != nil {
		return invoice.Invoice{}, err
	}
	return invoice.Rehydrate(id, tenantID, accountID, parseTime(ps), parseTime(pe), parseTime(gen), lines, totalCalls, totalCents), nil
}

// ListInvoices returns a tenant's invoices, newest-first (generated_at desc, id
// desc tie-break), each with its line items. Tenant-scoped (threat P1).
func (s *Store) ListInvoices(ctx context.Context, tenantID string) ([]invoice.Invoice, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, account_id, period_start, period_end, total_calls, total_cents, generated_at
		 FROM invoices WHERE tenant_id = ? ORDER BY generated_at DESC, id DESC`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("query invoices: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []invoice.Invoice
	for rows.Next() {
		var id, accountID, ps, pe, gen string
		var totalCalls int
		var totalCents int64
		if err := rows.Scan(&id, &accountID, &ps, &pe, &totalCalls, &totalCents, &gen); err != nil {
			return nil, fmt.Errorf("scan invoice: %w", err)
		}
		lines, err := s.invoiceItems(ctx, id)
		if err != nil {
			return nil, err
		}
		out = append(out, invoice.Rehydrate(id, tenantID, accountID, parseTime(ps), parseTime(pe), parseTime(gen), lines, totalCalls, totalCents))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate invoices: %w", err)
	}
	return out, nil
}

// invoiceItems reads one invoice's line items in stored document order (seq asc).
func (s *Store) invoiceItems(ctx context.Context, invoiceID string) ([]invoice.LineItem, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT endpoint, calls, subtotal_cents FROM invoice_items WHERE invoice_id = ? ORDER BY seq ASC`, invoiceID)
	if err != nil {
		return nil, fmt.Errorf("query invoice items: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []invoice.LineItem
	for rows.Next() {
		var endpoint string
		var calls int
		var subtotal int64
		if err := rows.Scan(&endpoint, &calls, &subtotal); err != nil {
			return nil, fmt.Errorf("scan invoice item: %w", err)
		}
		l, err := invoice.NewLineItem(endpoint, calls, subtotal)
		if err != nil {
			return nil, fmt.Errorf("rehydrate invoice item: %w", err)
		}
		out = append(out, l)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate invoice items: %w", err)
	}
	return out, nil
}

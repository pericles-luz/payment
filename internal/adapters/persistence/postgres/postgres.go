// Package postgres is the PostgreSQL-backed persistence adapter implementing the
// repository ports. It mirrors the sibling sqlite adapter query for query — same
// SQL, same tenant scoping (threats P1/P2), same ports — and the two are chosen
// by cmd wiring without the domain or the use-cases knowing which is in play.
//
// What genuinely differs from sqlite, and why (SIN-70xxx, migração lmhost):
//
//   - Placeholders are $N, not ?.
//   - A unique violation is SQLSTATE 23505, not a message substring. See
//     isUniqueViolation — getting this wrong disables the anti-double-charge path
//     silently.
//   - ClaimPendingDeliveries takes a row lock (FOR UPDATE SKIP LOCKED), so more
//     than one forwarder can drain the outbox without delivering twice.
//   - Migrations come from migrations/pg (BLOB->BYTEA, cents->BIGINT) and are
//     applied through the simple query protocol, which accepts multi-statement
//     files.
//   - tsLayout is fixed-width; see the constant.
package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	// database/sql driver for pgx. The adapter deliberately stays on database/sql
	// (rather than pgxpool) so the dbtx seam below is identical to sqlite's.
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/ia-dev-sindireceita/payment/internal/domain/account"
	"github.com/ia-dev-sindireceita/payment/internal/domain/billing"
	"github.com/ia-dev-sindireceita/payment/internal/domain/invoice"
	"github.com/ia-dev-sindireceita/payment/internal/domain/payment"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// tsLayout is the wire format for every timestamp column, which is TEXT here just
// as it is in sqlite so the two adapters read each other's rows during migration.
//
// It is NOT time.RFC3339Nano, and that is the point. RFC3339Nano trims trailing
// zeros from the fraction, so "…T00:00:00Z" and "…T00:00:00.5Z" have different
// widths and compare wrong as text: at index 19, 'Z' (0x5A) sorts AFTER '.'
// (0x2E), which puts a whole second BEFORE a fraction of that same second. Every
// ORDER BY at/created_at/granted_at and the LGPD purge's `at < $1` inherit that
// bug. A fixed-width fraction makes lexical order agree with chronological order.
//
// The ETL normalises existing rows to this width on the way in, so a migrated
// database has no mixed-width leftovers.
const tsLayout = "2006-01-02T15:04:05.000000000Z07:00"

// Open opens a PostgreSQL database at dsn (a libpq URL or keyword/value string)
// and configures the connection pool. The returned *sql.DB is owned by the caller.
//
// Unlike the sqlite adapter there is no PRAGMA step: foreign keys are always
// enforced. Worth knowing when reading migrated data — sqlite ran
// `PRAGMA foreign_keys = ON` on a single pooled connection and never bounded the
// pool, so FK enforcement there was inconsistent, and rows that slipped through
// will be rejected on the way in.
//
// The pool is bounded on purpose. This database is a shared cluster (data.lmhost),
// so an unbounded pool turns a traffic spike here into max_connections exhaustion
// for every other tenant of that box.
func Open(dsn string) (*sql.DB, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)
	db.SetConnMaxLifetime(connMaxLifetime)
	return db, nil
}

// Pool bounds. Sized for a single API instance against a shared cluster, not for
// throughput: the workload is a handful of short transactions per request.
const (
	maxOpenConns    = 10
	maxIdleConns    = 5
	connMaxLifetime = 30 * time.Minute
)

// Migrate applies every *.up.sql file from the given filesystem in lexical order,
// each exactly once, recording applied files in a schema_migrations ledger. Pass
// pgmigrations.FS (migrations/pg) — NOT the SQLite set, which declares BLOB
// columns Postgres has no type for.
//
// The ledger has the same shape and the same file names as the sqlite adapter's,
// so a database migrated from SQLite carries its history across unchanged and the
// 18 existing files are recognised as already applied.
//
// Each file is sent as one multi-statement batch wrapped in BEGIN/COMMIT through
// the SIMPLE query protocol. pgx's default extended protocol allows exactly one
// statement per Exec, and the migration files hold many; splitting them here would
// mean writing a SQL parser to find the statement boundaries. Postgres has
// transactional DDL, so the wrapping gives the same all-or-nothing guarantee the
// sqlite runner gets from its explicit transaction: a failure leaves neither the
// schema half-changed nor the file marked applied.
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
			`SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE name = $1)`, name).Scan(&applied); err != nil {
			return fmt.Errorf("check migration %s: %w", name, err)
		}
		if applied {
			continue
		}
		b, err := fs.ReadFile(fsys, name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}
		batch := "BEGIN;\n" + string(b) + "\n" +
			"INSERT INTO schema_migrations (name, applied_at) VALUES (" +
			quoteLiteral(name) + ", " + quoteLiteral(time.Now().UTC().Format(tsLayout)) + ");\nCOMMIT;"
		if err := execSimple(ctx, db, batch); err != nil {
			return fmt.Errorf("apply migration %s: %w", name, err)
		}
	}
	return nil
}

// execSimple runs a multi-statement batch through the simple query protocol by
// reaching past database/sql to the underlying pgx connection. This is the only
// place in the adapter that does so, and it only ever runs migration files that
// ship embedded in the binary.
func execSimple(ctx context.Context, db *sql.DB, batch string) error {
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire conn: %w", err)
	}
	defer func() { _ = conn.Close() }()
	return conn.Raw(func(driverConn any) error {
		c, ok := driverConn.(interface{ Conn() *pgx.Conn })
		if !ok {
			return errors.New("driver connection is not pgx")
		}
		return c.Conn().PgConn().Exec(ctx, batch).Close()
	})
}

// quoteLiteral renders a Go string as a SQL string literal. Needed because the
// simple query protocol carries no out-of-band parameters, so the two values the
// ledger insert writes have to be inlined. Both are ours (an embedded file name
// and a formatted timestamp), never user input, and doubling the quote keeps even
// a hand-added file name with an apostrophe from breaking out.
func quoteLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
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
		`INSERT INTO tenants (id, name, active, created_at, account_id) VALUES ($1, $2, $3, $4, $5)
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
	row := r.q.QueryRowContext(ctx, `SELECT id, name, active, created_at, account_id FROM tenants WHERE id = $1`, id)
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
		`INSERT INTO accounts (id, name, active, created_at) VALUES ($1, $2, $3, $4)
		 ON CONFLICT(id) DO UPDATE SET name = excluded.name, active = excluded.active`,
		a.ID(), a.Name(), boolToInt(a.Active()), a.CreatedAt().Format(tsLayout))
	if err != nil {
		return fmt.Errorf("save account: %w", err)
	}
	return nil
}

// FindAccountByID returns an account or ErrNotFound.
func (r repo) FindAccountByID(ctx context.Context, id string) (*account.Account, error) {
	row := r.q.QueryRowContext(ctx, `SELECT id, name, active, created_at FROM accounts WHERE id = $1`, id)
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
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
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
		 FROM payments WHERE tenant_id = $1 AND id = $2`, tenantID, id)
}

// FindPaymentByIdempotencyKey returns a tenant-scoped payment by idempotency key.
func (r repo) FindPaymentByIdempotencyKey(ctx context.Context, tenantID, key string) (*payment.Payment, error) {
	return r.queryPayment(ctx,
		`SELECT id, tenant_id, endpoint, amount_cents, currency, status, tx_id, idempotency_key, created_at, updated_at
		 FROM payments WHERE tenant_id = $1 AND idempotency_key = $2`, tenantID, key)
}

// FindPaymentByTxID returns a tenant-scoped payment by bank tx id.
func (r repo) FindPaymentByTxID(ctx context.Context, tenantID, txID string) (*payment.Payment, error) {
	return r.queryPayment(ctx,
		`SELECT id, tenant_id, endpoint, amount_cents, currency, status, tx_id, idempotency_key, created_at, updated_at
		 FROM payments WHERE tenant_id = $1 AND tx_id = $2`, tenantID, txID)
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
		`SELECT tenant_id, endpoint, price_cents FROM endpoint_pricing WHERE tenant_id = $1 AND endpoint = $2`,
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
		`INSERT INTO endpoint_pricing (tenant_id, endpoint, price_cents) VALUES ($1, $2, $3)
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
		`SELECT tenant_id, endpoint, price_cents FROM endpoint_pricing WHERE tenant_id = $1 ORDER BY endpoint ASC`,
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
		`INSERT INTO billing_ledger (id, tenant_id, endpoint, price_cents, reference, at, account_id) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
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
		 WHERE tenant_id = $1 ORDER BY at DESC, id DESC`, tenantID)
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
		 WHERE account_id = $1 ORDER BY at DESC, id DESC`, accountID)
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
		`INSERT INTO processed_events (tenant_id, event_key, processed_at) VALUES ($1, $2, $3)
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

// isUniqueViolation reports whether err is a Postgres unique-constraint violation
// (SQLSTATE 23505). On the payments table the only such constraint reachable from
// an INSERT (the primary key is absorbed by ON CONFLICT(id) DO UPDATE) is the
// per-tenant idempotency-key index, so the use-case can treat it as an idempotency
// conflict and resolve the race instead of double-charging.
//
// This is matched on the SQLSTATE code, never on the message text. The sqlite
// adapter matches the substring "UNIQUE constraint failed", which Postgres never
// emits; carrying that check over would have made this function silently return
// false, turned every idempotency race into a generic 500, and broken the
// anti-double-charge path without a single failing test to show for it.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == pgErrUniqueViolation
}

// pgErrUniqueViolation is SQLSTATE 23505.
const pgErrUniqueViolation = "23505"

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
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		inv.ID(), inv.TenantID(), inv.AccountID(),
		inv.PeriodStart().UTC().Format(tsLayout), inv.PeriodEnd().UTC().Format(tsLayout),
		inv.TotalCalls(), inv.TotalCents(), inv.GeneratedAt().UTC().Format(tsLayout)); err != nil {
		return fmt.Errorf("insert invoice: %w", err)
	}
	for i, l := range inv.Lines() {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO invoice_items (invoice_id, seq, endpoint, calls, subtotal_cents) VALUES ($1, $2, $3, $4, $5)`,
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
		 FROM invoices WHERE tenant_id = $1 AND id = $2`, tenantID, id).
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
		 FROM invoices WHERE tenant_id = $1 ORDER BY generated_at DESC, id DESC`, tenantID)
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
		`SELECT endpoint, calls, subtotal_cents FROM invoice_items WHERE invoice_id = $1 ORDER BY seq ASC`, invoiceID)
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

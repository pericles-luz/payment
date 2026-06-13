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

	"github.com/ia-dev-sindireceita/payment/internal/domain/billing"
	"github.com/ia-dev-sindireceita/payment/internal/domain/payment"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

const tsLayout = time.RFC3339Nano

// Open opens a SQLite database at dsn (e.g. a file path or ":memory:") with
// foreign keys enabled. The returned *sql.DB is owned by the caller.
func Open(dsn string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if _, err := db.Exec("PRAGMA foreign_keys = ON;"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("enable foreign keys: %w", err)
	}
	return db, nil
}

// Migrate applies all *.up.sql files from the given filesystem in lexical order.
func Migrate(ctx context.Context, db *sql.DB, fsys fs.FS) error {
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
		b, err := fs.ReadFile(fsys, name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}
		if _, err := db.ExecContext(ctx, string(b)); err != nil {
			return fmt.Errorf("apply migration %s: %w", name, err)
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

// SaveTenant inserts or updates a tenant.
func (r repo) SaveTenant(ctx context.Context, t *tenant.Tenant) error {
	_, err := r.q.ExecContext(ctx,
		`INSERT INTO tenants (id, name, active, created_at) VALUES (?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET name = excluded.name, active = excluded.active`,
		t.ID(), t.Name(), boolToInt(t.Active()), t.CreatedAt().Format(tsLayout))
	if err != nil {
		return fmt.Errorf("save tenant: %w", err)
	}
	return nil
}

// FindTenantByID returns a tenant or ErrNotFound.
func (r repo) FindTenantByID(ctx context.Context, id string) (*tenant.Tenant, error) {
	row := r.q.QueryRowContext(ctx, `SELECT id, name, active, created_at FROM tenants WHERE id = ?`, id)
	var gotID, name, createdAt string
	var active int
	if err := row.Scan(&gotID, &name, &active, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, fmt.Errorf("scan tenant: %w", err)
	}
	return tenant.Rehydrate(gotID, name, active != 0, parseTime(createdAt)), nil
}

// ListTenants returns every tenant, newest-first (created_at desc, id desc as a
// deterministic tie-break). Used by the admin console listing.
func (s *Store) ListTenants(ctx context.Context) ([]*tenant.Tenant, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, active, created_at FROM tenants ORDER BY created_at DESC, id DESC`)
	if err != nil {
		return nil, fmt.Errorf("query tenants: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*tenant.Tenant
	for rows.Next() {
		var id, name, createdAt string
		var active int
		if err := rows.Scan(&id, &name, &active, &createdAt); err != nil {
			return nil, fmt.Errorf("scan tenant: %w", err)
		}
		out = append(out, tenant.Rehydrate(id, name, active != 0, parseTime(createdAt)))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tenants: %w", err)
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

// AppendLedgerEntry appends a billable event (append-only).
func (r repo) AppendLedgerEntry(ctx context.Context, e billing.LedgerEntry) error {
	_, err := r.q.ExecContext(ctx,
		`INSERT INTO billing_ledger (id, tenant_id, endpoint, price_cents, reference, at) VALUES (?, ?, ?, ?, ?, ?)`,
		e.ID(), e.TenantID(), e.Endpoint(), e.PriceCents(), e.Reference(), e.At().Format(tsLayout))
	if err != nil {
		return fmt.Errorf("append ledger: %w", err)
	}
	return nil
}

// ListLedgerEntries returns one tenant's ledger entries, newest-first (at desc,
// id desc tie-break). Tenant-scoped (threat P1).
func (s *Store) ListLedgerEntries(ctx context.Context, tenantID string) ([]billing.LedgerEntry, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, tenant_id, endpoint, price_cents, reference, at FROM billing_ledger
		 WHERE tenant_id = ? ORDER BY at DESC, id DESC`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("query ledger: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []billing.LedgerEntry
	for rows.Next() {
		var id, gotTenant, endpoint, reference, at string
		var price int64
		if err := rows.Scan(&id, &gotTenant, &endpoint, &price, &reference, &at); err != nil {
			return nil, fmt.Errorf("scan ledger: %w", err)
		}
		e, err := billing.NewLedgerEntry(id, gotTenant, endpoint, reference, price, parseTime(at))
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

func parseTime(s string) time.Time {
	t, err := time.Parse(tsLayout, s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

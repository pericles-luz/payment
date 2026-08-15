package app

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/account"
	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
	"github.com/ia-dev-sindireceita/payment/internal/domain/invoice"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
)

// account_console.go holds the console use-cases for the two-level tenancy admin
// plane (SIN-69157, spec SIN-69122): the Contas CRUD, the empresas-clientes
// nested under an account, the account→tenant usage rollup, and the account-scoped
// Faturas. It sits on top of the account domain (F0/SIN-69124), the account-scoped
// ledger reader (F2/SIN-69127) and the invoice store (SIN-69121) — all already
// merged. Nothing here crosses a domain boundary: creating a tenant already-linked
// binds an owner while the tenant is still a self-account (tenant.AssignAccount from
// empty, ADR-0009 §3.2), never re-parents an existing one (that is C5, CTO-gated).

// ErrAccountsUnavailable is returned by the account use-cases when the console was
// wired without an AccountStore (a misconfiguration in production; some wiring-light
// tests omit it). The HTTP adapter maps it to 503, mirroring ErrInvoicesUnavailable.
var ErrAccountsUnavailable = errors.New("account store not configured")

// effectiveAccountID resolves the account a tenant belongs to: its explicit owner
// when bound, else the deterministic self-account derived from the tenant id
// (ADR-0009 §4 NULL-safe legacy semantics). This is the single place the "who owns
// this tenant" question is answered for the admin rollup, matching the ledger's own
// backfill ('acct-' || tenant_id).
func effectiveAccountID(t *tenant.Tenant) string {
	if a := strings.TrimSpace(t.AccountID()); a != "" {
		return a
	}
	return account.SelfAccountID(t.ID())
}

// AccountListItem is one row of the Contas screen: the account plus the number of
// empresas-clientes it owns (the count is a rollup over the tenant listing, so a
// brand-new account reads zero without any extra bookkeeping).
type AccountListItem struct {
	Account     *account.Account
	TenantCount int
}

// ListAccountsQuery describes a filtered account listing for the Contas screen.
type ListAccountsQuery struct {
	Search string       // case-insensitive substring over the account name
	Status StatusFilter // lifecycle filter (reuses the tenant status vocabulary)
	// IncludeSelf surfaces the per-tenant self-accounts (the "acct-<tenantID>"
	// legacy rows backfilled by migration 0007). They are hidden by default (§6) so
	// the list is not polluted by one implicit account per flat legacy tenant; the
	// toggle shows them for migration/inspection.
	IncludeSelf bool
}

// ListAccounts returns the accounts matching q, newest-first, each stamped with its
// empresa-cliente count. Self-accounts are filtered out unless q.IncludeSelf is set.
func (s *ConsoleService) ListAccounts(ctx context.Context, q ListAccountsQuery) ([]AccountListItem, error) {
	if s.accounts == nil {
		return nil, ErrAccountsUnavailable
	}
	all, err := s.accounts.ListAccounts(ctx)
	if err != nil {
		return nil, fmt.Errorf("list accounts: %w", err)
	}
	counts, err := s.tenantCountsByAccount(ctx)
	if err != nil {
		return nil, err
	}
	needle := strings.ToLower(strings.TrimSpace(q.Search))
	out := make([]AccountListItem, 0, len(all))
	for _, a := range all {
		if !q.IncludeSelf && account.IsSelfAccountID(a.ID()) {
			continue
		}
		if !matchesAccountStatus(a, q.Status) {
			continue
		}
		if needle != "" && !strings.Contains(strings.ToLower(a.Name()), needle) {
			continue
		}
		out = append(out, AccountListItem{Account: a, TenantCount: counts[a.ID()]})
	}
	sort.SliceStable(out, func(i, j int) bool {
		ci, cj := out[i].Account.CreatedAt(), out[j].Account.CreatedAt()
		if ci.Equal(cj) {
			return out[i].Account.ID() > out[j].Account.ID()
		}
		return ci.After(cj)
	})
	return out, nil
}

// tenantCountsByAccount tallies empresas-clientes per owning account over the full
// tenant listing (each tenant resolved to its effective account).
func (s *ConsoleService) tenantCountsByAccount(ctx context.Context) (map[string]int, error) {
	tenants, err := s.tenants.ListTenants(ctx)
	if err != nil {
		return nil, fmt.Errorf("list tenants: %w", err)
	}
	counts := make(map[string]int, len(tenants))
	for _, t := range tenants {
		counts[effectiveAccountID(t)]++
	}
	return counts, nil
}

func matchesAccountStatus(a *account.Account, f StatusFilter) bool {
	switch f {
	case StatusActive:
		return a.Active()
	case StatusSuspended:
		return !a.Active()
	default:
		return true
	}
}

// GetAccount returns an account by id, or shared.ErrNotFound.
func (s *ConsoleService) GetAccount(ctx context.Context, id string) (*account.Account, error) {
	if s.accounts == nil {
		return nil, ErrAccountsUnavailable
	}
	a, err := s.accounts.FindAccountByID(ctx, strings.TrimSpace(id))
	if err != nil {
		return nil, fmt.Errorf("find account: %w", err)
	}
	return a, nil
}

// CreateAccount provisions a new reseller account from the console form (name
// only). The domain enforces the name invariants; a validation error is surfaced
// inline at the boundary. The id is a fresh opaque id (never the "acct-" self
// prefix), so the new account is a real account, distinguishable from a self-account.
func (s *ConsoleService) CreateAccount(ctx context.Context, name string) (*account.Account, error) {
	if s.accounts == nil {
		return nil, ErrAccountsUnavailable
	}
	a, err := account.New(s.ids.NewID(), name, s.clock.Now())
	if err != nil {
		return nil, err
	}
	if err := s.accounts.SaveAccount(ctx, a); err != nil {
		return nil, fmt.Errorf("save account: %w", err)
	}
	return a, nil
}

// RenameAccount edits an account's display name (ADR-0012 §1). The domain enforces
// the name invariants AND refuses a derived self-account (its name reflects the
// underlying empresa-cliente) — both surface as a validation error at the boundary.
// A missing account yields the same clean 404 as the other account use-cases (no
// enumeration oracle, OWASP A01). The rename is audited (account.rename); the audit
// records only who/which-account/when — never the name value.
func (s *ConsoleService) RenameAccount(ctx context.Context, id, name string) (*account.Account, error) {
	return s.accountTransition(ctx, id, audit.ActionRenameAccount, func(a *account.Account) error {
		return a.Rename(name)
	})
}

// DeactivateAccount suspends an account (soft-delete / reversible, ADR-0012 §3).
// v1: an administrative label; the empresa-cliente auth coupling is enforced by the
// account-key guard (ADR-0011 B2), which already rejects a key on an inactive
// account. Audited (account.suspend).
func (s *ConsoleService) DeactivateAccount(ctx context.Context, id string) (*account.Account, error) {
	return s.accountTransition(ctx, id, audit.ActionSuspendAccount, func(a *account.Account) error {
		a.Deactivate()
		return nil
	})
}

// SuspendAccount suspends an account (reversible). Retained name alongside
// DeactivateAccount (ADR-0012 §3) for the existing console callers; both audit as
// account.suspend.
func (s *ConsoleService) SuspendAccount(ctx context.Context, id string) (*account.Account, error) {
	return s.DeactivateAccount(ctx, id)
}

// ActivateAccount re-enables a suspended account (ADR-0012 §3). Audited
// (account.activate). Returns the updated account.
func (s *ConsoleService) ActivateAccount(ctx context.Context, id string) (*account.Account, error) {
	return s.accountTransition(ctx, id, audit.ActionActivateAccount, func(a *account.Account) error {
		a.Activate()
		return nil
	})
}

// accountTransition loads an account, applies a mutation (which may reject with a
// validation error, e.g. a self-account rename), persists it and appends the
// account-scoped audit entry for the given action. Fail-closed: an audit-append
// error surfaces rather than silently dropping the forensic trail (mirroring the
// console's credential/creditor-key writes). The audit runs after the save, matching
// the console's other privileged single-store mutations.
func (s *ConsoleService) accountTransition(ctx context.Context, id string, action audit.Action, apply func(*account.Account) error) (*account.Account, error) {
	if s.accounts == nil {
		return nil, ErrAccountsUnavailable
	}
	a, err := s.accounts.FindAccountByID(ctx, strings.TrimSpace(id))
	if err != nil {
		return nil, fmt.Errorf("find account: %w", err)
	}
	if err := apply(a); err != nil {
		return nil, err
	}
	if err := s.accounts.SaveAccount(ctx, a); err != nil {
		return nil, fmt.Errorf("save account: %w", err)
	}
	e, err := audit.NewAccountActionEntry(s.ids.NewID(), OperatorIDFromContext(ctx), action, a.ID(), s.clock.Now())
	if err != nil {
		return nil, fmt.Errorf("build audit entry: %w", err)
	}
	if err := s.audit.Append(ctx, e); err != nil {
		return nil, fmt.Errorf("append audit entry: %w", err)
	}
	return a, nil
}

// ListTenantsByAccount returns the empresas-clientes owned by an account,
// newest-first. It filters the cross-tenant listing by each tenant's effective
// account, so a self-account resolves to exactly its 1:1 legacy tenant and a real
// account to every tenant bound to it. Isolation: only tenants that resolve to
// acctID are returned — the rollup never leaks another account's tenants.
func (s *ConsoleService) ListTenantsByAccount(ctx context.Context, acctID string) ([]*tenant.Tenant, error) {
	acctID = strings.TrimSpace(acctID)
	if acctID == "" {
		return nil, shared.NewValidationError("account_id", "account id is required")
	}
	all, err := s.tenants.ListTenants(ctx)
	if err != nil {
		return nil, fmt.Errorf("list tenants: %w", err)
	}
	out := make([]*tenant.Tenant, 0)
	for _, t := range all {
		if effectiveAccountID(t) == acctID {
			out = append(out, t)
		}
	}
	return out, nil
}

// CreateTenantUnderAccount provisions a new empresa-cliente already bound to an
// existing account. The account must exist (404 clean). The tenant is created as a
// self-account and immediately bound via tenant.AssignAccount — a one-time binding
// FROM empty, which is NOT the re-parenting that C5 gates (ADR-0009 §3.2). A
// validation error (name / binding) surfaces inline at the boundary.
func (s *ConsoleService) CreateTenantUnderAccount(ctx context.Context, acctID, name string) (*tenant.Tenant, error) {
	if s.accounts == nil {
		return nil, ErrAccountsUnavailable
	}
	acctID = strings.TrimSpace(acctID)
	if _, err := s.accounts.FindAccountByID(ctx, acctID); err != nil {
		return nil, fmt.Errorf("resolve account: %w", err)
	}
	t, err := tenant.New(s.ids.NewID(), name, s.clock.Now())
	if err != nil {
		return nil, err
	}
	if err := t.AssignAccount(acctID); err != nil {
		return nil, err
	}
	if err := s.tenants.SaveTenant(ctx, t); err != nil {
		return nil, fmt.Errorf("save tenant: %w", err)
	}
	return t, nil
}

// --- Account-scoped invoices (Faturas na ótica da Conta, spec §5.5) ---

// ListInvoicesByAccount returns every invoice of the account's empresas-clientes,
// newest-first across all of them (generated_at desc, id desc tie-break). v1 is
// invoices per empresa-cliente grouped under the account — there is no
// account-consolidated invoice (a board/pricing decision, spec §7). The account
// must exist (404 clean). Isolation: only the account's own tenants are scanned.
func (s *ConsoleService) ListInvoicesByAccount(ctx context.Context, acctID string) ([]invoice.Invoice, error) {
	if s.invoices == nil {
		return nil, ErrInvoicesUnavailable
	}
	if s.accounts == nil {
		return nil, ErrAccountsUnavailable
	}
	acctID = strings.TrimSpace(acctID)
	if _, err := s.accounts.FindAccountByID(ctx, acctID); err != nil {
		return nil, fmt.Errorf("resolve account: %w", err)
	}
	tenants, err := s.ListTenantsByAccount(ctx, acctID)
	if err != nil {
		return nil, err
	}
	var out []invoice.Invoice
	for _, t := range tenants {
		invs, err := s.invoices.ListInvoices(ctx, t.ID())
		if err != nil {
			return nil, fmt.Errorf("list invoices: %w", err)
		}
		out = append(out, invs...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		gi, gj := out[i].GeneratedAt(), out[j].GeneratedAt()
		if gi.Equal(gj) {
			return out[i].ID() > out[j].ID()
		}
		return gi.After(gj)
	})
	return out, nil
}

// GenerateBatchOption tunes GenerateAccountInvoices. The only option today is
// WithIdempotencyKey; it is variadic so existing callers (and tests) keep the
// bare three-arg call and get the default append-only behaviour.
type GenerateBatchOption func(*generateBatchConfig)

type generateBatchConfig struct{ idempotencyKey string }

// WithIdempotencyKey attaches a caller-supplied idempotency token to a batch
// invoice generation. A double-submit (double click / CSRF-valid retry) carrying
// the SAME token returns the FIRST submission's invoices instead of appending
// duplicate Faturas (SIN-69184). An empty key disables the guard (today's
// behaviour). A deliberate regeneration carries a FRESH token (the form embeds a
// per-render nonce) and is never collapsed, so the append-only invariant holds.
func WithIdempotencyKey(key string) GenerateBatchOption {
	return func(c *generateBatchConfig) { c.idempotencyKey = key }
}

// GenerateAccountInvoices freezes one invoice per empresa-cliente WITH consumption
// in the bounded window rng — the batch generation of the period on the account's
// ótica (spec §5.5). Each invoice is produced by the same GenerateInvoice path
// (append-only, sum of the recorded ledger, never a recomputed price), so the
// account view reuses exactly the per-tenant billing invariant. Tenants with zero
// consumption in the window are skipped (no empty invoices). The window MUST be
// bounded (an invoice bills a definite period); the account must exist. The returned
// slice is the invoices actually generated, in tenant order.
//
// Idempotency (SIN-69184): when called WithIdempotencyKey, an accidental
// double-submit carrying the same token returns the first submission's invoices
// verbatim instead of generating duplicate Faturas. The guard is process-local and
// TTL-bounded — a double-submit is inherently same-process/same-second, so this
// closes the realistic double-click window; durable cross-instance/cross-restart
// dedup would need a persisted key and is out of scope for this LOW hygiene fix.
func (s *ConsoleService) GenerateAccountInvoices(ctx context.Context, acctID string, rng ConsumptionRange, opts ...GenerateBatchOption) ([]invoice.Invoice, error) {
	var cfg generateBatchConfig
	for _, o := range opts {
		o(&cfg)
	}
	key := strings.TrimSpace(cfg.idempotencyKey)
	if key == "" || s.invoiceGuard == nil {
		return s.generateAccountInvoices(ctx, acctID, rng)
	}
	// Serialize the guarded generation on the idempotency key so two concurrent
	// double-submits (separate goroutines) cannot both miss the cache and both
	// generate. Admin batch invoicing is a rare manual action, so holding the
	// guard across the DB work is operationally free and makes dedup trivially
	// correct. Failures are NOT cached — a retry must still be able to succeed.
	gkey := strings.TrimSpace(acctID) + "\x00" + key
	g := s.invoiceGuard
	g.mu.Lock()
	defer g.mu.Unlock()
	now := s.clock.Now()
	g.pruneLocked(now)
	if invs, ok := g.seen[gkey]; ok {
		return invs.invoices, nil
	}
	invs, err := s.generateAccountInvoices(ctx, acctID, rng)
	if err != nil {
		return nil, err
	}
	g.seen[gkey] = invoiceBatchEntry{invoices: invs, at: now}
	return invs, nil
}

func (s *ConsoleService) generateAccountInvoices(ctx context.Context, acctID string, rng ConsumptionRange) ([]invoice.Invoice, error) {
	if s.invoices == nil {
		return nil, ErrInvoicesUnavailable
	}
	if s.accounts == nil {
		return nil, ErrAccountsUnavailable
	}
	if rng.Start.IsZero() || rng.End.IsZero() {
		return nil, shared.NewValidationError("period", "invoice period start and end are required")
	}
	if !rng.Start.Before(rng.End) {
		return nil, shared.NewValidationError("period", "invoice period start must be before end")
	}
	acctID = strings.TrimSpace(acctID)
	if _, err := s.accounts.FindAccountByID(ctx, acctID); err != nil {
		return nil, fmt.Errorf("resolve account: %w", err)
	}
	tenants, err := s.ListTenantsByAccount(ctx, acctID)
	if err != nil {
		return nil, err
	}
	out := make([]invoice.Invoice, 0, len(tenants))
	for _, t := range tenants {
		rep, err := s.ConsumptionInRange(ctx, t.ID(), rng)
		if err != nil {
			return nil, err
		}
		if rep.TotalCalls == 0 {
			continue // no consumption in the window — nothing to bill for this tenant
		}
		inv, err := s.GenerateInvoice(ctx, t.ID(), rng)
		if err != nil {
			return nil, err
		}
		out = append(out, inv)
	}
	return out, nil
}

// invoiceBatchIdempotencyTTL bounds how long a batch idempotency token is
// remembered. It is generous relative to the double-submit window it guards (a
// double click / retry lands within seconds) while keeping the in-memory map
// small — stale tokens are pruned lazily on the next guarded generation.
const invoiceBatchIdempotencyTTL = 15 * time.Minute

// invoiceBatchEntry is one remembered batch generation: the invoices it produced
// and when, so the guard can both replay the result and expire it.
type invoiceBatchEntry struct {
	invoices []invoice.Invoice
	at       time.Time
}

// invoiceBatchGuard is the process-local, TTL-bounded dedup store for account
// batch invoice generation (SIN-69184). It is keyed by "<acctID>\x00<token>", so
// a token only collapses submits for the same account. The mutex is held across
// the guarded generation (see GenerateAccountInvoices), so no separate reservation
// state is needed.
type invoiceBatchGuard struct {
	mu   sync.Mutex
	ttl  time.Duration
	seen map[string]invoiceBatchEntry
}

func newInvoiceBatchGuard(ttl time.Duration) *invoiceBatchGuard {
	return &invoiceBatchGuard{ttl: ttl, seen: make(map[string]invoiceBatchEntry)}
}

// pruneLocked drops entries older than the TTL. The caller MUST hold g.mu.
func (g *invoiceBatchGuard) pruneLocked(now time.Time) {
	for k, e := range g.seen {
		if now.Sub(e.at) > g.ttl {
			delete(g.seen, k)
		}
	}
}

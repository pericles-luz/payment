// Package stgseed is a boot-time helper that populates the staging STUB with a
// small, synthetic two-level-tenancy dataset so the board can navigate the admin
// console (Contas × empresas-clientes, consumo, faturas) with real screens
// instead of empty tables (SIN-69226, preview for SIN-69225).
//
// It is triple-gated and therefore inert in every real deployment:
//
//  1. Enabled — the operator explicitly set PAYMENT_STG_SEED (opt-in, default off).
//  2. StubMode — the bank adapter is the in-memory stub (PAYMENT_C6_BASE_URL empty).
//     The seed NEVER runs against a real C6 environment, so it can never touch a
//     real credential, a real charge, or real money.
//  3. Empty store — no account and no tenant exist yet. A populated store is a
//     no-op, so the seed is idempotent across restarts and never duplicates data.
//
// Any gate failing yields a silent no-op with a one-line reason. The helper writes
// only through existing use-cases (the ConsoleService account/tenant/invoice
// use-cases) and the append-only ledger port — it never issues SQL and never adds
// a migration (accounts/account_id landed in 0007, invoices in 0008). The data is
// fictional ("Verz", "Empresa Demo A/B") with no PII and no secrets.
package stgseed

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/account"
	"github.com/ia-dev-sindireceita/payment/internal/domain/billing"
	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// Config carries the two environment-derived gate decisions. Both are resolved by
// the caller (cmd/api) from configuration so this package stays free of os.Getenv
// and is trivially testable.
type Config struct {
	// Enabled mirrors PAYMENT_STG_SEED (opt-in, default off).
	Enabled bool
	// StubMode is true when the bank adapter is the in-memory stub, i.e.
	// PAYMENT_C6_BASE_URL is empty. The seed only ever runs in stub mode.
	StubMode bool
}

// AccountLister and TenantLister are the read-only capabilities the seed needs to
// decide whether the store is already populated (the idempotency gate). They are
// deliberately narrow (a single method each) and are satisfied by the concrete
// sqlite/inmemory stores.
type AccountLister interface {
	ListAccounts(ctx context.Context) ([]*account.Account, error)
}

// TenantLister lists every tenant for the emptiness check.
type TenantLister interface {
	ListTenants(ctx context.Context) ([]*tenant.Tenant, error)
}

// Deps bundles the ports/use-cases the seed reuses. Nothing here reaches past a
// port: account/tenant/invoice creation goes through the ConsoleService use-cases
// and consumption is appended through the append-only ledger port.
type Deps struct {
	// Console provides the account/tenant/invoice creation use-cases (SIN-69157 /
	// SIN-69121). Required.
	Console *app.ConsoleService
	// Accounts / Tenants power the emptiness (idempotency) gate. Required.
	Accounts AccountLister
	Tenants  TenantLister
	// Ledger is the append-only billing ledger. The seed writes a handful of
	// synthetic consumption entries through it (WithAccount attribution) so the
	// "Uso por Conta" screens are populated. Required.
	Ledger ports.LedgerRepository
	// Clock / IDs supply the ledger-entry timestamps and ids. Required.
	Clock ports.Clock
	IDs   ports.IDProvider
	// Logger receives the single applied/skipped summary line. Optional: nil uses
	// slog.Default().
	Logger *slog.Logger
}

// Result reports what the seed did, for the boot log. When Applied is false,
// SkipReason explains why (disabled, not stub, or store not empty).
type Result struct {
	Applied    bool
	SkipReason string
	AccountID  string
	Tenants    int
	Entries    int
	Invoices   int
}

// the fictional dataset — synthetic names only, no PII, no secrets.
const (
	seedAccountName = "Verz"
	seedReference   = "stg-seed" // ledger reference tying entries to this helper
)

var seedTenantNames = []string{"Empresa Demo A", "Empresa Demo B"}

// seedEndpoints are the 1–2 billable endpoints the synthetic consumption is spread
// across, each with a fixed unit price (in cents) and call count per tenant. The
// prices are round demo values, not the production tariff.
var seedEndpoints = []struct {
	endpoint   string
	priceCents int64
	calls      int
}{
	{app.PixCreateEndpoint, 500, 3},
	{app.CheckoutCreateEndpoint, 1000, 2},
}

// Apply runs the gated seed. It returns the outcome for logging plus an error only
// on an unexpected failure of an underlying use-case (a gate miss is a nil-error
// no-op, never an error). The caller logs the summary; Apply also emits it so a
// misconfigured boot is visible even if the caller ignores the return.
func Apply(ctx context.Context, cfg Config, d Deps) (Result, error) {
	logger := d.Logger
	if logger == nil {
		logger = slog.Default()
	}

	if !cfg.Enabled {
		return skip(logger, "disabled (PAYMENT_STG_SEED not set)"), nil
	}
	if !cfg.StubMode {
		// Defence in depth: never seed against a real bank environment.
		return skip(logger, "not stub mode (PAYMENT_C6_BASE_URL set)"), nil
	}

	// Idempotency gate: a non-empty store means a previous boot already seeded (or
	// real data exists) — do nothing so restarts never duplicate.
	accts, err := d.Accounts.ListAccounts(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("stg seed: list accounts: %w", err)
	}
	tenants, err := d.Tenants.ListTenants(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("stg seed: list tenants: %w", err)
	}
	if len(accts) > 0 || len(tenants) > 0 {
		return skip(logger, "store not empty"), nil
	}

	res, err := seed(ctx, d)
	if err != nil {
		return Result{}, err
	}
	logger.Info("stg seed applied",
		slog.String("account", seedAccountName),
		slog.String("account_id", res.AccountID),
		slog.Int("tenants", res.Tenants),
		slog.Int("ledger_entries", res.Entries),
		slog.Int("invoices", res.Invoices),
	)
	return res, nil
}

// seed performs the actual population: one account, two empresas-clientes, a few
// consumption entries per tenant, and one batch of account invoices.
func seed(ctx context.Context, d Deps) (Result, error) {
	acct, err := d.Console.CreateAccount(ctx, seedAccountName)
	if err != nil {
		return Result{}, fmt.Errorf("stg seed: create account: %w", err)
	}
	res := Result{Applied: true, AccountID: acct.ID()}

	// earliest ledger timestamp, so the invoice window [start, now+ε) covers it.
	start := d.Clock.Now()
	for _, name := range seedTenantNames {
		t, err := d.Console.CreateTenantUnderAccount(ctx, acct.ID(), name)
		if err != nil {
			return Result{}, fmt.Errorf("stg seed: create tenant %q: %w", name, err)
		}
		res.Tenants++

		for _, se := range seedEndpoints {
			for i := 0; i < se.calls; i++ {
				entry, err := billing.NewLedgerEntry(
					d.IDs.NewID(), t.ID(), se.endpoint, seedReference,
					se.priceCents, d.Clock.Now(), billing.WithAccount(acct.ID()),
				)
				if err != nil {
					return Result{}, fmt.Errorf("stg seed: build ledger entry: %w", err)
				}
				if err := d.Ledger.AppendLedgerEntry(ctx, entry); err != nil {
					return Result{}, fmt.Errorf("stg seed: append ledger entry: %w", err)
				}
				res.Entries++
			}
		}
	}

	// Freeze one Fatura batch for the account over a window that brackets every
	// entry just appended. End is nudged past Now so the half-open [start, end)
	// window includes entries stamped at the current instant.
	rng := app.ConsumptionRange{Start: start.Add(-time.Second), End: d.Clock.Now().Add(time.Minute)}
	invs, err := d.Console.GenerateAccountInvoices(ctx, acct.ID(), rng, app.WithIdempotencyKey(seedReference))
	if err != nil {
		return Result{}, fmt.Errorf("stg seed: generate invoices: %w", err)
	}
	res.Invoices = len(invs)
	return res, nil
}

// skip logs and returns a no-op result with the reason.
func skip(logger *slog.Logger, reason string) Result {
	logger.Info("stg seed skipped", slog.String("reason", reason))
	return Result{Applied: false, SkipReason: reason}
}

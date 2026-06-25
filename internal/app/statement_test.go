package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// fakeStmtProvider is a controllable StatementProvider for the use-case tests: it
// returns a fixed statement and/or a fixed error so the service's domain re-validation
// and error-wrapping paths can be exercised without the stub's window filtering.
type fakeStmtProvider struct {
	res ports.Statement
	err error
}

func (f *fakeStmtProvider) GetStatement(_ context.Context, _ string, _ ports.StatementFilter) (ports.Statement, error) {
	if f.err != nil {
		return ports.Statement{}, f.err
	}
	return f.res, nil
}

// newStatementHarness wires a StatementService over the given provider plus a seeded,
// credentialed tenant. The extrato is not a billable surface, so no pricing is needed.
func newStatementHarness(t *testing.T, prov ports.StatementProvider) (*app.StatementService, string) {
	t.Helper()
	h := newHarness(t)
	h.deps.Statement = prov
	admin := app.NewAdminService(h.deps)
	tn, err := admin.CreateTenant(context.Background(), "Acme")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	h.deps.Credentials.(*secret.Store).Set(tn.ID(), ports.BankCredential{ClientID: "cid", Secret: "shh"})
	return app.NewStatementService(h.deps), tn.ID()
}

func stmtDay(d int) time.Time { return time.Date(2026, 6, d, 0, 0, 0, 0, time.UTC) }

// TestStatementGet covers the happy path (window filtering through the stub) and the
// unknown-tenant guard.
func TestStatementGet(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.deps.Statement = h.bank
	admin := app.NewAdminService(h.deps)
	tn, err := admin.CreateTenant(context.Background(), "Acme")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	h.deps.Credentials.(*secret.Store).Set(tn.ID(), ports.BankCredential{ClientID: "cid", Secret: "shh"})
	h.bank.SeedStatementEntries(tn.ID(), []ports.StatementEntry{
		{ID: "e1", Date: stmtDay(5), AmountCents: 1000, Kind: "credit", Description: "in"},
		{ID: "e2", Date: stmtDay(25), AmountCents: 500, Kind: "debit", Description: "out"},
	})
	svc := app.NewStatementService(h.deps)

	got, err := svc.GetStatement(context.Background(), app.GetStatementInput{
		TenantID: tn.ID(), Start: stmtDay(1), End: stmtDay(10),
	})
	if err != nil {
		t.Fatalf("GetStatement: %v", err)
	}
	if len(got.Entries) != 1 || got.Entries[0].ID != "e1" {
		t.Fatalf("window filter: %+v", got.Entries)
	}

	// Unknown tenant → error (resolve tenant fails).
	if _, err := svc.GetStatement(context.Background(), app.GetStatementInput{
		TenantID: "missing", Start: stmtDay(1), End: stmtDay(10),
	}); err == nil {
		t.Fatal("unknown tenant must error")
	}
}

func TestStatementPeriodValidation(t *testing.T) {
	t.Parallel()
	svc, tenantID := newStatementHarness(t, &fakeStmtProvider{})

	bad := []struct {
		name       string
		start, end time.Time
	}{
		{"fim before inicio", stmtDay(10), stmtDay(1)},
		{"window over 30 days", stmtDay(1), stmtDay(1).Add(31 * 24 * time.Hour)},
		{"missing inicio", time.Time{}, stmtDay(10)},
		{"missing fim", stmtDay(1), time.Time{}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := svc.GetStatement(context.Background(), app.GetStatementInput{
				TenantID: tenantID, Start: tc.start, End: tc.end,
			}); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want ErrValidation, got %v", err)
			}
		})
	}
}

func TestStatementProviderError(t *testing.T) {
	t.Parallel()
	svc, tenantID := newStatementHarness(t, &fakeStmtProvider{err: shared.ErrUnavailable})
	if _, err := svc.GetStatement(context.Background(), app.GetStatementInput{
		TenantID: tenantID, Start: stmtDay(1), End: stmtDay(10),
	}); !errors.Is(err, shared.ErrUnavailable) {
		t.Fatalf("want ErrUnavailable wrapped, got %v", err)
	}
}

// TestStatementMalformedResponseRejected proves the use-case re-validates the PSP
// response through the domain: a malformed entry (here an unknown kind) is rejected
// rather than surfaced (defense in depth).
func TestStatementMalformedResponseRejected(t *testing.T) {
	t.Parallel()
	prov := &fakeStmtProvider{res: ports.Statement{Entries: []ports.StatementEntry{
		{ID: "e1", Date: stmtDay(5), AmountCents: 1000, Kind: "bogus", Description: "in"},
	}}}
	svc, tenantID := newStatementHarness(t, prov)
	if _, err := svc.GetStatement(context.Background(), app.GetStatementInput{
		TenantID: tenantID, Start: stmtDay(1), End: stmtDay(10),
	}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation for malformed entry, got %v", err)
	}
}

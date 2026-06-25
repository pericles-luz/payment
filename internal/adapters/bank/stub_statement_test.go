package bank_test

import (
	"context"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/bank"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

func newStmtStub(t *testing.T) *bank.StubProvider {
	t.Helper()
	creds := secret.NewStore(map[string]ports.BankCredential{
		"t1": {ClientID: "c", Secret: "s"},
		"t2": {ClientID: "c2", Secret: "s2"},
	})
	return bank.NewStubProvider(creds)
}

func stmtDate(d int) time.Time {
	return time.Date(2026, 6, d, 0, 0, 0, 0, time.UTC)
}

func stmtFilter(startDay, endDay int) ports.StatementFilter {
	return ports.StatementFilter{Start: stmtDate(startDay), End: stmtDate(endDay)}
}

func TestStubStatementEmptyByDefault(t *testing.T) {
	t.Parallel()
	p := newStmtStub(t)
	got, err := p.GetStatement(context.Background(), "t1", stmtFilter(1, 30))
	if err != nil || len(got.Entries) != 0 {
		t.Fatalf("empty: %v %v", got, err)
	}
}

func TestStubStatementWindowFilterAndIsolation(t *testing.T) {
	t.Parallel()
	p := newStmtStub(t)
	ctx := context.Background()

	seed := []ports.StatementEntry{
		{ID: "e1", Date: stmtDate(5), AmountCents: 1000, Kind: "credit", Description: "in"},
		{ID: "e2", Date: stmtDate(10), AmountCents: 500, Kind: "debit", Description: "out"},
		{ID: "e3", Date: stmtDate(25), AmountCents: 2000, Kind: "credit", Description: "in2"},
	}
	p.SeedStatementEntries("t1", seed)

	// Window [5,10] includes e1 and e2 (inclusive bounds), excludes e3.
	got, err := p.GetStatement(ctx, "t1", stmtFilter(5, 10))
	if err != nil {
		t.Fatalf("GetStatement: %v", err)
	}
	if len(got.Entries) != 2 || got.Entries[0].ID != "e1" || got.Entries[1].ID != "e2" {
		t.Fatalf("window filter: %+v", got.Entries)
	}

	// Mutating the returned slice must not affect stored state.
	got.Entries[0].ID = "mutated"
	again, _ := p.GetStatement(ctx, "t1", stmtFilter(5, 10))
	if again.Entries[0].ID != "e1" {
		t.Fatal("GetStatement must return a defensive copy")
	}

	// Another tenant sees nothing (isolation).
	if other, _ := p.GetStatement(ctx, "t2", stmtFilter(1, 30)); len(other.Entries) != 0 {
		t.Fatalf("tenant isolation: t2 should see no entries, got %d", len(other.Entries))
	}
}

func TestStubStatementUnknownTenantCredential(t *testing.T) {
	t.Parallel()
	p := newStmtStub(t)
	if _, err := p.GetStatement(context.Background(), "nope", stmtFilter(1, 30)); err == nil {
		t.Fatal("missing credential must error (isolation)")
	}
}

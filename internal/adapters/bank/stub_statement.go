package bank

import (
	"context"

	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// This file extends StubProvider to back ports.StatementProvider (account statement
// / extrato, roteiro grupo 13) in-memory, so the use-case and HTTP route run
// end-to-end in stub mode (PAYMENT_C6_BASE_URL unset) without C6. The behaviour
// mirrors the real C6 adapter's observable contract: per-tenant credential isolation
// resolved on every call (the secret is never logged) and a tenant-scoped read where
// another tenant's entries are never observable (no cross-tenant leak).

// compile-time assertion that StubProvider satisfies the statement port.
var _ ports.StatementProvider = (*StubProvider)(nil)

// SeedStatementEntries sets the statement entries posted to a tenant's account
// (roteiro 13.a) for tests and local dev. It overwrites any previously seeded list
// for the tenant.
func (s *StubProvider) SeedStatementEntries(tenantID string, entries []ports.StatementEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	owned := make([]ports.StatementEntry, len(entries))
	copy(owned, entries)
	s.stmtEntries[tenantID] = owned
}

// GetStatement returns the entries posted to the tenant's account within the filter's
// date window (roteiro 13.a). It resolves the tenant credential first (isolation),
// then returns the entries whose posting date falls within [Start, End] inclusive.
// The result is a fresh slice so a caller cannot mutate the stub's stored state.
func (s *StubProvider) GetStatement(ctx context.Context, tenantID string, filter ports.StatementFilter) (ports.Statement, error) {
	if _, err := s.creds.GetBankCredential(ctx, tenantID); err != nil {
		return ports.Statement{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ports.StatementEntry, 0, len(s.stmtEntries[tenantID]))
	for _, e := range s.stmtEntries[tenantID] {
		// Within window when not before Start and not after End (inclusive bounds).
		if e.Date.Before(filter.Start) || e.Date.After(filter.End) {
			continue
		}
		out = append(out, e)
	}
	return ports.Statement{Entries: out}, nil
}

package app

import (
	"context"
	"fmt"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/domain/statement"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// StatementService orchestrates the account-statement surface (extrato, roteiro
// grupo 13): read the entries posted to the authenticated tenant's account over a
// requested period. The period invariants (fim >= inicio, window <= 30 days) live in
// the statement.Period value object, not here — this service builds the domain period
// first, so an illegal window is refused before the bank is ever called, then
// re-validates the PSP response through the domain (defense in depth) so a malformed
// entry never reaches the caller. The tenant is ALWAYS the authenticated tenant,
// never client input (threat H1/P1): no query/body parameter selects which tenant's
// extrato is read.
type StatementService struct {
	tenants    ports.TenantRepository
	statements ports.StatementProvider
}

// NewStatementService wires a StatementService from the provided ports.
func NewStatementService(d Deps) *StatementService {
	return &StatementService{tenants: d.Tenants, statements: d.Statement}
}

// GetStatementInput is the validated boundary input to read an extrato (roteiro
// 13.a). TenantID is the authenticated tenant; Start/End are the inicio/fim bounds.
type GetStatementInput struct {
	TenantID string
	Start    time.Time
	End      time.Time
}

// requireActiveTenant resolves the authenticated tenant and asserts it is active. It
// is the deny-by-default guard the extrato read runs first.
func (s *StatementService) requireActiveTenant(ctx context.Context, tenantID string) error {
	t, err := s.tenants.FindTenantByID(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("resolve tenant: %w", err)
	}
	if !t.Active() {
		return shared.NewValidationError("tenant", "tenant is not active")
	}
	return nil
}

// GetStatement returns the authenticated tenant's account statement for the requested
// period (roteiro 13.a). The period is validated through the domain (fim >= inicio,
// window <= 30 days) before the bank is called; the returned entries are re-validated
// through the domain so an inconsistent PSP response is rejected rather than surfaced.
func (s *StatementService) GetStatement(ctx context.Context, in GetStatementInput) (ports.Statement, error) {
	if err := s.requireActiveTenant(ctx, in.TenantID); err != nil {
		return ports.Statement{}, err
	}
	period, err := statement.NewPeriod(in.Start, in.End)
	if err != nil {
		return ports.Statement{}, err
	}
	res, err := s.statements.GetStatement(ctx, in.TenantID, ports.StatementFilter{
		Start: period.Start(),
		End:   period.End(),
	})
	if err != nil {
		return ports.Statement{}, fmt.Errorf("bank get statement: %w", err)
	}
	// Re-validate the PSP response through the domain (entries well-formed, tenant
	// present) so a malformed extrato never reaches the caller.
	if _, err := toDomainStatement(in.TenantID, period, res); err != nil {
		return ports.Statement{}, err
	}
	return res, nil
}

// toDomainStatement maps a transported statement onto the domain aggregate, mapping
// each transport entry through the domain entry constructor so a malformed PSP
// response is rejected at the trust boundary (defense in depth).
func toDomainStatement(tenantID string, period statement.Period, res ports.Statement) (statement.Statement, error) {
	entries := make([]statement.Entry, 0, len(res.Entries))
	for _, e := range res.Entries {
		kind, err := statement.ParseEntryKind(e.Kind)
		if err != nil {
			return statement.Statement{}, err
		}
		de, err := statement.NewEntry(e.ID, e.Date, e.AmountCents, kind, e.Description)
		if err != nil {
			return statement.Statement{}, err
		}
		entries = append(entries, de)
	}
	return statement.New(tenantID, period, entries)
}

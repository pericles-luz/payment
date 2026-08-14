package app

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
	"github.com/ia-dev-sindireceita/payment/internal/domain/recurrence"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// RecurrenceService originates recurring charge instances (CobR) for a mandate
// (PIX Automático F4, SIN-66039). Its reason to exist is the CTO acceptance
// invariant carried over from the F3 review (SIN-66037): a recurring charge may be
// created ONLY against an approved mandate (a durable Rec in status APROVADA) of
// the same (tenant_id, id_rec). The bank does not enforce this — the C6/stub
// CreateCobR creates a charge for any idRec — so the gate lives here, BEFORE the
// bank is asked to originate the charge. The same domain rule
// (recurrence.RequireApprovedMandate) guards the settle path when liquidation is
// wired.
//
// The tenant is always the authenticated tenant, never client input (threat
// H1/P1). Origination is idempotent on the charge txid: a retry returns the
// already-persisted charge without charging or auditing twice. The charge and its
// audit record are persisted together in one unit of work so a forensic gap (a
// charge persisted without its audit entry, or vice-versa) cannot open.
type RecurrenceService struct {
	recs  ports.RecRepository
	cobrs ports.CobRRepository
	cobr  ports.CobRProvider
	audit ports.AuditLog
	clock ports.Clock
	ids   ports.IDProvider
	uow   ports.UnitOfWork
}

// NewRecurrenceService wires a RecurrenceService from the provided ports. A nil
// Deps.Audit falls back to a no-op log (unit tests with per-port fakes);
// production MUST wire a real append-only audit log.
func NewRecurrenceService(d Deps) *RecurrenceService {
	a := d.Audit
	if a == nil {
		a = noopAudit{}
	}
	return &RecurrenceService{
		recs:  d.Recs,
		cobrs: d.CobRs,
		cobr:  d.CobRReader,
		audit: a,
		clock: d.Clock,
		ids:   d.IDs,
		uow:   resolveUoW(d),
	}
}

// OriginateCobRInput is the validated boundary input for creating one recurring
// charge instance. TenantID is the authenticated tenant. OperatorID attributes the
// action in the audit trail (server-derived; empty for a non-attributed caller).
type OriginateCobRInput struct {
	TenantID   string
	OperatorID string
	IDRec      string
	TxID       string
	Vencimento string
	ValorCents int64
	// IdempotencyKey collapses retried originations of the same charge at the bank.
	IdempotencyKey string
}

// OriginateCobR creates one recurring charge instance against an APROVADA mandate
// and records it durably. It enforces the referential gate (an approved mandate of
// the same tenant/idRec MUST exist) BEFORE the bank is asked to originate the
// charge, returning recurrence.ErrMandateNotFound / ErrMandateNotApproved /
// ErrMandateMismatch when the gate refuses. A retry with an already-persisted txid
// returns the existing charge (idempotent — no second charge, no second audit).
func (s *RecurrenceService) OriginateCobR(ctx context.Context, in OriginateCobRInput) (*recurrence.CobR, error) {
	tenantID := strings.TrimSpace(in.TenantID)
	if tenantID == "" {
		return nil, shared.NewValidationError("tenant_id", "is required")
	}
	idRec := strings.TrimSpace(in.IDRec)
	if idRec == "" {
		return nil, shared.NewValidationError("id_rec", "is required")
	}
	txID := strings.TrimSpace(in.TxID)
	if txID == "" {
		return nil, shared.NewValidationError("tx_id", "is required")
	}
	if s.cobr == nil {
		return nil, fmt.Errorf("recurrence charge port not configured: %w", shared.ErrUnavailable)
	}

	// Idempotency: a charge already persisted for this txid is returned as-is. It
	// was validly gated and originated by an earlier attempt, so we neither re-call
	// the bank nor re-audit.
	if existing, err := s.cobrs.FindCobRByTxID(ctx, tenantID, txID); err == nil {
		return existing, nil
	} else if !errors.Is(err, shared.ErrNotFound) {
		return nil, fmt.Errorf("idempotency lookup: %w", err)
	}

	// Referential gate (CTO acceptance invariant, SIN-66039): load the durable
	// mandate tenant-scoped and require it be APROVADA before originating a charge.
	rec, err := s.recs.FindRecByID(ctx, tenantID, idRec)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return nil, recurrence.ErrMandateNotFound
		}
		return nil, fmt.Errorf("load mandate: %w", err)
	}
	if err := recurrence.RequireApprovedMandate(rec, tenantID, idRec); err != nil {
		return nil, err
	}

	// Over-charge gate (SIN-66070): a fixed-value mandate caps every charge at the
	// value the payer authorized. Refuse BEFORE the bank is asked to originate, so an
	// amount above the mandate's ceiling never debits the payer.
	if err := recurrence.RequireWithinAuthorizedValue(rec, in.ValorCents); err != nil {
		return nil, err
	}

	// Build the durable charge aggregate (validates txid/idRec/tenant/vencimento and
	// a strictly positive amount).
	cobr, err := recurrence.NewCobR(recurrence.NewCobRParams{
		TxID:       txID,
		IDRec:      idRec,
		TenantID:   tenantID,
		Vencimento: strings.TrimSpace(in.Vencimento),
		ValorCents: in.ValorCents,
	}, s.clock.Now())
	if err != nil {
		return nil, err
	}

	// Originate at the bank. Idempotent on txid (a retry targets the same instance).
	if _, err := s.cobr.CreateCobR(ctx, tenantID, ports.CreateCobRRequest{
		IDRec:          idRec,
		TxID:           txID,
		DataVencimento: cobr.Vencimento(),
		ValorCents:     cobr.ValorCents(),
		IdempotencyKey: strings.TrimSpace(in.IdempotencyKey),
	}); err != nil {
		return nil, fmt.Errorf("bank create cobr: %w", err)
	}

	entry, err := audit.NewCobROriginationEntry(s.ids.NewID(), in.OperatorID, tenantID, txID, s.clock.Now())
	if err != nil {
		return nil, err
	}

	// Persist the charge and its audit record atomically.
	if err := s.uow.WithinTx(ctx, func(r ports.Repository) error {
		if err := r.SaveCobR(ctx, cobr); err != nil {
			return fmt.Errorf("save cobr: %w", err)
		}
		if err := r.Append(ctx, entry); err != nil {
			return fmt.Errorf("append audit: %w", err)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return cobr, nil
}

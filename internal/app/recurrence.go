package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
	"github.com/ia-dev-sindireceita/payment/internal/domain/billing"
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
// Billable endpoint keys for the PIX Automático surface, anchoring per-tenant pricing
// exactly like pix.create / pix.cobv.create. Only the two ORIGINATION writes are
// billed — registering the mandate that a payer will authorize, and originating one
// recurring charge against it. Reads, the activation request, the location mint and a
// cancel are not billed: charging for them would price the recovery paths of a journey
// whose value is the charge itself, and a tenant would be metered for retrying a QR.
const (
	RecCreateEndpoint  = "pix.rec.create"
	CobRCreateEndpoint = "pix.cobr.create"
)

type RecurrenceService struct {
	recs  ports.RecRepository
	cobrs ports.CobRRepository
	cobr  ports.CobRProvider
	// rec / solicRec / locRec are the bank-side write surfaces of the mandate journey:
	// registering a mandate, asking the payer's participant to confirm it, and minting
	// the payload location a composite QR is built on. Any of them may be nil, which
	// makes the matching operation unavailable rather than a panic.
	rec      ports.RecProvider
	solicRec ports.SolicRecProvider
	locRec   ports.LocRecProvider
	tenants  ports.TenantRepository
	pricing  ports.PricingRepository
	audit    ports.AuditLog
	clock    ports.Clock
	ids      ports.IDProvider
	uow      ports.UnitOfWork
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
		recs:     d.Recs,
		cobrs:    d.CobRs,
		cobr:     d.CobRReader,
		rec:      d.RecReader,
		solicRec: d.SolicRecs,
		locRec:   d.LocRecs,
		tenants:  d.Tenants,
		pricing:  d.Pricing,
		audit:    a,
		clock:    d.Clock,
		ids:      d.IDs,
		uow:      resolveUoW(d),
	}
}

// OriginateCobRInput is the validated boundary input for creating one recurring
// charge instance. TenantID is the authenticated tenant. OperatorID attributes the
// action in the audit trail (server-derived; empty for a non-attributed caller).
type OriginateCobRInput struct {
	TenantID string
	// AccountID is the owning account resolved at the auth choke-point, stamped on the
	// ledger for account→tenant→endpoint metering (SIN-69127). Attribution only —
	// isolation is always by TenantID.
	AccountID  string
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

	// Unpriced endpoint = free (bill 0), not a rejection — see resolvePriceOrFree.
	// Resolved BEFORE the bank is asked to originate, so a pricing read failure never
	// leaves a charge created at the bank that we then refuse to record.
	price, err := resolvePriceOrFree(ctx, s.pricing, tenantID, CobRCreateEndpoint)
	if err != nil {
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
	ledger, err := billing.NewLedgerEntry(s.ids.NewID(), tenantID, CobRCreateEndpoint, txID, price.PriceCents(), s.clock.Now(), billing.WithAccount(in.AccountID))
	if err != nil {
		return nil, err
	}

	// Persist the charge, its audit record and its ledger entry atomically. The ledger
	// belongs in the SAME transaction for the same reason the audit entry does: a
	// charge that exists unbilled, or a bill with no charge behind it, is a
	// reconciliation defect nobody can resolve after the fact.
	if err := s.uow.WithinTx(ctx, func(r ports.Repository) error {
		if err := r.SaveCobR(ctx, cobr); err != nil {
			return fmt.Errorf("save cobr: %w", err)
		}
		if err := r.Append(ctx, entry); err != nil {
			return fmt.Errorf("append audit: %w", err)
		}
		if err := r.AppendLedgerEntry(ctx, ledger); err != nil {
			return fmt.Errorf("append ledger: %w", err)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return cobr, nil
}

// ---- mandate journey (Jornada 3: composite QR = immediate charge + recurrence) ----

// CreateLocRecInput asks the bank for a payload location — the URL a composite QR
// points the payer's PSP at to read the mandate parameters. It carries nothing but the
// authenticated tenant and an idempotency anchor: the BACEN contract takes no body, so
// there is no field a caller could use to steer where the location points.
type CreateLocRecInput struct {
	TenantID       string
	IdempotencyKey string
}

// CreateLocRec mints a payload location for the mandate journeys. It is deliberately
// stateless on our side: a location is bank-owned presentation plumbing, carries no
// money and no payer, and is bound to a mandate later by passing its id to
// CreateMandate. Nothing durable is written, so nothing can drift.
func (s *RecurrenceService) CreateLocRec(ctx context.Context, in CreateLocRecInput) (ports.LocRecResult, error) {
	tenantID := strings.TrimSpace(in.TenantID)
	if tenantID == "" {
		return ports.LocRecResult{}, shared.NewValidationError("tenant_id", "is required")
	}
	if s.locRec == nil {
		return ports.LocRecResult{}, fmt.Errorf("recurrence location port not configured: %w", shared.ErrUnavailable)
	}
	return s.locRec.CreateLocRec(ctx, tenantID, strings.TrimSpace(in.IdempotencyKey))
}

// CreateMandateInput is the validated boundary input for registering a recurring-debit
// mandate. TenantID is the authenticated tenant and OperatorID attributes the action in
// the audit trail; both are server-derived, never client input (threat H1/P1).
type CreateMandateInput struct {
	TenantID   string
	AccountID  string
	OperatorID string
	// Contrato and Devedor are the vínculo: what is being charged and who authorized it.
	Contrato    string
	Objeto      string
	DevedorDoc  string
	DevedorNome string
	// DataInicial (yyyy-MM-dd) and Periodicidade are the recurring calendar.
	DataInicial   string
	Periodicidade string
	// PoliticaRetentativa is the BACEN retry policy applied to a failed debit.
	PoliticaRetentativa string
	// LocID binds the mandate to a payload location so the bank can compose a QR.
	// Required for the QR journeys (2/3/4); zero is legal only for the solicrec journey.
	LocID int64
	// JornadaTxID is the txid of the ALREADY-CREATED immediate charge the Jornada 3
	// composite QR settles. It is what ties the first payment to the authorization.
	JornadaTxID string
	// ValorRecCents is the fixed amount each cycle debits. Zero = variable-value
	// mandate. A non-zero value becomes the ceiling every CobR is capped at.
	ValorRecCents  int64
	IdempotencyKey string
}

// CreateMandate registers a recurring-debit mandate at the bank and records it durably
// in the same unit of work as its audit entry, so a mandate can never exist without its
// forensic trail (or the reverse).
//
// The mandate is born CRIADA — NOT chargeable. It becomes chargeable only when the payer
// authorizes it at their own bank and that approval reaches us through the reconciled
// recurrence webhook. That is the whole point of the journey and the reason
// OriginateCobR consults the durable mandate rather than the caller's word for it.
//
// Ordering: the bank call happens BEFORE the durable write, like the cob/cobv path, so a
// mandate is never recorded locally that the bank does not have. The bank's idRec is the
// aggregate's identity, so there is nothing to reserve up front.
func (s *RecurrenceService) CreateMandate(ctx context.Context, in CreateMandateInput) (*recurrence.Rec, ports.RecResult, error) {
	tenantID := strings.TrimSpace(in.TenantID)
	if tenantID == "" {
		return nil, ports.RecResult{}, shared.NewValidationError("tenant_id", "is required")
	}
	if s.rec == nil {
		return nil, ports.RecResult{}, fmt.Errorf("recurrence mandate port not configured: %w", shared.ErrUnavailable)
	}
	if strings.TrimSpace(in.IdempotencyKey) == "" {
		return nil, ports.RecResult{}, shared.NewValidationError("idempotency_key", "idempotency key is required")
	}
	t, err := s.tenants.FindTenantByID(ctx, tenantID)
	if err != nil {
		return nil, ports.RecResult{}, fmt.Errorf("resolve tenant: %w", err)
	}
	if !t.Active() {
		return nil, ports.RecResult{}, shared.NewValidationError("tenant", "tenant is not active")
	}
	// Build the payer in the core first: it is the one field that carries PII, and an
	// invalid CPF/CNPJ must be refused here rather than shipped to the bank.
	devedor, err := recurrence.NewDevedor(in.DevedorDoc, in.DevedorNome)
	if err != nil {
		return nil, ports.RecResult{}, err
	}
	if in.ValorRecCents < 0 {
		return nil, ports.RecResult{}, shared.NewValidationError("valor_rec_cents", "must not be negative")
	}
	// Unpriced endpoint = free (bill 0), not a rejection — see resolvePriceOrFree.
	price, err := resolvePriceOrFree(ctx, s.pricing, tenantID, RecCreateEndpoint)
	if err != nil {
		return nil, ports.RecResult{}, err
	}

	res, err := s.rec.CreateRec(ctx, tenantID, ports.CreateRecRequest{
		Vinculo: ports.RecVinculo{
			Contrato: strings.TrimSpace(in.Contrato),
			Devedor:  toRecDevedor(devedor),
			Objeto:   strings.TrimSpace(in.Objeto),
		},
		Calendario: ports.RecCalendario{
			DataInicial:   strings.TrimSpace(in.DataInicial),
			Periodicidade: ports.RecPeriodicidade(strings.TrimSpace(in.Periodicidade)),
		},
		PoliticaRetentativa: ports.RetryPolicy(strings.TrimSpace(in.PoliticaRetentativa)),
		LocID:               in.LocID,
		JornadaTxID:         strings.TrimSpace(in.JornadaTxID),
		ValorRecCents:       in.ValorRecCents,
		IdempotencyKey:      strings.TrimSpace(in.IdempotencyKey),
	})
	if err != nil {
		return nil, ports.RecResult{}, fmt.Errorf("bank create rec: %w", err)
	}

	// Idempotency: the bank collapses a retried registration onto the same idRec, so a
	// mandate we have already recorded is returned as-is — no second audit, no second
	// ledger entry.
	if existing, ferr := s.recs.FindRecByID(ctx, tenantID, res.IDRec); ferr == nil {
		return existing, res, nil
	} else if !errors.Is(ferr, shared.ErrNotFound) {
		return nil, ports.RecResult{}, fmt.Errorf("idempotency lookup: %w", ferr)
	}

	rec, err := recurrence.NewRec(recurrence.NewRecParams{
		IDRec:         res.IDRec,
		TenantID:      tenantID,
		BankID:        bankIDOrDefault(res),
		Contrato:      strings.TrimSpace(in.Contrato),
		Devedor:       devedor,
		DataInicial:   strings.TrimSpace(in.DataInicial),
		Periodicidade: recurrence.RecPeriodicidade(strings.TrimSpace(in.Periodicidade)),
		ValorCents:    in.ValorRecCents,
		LocID:         in.LocID,
		JornadaTxID:   strings.TrimSpace(in.JornadaTxID),
	}, s.clock.Now())
	if err != nil {
		return nil, ports.RecResult{}, err
	}
	entry, err := audit.NewRecurrenceTransitionEntry(s.ids.NewID(), in.OperatorID, tenantID, rec.IDRec(), string(rec.Status()), s.clock.Now())
	if err != nil {
		return nil, ports.RecResult{}, err
	}
	ledger, err := billing.NewLedgerEntry(s.ids.NewID(), tenantID, RecCreateEndpoint, rec.IDRec(), price.PriceCents(), s.clock.Now(), billing.WithAccount(in.AccountID))
	if err != nil {
		return nil, ports.RecResult{}, err
	}

	if err := s.uow.WithinTx(ctx, func(r ports.Repository) error {
		if err := r.SaveRec(ctx, rec); err != nil {
			return fmt.Errorf("save rec: %w", err)
		}
		if err := r.Append(ctx, entry); err != nil {
			return fmt.Errorf("append audit: %w", err)
		}
		if err := r.AppendLedgerEntry(ctx, ledger); err != nil {
			return fmt.Errorf("append ledger: %w", err)
		}
		return nil
	}); err != nil {
		return nil, ports.RecResult{}, err
	}
	return rec, res, nil
}

// toRecDevedor maps the validated core payer onto the BACEN oneOf shape (an 11-digit
// document is a CPF, a 14-digit one a CNPJ — NewDevedor already guaranteed one of the
// two).
func toRecDevedor(d recurrence.Devedor) ports.RecDevedor {
	out := ports.RecDevedor{Nome: d.Nome()}
	if len(d.Doc()) == 11 {
		out.CPF = d.Doc()
		return out
	}
	out.CNPJ = d.Doc()
	return out
}

// bankIDOrDefault names the bank the mandate lives at. PIX Automático is wired only for
// C6 today (the recurrence ports are not yet part of the per-bank routing surface —
// see cmd/api recurrenceReaders), so the slug is fixed here rather than guessed from a
// request field; a bank selector on a business request is exactly what ADR-0007 §3 keeps
// out of the contract.
func bankIDOrDefault(ports.RecResult) string { return ports.BankIDC6 }

// GetMandate reconciles the authoritative mandate state from the bank for the
// authenticated tenant. An idRec belonging to another tenant surfaces as not-found: the
// bank read is tenant-scoped, so there is no cross-tenant existence oracle.
func (s *RecurrenceService) GetMandate(ctx context.Context, tenantID, idRec string) (ports.RecResult, error) {
	tenantID, idRec = strings.TrimSpace(tenantID), strings.TrimSpace(idRec)
	if tenantID == "" {
		return ports.RecResult{}, shared.NewValidationError("tenant_id", "is required")
	}
	if idRec == "" {
		return ports.RecResult{}, shared.NewValidationError("id_rec", "is required")
	}
	if s.rec == nil {
		return ports.RecResult{}, fmt.Errorf("recurrence mandate port not configured: %w", shared.ErrUnavailable)
	}
	return s.rec.GetRec(ctx, tenantID, idRec)
}

// GetMandateQR reads the mandate asking the bank to compose the QR for a journey. txID
// selects it: the txid of the immediate charge the mandate was created against composes
// the Jornada 3 composite QR (pay now + authorize); the txid of a cobrança com
// vencimento composes the Jornada 4 QR.
//
// An EMPTY txID does not mean "no charge" — it means "use the one this mandate was
// created against". The binding was persisted at creation precisely so a caller does not
// have to keep a mandate→charge map of its own, and so a QR can still be re-rendered
// months later by a different process than the one that created it. Only when the
// mandate has no binding at all (a solicrec/Jornada 1 mandate) does an empty txID fall
// through to the bank, which then composes the mandate-only Jornada 2 QR.
//
// A read that comes back WITHOUT a composed QR is not an error at the bank and is not
// invented into one here — it means the bank did not yet have everything the QR needs.
// The caller is told plainly rather than handed a blank string that would render as a
// broken QR in front of a payer.
func (s *RecurrenceService) GetMandateQR(ctx context.Context, tenantID, idRec, txID string) (ports.RecResult, error) {
	tenantID, idRec, txID = strings.TrimSpace(tenantID), strings.TrimSpace(idRec), strings.TrimSpace(txID)
	if tenantID == "" {
		return ports.RecResult{}, shared.NewValidationError("tenant_id", "is required")
	}
	if idRec == "" {
		return ports.RecResult{}, shared.NewValidationError("id_rec", "is required")
	}
	if s.rec == nil {
		return ports.RecResult{}, fmt.Errorf("recurrence mandate port not configured: %w", shared.ErrUnavailable)
	}
	if txID == "" {
		// Tenant-scoped lookup: a mandate of another tenant can never supply the txid for
		// this one. A mandate we never recorded simply has no default to offer.
		if rec, err := s.recs.FindRecByID(ctx, tenantID, idRec); err == nil {
			txID = rec.JornadaTxID()
		} else if !errors.Is(err, shared.ErrNotFound) {
			return ports.RecResult{}, fmt.Errorf("load mandate: %w", err)
		}
	}
	return s.rec.GetRecForQR(ctx, tenantID, idRec, txID)
}

// GetLocRec reads a payload location back for the authenticated tenant.
func (s *RecurrenceService) GetLocRec(ctx context.Context, tenantID string, id int64) (ports.LocRecResult, error) {
	if strings.TrimSpace(tenantID) == "" {
		return ports.LocRecResult{}, shared.NewValidationError("tenant_id", "is required")
	}
	if s.locRec == nil {
		return ports.LocRecResult{}, fmt.Errorf("recurrence location port not configured: %w", shared.ErrUnavailable)
	}
	return s.locRec.GetLocRec(ctx, strings.TrimSpace(tenantID), id)
}

// UnlinkLocRec detaches the mandate from a location so it can be rebound — the recovery
// path after a mandate is cancelled or was never authorized, which otherwise strands a
// location that the tenant already paid the round-trip to mint.
func (s *RecurrenceService) UnlinkLocRec(ctx context.Context, tenantID string, id int64) (ports.LocRecResult, error) {
	if strings.TrimSpace(tenantID) == "" {
		return ports.LocRecResult{}, shared.NewValidationError("tenant_id", "is required")
	}
	if s.locRec == nil {
		return ports.LocRecResult{}, fmt.Errorf("recurrence location port not configured: %w", shared.ErrUnavailable)
	}
	return s.locRec.UnlinkLocRec(ctx, strings.TrimSpace(tenantID), id)
}

// CancelMandate revokes a mandate at the bank so no further debits can be originated,
// then records the CANCELADA transition durably with its audit entry.
//
// The bank is the authority on revocation and is called first: a mandate marked
// cancelled locally while still live at the bank would keep debiting a payer who was
// told the charging had stopped — the failure that actually harms someone. The durable
// write is idempotent through the domain state machine: cancelling an already-cancelled
// mandate is a no-op transition, so a retry neither errors nor re-audits.
func (s *RecurrenceService) CancelMandate(ctx context.Context, tenantID, operatorID, idRec string) (ports.RecResult, error) {
	tenantID, idRec = strings.TrimSpace(tenantID), strings.TrimSpace(idRec)
	if tenantID == "" {
		return ports.RecResult{}, shared.NewValidationError("tenant_id", "is required")
	}
	if idRec == "" {
		return ports.RecResult{}, shared.NewValidationError("id_rec", "is required")
	}
	if s.rec == nil {
		return ports.RecResult{}, fmt.Errorf("recurrence mandate port not configured: %w", shared.ErrUnavailable)
	}
	res, err := s.rec.CancelRec(ctx, tenantID, idRec)
	if err != nil {
		return ports.RecResult{}, fmt.Errorf("bank cancel rec: %w", err)
	}

	if err := s.uow.WithinTx(ctx, func(r ports.Repository) error {
		rec, ferr := r.FindRecByID(ctx, tenantID, idRec)
		if ferr != nil {
			if errors.Is(ferr, shared.ErrNotFound) {
				// Cancelled at the bank, never recorded here (registered out-of-band). The
				// revocation still took effect, which is what the caller asked for.
				return nil
			}
			return fmt.Errorf("load mandate: %w", ferr)
		}
		if rec.Status() == recurrence.RecCancelada {
			return nil // already recorded — idempotent retry
		}
		if err := rec.Transition(recurrence.RecCancelada, s.clock.Now()); err != nil {
			return err
		}
		if err := r.SaveRec(ctx, rec); err != nil {
			return fmt.Errorf("save rec: %w", err)
		}
		entry, aerr := audit.NewRecurrenceTransitionEntry(s.ids.NewID(), operatorID, tenantID, idRec, string(recurrence.RecCancelada), s.clock.Now())
		if aerr != nil {
			return aerr
		}
		if err := r.Append(ctx, entry); err != nil {
			return fmt.Errorf("append audit: %w", err)
		}
		return nil
	}); err != nil {
		return ports.RecResult{}, err
	}
	return res, nil
}

// ---- solicrec (Jornada 1: activation request, no QR) ----

// RequestConfirmationInput asks the payer's participant to confirm an existing mandate.
// The destinatário is the payer's transactional account at their own institution.
type RequestConfirmationInput struct {
	TenantID string
	IDRec    string
	// Exactly one of CPF/CNPJ identifies the payer (BACEN oneOf).
	CPF              string
	CNPJ             string
	Agencia          string
	Conta            string
	ISPBParticipante string
	// ExpiraEm is when the activation request lapses. BACEN CMT-APR-SOLI-016 caps it at
	// under 30 days from now.
	ExpiraEm       time.Time
	IdempotencyKey string
}

// solicRecMaxExpiry is the BACEN ceiling on an activation request's lifetime
// (CMT-APR-SOLI-016: strictly less than 30 days ahead).
const solicRecMaxExpiry = 30 * 24 * time.Hour

// RequestConfirmation sends the mandate to the payer's participant for confirmation.
// It is the Jornada 1 activation path — no QR, the payer approves in their own bank's
// app — and is also how a QR journey is re-offered to a payer who never scanned.
//
// The expiry window is validated HERE rather than left to the bank: a request that
// expires in the past or beyond the BACEN ceiling is refused at our boundary, so the
// tenant gets a precise validation error instead of an opaque upstream 400.
func (s *RecurrenceService) RequestConfirmation(ctx context.Context, in RequestConfirmationInput) (ports.SolicRecResult, error) {
	tenantID := strings.TrimSpace(in.TenantID)
	if tenantID == "" {
		return ports.SolicRecResult{}, shared.NewValidationError("tenant_id", "is required")
	}
	idRec := strings.TrimSpace(in.IDRec)
	if idRec == "" {
		return ports.SolicRecResult{}, shared.NewValidationError("id_rec", "is required")
	}
	if s.solicRec == nil {
		return ports.SolicRecResult{}, fmt.Errorf("recurrence activation port not configured: %w", shared.ErrUnavailable)
	}
	now := s.clock.Now()
	if in.ExpiraEm.IsZero() || !in.ExpiraEm.After(now) {
		return ports.SolicRecResult{}, shared.NewValidationError("expira_em", "must be in the future")
	}
	if in.ExpiraEm.Sub(now) >= solicRecMaxExpiry {
		return ports.SolicRecResult{}, shared.NewValidationError("expira_em", "must be less than 30 days ahead")
	}
	return s.solicRec.CreateSolicRec(ctx, tenantID, ports.CreateSolicRecRequest{
		IDRec: idRec,
		Destinatario: ports.SolicRecDestinatario{
			CPF:              strings.TrimSpace(in.CPF),
			CNPJ:             strings.TrimSpace(in.CNPJ),
			Agencia:          strings.TrimSpace(in.Agencia),
			Conta:            strings.TrimSpace(in.Conta),
			ISPBParticipante: strings.TrimSpace(in.ISPBParticipante),
		},
		ExpiraEm:       in.ExpiraEm,
		IdempotencyKey: strings.TrimSpace(in.IdempotencyKey),
	})
}

// GetConfirmation reconciles the authoritative activation-request state for the tenant.
func (s *RecurrenceService) GetConfirmation(ctx context.Context, tenantID, idSolicRec string) (ports.SolicRecResult, error) {
	tenantID, idSolicRec = strings.TrimSpace(tenantID), strings.TrimSpace(idSolicRec)
	if tenantID == "" {
		return ports.SolicRecResult{}, shared.NewValidationError("tenant_id", "is required")
	}
	if idSolicRec == "" {
		return ports.SolicRecResult{}, shared.NewValidationError("id_solic_rec", "is required")
	}
	if s.solicRec == nil {
		return ports.SolicRecResult{}, fmt.Errorf("recurrence activation port not configured: %w", shared.ErrUnavailable)
	}
	return s.solicRec.GetSolicRec(ctx, tenantID, idSolicRec)
}

// ---- cobr reads and amendments ----

// GetCobR reconciles the authoritative recurring-charge state for the tenant.
func (s *RecurrenceService) GetCobR(ctx context.Context, tenantID, txID string) (ports.CobRResult, error) {
	tenantID, txID = strings.TrimSpace(tenantID), strings.TrimSpace(txID)
	if tenantID == "" {
		return ports.CobRResult{}, shared.NewValidationError("tenant_id", "is required")
	}
	if txID == "" {
		return ports.CobRResult{}, shared.NewValidationError("tx_id", "is required")
	}
	if s.cobr == nil {
		return ports.CobRResult{}, fmt.Errorf("recurrence charge port not configured: %w", shared.ErrUnavailable)
	}
	return s.cobr.GetCobR(ctx, tenantID, txID)
}

// CancelCobR cancels ONE scheduled recurring charge without touching the mandate: the
// payer's authorization stays standing and later cycles still charge. It is the only
// amendment the BACEN contract admits on a cobr (status=CANCELADA is the sole revisable
// field and the sole allowed value), so an instalment whose amount or date must change
// is cancelled here and re-originated as a new charge.
//
// Deliberately NOT gated on the mandate being APROVADA, unlike origination. Every other
// gate on this surface exists to stop money moving without authorization; this one
// stops money moving. Refusing to cancel an instalment because the mandate had since
// been revoked or expired would leave a scheduled debit standing against a payer who
// already withdrew consent — the gate would cause the harm it exists to prevent. Tenant
// scoping still applies: a charge of another tenant is not found.
//
// Idempotent: cancelling an already-cancelled charge is a no-op that neither errors nor
// re-audits.
func (s *RecurrenceService) CancelCobR(ctx context.Context, tenantID, operatorID, txID string) (ports.CobRResult, error) {
	tenantID, txID = strings.TrimSpace(tenantID), strings.TrimSpace(txID)
	if tenantID == "" {
		return ports.CobRResult{}, shared.NewValidationError("tenant_id", "is required")
	}
	if txID == "" {
		return ports.CobRResult{}, shared.NewValidationError("tx_id", "is required")
	}
	if s.cobr == nil {
		return ports.CobRResult{}, fmt.Errorf("recurrence charge port not configured: %w", shared.ErrUnavailable)
	}
	// Tenant-scope the charge BEFORE asking the bank, so one tenant can never cancel
	// another's instalment by guessing a txid (threat P1). A charge we never recorded is
	// not cancellable here — there is nothing proving it is ours.
	if _, err := s.cobrs.FindCobRByTxID(ctx, tenantID, txID); err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return ports.CobRResult{}, shared.ErrNotFound
		}
		return ports.CobRResult{}, fmt.Errorf("load recurring charge: %w", err)
	}

	res, err := s.cobr.CancelCobR(ctx, tenantID, txID)
	if err != nil {
		return ports.CobRResult{}, fmt.Errorf("bank cancel cobr: %w", err)
	}

	if err := s.uow.WithinTx(ctx, func(r ports.Repository) error {
		current, ferr := r.FindCobRByTxID(ctx, tenantID, txID)
		if ferr != nil {
			if errors.Is(ferr, shared.ErrNotFound) {
				return nil
			}
			return fmt.Errorf("reload recurring charge: %w", ferr)
		}
		if current.Status() == recurrence.CobRCancelada {
			return nil // already recorded — idempotent retry
		}
		if terr := current.Transition(recurrence.CobRCancelada, s.clock.Now()); terr != nil {
			// The charge already reached a terminal state at the bank (settled, refused,
			// expired). The cancel changed nothing, so there is nothing to record.
			return nil
		}
		if err := r.SaveCobR(ctx, current); err != nil {
			return fmt.Errorf("save recurring charge: %w", err)
		}
		entry, aerr := audit.NewCobRCancellationEntry(s.ids.NewID(), operatorID, tenantID, txID, s.clock.Now())
		if aerr != nil {
			return aerr
		}
		if err := r.Append(ctx, entry); err != nil {
			return fmt.Errorf("append audit: %w", err)
		}
		return nil
	}); err != nil {
		return ports.CobRResult{}, err
	}
	return res, nil
}

// RetryCobR schedules a retry of a failed debit on the given date (yyyy-MM-dd), per the
// mandate's política de retentativa. The mandate gate still applies: a cancelled or
// expired mandate must not be able to reach back and retry a debit against a payer who
// has already revoked their authorization.
func (s *RecurrenceService) RetryCobR(ctx context.Context, tenantID, idRec, txID, dataRetentativa string) (ports.CobRResult, error) {
	tenantID = strings.TrimSpace(tenantID)
	idRec = strings.TrimSpace(idRec)
	txID = strings.TrimSpace(txID)
	dataRetentativa = strings.TrimSpace(dataRetentativa)
	if tenantID == "" {
		return ports.CobRResult{}, shared.NewValidationError("tenant_id", "is required")
	}
	if idRec == "" {
		return ports.CobRResult{}, shared.NewValidationError("id_rec", "is required")
	}
	if txID == "" {
		return ports.CobRResult{}, shared.NewValidationError("tx_id", "is required")
	}
	if dataRetentativa == "" {
		return ports.CobRResult{}, shared.NewValidationError("data_retentativa", "is required")
	}
	if s.cobr == nil {
		return ports.CobRResult{}, fmt.Errorf("recurrence charge port not configured: %w", shared.ErrUnavailable)
	}
	rec, err := s.recs.FindRecByID(ctx, tenantID, idRec)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return ports.CobRResult{}, recurrence.ErrMandateNotFound
		}
		return ports.CobRResult{}, fmt.Errorf("load mandate: %w", err)
	}
	if err := recurrence.RequireApprovedMandate(rec, tenantID, idRec); err != nil {
		return ports.CobRResult{}, err
	}
	return s.cobr.RetryCobR(ctx, tenantID, txID, dataRetentativa)
}

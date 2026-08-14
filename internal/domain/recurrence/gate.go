package recurrence

import "errors"

// Referential-integrity gate for the recurring-charge cycle (PIX Automático F4,
// SIN-66039). It encodes the CTO acceptance invariant carried over from the F3
// review (SIN-66037): no recurring charge (CobR) may be ORIGINATED or SETTLED
// unless an approved mandate (a Rec in status APROVADA) exists for the same
// (tenant_id, id_rec). F3 persists pix_cobr.id_rec with NO referential check —
// inócuo there because nothing moves money — so this rule is where F4 closes that
// gap, at every site that creates or liquidates a charge.
//
// It is PURE domain: it inspects an already-loaded Rec aggregate and decides,
// touching neither storage nor the network. Callers load the mandate tenant-scoped
// (ports.RecRepository.FindRecByID) and pass it here; the gate also re-checks the
// (tenant_id, id_rec) identity so a mis-scoped lookup that returned the wrong
// aggregate can never authorize a charge (threat P1 IDOR). The neither-mandate nor
// the bank/stub enforces this — the bank happily creates a CobR for any idRec — so
// the use-case MUST consult this rule before acting.

var (
	// ErrMandateNotFound means no mandate backs the charge: the caller looked up
	// (tenant_id, id_rec) and found nothing (rec is nil). A charge with no mandate
	// can never be originated or settled — there is no authorization behind it.
	ErrMandateNotFound = errors.New("recurrence: no mandate for charge")

	// ErrMandateNotApproved means a mandate exists but is not APROVADA: it is still
	// CRIADA (the payer has not confirmed it) or terminal (REJEITADA/EXPIRADA/
	// CANCELADA). Without an approved mandate no recurring charge may be created or
	// liquidated.
	ErrMandateNotApproved = errors.New("recurrence: mandate is not APROVADA")

	// ErrMandateMismatch means the loaded mandate does not match the (tenant_id,
	// id_rec) the charge claims. A defense-in-depth check: even if a lookup is
	// mis-scoped, a mandate belonging to another tenant or another idRec can never
	// authorize this charge.
	ErrMandateMismatch = errors.New("recurrence: mandate does not match charge tenant/idRec")

	// ErrChargeExceedsMandate means the recurring charge (CobR) amount is greater
	// than the value the payer authorized on the mandate. A fixed-value mandate
	// (Rec.ValorCents > 0) caps every charge at that ceiling; originating a CobR
	// above it would debit the payer for more than they consented to (threat: a
	// compromised/over-eager recebedor over-charging within an approved mandate).
	ErrChargeExceedsMandate = errors.New("recurrence: charge exceeds mandate authorized value")
)

// RequireApprovedMandate enforces the referential gate. It returns nil only when
// rec is a non-nil mandate for exactly (tenantID, idRec) whose status is APROVADA.
// Otherwise it returns the specific sentinel — ErrMandateNotFound (nil rec),
// ErrMandateMismatch (wrong tenant/idRec) or ErrMandateNotApproved (not APROVADA)
// — so a caller can refuse an origination or ack-and-drop a settle accordingly. It
// never mutates rec.
func RequireApprovedMandate(rec *Rec, tenantID, idRec string) error {
	if rec == nil {
		return ErrMandateNotFound
	}
	if rec.TenantID() != tenantID || rec.IDRec() != idRec {
		return ErrMandateMismatch
	}
	if rec.Status() != RecAprovada {
		return ErrMandateNotApproved
	}
	return nil
}

// RequireWithinAuthorizedValue enforces the over-charge gate (SIN-66070): a CobR's
// amount must not exceed the value the payer authorized on the mandate. rec must be
// the already-loaded, referential-gated mandate (RequireApprovedMandate passed) for
// the charge.
//
// A fixed-value mandate (rec.ValorCents() > 0) authorizes charges only up to that
// ceiling; chargeCents == the ceiling is allowed, anything above it is refused with
// ErrChargeExceedsMandate. A variable-value mandate (rec.ValorCents() == 0) carries
// no in-house ceiling — its amount is decided per cycle — so the gate is a no-op for
// it. A nil rec is ErrMandateNotFound (no mandate authorizes any amount). It never
// mutates rec.
func RequireWithinAuthorizedValue(rec *Rec, chargeCents int64) error {
	if rec == nil {
		return ErrMandateNotFound
	}
	authorized := rec.ValorCents()
	if authorized > 0 && chargeCents > authorized {
		return ErrChargeExceedsMandate
	}
	return nil
}

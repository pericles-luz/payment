package app

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// Charge status vocabulary of the C6 Bolepix contract, as the settlement path reads it.
//
// CANCELED carries one L in the v2 contract and two in the legacy v1 boleto API, so both
// spellings are accepted: comparing against only one reads a dead charge as live.
const (
	boletoStatusPaid                = "PAID"
	boletoStatusWaitingConfirmation = "WAITING_CONFIRMATION"
	boletoStatusCanceledV2          = "CANCELED"
	boletoStatusCanceledLegacy      = "CANCELLED"
)

// HandleBoletoEvent reconciles and settles a boleto or BolePix payment from a bank webhook.
//
// The hard part is not the settlement, it is knowing WHICH charge the notification is
// about. Three identifiers are in play: our boleto id (which is the payment id), the
// external_reference_id we derive from it, and the bank's own charge id. The notification
// carries one of the last two, and the two are indistinguishable by shape — both are 26
// uppercase alphanumerics. So rather than guess, resolution is attempted in the order that
// is cheapest and most certain first:
//
//  1. Look the payment up locally by the id the notification carried. A hit means it is
//     whatever registration stored, we now know the local boleto id, and no PSP call is
//     needed to find out.
//  2. Otherwise read the charge from the bank BY THAT REFERENCE, verbatim. A 200 means the
//     notification carried our reference, and the response hands back the bank id the local
//     row is actually keyed by — which is what SettlementKey then carries.
//  3. Neither ⇒ fail loudly (see below), never silently.
//
// This is correct under every combination of "what the notification carries" and "what the
// payment row is keyed by", so none of it rests on an assumption that has not been measured
// against the real bank.
func (s *WebhookService) HandleBoletoEvent(ctx context.Context, ev PaymentEvent) error {
	if s.boleto == nil {
		return fmt.Errorf("boleto webhook not configured: %w", shared.ErrUnavailable)
	}
	if strings.TrimSpace(ev.TxID) == "" {
		return shared.NewValidationError("tx_id", "tx id is required")
	}

	// Step 1: our own store. Cheap, certain, and it runs before the transaction because it
	// touches nothing but a row we own.
	if s.payments != nil {
		p, err := s.payments.FindPaymentByTxID(ctx, ev.TenantID, ev.TxID)
		switch {
		case err == nil:
			boletoID := p.ID()
			return s.settle(ctx, ev, func(ctx context.Context, tenantID, _ string) (ports.ChargeResult, error) {
				res, err := s.boleto.GetBoleto(ctx, tenantID, boletoID)
				if err != nil {
					return ports.ChargeResult{}, err
				}
				// The row is already keyed by the event's tx id, so no override is needed.
				return toBoletoChargeResult(res, "")
			})
		case !errors.Is(err, shared.ErrNotFound):
			// An infrastructure fault must not be mistaken for "unknown id": returning the
			// error rolls the work back and lets the PSP redeliver.
			return fmt.Errorf("resolve boleto payment: %w", err)
		}
	}

	// Step 2: ask the bank about this reference directly.
	return s.settle(ctx, ev, s.reconcileBoletoByBankRef)
}

// reconcileBoletoByBankRef reads the charge by the reference the notification carried and
// reports the bank's own id as the key the local payment row is stored under.
func (s *WebhookService) reconcileBoletoByBankRef(ctx context.Context, tenantID, bankRef string) (ports.ChargeResult, error) {
	res, err := s.boleto.GetBoletoByBankRef(ctx, tenantID, bankRef)
	if err != nil {
		// Step 3. Nothing resolved: this is NOT acked away. The unit of work rolls back
		// (so the anti-replay mark is not burned), the PSP redelivers, and the receiver
		// logs the raw body — which is exactly the evidence needed to learn which
		// identifier the bank actually sends. Silently acking an id we could not map is
		// indistinguishable from acking a real payment we failed to settle.
		return ports.ChargeResult{}, err
	}
	return toBoletoChargeResult(res, res.TxID)
}

// toBoletoChargeResult maps a registered boleto onto the generic charge result the
// settlement core consumes.
//
// The money check is the honest weak point of this rail and is documented as such rather
// than hidden. ChargeResult.AmountReconciled demands strict equality between expected and
// received, but the bank's single-charge read returns only the REGISTERED amount and a
// status — the per-payment breakdown (paid amount, payment date, credit date) exists only
// on the list endpoint. So for a settled charge, expected and received are both the
// registered amount, and the money gate degenerates to "the bank, re-read, says this charge
// of value X is PAID".
//
// That is weaker than the PIX and checkout paths, where a received amount is actually
// compared. It is accepted here for two reasons: the bank does not do partial baixa on a
// boleto, and a boleto paid late legitimately credits MORE than the principal (multa plus
// pro-rata mora, which the boleto domain already computes) — so strict equality against the
// credited amount would refuse legitimate payments rather than catch fraud. Restoring a
// genuine comparison needs the list endpoint's payments[] array.
//
// On any non-settled status, received stays zero so the money gate remains fail-secure if
// the status gate above it is ever loosened.
func toBoletoChargeResult(res ports.BoletoResult, settlementKey string) (ports.ChargeResult, error) {
	status := strings.ToUpper(strings.TrimSpace(res.Status))

	switch status {
	case boletoStatusWaitingConfirmation:
		// Confirmed by the payer, NOT yet credited to the merchant. It is neither "unpaid"
		// nor settleable, and the distinction decides whether the PSP redelivers.
		//
		// errSettlementLag (not errNotYetPayable) because the anti-replay mark must be
		// rolled back AND the notification must come back. Acking it would depend on the
		// bank sending a second notification when the funds land — which has not been
		// verified. If that assumption were wrong, the payment would be lost forever, and
		// that is the exact failure this codebase has already paid for once.
		return ports.ChargeResult{}, fmt.Errorf(
			"cobrança %s: pagamento confirmado, recursos ainda não creditados: %w",
			res.ExternalReferenceID, errSettlementLag)
	case boletoStatusCanceledV2, boletoStatusCanceledLegacy:
		// Terminal and not paid: ack it, do not settle, do not ask for a redelivery.
		return ports.ChargeResult{
			TxID:                res.TxID,
			Status:              status,
			ExpectedAmountCents: res.AmountCents,
			SettlementKey:       settlementKey,
		}, nil
	}

	out := ports.ChargeResult{
		TxID:                res.TxID,
		Status:              status,
		ExpectedAmountCents: res.AmountCents,
		SettlementKey:       settlementKey,
		// Carry the rail and the bank's own wording through to the Conta's outbound
		// webhook, so a reseller can tell a boleto payment from a PIX one on the same
		// charge.
		Message: boletoSettlementMessage(res),
	}
	if status == boletoStatusPaid {
		out.Status = bankStatusPaid
		out.ReceivedAmountCents = res.AmountCents
	}
	return out, nil
}

// boletoSettlementMessage describes which rail the charge was payable by, for the outbound
// envelope. It carries no PII — a modality and a status token.
func boletoSettlementMessage(res ports.BoletoResult) string {
	modality := string(res.Modality.Normalized())
	if res.Status == "" {
		return modality
	}
	return modality + " " + strings.ToUpper(strings.TrimSpace(res.Status))
}

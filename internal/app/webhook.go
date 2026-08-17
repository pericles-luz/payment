package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
	"github.com/ia-dev-sindireceita/payment/internal/domain/payment"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// bankStatusPaid is the authoritative bank status that settles a payment.
const bankStatusPaid = "paid"

// systemOperatorWebhook is the reserved synthetic operator id recorded on
// money-movement audit events raised by the PSP webhook path. A webhook has no
// human operator; this names the system actor so the audit trail stays
// attributable without inventing a fake user.
const systemOperatorWebhook = "system:c6-webhook"

// WebhookService processes bank webhook events. A webhook is only a trigger: the
// service is idempotent (anti-replay) and reconciles the authoritative state
// with the bank before settling any payment (threats W2/W3).
type WebhookService struct {
	bank     ports.BankProvider
	checkout ports.CheckoutReconciler
	bus      ports.MessageBus
	clock    ports.Clock
	uow      ports.UnitOfWork
	audit    ports.AuditLog
	ids      ports.IDProvider
	// recReader / cobrReader reconcile the authoritative recurrence state before a
	// recurrence webhook is acted on (PIX Automático, SIN-66036). Nil leaves the
	// recurrence dispatch unwired: HandleRecEvent/HandleCobREvent then fail closed.
	recReader  ports.RecProvider
	cobrReader ports.CobRProvider
	// attributor materialises a settled event onto its owning Conta's outbound-delivery
	// outbox (SIN-69491, F1 of SIN-69486). Nil / disabled ⇒ the feature is dark and
	// settlement is unchanged. Its calls are best-effort: never affect the ACK to C6.
	attributor *OutboundAttributor
}

// NewWebhookService wires a WebhookService from the provided ports. A nil
// Deps.Audit degrades to a no-op log (foundation default), mirroring
// AdminService; production MUST wire a real append-only audit log so refused
// settlements are recorded for forensics/compliance. A nil Deps.Checkout simply
// leaves the checkout-webhook path unconfigured (HandleCheckoutEvent then refuses).
func NewWebhookService(d Deps) *WebhookService {
	a := d.Audit
	if a == nil {
		a = noopAudit{}
	}
	return &WebhookService{
		bank:       d.Bank,
		checkout:   d.Checkout,
		bus:        d.Bus,
		clock:      d.Clock,
		uow:        resolveUoW(d),
		audit:      a,
		ids:        d.IDs,
		recReader:  d.RecReader,
		cobrReader: d.CobRReader,
		attributor: d.OutboundAttributor,
	}
}

// PaymentEvent is the validated webhook payload (after transport auth). EventKey
// uniquely identifies the delivery for idempotency (e.g. endToEndId+event).
type PaymentEvent struct {
	TenantID string
	TxID     string
	EventKey string
}

// reconcileFunc reconciles the authoritative state of the resource named by a webhook
// event (a charge, or a checkout session) into the generic charge result the
// settlement core consumes. It is the single seam that differs between the PIX/charge
// and checkout webhook paths; everything else (dedup, reconcile-before-settle, money
// reconciliation, audit) is shared.
type reconcileFunc func(ctx context.Context, tenantID, txID string) (ports.ChargeResult, error)

// HandlePaymentEvent reconciles and settles a PIX/charge payment from a bank webhook
// (the authoritative state is read via GetCharge). It is a thin wrapper over settle.
func (s *WebhookService) HandlePaymentEvent(ctx context.Context, ev PaymentEvent) error {
	return s.settle(ctx, ev, s.bank.GetCharge)
}

// HandleCheckoutEvent reconciles and settles a checkout-session payment from a bank
// webhook (roteiro 12). It reuses settle's exact dedup + reconcile-before-settle unit
// of work, differing only in the reconcile source: the checkout session's
// authoritative state (GetCheckoutSession) rather than GetCharge. The payment is
// located by its tx id — the session id stored at session creation. A nil checkout
// port (the webhook path was not wired) fails closed rather than silently dropping the
// notification.
func (s *WebhookService) HandleCheckoutEvent(ctx context.Context, ev PaymentEvent) error {
	if s.checkout == nil {
		return fmt.Errorf("checkout webhook not configured: %w", shared.ErrUnavailable)
	}
	return s.settle(ctx, ev, s.reconcileCheckout)
}

// reconcileCheckout reads the authoritative checkout-session state and maps it onto the
// generic charge result the settlement core understands: the session's authorized
// total is the expected amount and the PSP-reported capture is the received amount, so
// the shared money reconciliation (AmountReconciled) refuses to settle a partial/over
// capture exactly as it does for a charge.
func (s *WebhookService) reconcileCheckout(ctx context.Context, tenantID, sessionID string) (ports.ChargeResult, error) {
	res, err := s.checkout.GetCheckoutSession(ctx, tenantID, sessionID)
	if err != nil {
		return ports.ChargeResult{}, err
	}
	return ports.ChargeResult{
		TxID:                res.SessionID,
		Status:              res.Status,
		ExpectedAmountCents: res.AmountCents,
		ReceivedAmountCents: res.ReceivedAmountCents,
	}, nil
}

// settle reconciles and settles a payment. Duplicate deliveries are acked without side
// effects. The webhook payload is never trusted as financial truth — settlement
// requires a positive reconciliation (via reconcile) with the bank.
//
// F2 (SIN-64719): marking the event processed (anti-replay) and settling the
// payment happen in ONE transaction. The previous code committed MarkProcessed
// first, so a transient failure during reconciliation/settlement left the key
// marked — the bank's redelivery was then acked as a duplicate no-op and the
// payment was never settled (exactly-once-settlement silently lost). Now a
// transient failure rolls the whole unit of work back, including the mark, so the
// redelivery re-attempts and eventually settles. The mark is durable only once
// the terminal outcome (settled, or authoritatively not-yet-payable) is durable.
func (s *WebhookService) settle(ctx context.Context, ev PaymentEvent, reconcile reconcileFunc) error {
	if strings.TrimSpace(ev.TenantID) == "" {
		return shared.NewValidationError("tenant_id", "tenant id is required")
	}
	if strings.TrimSpace(ev.TxID) == "" {
		return shared.NewValidationError("tx_id", "tx id is required")
	}
	if strings.TrimSpace(ev.EventKey) == "" {
		return shared.NewValidationError("event_key", "event key is required")
	}

	var settled *payment.Payment
	err := s.uow.WithinTx(ctx, func(r ports.Repository) error {
		// Anti-replay: first-time wins, duplicates are acked as no-ops. Marking
		// inside the tx means the key only persists if the rest of the unit of
		// work commits.
		first, err := r.MarkProcessed(ctx, ev.TenantID, ev.EventKey)
		if err != nil {
			return fmt.Errorf("mark processed: %w", err)
		}
		if !first {
			return nil // duplicate delivery
		}

		// Reconcile authoritative state with the bank (never trust the raw
		// webhook). A transient error here rolls back the mark so the bank's
		// redelivery is reprocessed rather than swallowed.
		res, err := reconcile(ctx, ev.TenantID, ev.TxID)
		if err != nil {
			return fmt.Errorf("reconcile charge: %w", err)
		}
		if !strings.EqualFold(res.Status, bankStatusPaid) {
			// Authoritatively not payable yet; record the delivery as processed.
			return nil
		}

		// Reconcile the MONEY, not only the status (threat W3, SIN-64777). A charge
		// the PSP marked paid may still have been paid to a lesser/greater value
		// (partial payment, adjustable cob, manipulation); settling on status alone
		// would liquidate for the wrong amount.
		//
		// Divergence is a TERMINAL, audited, COMMITTING outcome — deliberately NOT
		// an error. Returning an error here would roll back WithinTx, undoing
		// MarkProcessed, so C6 would redeliver the identical event forever (an
		// infinite settle-retry on a mismatch that will never reconcile) and the
		// audit record would be lost. Instead we keep MarkProcessed, do NOT MarkPaid,
		// durably record the divergence, log a security event, and return nil so the
		// tx commits and the handler returns 202 (notification accepted and recorded;
		// settlement refused). A failure to record the divergence DOES propagate (and
		// roll back) so a transient audit-store outage retries on redelivery rather
		// than committing an unaudited refusal.
		if !res.AmountReconciled() {
			if err := s.recordSettlementMismatch(ctx, ev, res); err != nil {
				return fmt.Errorf("record settlement divergence: %w", err)
			}
			slog.WarnContext(ctx, "settlement amount divergence: refusing to settle",
				"event", "settlement.amount_mismatch",
				"tenant_id", ev.TenantID,
				"tx_id", ev.TxID,
				"expected_cents", res.ExpectedAmountCents,
				"received_cents", res.ReceivedAmountCents,
			)
			return nil
		}

		p, err := r.FindPaymentByTxID(ctx, ev.TenantID, ev.TxID)
		if err != nil {
			return fmt.Errorf("find payment by tx: %w", err)
		}
		if err := p.MarkPaid(ev.TxID, s.clock.Now()); err != nil {
			if errors.Is(err, shared.ErrConflict) {
				return nil // already settled with a different txid: ignore on replay
			}
			return fmt.Errorf("settle payment: %w", err)
		}
		if err := r.SavePayment(ctx, p); err != nil {
			return fmt.Errorf("save settled payment: %w", err)
		}
		settled = p
		return nil
	})
	if err != nil {
		return err
	}
	if settled == nil {
		return nil
	}
	return s.publishSettled(ctx, settled, ev)
}

// recordSettlementMismatch appends the durable audit record for a refused
// settlement (expected/received cents, txid, tenant, system actor — no secret).
// It is called inside the webhook's transaction so the record commits together
// with MarkProcessed; an append error is returned so the caller can roll back and
// retry on redelivery rather than commit an unaudited refusal.
func (s *WebhookService) recordSettlementMismatch(ctx context.Context, ev PaymentEvent, res ports.ChargeResult) error {
	e, err := audit.NewSettlementMismatchEntry(
		s.ids.NewID(),
		systemOperatorWebhook,
		ev.TenantID,
		ev.TxID,
		res.ExpectedAmountCents,
		res.ReceivedAmountCents,
		s.clock.Now(),
	)
	if err != nil {
		return fmt.Errorf("build audit entry: %w", err)
	}
	if err := s.audit.Append(ctx, e); err != nil {
		return fmt.Errorf("append audit entry: %w", err)
	}
	return nil
}

// publishSettled emits the payment-paid event after a successful settlement.
func (s *WebhookService) publishSettled(ctx context.Context, settled *payment.Payment, ev PaymentEvent) error {
	payload := []byte(fmt.Sprintf(`{"payment_id":%q,"tenant_id":%q,"tx_id":%q}`, settled.ID(), settled.TenantID(), settled.TxID()))
	_ = s.bus.Publish(ctx, TopicPaymentPaid, ports.Message{
		TenantID:       settled.TenantID(),
		Type:           TopicPaymentPaid,
		IdempotencyKey: ev.EventKey,
		Payload:        payload,
	})
	// F1 (SIN-69491): attribute the settled event to its owning Conta and materialise
	// it on that Conta's outbound-delivery outbox for F2 to forward. Best-effort and
	// dark: the attributor is a no-op unless PAYMENT_ACCOUNT_OUTBOUND_WEBHOOK is on and
	// it is fully wired, and it NEVER returns an error — an attribution failure must not
	// turn a settled payment into a webhook error to C6 (threat D3). The tenant is the
	// settled payment's own tenant (server-side authoritative), the dedup key is the
	// inbound event_key, and the business event type is payment.paid.
	s.attributor.Attribute(ctx, settled.TenantID(), ev.EventKey, settled.TxID(), TopicPaymentPaid)
	return nil
}

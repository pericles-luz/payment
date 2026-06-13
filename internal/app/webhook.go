package app

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/ia-dev-sindireceita/payment/internal/domain/payment"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// bankStatusPaid is the authoritative bank status that settles a payment.
const bankStatusPaid = "paid"

// WebhookService processes bank webhook events. A webhook is only a trigger: the
// service is idempotent (anti-replay) and reconciles the authoritative state
// with the bank before settling any payment (threats W2/W3).
type WebhookService struct {
	bank  ports.BankProvider
	bus   ports.MessageBus
	clock ports.Clock
	uow   ports.UnitOfWork
}

// NewWebhookService wires a WebhookService from the provided ports.
func NewWebhookService(d Deps) *WebhookService {
	return &WebhookService{
		bank:  d.Bank,
		bus:   d.Bus,
		clock: d.Clock,
		uow:   resolveUoW(d),
	}
}

// PaymentEvent is the validated webhook payload (after transport auth). EventKey
// uniquely identifies the delivery for idempotency (e.g. endToEndId+event).
type PaymentEvent struct {
	TenantID string
	TxID     string
	EventKey string
}

// HandlePaymentEvent reconciles and settles a payment. Duplicate deliveries are
// acked without side effects. The webhook payload is never trusted as financial
// truth — settlement requires a positive reconciliation with the bank.
//
// F2 (SIN-64719): marking the event processed (anti-replay) and settling the
// payment happen in ONE transaction. The previous code committed MarkProcessed
// first, so a transient failure during reconciliation/settlement left the key
// marked — the bank's redelivery was then acked as a duplicate no-op and the
// payment was never settled (exactly-once-settlement silently lost). Now a
// transient failure rolls the whole unit of work back, including the mark, so the
// redelivery re-attempts and eventually settles. The mark is durable only once
// the terminal outcome (settled, or authoritatively not-yet-payable) is durable.
func (s *WebhookService) HandlePaymentEvent(ctx context.Context, ev PaymentEvent) error {
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
		res, err := s.bank.GetCharge(ctx, ev.TenantID, ev.TxID)
		if err != nil {
			return fmt.Errorf("reconcile charge: %w", err)
		}
		if !strings.EqualFold(res.Status, bankStatusPaid) {
			// Authoritatively not payable yet; record the delivery as processed.
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

	payload := []byte(fmt.Sprintf(`{"payment_id":%q,"tenant_id":%q,"tx_id":%q}`, settled.ID(), settled.TenantID(), settled.TxID()))
	_ = s.bus.Publish(ctx, TopicPaymentPaid, ports.Message{
		TenantID:       settled.TenantID(),
		Type:           TopicPaymentPaid,
		IdempotencyKey: ev.EventKey,
		Payload:        payload,
	})
	return nil
}

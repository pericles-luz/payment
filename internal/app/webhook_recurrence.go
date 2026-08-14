package app

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// Recurrence webhook dispatch (PIX Automático F2, SIN-66036). C6 POSTs two
// recurrence notification streams to the tenant's opaque callback channel
// (/webhooks/c6/{tenantRef}/rec and /cobr): a mandate-status notification
// (WebhookRec: CRIADA/APROVADA/REJEITADA/EXPIRADA/CANCELADA) and a recurring-charge
// notification (WebhookCobR). Like every C6 webhook the payload carries NO message
// authenticity (the channel ref IS the credential), so the body is a trigger only:
//
//   - anti-replay dedup by EventKey, inside the unit of work (first delivery wins,
//     redeliveries are acked as no-ops), exactly as the PIX/charge path;
//   - reconcile-before-settle: the authoritative state is read back from C6
//     (GetRec / GetCobR, both JWS-verified in the adapter) — the raw body's status
//     is NEVER trusted (threat W3). A notification for a mandate/charge that does
//     not authoritatively exist is acked and dropped (no settle, no infinite
//     redelivery); a transient read failure rolls the mark back so the redelivery
//     is reprocessed.
//
// Durable recording of the reconciled Rec/CobR state and its status transitions is
// the next phase (F3, persistência/auditoria — SIN-66016). F2 establishes the
// authenticated dispatch + reconcile-before-settle seam; it does not yet liquidate
// a recurring charge into a local payment (that linkage is built in F3 with the
// durable recurrence model), so both handlers reconcile and ack.

// RecEvent is the validated mandate-status webhook (after channel auth). IDRec
// names the mandate to reconcile; EventKey uniquely identifies the delivery for
// idempotency (e.g. idRec|status).
type RecEvent struct {
	TenantID string
	IDRec    string
	EventKey string
}

// CobREvent is the validated recurring-charge webhook (after channel auth). TxID
// names the charge instance to reconcile; EventKey identifies the delivery.
type CobREvent struct {
	TenantID string
	TxID     string
	EventKey string
}

// HandleRecEvent processes a mandate-status notification: it deduplicates the
// delivery and reconciles the authoritative mandate state (GetRec) before trusting
// the event. A first delivery for a mandate that authoritatively exists is recorded
// as processed and acked; a duplicate is a no-op; an unknown mandate is acked and
// dropped (recorded processed so it is not reconciled forever). A transient
// reconcile failure rolls back the dedup mark so C6's redelivery is reprocessed.
func (s *WebhookService) HandleRecEvent(ctx context.Context, ev RecEvent) error {
	if strings.TrimSpace(ev.TenantID) == "" {
		return shared.NewValidationError("tenant_id", "tenant id is required")
	}
	if strings.TrimSpace(ev.IDRec) == "" {
		return shared.NewValidationError("id_rec", "id rec is required")
	}
	if strings.TrimSpace(ev.EventKey) == "" {
		return shared.NewValidationError("event_key", "event key is required")
	}
	if s.recReader == nil {
		return fmt.Errorf("recurrence webhook not configured: %w", shared.ErrUnavailable)
	}
	return s.reconcileRecurrence(ctx, ev.TenantID, ev.EventKey, func(ctx context.Context) error {
		_, err := s.recReader.GetRec(ctx, ev.TenantID, ev.IDRec)
		return err
	})
}

// HandleCobREvent processes a recurring-charge notification: it deduplicates the
// delivery and reconciles the authoritative charge state (GetCobR) before trusting
// the event. Same posture as HandleRecEvent — never settle on the raw body; an
// unknown charge is acked and dropped; a transient read failure rolls back the mark.
func (s *WebhookService) HandleCobREvent(ctx context.Context, ev CobREvent) error {
	if strings.TrimSpace(ev.TenantID) == "" {
		return shared.NewValidationError("tenant_id", "tenant id is required")
	}
	if strings.TrimSpace(ev.TxID) == "" {
		return shared.NewValidationError("tx_id", "tx id is required")
	}
	if strings.TrimSpace(ev.EventKey) == "" {
		return shared.NewValidationError("event_key", "event key is required")
	}
	if s.cobrReader == nil {
		return fmt.Errorf("recurrence webhook not configured: %w", shared.ErrUnavailable)
	}
	return s.reconcileRecurrence(ctx, ev.TenantID, ev.EventKey, func(ctx context.Context) error {
		_, err := s.cobrReader.GetCobR(ctx, ev.TenantID, ev.TxID)
		return err
	})
}

// reconcileRecurrence is the shared dedup + reconcile-before-settle unit of work for
// both recurrence streams. It marks the event processed (anti-replay) and runs the
// authoritative reconcile read inside ONE transaction so the dedup mark is durable
// only once the reconcile reaches a terminal outcome:
//
//   - duplicate delivery → ack, no reconcile;
//   - reconcile OK → mark stays, ack (F3 records the transition here);
//   - reconcile ErrNotFound → the body referenced a mandate/charge the bank does not
//     know: ack and DROP (keep the mark so a forged/stale event is not reconciled on
//     every redelivery — there is nothing to settle);
//   - reconcile transient error (ErrUnavailable, etc.) → return the error so the tx
//     rolls back, undoing the mark, and C6's redelivery is reprocessed.
func (s *WebhookService) reconcileRecurrence(ctx context.Context, tenantID, eventKey string, reconcile func(context.Context) error) error {
	return s.uow.WithinTx(ctx, func(r ports.Repository) error {
		first, err := r.MarkProcessed(ctx, tenantID, eventKey)
		if err != nil {
			return fmt.Errorf("mark processed: %w", err)
		}
		if !first {
			return nil // duplicate delivery
		}
		if err := reconcile(ctx); err != nil {
			if errors.Is(err, shared.ErrNotFound) {
				// Authoritatively unknown: ack and drop (commit the mark).
				return nil
			}
			return fmt.Errorf("reconcile recurrence: %w", err)
		}
		return nil
	})
}

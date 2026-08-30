package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
	"github.com/ia-dev-sindireceita/payment/internal/domain/recurrence"
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
//     (GetRec / GetCobR, over the adapter's authenticated channel) — the raw body's
//     status is NEVER trusted (threat W3). A notification for a mandate/charge that does
//     not authoritatively exist is acked and dropped (no settle, no infinite
//     redelivery); a transient read failure rolls the mark back so the redelivery
//     is reprocessed.
//
// The reconciled state is then RECORDED DURABLY, inside the same unit of work: the
// mandate/charge aggregate is created or transitioned and saved, and a status change
// appends its audit entry alongside it. This is what makes the recurring-charge cycle
// work at all — recurrence.RequireApprovedMandate reads the DURABLE mandate, so a
// mandate the payer approved at their bank is chargeable only once that approval has
// landed here. Reconciling and discarding would leave every mandate stuck CRIADA and
// every origination refused.
//
// The durable write inherits the domain state machine, which is deny-by-default: an
// out-of-order or replayed notification that would drive an illegal transition (a
// terminal mandate moving again, APROVADA going back to CRIADA) is ACKED AND DROPPED
// rather than 500'd. C6 would otherwise redeliver it forever, and there is nothing a
// retry could fix — the event is simply stale.

// RecEvent is the validated mandate-status webhook (after channel auth). IDRec
// names the mandate to reconcile; EventKey uniquely identifies the delivery for
// idempotency (e.g. idRec|status).
type RecEvent struct {
	TenantID string
	IDRec    string
	EventKey string
	// BankID is the non-secret bank slug the mandate belongs to (ADR-0007). It is
	// stamped on the aggregate the first time a mandate is recorded. Empty defaults to
	// C6, which is the only bank with a PIX Automático wire today and the only bank
	// whose inbound webhook route exists.
	BankID string
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
	return s.reconcileRecurrence(ctx, ev.TenantID, ev.EventKey, func(ctx context.Context, r ports.Repository) error {
		res, err := s.recReader.GetRec(ctx, ev.TenantID, ev.IDRec)
		if err != nil {
			return err
		}
		return s.recordRec(ctx, r, ev, res)
	})
}

// recordRec persists the reconciled mandate. It loads the durable aggregate
// tenant-scoped, creating it on first sight (a mandate can be registered at the bank
// by a caller we never saw — the notification is then the first time it reaches us),
// and otherwise transitions it. Only a REAL status change writes an audit entry, so a
// redelivery that reconciles to the same status does not inflate the trail.
func (s *WebhookService) recordRec(ctx context.Context, r ports.Repository, ev RecEvent, res ports.RecResult) error {
	status := recurrence.RecStatus(res.Status)
	rec, err := r.FindRecByID(ctx, ev.TenantID, ev.IDRec)
	switch {
	case err == nil:
		if rec.Status() == status {
			return nil // already recorded at this status — nothing to write
		}
		if err := rec.Transition(status, s.clock.Now()); err != nil {
			// Illegal transition = stale/out-of-order delivery. Ack and drop: the domain
			// refused it on purpose and no redelivery will make it legal (threat W3).
			return nil
		}
	case errors.Is(err, shared.ErrNotFound):
		bankID := strings.TrimSpace(ev.BankID)
		if bankID == "" {
			bankID = ports.BankIDC6
		}
		devedor, derr := recurrence.NewDevedor(recDevedorDoc(res.Vinculo.Devedor), res.Vinculo.Devedor.Nome)
		if derr != nil {
			// The bank's own mandate lacks a usable payer. We cannot invent one, and a
			// half-built aggregate is worse than none: ack and drop so the delivery is
			// not retried forever, leaving the reconcile read as the source of truth.
			return nil
		}
		rec, err = recurrence.NewRec(recurrence.NewRecParams{
			IDRec:         ev.IDRec,
			TenantID:      ev.TenantID,
			BankID:        bankID,
			Contrato:      res.Vinculo.Contrato,
			Devedor:       devedor,
			DataInicial:   res.Calendario.DataInicial,
			Periodicidade: recurrence.RecPeriodicidade(res.Calendario.Periodicidade),
			ValorCents:    res.ValorRecCents,
		}, s.clock.Now())
		if err != nil {
			return nil // same reasoning: an unrepresentable mandate is acked and dropped
		}
		// A mandate first seen already past CRIADA is transitioned into its reconciled
		// status, so the very first notification we receive still lands the right state.
		if status != rec.Status() {
			if err := rec.Transition(status, s.clock.Now()); err != nil {
				return nil
			}
		}
	default:
		return fmt.Errorf("load mandate: %w", err)
	}

	if err := r.SaveRec(ctx, rec); err != nil {
		return fmt.Errorf("save mandate: %w", err)
	}
	entry, err := audit.NewRecurrenceTransitionEntry(s.ids.NewID(), "", ev.TenantID, ev.IDRec, string(rec.Status()), s.clock.Now())
	if err != nil {
		return fmt.Errorf("build audit entry: %w", err)
	}
	if err := r.Append(ctx, entry); err != nil {
		return fmt.Errorf("append audit: %w", err)
	}
	return nil
}

// recDevedorDoc picks the populated document of a BACEN oneOf payer (exactly one of
// CPF/CNPJ is set on the wire).
func recDevedorDoc(d ports.RecDevedor) string {
	if doc := strings.TrimSpace(d.CPF); doc != "" {
		return doc
	}
	return strings.TrimSpace(d.CNPJ)
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
	return s.reconcileRecurrence(ctx, ev.TenantID, ev.EventKey, func(ctx context.Context, r ports.Repository) error {
		res, err := s.cobrReader.GetCobR(ctx, ev.TenantID, ev.TxID)
		if err != nil {
			return err
		}
		return s.recordCobR(ctx, r, ev, res)
	})
}

// recordCobR persists the reconciled recurring charge. Same posture as recordRec: the
// charge is created on first sight or transitioned, an illegal transition is acked and
// dropped, and only a real status change is recorded.
//
// A settlement is NOT taken from the notification body — res is what the bank answered
// when asked directly, which is what reconcile-before-settle means here.
func (s *WebhookService) recordCobR(ctx context.Context, r ports.Repository, ev CobREvent, res ports.CobRResult) error {
	// The domain vocabulary is the cobr wire vocabulary verbatim, so this is a lossless
	// cast rather than a mapping. A status outside it means the PSP extended the
	// contract: the charge is still recorded at the state we DO know, and the unknown
	// value is logged so the drift is visible. Dropping the record instead would hide a
	// contract change behind a silently missing charge.
	status := recurrence.CobRStatus(res.Status)
	cobr, err := r.FindCobRByTxID(ctx, ev.TenantID, ev.TxID)
	switch {
	case err == nil:
		if cobr.Status() == status {
			return nil
		}
		if terr := cobr.Transition(status, s.clock.Now()); terr != nil {
			// Illegal transition = stale/out-of-order delivery, which no retry can fix;
			// an unrecognised status = contract drift. Either way the durable state is
			// left alone and the delivery is acked.
			s.logCobRStatusRefused(ctx, ev, res.Status, terr)
			return nil
		}
	case errors.Is(err, shared.ErrNotFound):
		// A charge the bank knows and we do not: record it so the cycle is auditable,
		// but only if the bank's own view is representable (a non-positive amount or a
		// missing mandate reference is not a charge we can hold).
		cobr, err = recurrence.NewCobR(recurrence.NewCobRParams{
			TxID:       ev.TxID,
			IDRec:      res.IDRec,
			TenantID:   ev.TenantID,
			Vencimento: s.clock.Now().UTC().Format("2006-01-02"),
			ValorCents: res.ValorCents,
		}, s.clock.Now())
		if err != nil {
			return nil
		}
		if status != cobr.Status() {
			if terr := cobr.Transition(status, s.clock.Now()); terr != nil {
				// Record the charge at its initial state rather than discarding it: a
				// charge we cannot classify is still a charge that exists at the bank, and
				// losing the row entirely would leave the cycle with a hole.
				s.logCobRStatusRefused(ctx, ev, res.Status, terr)
			}
		}
	default:
		return fmt.Errorf("load recurring charge: %w", err)
	}

	if err := r.SaveCobR(ctx, cobr); err != nil {
		return fmt.Errorf("save recurring charge: %w", err)
	}
	return nil
}

// logCobRStatusRefused records that a reconciled charge status could not be applied.
// It names the tenant, the charge and the status verbatim — none of which is a secret
// or PII — so an unrecognised value shows up as a searchable line instead of as a
// charge that quietly never advanced.
func (s *WebhookService) logCobRStatusRefused(ctx context.Context, ev CobREvent, status string, cause error) {
	slog.WarnContext(ctx, "recurrence.cobr_status_refused",
		slog.String("tenant_id", ev.TenantID),
		slog.String("tx_id", ev.TxID),
		slog.String("reconciled_status", status),
		slog.String("reason", cause.Error()),
	)
}

// reconcileRecurrence is the shared dedup + reconcile-before-settle unit of work for
// both recurrence streams. It marks the event processed (anti-replay) and runs the
// authoritative reconcile read inside ONE transaction so the dedup mark is durable
// only once the reconcile reaches a terminal outcome:
//
//   - duplicate delivery → ack, no reconcile;
//   - reconcile OK → the reconciled state is recorded durably in the SAME tx as the
//     dedup mark, so the mark and the transition it authorised commit together;
//   - reconcile ErrNotFound → the body referenced a mandate/charge the bank does not
//     know: ack and DROP (keep the mark so a forged/stale event is not reconciled on
//     every redelivery — there is nothing to settle);
//   - reconcile transient error (ErrUnavailable, etc.) → return the error so the tx
//     rolls back, undoing the mark, and C6's redelivery is reprocessed.
func (s *WebhookService) reconcileRecurrence(ctx context.Context, tenantID, eventKey string, reconcile func(context.Context, ports.Repository) error) error {
	return s.uow.WithinTx(ctx, func(r ports.Repository) error {
		first, err := r.MarkProcessed(ctx, tenantID, eventKey)
		if err != nil {
			return fmt.Errorf("mark processed: %w", err)
		}
		if !first {
			return nil // duplicate delivery
		}
		if err := reconcile(ctx, r); err != nil {
			if errors.Is(err, shared.ErrNotFound) {
				// Authoritatively unknown: ack and drop (commit the mark).
				return nil
			}
			return fmt.Errorf("reconcile recurrence: %w", err)
		}
		return nil
	})
}

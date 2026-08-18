package app

import (
	"context"
	"log/slog"

	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// WebhookReconcileWorker performs a periodic sweep that re-attempts C6 PIX webhook
// registration for every tenant that has a C6 credential. It closes the silent-failure
// gap (SIN-69585 / B2 of SIN-69558): if the in-flow TryRegister (F2) failed due to a
// transient C6 outage, the next sweep picks it up with no operator intervention.
//
// Design constraints (CTO):
//   - Reuse WebhookRegistrationService.TryRegister — idempotent via GET-gate.
//   - Enumerate tenants by credential presence, NOT by webhook-ref (hash-only store).
//   - Never log refs or callback URLs; tenant_id is safe to log.
//   - Flag PAYMENT_WEBHOOK_RECONCILE off → Sweep is a no-op (reversibility).
//   - Respects ctx cancellation (no goroutine leak).
//   - Observability: one Info log per sweep with eligible/confirmed/skipped counts.
type WebhookReconcileWorker struct {
	enabled    bool
	enumerator ports.CredentialEnumerator
	registrar  *WebhookRegistrationService
	logger     *slog.Logger
}

// NewWebhookReconcileWorker creates the worker. When enabled is false Sweep is a
// cheap no-op. A nil logger falls back to slog.Default.
func NewWebhookReconcileWorker(enabled bool, enumerator ports.CredentialEnumerator, registrar *WebhookRegistrationService, logger *slog.Logger) *WebhookReconcileWorker {
	if logger == nil {
		logger = slog.Default()
	}
	return &WebhookReconcileWorker{
		enabled:    enabled,
		enumerator: enumerator,
		registrar:  registrar,
		logger:     logger,
	}
}

// Sweep iterates every tenant with a C6 credential and calls TryRegister on each.
// TryRegister's GET-gate makes already-registered tenants a no-op; tenants without a
// creditor key are silently skipped inside TryRegister. The sweep never revives a
// revoked ref: PutWebhookRef's supersede semantics ensure only the LATEST ref is
// active — a revoked ref is gone, and the new mint here becomes the single active one
// if registration succeeds.
//
// Sweep returns (eligible, err) where eligible is the number of tenant ids returned
// by the enumerator. Individual TryRegister failures are swallowed inside TryRegister
// (best-effort); only enumerator errors are surfaced here.
func (w *WebhookReconcileWorker) Sweep(ctx context.Context) (int, error) {
	if !w.enabled {
		return 0, nil
	}
	tenantIDs, err := w.enumerator.ListTenantsWithC6Credential(ctx)
	if err != nil {
		return 0, err
	}
	eligible := len(tenantIDs)
	for _, id := range tenantIDs {
		if ctx.Err() != nil {
			// context cancelled mid-sweep — stop cleanly
			break
		}
		w.registrar.TryRegister(ctx, id)
	}
	w.logger.InfoContext(ctx, "webhook reconcile sweep done",
		slog.Int("eligible_tenants", eligible))
	return eligible, nil
}

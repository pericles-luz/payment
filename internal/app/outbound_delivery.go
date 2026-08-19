package app

import (
	"context"
	"log/slog"
	"strings"

	"github.com/ia-dev-sindireceita/payment/internal/domain/outboundqueue"
	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// outbound_delivery.go is F1 of "webhook de saída por Conta" (SIN-69491, child of
// SIN-69486, model (b) ADR-0011): the inbound→Conta ATTRIBUTION step. Given an event
// on our inbound webhook (today C6-D Pix/recurrence, already tenant-resolved by the
// capability URL), it resolves the owning Conta SERVER-SIDE and materialises the event
// for delivery — enqueuing it on that Conta's durable outbox (F2 will forward) or, when
// the owner cannot be determined, parking it as a dead-letter. There is NO network I/O
// here; the whole path is DARK behind the same PAYMENT_ACCOUNT_OUTBOUND_WEBHOOK flag as
// F0 and is a genuine no-op until it is turned on.
//
// Security bar (threat model SIN-69489 §6): A01 isolation (the outbox is keyed by the
// resolved accountID, never anything from the payload), fail-closed (unattributable ⇒
// dead-letter, never a forward, never a fallback to another Conta), idempotent (dedup by
// event_key), and best-effort with respect to the inbound ACK — an attribution failure
// NEVER propagates an error to the C6 webhook response (that would turn a delivery hiccup
// into a redelivery storm / repudiation channel, threat D3). Hexagonal: the resolver and
// the outbox/dead-letter live behind ports; the domain aggregates are pure.

// AccountResolver resolves an authenticated tenant to its owning Account for outbound
// ATTRIBUTION. It is deliberately DISTINCT from the http choke-point's AccountResolver
// (which is fail-SAFE: any error collapses to "" so it never widens the auth scope):
// here the error must be OBSERVABLE, because "we could not determine the owner" is a
// fail-CLOSED signal to dead-letter the event rather than silently drop it. A nil error
// with an empty accountID means the tenant is validly its own owner (a legacy
// self-account / direct customer with no reseller Conta) — a skip, not an anomaly.
type AccountResolver interface {
	// ResolveAccountID returns the tenant's owning Account id (the reseller Conta), or
	// "" when the tenant has no assigned reseller (self-account). A non-nil error means
	// the ownership is INDETERMINABLE (transient store failure, missing tenant) and the
	// caller must fail-closed (dead-letter), never assume an owner.
	ResolveAccountID(ctx context.Context, tenantID string) (string, error)
}

// OutboundDeliveryQueue is the durable per-Conta outbox the attributor writes to and F2
// consumes. EnqueueDelivery MUST be idempotent on the (accountID, eventKey) pair so a
// redelivered inbound event never enqueues a duplicate forward.
type OutboundDeliveryQueue interface {
	EnqueueDelivery(ctx context.Context, d *outboundqueue.Delivery) error
}

// DeadLetterSink persists inbound events that could not be attributed to a Conta, for
// inspection/replay. DeadLetter MUST be idempotent on the (tenantID, eventKey) pair.
type DeadLetterSink interface {
	DeadLetter(ctx context.Context, dl *outboundqueue.DeadLetter) error
}

// tenantAccountFinder is the narrow slice of the tenant read store the default resolver
// needs (accept-narrow): look up one tenant to read its owning account. ports.TenantRepository
// and both persistence adapters satisfy it.
type tenantAccountFinder interface {
	FindTenantByID(ctx context.Context, id string) (*tenant.Tenant, error)
}

// storeAccountResolver is the default AccountResolver: it reads the owning Account from
// the tenant store, surfacing (unlike the http choke-point variant) any read error so
// the attributor fails-closed to a dead-letter. It never widens isolation scope — it only
// reports which Account the tenant was grouped under (tenants.account_id).
type storeAccountResolver struct {
	tenants tenantAccountFinder
}

// NewStoreAccountResolver builds the default resolver over the tenant read store.
func NewStoreAccountResolver(finder tenantAccountFinder) AccountResolver {
	return &storeAccountResolver{tenants: finder}
}

// ResolveAccountID reads the tenant's owning account. An empty tenant id resolves to
// "" with no error (nothing to look up → treated as no reseller owner). A store error is
// returned so the caller dead-letters (fail-closed) rather than dropping the event.
func (r *storeAccountResolver) ResolveAccountID(ctx context.Context, tenantID string) (string, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return "", nil
	}
	t, err := r.tenants.FindTenantByID(ctx, tenantID)
	if err != nil {
		return "", err
	}
	return t.AccountID(), nil
}

// OutboundAttributor performs the F1 attribution: resolve the owning Conta and either
// enqueue the event on that Conta's outbox or dead-letter it. It is safe to call on a nil
// receiver and no-ops when disabled, so the inbound path can invoke it unconditionally and
// the feature stays dark until the flag turns it on.
type OutboundAttributor struct {
	enabled     bool
	resolver    AccountResolver
	queue       OutboundDeliveryQueue
	deadLetters DeadLetterSink
	clock       ports.Clock
	ids         ports.IDProvider
}

// OutboundAttributorDeps wires the attributor. All fields are required when enabled; if
// any port is nil the attributor stays inert (fail-closed to no-op) so a half-wired
// deployment can never originate a mis-attributed delivery.
type OutboundAttributorDeps struct {
	Enabled     bool
	Resolver    AccountResolver
	Queue       OutboundDeliveryQueue
	DeadLetters DeadLetterSink
	Clock       ports.Clock
	IDs         ports.IDProvider
}

// NewOutboundAttributor builds an attributor from its deps.
func NewOutboundAttributor(d OutboundAttributorDeps) *OutboundAttributor {
	return &OutboundAttributor{
		enabled:     d.Enabled,
		resolver:    d.Resolver,
		queue:       d.Queue,
		deadLetters: d.DeadLetters,
		clock:       d.Clock,
		ids:         d.IDs,
	}
}

// active reports whether the attributor should do anything: it is enabled and every
// port it needs is wired. Anything else is an inert no-op (dark-ship default).
func (a *OutboundAttributor) active() bool {
	return a != nil && a.enabled && a.resolver != nil && a.queue != nil &&
		a.deadLetters != nil && a.clock != nil && a.ids != nil
}

// Attribute resolves the owning Conta of an inbound event and materialises it for F2:
//   - resolver error (owner INDETERMINABLE) ⇒ dead-letter (fail-closed);
//   - resolved to a real reseller Conta (accountID != "") ⇒ enqueue on that Conta's outbox;
//   - resolved to no reseller (accountID == "", a self-account/direct customer) ⇒ skip —
//     there is no outbound webhook owner, which is the normal direct case, not an anomaly.
//
// It NEVER returns an error: every failure is logged and swallowed so the inbound webhook
// ACK to C6 is fully decoupled from attribution (best-effort, threat D3). It is a no-op
// when the attributor is inactive (flag off / not wired), keeping the feature dark.
// detail carries the NON-PII settlement detail forwarded with the delivery (amount in
// cents, card installments, PSP capture message). A caller with nothing to add passes
// the zero value, which forwards exactly as before this field existed.
func (a *OutboundAttributor) Attribute(ctx context.Context, tenantID, eventKey, txID, eventType string, detail outboundqueue.Detail) {
	if !a.active() {
		return
	}

	accountID, err := a.resolver.ResolveAccountID(ctx, tenantID)
	if err != nil {
		// Owner indeterminable: park for inspection/replay, never guess a Conta.
		a.park(ctx, tenantID, eventKey, txID, eventType, outboundqueue.ReasonUnresolvable, err)
		return
	}
	if strings.TrimSpace(accountID) == "" {
		// No reseller Conta owns this tenant (self-account / direct customer). There is
		// nothing to deliver outbound; this is the normal direct case, so we skip WITHOUT
		// dead-lettering (dead-lettering every direct-customer settlement would flood the
		// park with non-anomalies). A01 is preserved: no forward, no fallback.
		slog.DebugContext(ctx, "outbound attribution: tenant has no reseller Conta, skipping",
			"event", "outbound.attribution.skip",
			"tenant_id", tenantID,
			"event_type", eventType)
		return
	}

	d, err := outboundqueue.NewDelivery(a.ids.NewID(), accountID, tenantID, eventKey, txID, eventType, detail, a.clock.Now())
	if err != nil {
		slog.ErrorContext(ctx, "outbound attribution: could not build delivery",
			"event", "outbound.attribution.error",
			"tenant_id", tenantID,
			"account_id", accountID,
			"event_type", eventType,
			"err", err)
		return
	}
	if err := a.queue.EnqueueDelivery(ctx, d); err != nil {
		slog.ErrorContext(ctx, "outbound attribution: could not enqueue delivery",
			"event", "outbound.attribution.error",
			"tenant_id", tenantID,
			"account_id", accountID,
			"event_type", eventType,
			"err", err)
		return
	}
}

// park persists a dead-letter for an unattributable event. It swallows its own errors
// (logging them) so attribution stays best-effort: a park failure must not surface to the
// inbound ACK. The resolver error that triggered the park is logged for diagnosis but its
// text is never persisted (the DeadLetter carries only a classified reason).
func (a *OutboundAttributor) park(ctx context.Context, tenantID, eventKey, txID, eventType string, reason outboundqueue.Reason, cause error) {
	slog.WarnContext(ctx, "outbound attribution: owner indeterminable, dead-lettering",
		"event", "outbound.attribution.dead_letter",
		"tenant_id", tenantID,
		"event_type", eventType,
		"reason", string(reason),
		"err", cause)
	dl, err := outboundqueue.NewDeadLetter(a.ids.NewID(), tenantID, eventKey, txID, eventType, reason, a.clock.Now())
	if err != nil {
		slog.ErrorContext(ctx, "outbound attribution: could not build dead-letter",
			"event", "outbound.attribution.error",
			"tenant_id", tenantID,
			"event_type", eventType,
			"err", err)
		return
	}
	if err := a.deadLetters.DeadLetter(ctx, dl); err != nil {
		slog.ErrorContext(ctx, "outbound attribution: could not persist dead-letter",
			"event", "outbound.attribution.error",
			"tenant_id", tenantID,
			"event_type", eventType,
			"err", err)
	}
}

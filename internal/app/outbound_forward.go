package app

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strconv"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
	"github.com/ia-dev-sindireceita/payment/internal/domain/outboundqueue"
	"github.com/ia-dev-sindireceita/payment/internal/domain/outboundwebhook"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// outbound_forward.go is F2 of "webhook de saída por Conta" (SIN-69492, child of
// SIN-69486, model (b) ADR-0011): it CONSUMES the F1 outbox and DELIVERS each attributed
// event to the owning Conta's outbound endpoint, signed per-Conta, best-effort. It is the
// orchestration the threat model SIN-69489 governs; the SSRF-safe network edge, the guard
// and the limiter are OUT-adapters (internal/adapters/outbound) injected as ports, so this
// layer never imports net/http (hexagonal).
//
// Security bar (SIN-69489 §7 blocking checklist), enforced here:
//   - A01 isolation: the endpoint is loaded by the delivery's OWN server-side accountID
//     (never anything from a payload), so an event is only ever delivered to its Conta.
//   - Fail-closed: a deliberately-disabled endpoint ⇒ dead-letter; a Conta with NO endpoint
//     configured at all ⇒ Info log + terminal settle (SIN-69508, a normal operational state,
//     not a failure). Either way: never a forward, never a fallback to another Conta.
//   - Best-effort / D3: the whole path runs OUT-OF-BAND of the inbound C6 ACK (a
//     background consumer, not the webhook handler), so a forward failure can never turn
//     into an error response to C6 — it becomes a bounded retry then a dead-letter.
//   - HMAC per Conta with a signed timestamp (anti-replay); the secret stays write-only.
//   - Bounded retry with backoff+jitter and a per-Conta limiter (no retry storm, no
//     cross-Conta starvation); persistent failure ⇒ dead-letter (no infinite loop).
//   - Per-attempt audit (delivered / dead_letter), account-scoped, never the payload/secret.
//   - Dark behind PAYMENT_ACCOUNT_OUTBOUND_WEBHOOK: inert no-op until the flag turns it on.

// OutboundOutbox is the durable per-Conta outbox F2 consumes: claim a cross-account batch
// of pending deliveries, and delete one once it is settled (delivered or dead-lettered).
// The sqlite and in-memory OutboundDeliveryStore satisfy it.
type OutboundOutbox interface {
	ClaimPendingDeliveries(ctx context.Context, limit int) ([]*outboundqueue.Delivery, error)
	DeleteDelivery(ctx context.Context, id string) error
}

// OutboundConfigReader is the narrow read slice of the F0 config store the forwarder needs
// (accept-narrow): load a Conta's endpoint (URL + transient signing secret) by accountID.
// The encrypted sqlite vault and the in-memory store satisfy it. Get returns
// shared.ErrNotFound when the Conta has no endpoint.
type OutboundConfigReader interface {
	GetOutboundWebhook(ctx context.Context, accountID string) (*outboundwebhook.Config, error)
}

// OutboundForwarder POSTs a signed body to a destination over an SSRF-safe client and
// returns the response status. It is the port the outbound.Forwarder adapter implements;
// this layer treats it as an opaque one-shot delivery (all SSRF hardening lives inside it).
type OutboundForwarder interface {
	Deliver(ctx context.Context, url string, headers map[string]string, body []byte) (int, error)
}

// OutboundLimiter paces forwards per Conta (threats D1/D2). The outbound.PerAccountLimiter
// adapter implements it. Wait blocks until the account may send or ctx is cancelled.
type OutboundLimiter interface {
	Wait(ctx context.Context, accountID string) error
}

// forwardSleeper waits for d or until ctx is done (injected so tests drive backoff without
// real sleeps). Returns ctx.Err() on cancellation.
type forwardSleeper func(ctx context.Context, d time.Duration) error

const (
	// defaultForwardMaxAttempts is the total number of delivery attempts before giving up
	// and dead-lettering (threat D1 — no infinite retry). Small on purpose: a degraded
	// receiver is not hammered.
	defaultForwardMaxAttempts = 3
	// defaultForwardBackoffBase / defaultForwardBackoffMax bound the exponential backoff
	// between attempts.
	defaultForwardBackoffBase = 250 * time.Millisecond
	defaultForwardBackoffMax  = 5 * time.Second
	// defaultForwardBatch caps how many pending deliveries one ProcessPending tick claims,
	// bounding the work (and memory) per cycle.
	defaultForwardBatch = 64
)

// systemOperatorOutboundForward names the system actor on the per-attempt audit records
// (a forward has no human operator), mirroring systemOperatorWebhook.
const systemOperatorOutboundForward = "system:outbound-forward"

// OutboundProcessor consumes the F1 outbox and forwards each delivery. Construct it via
// NewOutboundProcessor; ProcessPending is safe to call on a nil/disabled receiver (no-op),
// so a background runner can tick it unconditionally and the feature stays dark until the
// flag and every port are wired.
type OutboundProcessor struct {
	enabled     bool
	outbox      OutboundOutbox
	configs     OutboundConfigReader
	forwarder   OutboundForwarder
	limiter     OutboundLimiter
	deadLetters DeadLetterSink
	audit       ports.AuditLog
	clock       ports.Clock
	ids         ports.IDProvider

	maxAttempts int
	backoffBase time.Duration
	backoffMax  time.Duration
	batch       int
	rand        func() float64
	sleep       forwardSleeper
}

// OutboundProcessorDeps wires the processor. All ports are required when enabled; if any
// is nil the processor stays inert (fail-closed to no-op) so a half-wired deployment never
// originates an unsigned or mis-routed forward.
type OutboundProcessorDeps struct {
	Enabled     bool
	Outbox      OutboundOutbox
	Configs     OutboundConfigReader
	Forwarder   OutboundForwarder
	Limiter     OutboundLimiter
	DeadLetters DeadLetterSink
	Audit       ports.AuditLog
	Clock       ports.Clock
	IDs         ports.IDProvider
	// Rand is the jitter source (defaults to a fixed 0.5 half-jitter when nil, still
	// bounded and safe). Sleep is the backoff waiter (defaults to a real timer when nil).
	Rand  func() float64
	Sleep func(ctx context.Context, d time.Duration) error
	// MaxAttempts / BackoffBase / BackoffMax / Batch override the defaults (0 ⇒ default).
	MaxAttempts int
	BackoffBase time.Duration
	BackoffMax  time.Duration
	Batch       int
}

// NewOutboundProcessor builds a processor from its deps, applying defaults for the tuning
// knobs left zero.
func NewOutboundProcessor(d OutboundProcessorDeps) *OutboundProcessor {
	p := &OutboundProcessor{
		enabled:     d.Enabled,
		outbox:      d.Outbox,
		configs:     d.Configs,
		forwarder:   d.Forwarder,
		limiter:     d.Limiter,
		deadLetters: d.DeadLetters,
		audit:       d.Audit,
		clock:       d.Clock,
		ids:         d.IDs,
		maxAttempts: d.MaxAttempts,
		backoffBase: d.BackoffBase,
		backoffMax:  d.BackoffMax,
		batch:       d.Batch,
		rand:        d.Rand,
		sleep:       d.Sleep,
	}
	if p.maxAttempts <= 0 {
		p.maxAttempts = defaultForwardMaxAttempts
	}
	if p.backoffBase <= 0 {
		p.backoffBase = defaultForwardBackoffBase
	}
	if p.backoffMax <= 0 {
		p.backoffMax = defaultForwardBackoffMax
	}
	if p.batch <= 0 {
		p.batch = defaultForwardBatch
	}
	if p.rand == nil {
		p.rand = func() float64 { return 0.5 }
	}
	if p.sleep == nil {
		p.sleep = realForwardSleep
	}
	return p
}

// realForwardSleep is the production backoff waiter: one timer, no goroutine leak, prompt
// ctx cancellation.
func realForwardSleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// active reports whether the processor should do anything: enabled and every port wired.
// Anything else is an inert no-op (dark-ship default, fail-closed).
func (p *OutboundProcessor) active() bool {
	return p != nil && p.enabled && p.outbox != nil && p.configs != nil &&
		p.forwarder != nil && p.limiter != nil && p.deadLetters != nil &&
		p.audit != nil && p.clock != nil && p.ids != nil
}

// ProcessPending claims one batch of pending outbox deliveries and forwards each. It
// returns the number of deliveries it reached a TERMINAL outcome for (delivered or
// dead-lettered) this cycle. It is a no-op returning (0, nil) when inactive. A claim error
// is returned so a runner can log/back off; per-delivery failures never abort the batch
// (best-effort) and never surface as an error.
func (p *OutboundProcessor) ProcessPending(ctx context.Context) (int, error) {
	if !p.active() {
		return 0, nil
	}
	deliveries, err := p.outbox.ClaimPendingDeliveries(ctx, p.batch)
	if err != nil {
		return 0, err
	}
	settled := 0
	for _, d := range deliveries {
		if ctx.Err() != nil {
			break
		}
		if p.deliverOne(ctx, d) {
			settled++
		}
	}
	return settled, nil
}

// deliverOne forwards a single attributed delivery to its owning Conta's endpoint, or
// dead-letters it. It returns true when the delivery reached a terminal outcome (removed
// from the outbox), false when it was left on the outbox to retry on a later tick (a
// transient config-store read failure — fail-SAFE: we do not dead-letter an event just
// because the store blipped, and we never forward without a proven endpoint).
func (p *OutboundProcessor) deliverOne(ctx context.Context, d *outboundqueue.Delivery) bool {
	cfg, err := p.configs.GetOutboundWebhook(ctx, d.AccountID())
	switch {
	case err == nil && cfg.Enabled():
		// active endpoint — fall through to forward.
	case err == nil && !cfg.Enabled():
		// Configured but switched off ⇒ fail-closed park (never forward a disabled Conta).
		return p.parkAndSettle(ctx, d, outboundqueue.ReasonEndpointInactive)
	case errors.Is(err, shared.ErrNotFound):
		// No endpoint configured at all ⇒ NOT a failure (SIN-69508). This is a valid
		// reseller Conta that simply never set up an outbound webhook: the board wants that
		// treated as a normal, observable operational condition — emit ONE Info log and
		// settle terminally, WITHOUT a dead-letter/audit/retry. This is deliberately DISTINCT
		// from the !cfg.Enabled() branch above (an operator switched an existing endpoint
		// off), which still parks for visibility. A01 is preserved either way: no fallback to
		// another Conta, and there is no URL/secret to leak here (none is configured).
		return p.settleNoConfig(ctx, d)
	default:
		// Transient store error: leave on the outbox for the next tick (fail-safe). Do NOT
		// dead-letter (the owner may be perfectly valid) and do NOT forward (no endpoint).
		slog.WarnContext(ctx, "outbound forward: config read failed, will retry",
			"event", "outbound.forward.config_error",
			"account_id", d.AccountID(),
			"event_type", d.EventType(),
			"err", err)
		return false
	}

	// A01 note: cfg is the endpoint of d.AccountID() and nothing else — the load key is the
	// server-side resolved account, so cross-Conta delivery is impossible by construction.
	if err := p.limiter.Wait(ctx, d.AccountID()); err != nil {
		// ctx cancelled while throttled: leave on the outbox for the next run.
		return false
	}

	body, err := buildForwardBody(d, p.clock.Now())
	if err != nil {
		// Serialising our own event should never fail; if it does, park it rather than loop.
		slog.ErrorContext(ctx, "outbound forward: could not build body",
			"event", "outbound.forward.error", "account_id", d.AccountID(), "err", err)
		return p.parkAndSettle(ctx, d, outboundqueue.ReasonDeliveryExhausted)
	}

	if p.attemptDelivery(ctx, d, cfg, body) {
		return p.settleDelivered(ctx, d)
	}
	// Every bounded attempt failed ⇒ terminal dead-letter (threat D1: no infinite retry).
	return p.parkAndSettle(ctx, d, outboundqueue.ReasonDeliveryExhausted)
}

// attemptDelivery runs the bounded retry loop for one delivery and reports whether the
// destination accepted it (2xx) on some attempt. Each attempt re-stamps a fresh timestamp
// and re-signs, so the signed timestamp always reflects the actual send instant
// (anti-replay). Between attempts it backs off with jitter; ctx cancellation aborts.
func (p *OutboundProcessor) attemptDelivery(ctx context.Context, d *outboundqueue.Delivery, cfg *outboundwebhook.Config, body []byte) bool {
	for attempt := 0; attempt < p.maxAttempts; attempt++ {
		if ctx.Err() != nil {
			return false
		}
		ts := p.clock.Now().Unix()
		headers := map[string]string{
			outboundwebhook.SignatureHeader:   cfg.Sign(ts, body),
			outboundwebhook.TimestampHeader:   strconv.FormatInt(ts, 10),
			outboundwebhook.IdempotencyHeader: d.EventKey(),
		}
		status, err := p.forwarder.Deliver(ctx, cfg.URL(), headers, body)
		if err == nil && status >= 200 && status < 300 {
			return true
		}
		// Failed attempt: log the (non-sensitive) status only — never the destination's
		// response body, which the forwarder already discarded (SSRF-7).
		slog.WarnContext(ctx, "outbound forward: attempt failed",
			"event", "outbound.forward.attempt_failed",
			"account_id", d.AccountID(),
			"event_type", d.EventType(),
			"attempt", attempt+1,
			"status", status,
			"err", err)
		if attempt < p.maxAttempts-1 {
			if serr := p.sleep(ctx, p.backoff(attempt)); serr != nil {
				return false
			}
		}
	}
	return false
}

// backoff computes the delay before the retry after `attempt`: base·2^attempt capped at
// backoffMax, with equal jitter (half fixed, half scaled by the injected rand) so retries
// from many deliveries do not synchronise into a thundering herd.
func (p *OutboundProcessor) backoff(attempt int) time.Duration {
	d := p.backoffBase << attempt
	if d <= 0 || d > p.backoffMax {
		d = p.backoffMax
	}
	half := d / 2
	jitter := time.Duration(p.rand() * float64(half))
	return half + jitter
}

// settleNoConfig handles a delivery whose owning Conta has NO outbound endpoint configured
// (shared.ErrNotFound). Per SIN-69508 this is a normal, observable operational condition —
// not a failure: emit ONE structured Info log identifying the Conta by accountID (plus the
// non-PII routing IDs event_key/tx_id) and remove the delivery from the outbox terminally
// (settle). No dead-letter, no audit, no retry — distinct from a deliberately-disabled
// endpoint, which parks. The Conta is identified only by ID; there is no URL or secret to
// leak (none is configured), matching the SSRF-7 redaction the rest of the file follows.
// The delivery MUST be removed from the outbox: otherwise it is re-claimed every tick,
// spamming the log and keeping the outbox dirty.
func (p *OutboundProcessor) settleNoConfig(ctx context.Context, d *outboundqueue.Delivery) bool {
	slog.InfoContext(ctx, "outbound forward: no endpoint configured for account, nothing to forward",
		"event", "outbound.forward.no_endpoint_configured",
		"account_id", d.AccountID(),
		"event_type", d.EventType(),
		"event_key", d.EventKey(),
		"tx_id", d.TxID())
	if err := p.outbox.DeleteDelivery(ctx, d.ID()); err != nil {
		slog.ErrorContext(ctx, "outbound forward: could not remove no-config event",
			"event", "outbound.forward.error", "account_id", d.AccountID(), "err", err)
	}
	return true
}

// settleDelivered removes a delivered event from the outbox and records the per-attempt
// audit (delivered). The audit is the durable outcome record (the outbox is a work queue).
func (p *OutboundProcessor) settleDelivered(ctx context.Context, d *outboundqueue.Delivery) bool {
	if err := p.outbox.DeleteDelivery(ctx, d.ID()); err != nil {
		slog.ErrorContext(ctx, "outbound forward: could not remove delivered event",
			"event", "outbound.forward.error", "account_id", d.AccountID(), "err", err)
	}
	p.auditDelivery(ctx, audit.ActionOutboundWebhookDelivered, d)
	slog.InfoContext(ctx, "outbound forward: delivered",
		"event", "outbound.forward.delivered",
		"account_id", d.AccountID(), "event_type", d.EventType())
	return true
}

// parkAndSettle dead-letters a delivery it could not deliver (endpoint inactive / retries
// exhausted) and removes it from the outbox, recording the per-attempt audit. A dead-letter
// write failure is logged, not fatal — attribution/delivery stay best-effort — but the
// event is still removed from the outbox so it is not retried forever.
func (p *OutboundProcessor) parkAndSettle(ctx context.Context, d *outboundqueue.Delivery, reason outboundqueue.Reason) bool {
	dl, err := outboundqueue.DeadLetterFromDelivery(p.ids.NewID(), d, reason, p.clock.Now())
	if err != nil {
		slog.ErrorContext(ctx, "outbound forward: could not build dead-letter",
			"event", "outbound.forward.error", "account_id", d.AccountID(), "err", err)
	} else if err := p.deadLetters.DeadLetter(ctx, dl); err != nil {
		slog.ErrorContext(ctx, "outbound forward: could not persist dead-letter",
			"event", "outbound.forward.error", "account_id", d.AccountID(), "err", err)
	}
	if err := p.outbox.DeleteDelivery(ctx, d.ID()); err != nil {
		slog.ErrorContext(ctx, "outbound forward: could not remove dead-lettered event",
			"event", "outbound.forward.error", "account_id", d.AccountID(), "err", err)
	}
	p.auditDelivery(ctx, audit.ActionOutboundWebhookDeadLettered, d)
	slog.WarnContext(ctx, "outbound forward: dead-lettered",
		"event", "outbound.forward.dead_letter",
		"account_id", d.AccountID(), "event_type", d.EventType(), "reason", string(reason))
	return true
}

// auditDelivery appends the account-scoped per-attempt audit entry (delivered /
// dead_letter). It swallows its own errors (logging them) so the forensic append never
// aborts a best-effort delivery — but production wires a durable audit log so the trail is
// real (threat R1).
func (p *OutboundProcessor) auditDelivery(ctx context.Context, action audit.Action, d *outboundqueue.Delivery) {
	e, err := audit.NewOutboundDeliveryEntry(p.ids.NewID(), systemOperatorOutboundForward, action, d.AccountID(), d.EventKey(), p.clock.Now())
	if err != nil {
		slog.ErrorContext(ctx, "outbound forward: could not build audit entry",
			"event", "outbound.forward.error", "account_id", d.AccountID(), "err", err)
		return
	}
	if err := p.audit.Append(ctx, e); err != nil {
		slog.ErrorContext(ctx, "outbound forward: could not append audit entry",
			"event", "outbound.forward.error", "account_id", d.AccountID(), "err", err)
	}
}

// forwardBody is the canonical JSON envelope delivered to a Conta's endpoint. It carries
// only NON-PII routing/notification fields — the event type, the referenced charge id, the
// dedup event_key, the owning account and the send timestamp — never the devedor PII a Pix
// payload can hold (sin-68744); a receiver that needs charge detail calls our API back with
// its account key. Struct field order is stable, so json.Marshal is deterministic and the
// signed bytes match the transmitted bytes exactly.
type forwardBody struct {
	EventKey  string `json:"event_key"`
	EventType string `json:"event_type"`
	TxID      string `json:"tx_id"`
	AccountID string `json:"account_id"`
	Timestamp int64  `json:"timestamp"`
}

// buildForwardBody serialises the canonical envelope for a delivery at instant now.
func buildForwardBody(d *outboundqueue.Delivery, now time.Time) ([]byte, error) {
	return json.Marshal(forwardBody{
		EventKey:  d.EventKey(),
		EventType: d.EventType(),
		TxID:      d.TxID(),
		AccountID: d.AccountID(),
		Timestamp: now.Unix(),
	})
}

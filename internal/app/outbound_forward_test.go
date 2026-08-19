package app_test

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
	"github.com/ia-dev-sindireceita/payment/internal/domain/outboundqueue"
	"github.com/ia-dev-sindireceita/payment/internal/domain/outboundwebhook"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// --- F2 forward test doubles ------------------------------------------------

// fwdConfigReader is a programmable app.OutboundConfigReader keyed by accountID. A missing
// key returns shared.ErrNotFound; err (if set) is returned for every account (transient
// store failure).
type fwdConfigReader struct {
	cfgs map[string]*outboundwebhook.Config
	err  error
}

func (r *fwdConfigReader) GetOutboundWebhook(_ context.Context, accountID string) (*outboundwebhook.Config, error) {
	if r.err != nil {
		return nil, r.err
	}
	if c, ok := r.cfgs[accountID]; ok {
		return c, nil
	}
	return nil, shared.ErrNotFound
}

// fwdCall records one Deliver invocation.
type fwdCall struct {
	url     string
	headers map[string]string
	body    []byte
}

// fakeForwarder returns a scripted sequence of (status, err) results and records every
// call. Once the script is exhausted it repeats the last result.
type fakeForwarder struct {
	mu      sync.Mutex
	results []fwdResult
	calls   []fwdCall
}

type fwdResult struct {
	status int
	err    error
}

func (f *fakeForwarder) Deliver(_ context.Context, url string, headers map[string]string, body []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, fwdCall{url: url, headers: headers, body: append([]byte(nil), body...)})
	i := len(f.calls) - 1
	if i >= len(f.results) {
		i = len(f.results) - 1
	}
	if len(f.results) == 0 {
		return 200, nil
	}
	return f.results[i].status, f.results[i].err
}

func (f *fakeForwarder) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// noopLimiter admits every forward immediately.
type noopLimiter struct{ waited []string }

func (l *noopLimiter) Wait(_ context.Context, accountID string) error {
	l.waited = append(l.waited, accountID)
	return nil
}

// recAudit records appended entries.
type recAudit struct {
	mu      sync.Mutex
	entries []audit.Entry
}

func (a *recAudit) Append(_ context.Context, e audit.Entry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, e)
	return nil
}

func (a *recAudit) actions() []audit.Action {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]audit.Action, len(a.entries))
	for i, e := range a.entries {
		out[i] = e.Action()
	}
	return out
}

var fwdNow = time.Date(2026, 8, 17, 16, 0, 0, 0, time.UTC)

func mustConfig(t *testing.T, accountID, url, secret string, enabled bool) *outboundwebhook.Config {
	t.Helper()
	c, err := outboundwebhook.New(accountID, url, secret, enabled, fwdNow)
	if err != nil {
		t.Fatalf("new config: %v", err)
	}
	return c
}

// procHarness bundles a processor with the real in-memory outbox (no DB mock) and the
// programmable doubles.
type procHarness struct {
	proc      *app.OutboundProcessor
	outbox    *inmemory.OutboundDeliveryStore
	forwarder *fakeForwarder
	audit     *recAudit
	sleeps    int
}

func newProcHarness(t *testing.T, enabled bool, reader app.OutboundConfigReader, fwd *fakeForwarder) *procHarness {
	t.Helper()
	outbox := inmemory.NewOutboundDeliveryStore()
	aud := &recAudit{}
	h := &procHarness{outbox: outbox, forwarder: fwd, audit: aud}
	h.proc = app.NewOutboundProcessor(app.OutboundProcessorDeps{
		Enabled:     enabled,
		Outbox:      outbox,
		Configs:     reader,
		Forwarder:   fwd,
		Limiter:     &noopLimiter{},
		DeadLetters: outbox,
		Audit:       aud,
		Clock:       fixedClock{t: fwdNow},
		IDs:         &seqIDs{},
		MaxAttempts: 3,
		Rand:        func() float64 { return 0.5 },
		Sleep: func(_ context.Context, _ time.Duration) error {
			h.sleeps++
			return nil
		},
	})
	return h
}

func (h *procHarness) enqueue(t *testing.T, id, acct, ek string) {
	t.Helper()
	d, err := outboundqueue.NewDelivery(id, acct, "ten-1", ek, "tx-1", "payment.paid", outboundqueue.Detail{}, fwdNow)
	if err != nil {
		t.Fatalf("new delivery: %v", err)
	}
	if err := h.outbox.EnqueueDelivery(context.Background(), d); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
}

// --- tests ------------------------------------------------------------------

// Happy path + T-AUDIT + HMAC: a 2xx delivery signs the body per-Conta, removes the row,
// and records a delivered audit entry.
func TestProcessDeliversAndAudits(t *testing.T) {
	secret := "whsec_test_secret"
	reader := &fwdConfigReader{cfgs: map[string]*outboundwebhook.Config{
		"acct-A": mustConfig(t, "acct-A", "https://a.example.com/hook", secret, true),
	}}
	fwd := &fakeForwarder{results: []fwdResult{{status: 202}}}
	h := newProcHarness(t, true, reader, fwd)
	h.enqueue(t, "d1", "acct-A", "ek-1")

	n, err := h.proc.ProcessPending(context.Background())
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if n != 1 {
		t.Fatalf("settled = %d, want 1", n)
	}
	if fwd.callCount() != 1 {
		t.Fatalf("forwarder calls = %d, want 1", fwd.callCount())
	}
	// Delivered to acct-A's URL, signed with acct-A's secret over the exact body.
	call := fwd.calls[0]
	if call.url != "https://a.example.com/hook" {
		t.Fatalf("url = %q", call.url)
	}
	ts, _ := strconv.ParseInt(call.headers[outboundwebhook.TimestampHeader], 10, 64)
	wantSig := outboundwebhook.Sign(secret, ts, call.body)
	if call.headers[outboundwebhook.SignatureHeader] != wantSig {
		t.Fatalf("signature header %q != recomputed %q", call.headers[outboundwebhook.SignatureHeader], wantSig)
	}
	if call.headers[outboundwebhook.IdempotencyHeader] != "ek-1" {
		t.Fatalf("idempotency header = %q, want ek-1", call.headers[outboundwebhook.IdempotencyHeader])
	}
	// Row removed from outbox.
	if left, _ := h.outbox.ClaimPendingDeliveries(context.Background(), 10); len(left) != 0 {
		t.Fatalf("outbox should be empty after delivery, got %d", len(left))
	}
	if acts := h.audit.actions(); len(acts) != 1 || acts[0] != audit.ActionOutboundWebhookDelivered {
		t.Fatalf("audit actions = %v, want [delivered]", acts)
	}
}

// T-ISO-crossaccount (A01): the endpoint is loaded by the delivery's OWN accountID; an
// event for acct-A is never delivered to acct-B's URL, even with both configured.
func TestProcessIsolatesPerAccount(t *testing.T) {
	reader := &fwdConfigReader{cfgs: map[string]*outboundwebhook.Config{
		"acct-A": mustConfig(t, "acct-A", "https://a.example.com/hook", "whsec_a", true),
		"acct-B": mustConfig(t, "acct-B", "https://b.example.com/hook", "whsec_b", true),
	}}
	fwd := &fakeForwarder{results: []fwdResult{{status: 200}}}
	h := newProcHarness(t, true, reader, fwd)
	h.enqueue(t, "d1", "acct-A", "ek-1")

	if _, err := h.proc.ProcessPending(context.Background()); err != nil {
		t.Fatalf("process: %v", err)
	}
	if fwd.callCount() != 1 {
		t.Fatalf("calls = %d, want 1", fwd.callCount())
	}
	if got := fwd.calls[0].url; got != "https://a.example.com/hook" {
		t.Fatalf("delivered to %q, want acct-A's URL only (cross-account leak)", got)
	}
}

// T-ISO-disabled / fail-closed: a deliberately-DISABLED endpoint (!cfg.Enabled()) ⇒
// dead-letter endpoint_inactive, ZERO forward, row removed, audit dead_letter. (The
// "no endpoint configured at all" case is now handled by TestProcessNoConfigLogsAndSettles
// below, per SIN-69508 — an operator switching an endpoint OFF is a distinct, deliberate
// state that still merits a dead-letter for visibility.)
func TestProcessDeadLettersInactiveEndpoint(t *testing.T) {
	reader := &fwdConfigReader{cfgs: map[string]*outboundwebhook.Config{
		"acct-A": mustConfig(t, "acct-A", "https://a.example.com/hook", "whsec_a", false),
	}}
	fwd := &fakeForwarder{results: []fwdResult{{status: 200}}}
	h := newProcHarness(t, true, reader, fwd)
	h.enqueue(t, "d1", "acct-A", "ek-1")

	n, err := h.proc.ProcessPending(context.Background())
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if n != 1 {
		t.Fatalf("settled = %d, want 1 (dead-lettered)", n)
	}
	if fwd.callCount() != 0 {
		t.Fatalf("forwarder must NOT be called for a disabled endpoint, calls=%d", fwd.callCount())
	}
	dls, _ := h.outbox.DeadLetters(context.Background())
	if len(dls) != 1 || dls[0].Reason() != outboundqueue.ReasonEndpointInactive {
		t.Fatalf("want 1 endpoint_inactive dead-letter, got %+v", dls)
	}
	if left, _ := h.outbox.ClaimPendingDeliveries(context.Background(), 10); len(left) != 0 {
		t.Fatalf("outbox should be empty, got %d", len(left))
	}
	if acts := h.audit.actions(); len(acts) != 1 || acts[0] != audit.ActionOutboundWebhookDeadLettered {
		t.Fatalf("audit = %v, want [dead_letter]", acts)
	}
}

// SIN-69508: a delivery attributed to a valid (reseller) Conta that has NO outbound webhook
// configured (GetOutboundWebhook ⇒ shared.ErrNotFound) is a normal operational condition,
// not a failure: exactly ZERO forwards, ZERO dead-letters, ZERO audit entries, and the row
// is REMOVED from the outbox (settled — so it is not re-claimed and re-logged every tick).
// The Info log itself is not asserted here (slog has no injected sink), but the terminal
// settle + absence of any dead-letter/forward/audit pins down the mandated behaviour.
func TestProcessNoConfigLogsAndSettles(t *testing.T) {
	reader := &fwdConfigReader{cfgs: map[string]*outboundwebhook.Config{}} // no config for anyone
	fwd := &fakeForwarder{results: []fwdResult{{status: 200}}}
	h := newProcHarness(t, true, reader, fwd)
	h.enqueue(t, "d1", "acct-A", "ek-1")

	n, err := h.proc.ProcessPending(context.Background())
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if n != 1 {
		t.Fatalf("settled = %d, want 1 (terminal, no dead-letter)", n)
	}
	if fwd.callCount() != 0 {
		t.Fatalf("forwarder must NOT be called when no endpoint is configured, calls=%d", fwd.callCount())
	}
	if dls, _ := h.outbox.DeadLetters(context.Background()); len(dls) != 0 {
		t.Fatalf("no-config must NOT dead-letter, got %d", len(dls))
	}
	if acts := h.audit.actions(); len(acts) != 0 {
		t.Fatalf("no-config must NOT write an audit entry, got %v", acts)
	}
	if left, _ := h.outbox.ClaimPendingDeliveries(context.Background(), 10); len(left) != 0 {
		t.Fatalf("delivery MUST be removed from the outbox (settled), got %d still pending", len(left))
	}
}

// T-RETRY-cap: a persistently failing endpoint is retried up to the cap (with a backoff
// sleep between attempts) then dead-lettered delivery_exhausted — no infinite loop.
func TestProcessRetriesThenDeadLetters(t *testing.T) {
	reader := &fwdConfigReader{cfgs: map[string]*outboundwebhook.Config{
		"acct-A": mustConfig(t, "acct-A", "https://a.example.com/hook", "whsec_a", true),
	}}
	fwd := &fakeForwarder{results: []fwdResult{{status: 500}}} // always fails
	h := newProcHarness(t, true, reader, fwd)
	h.enqueue(t, "d1", "acct-A", "ek-1")

	n, err := h.proc.ProcessPending(context.Background())
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if n != 1 {
		t.Fatalf("settled = %d, want 1", n)
	}
	if fwd.callCount() != 3 {
		t.Fatalf("attempts = %d, want 3 (the cap)", fwd.callCount())
	}
	if h.sleeps != 2 {
		t.Fatalf("backoff sleeps = %d, want 2 (between the 3 attempts)", h.sleeps)
	}
	dls, _ := h.outbox.DeadLetters(context.Background())
	if len(dls) != 1 || dls[0].Reason() != outboundqueue.ReasonDeliveryExhausted {
		t.Fatalf("want 1 delivery_exhausted dead-letter, got %+v", dls)
	}
}

// A transient failure that recovers within the cap succeeds without dead-lettering.
func TestProcessRetriesThenSucceeds(t *testing.T) {
	reader := &fwdConfigReader{cfgs: map[string]*outboundwebhook.Config{
		"acct-A": mustConfig(t, "acct-A", "https://a.example.com/hook", "whsec_a", true),
	}}
	fwd := &fakeForwarder{results: []fwdResult{{status: 503}, {status: 200}}}
	h := newProcHarness(t, true, reader, fwd)
	h.enqueue(t, "d1", "acct-A", "ek-1")

	if _, err := h.proc.ProcessPending(context.Background()); err != nil {
		t.Fatalf("process: %v", err)
	}
	if fwd.callCount() != 2 {
		t.Fatalf("attempts = %d, want 2", fwd.callCount())
	}
	dls, _ := h.outbox.DeadLetters(context.Background())
	if len(dls) != 0 {
		t.Fatalf("should not dead-letter on recovery, got %d", len(dls))
	}
	if acts := h.audit.actions(); len(acts) != 1 || acts[0] != audit.ActionOutboundWebhookDelivered {
		t.Fatalf("audit = %v, want [delivered]", acts)
	}
}

// Best-effort / T-ACK-independent: a forward that errors (e.g. blocked destination) never
// makes ProcessPending return an error — it is retried then dead-lettered out-of-band.
func TestProcessBestEffortSwallowsForwardError(t *testing.T) {
	reader := &fwdConfigReader{cfgs: map[string]*outboundwebhook.Config{
		"acct-A": mustConfig(t, "acct-A", "https://a.example.com/hook", "whsec_a", true),
	}}
	fwd := &fakeForwarder{results: []fwdResult{{err: errors.New("blocked/transport")}}}
	h := newProcHarness(t, true, reader, fwd)
	h.enqueue(t, "d1", "acct-A", "ek-1")

	if _, err := h.proc.ProcessPending(context.Background()); err != nil {
		t.Fatalf("ProcessPending must not propagate a per-delivery error, got %v", err)
	}
	dls, _ := h.outbox.DeadLetters(context.Background())
	if len(dls) != 1 {
		t.Fatalf("want 1 dead-letter after exhausting errors, got %d", len(dls))
	}
}

// A transient config-store error leaves the delivery on the outbox for a later tick
// (fail-SAFE) — it is NOT dead-lettered and NOT forwarded.
func TestProcessLeavesOnTransientConfigError(t *testing.T) {
	reader := &fwdConfigReader{err: errors.New("store blip")}
	fwd := &fakeForwarder{}
	h := newProcHarness(t, true, reader, fwd)
	h.enqueue(t, "d1", "acct-A", "ek-1")

	n, err := h.proc.ProcessPending(context.Background())
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if n != 0 {
		t.Fatalf("settled = %d, want 0 (left on outbox)", n)
	}
	if fwd.callCount() != 0 {
		t.Fatalf("must not forward on a config read error, calls=%d", fwd.callCount())
	}
	if dls, _ := h.outbox.DeadLetters(context.Background()); len(dls) != 0 {
		t.Fatalf("must not dead-letter on a transient store error, got %d", len(dls))
	}
	if left, _ := h.outbox.ClaimPendingDeliveries(context.Background(), 10); len(left) != 1 {
		t.Fatalf("delivery should remain on the outbox, got %d", len(left))
	}
}

// T-FLAG-off: with the processor disabled, ProcessPending is a genuine no-op — nothing is
// claimed, nothing forwarded, the outbox is untouched.
func TestProcessDisabledIsNoop(t *testing.T) {
	reader := &fwdConfigReader{cfgs: map[string]*outboundwebhook.Config{
		"acct-A": mustConfig(t, "acct-A", "https://a.example.com/hook", "whsec_a", true),
	}}
	fwd := &fakeForwarder{results: []fwdResult{{status: 200}}}
	h := newProcHarness(t, false, reader, fwd)
	h.enqueue(t, "d1", "acct-A", "ek-1")

	n, err := h.proc.ProcessPending(context.Background())
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if n != 0 {
		t.Fatalf("disabled settled = %d, want 0", n)
	}
	if fwd.callCount() != 0 {
		t.Fatalf("disabled processor must not forward, calls=%d", fwd.callCount())
	}
	if left, _ := h.outbox.ClaimPendingDeliveries(context.Background(), 10); len(left) != 1 {
		t.Fatalf("outbox should be untouched when disabled, got %d", len(left))
	}
}

// A nil processor and a half-wired (missing ports) processor are safe no-ops.
func TestProcessNilAndUnwiredAreSafe(t *testing.T) {
	var nilP *app.OutboundProcessor
	if n, err := nilP.ProcessPending(context.Background()); n != 0 || err != nil {
		t.Fatalf("nil processor: n=%d err=%v", n, err)
	}
	half := app.NewOutboundProcessor(app.OutboundProcessorDeps{Enabled: true})
	if n, err := half.ProcessPending(context.Background()); n != 0 || err != nil {
		t.Fatalf("half-wired processor: n=%d err=%v", n, err)
	}
}

// A claim error surfaces so a runner can back off, but does not panic.
func TestProcessClaimErrorSurfaces(t *testing.T) {
	reader := &fwdConfigReader{cfgs: map[string]*outboundwebhook.Config{}}
	h := app.NewOutboundProcessor(app.OutboundProcessorDeps{
		Enabled:     true,
		Outbox:      failingOutbox{},
		Configs:     reader,
		Forwarder:   &fakeForwarder{},
		Limiter:     &noopLimiter{},
		DeadLetters: failingSink{},
		Audit:       &recAudit{},
		Clock:       fixedClock{t: fwdNow},
		IDs:         &seqIDs{},
	})
	if _, err := h.ProcessPending(context.Background()); err == nil {
		t.Fatal("expected the claim error to surface")
	}
}

// failingOutbox errors on claim (drives the claim-error path).
type failingOutbox struct{}

func (failingOutbox) ClaimPendingDeliveries(_ context.Context, _ int) ([]*outboundqueue.Delivery, error) {
	return nil, errors.New("claim boom")
}
func (failingOutbox) DeleteDelivery(_ context.Context, _ string) error { return nil }

// Guard: the processor's ports satisfy the expected interfaces at compile time.
var _ ports.AuditLog = (*recAudit)(nil)

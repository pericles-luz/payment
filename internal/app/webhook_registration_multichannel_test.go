package app

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// One ref serves every PSP channel, so a mint kills them all at once. Registering only the
// PIX channel therefore left recurrence and the proprietary channels pointing at a
// superseded ref — dead, and invisibly so, because nothing reads them back. These tests
// pin the two properties that prevent the regression: the gate looks at EVERY channel, and
// a registration pass writes the SAME ref to all of them.

// fakeRecRegistrar records the recurrence callbacks and can be scripted to fail.
type fakeRecRegistrar struct {
	mu          sync.Mutex
	rec, cobr   string
	registerErr error
}

func (f *fakeRecRegistrar) RegisterRecWebhook(_ context.Context, _, url string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.registerErr != nil {
		return f.registerErr
	}
	f.rec = url
	return nil
}

func (f *fakeRecRegistrar) GetRecWebhook(context.Context, string) (ports.WebhookRegistration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.rec == "" {
		return ports.WebhookRegistration{}, shared.ErrNotFound
	}
	return ports.WebhookRegistration{WebhookURL: f.rec}, nil
}

func (f *fakeRecRegistrar) RegisterCobRWebhook(_ context.Context, _, url string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cobr = url
	return nil
}

func (f *fakeRecRegistrar) GetCobRWebhook(context.Context, string) (ports.WebhookRegistration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cobr == "" {
		return ports.WebhookRegistration{}, shared.ErrNotFound
	}
	return ports.WebhookRegistration{WebhookURL: f.cobr}, nil
}

// fakeServiceRegistrar records per-service proprietary callbacks.
type fakeServiceRegistrar struct {
	mu   sync.Mutex
	urls map[string]string
}

func newFakeServiceRegistrar() *fakeServiceRegistrar {
	return &fakeServiceRegistrar{urls: map[string]string{}}
}

func (f *fakeServiceRegistrar) RegisterServiceWebhook(_ context.Context, _, service, url string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.urls[service] = url
	return nil
}

func (f *fakeServiceRegistrar) GetServiceWebhook(_ context.Context, _, service string) (ports.WebhookRegistration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	url, ok := f.urls[service]
	if !ok {
		return ports.WebhookRegistration{}, shared.ErrNotFound
	}
	return ports.WebhookRegistration{WebhookURL: url}, nil
}

func multiChannelService(t *testing.T, refs webhookRefLookup, mintedRef string) (*WebhookRegistrationService, *fakeRegistrar, *fakeRecRegistrar, *fakeServiceRegistrar) {
	t.Helper()
	creds := &fakeCredStore{cred: completeCred()}
	minter := &fakeMinter{ref: mintedRef}
	pix := &fakeRegistrar{}
	rec := &fakeRecRegistrar{}
	svc := newFakeServiceRegistrar()
	logger, _ := newBufLogger()
	s := NewWebhookRegistrationService(creds, pix, minter, testBaseURL, logger).
		WithRefLookup(refs).
		WithRecurrenceRegistrar(rec).
		WithServiceRegistrar(svc, "CHECKOUT")
	return s, pix, rec, svc
}

// Nothing registered anywhere: one mint, and the SAME URL written to every channel.
func TestTryRegisterWritesOneRefToEveryChannel(t *testing.T) {
	t.Parallel()
	const ref = "MULTI-channel-ref-value"
	s, pix, rec, svc := multiChannelService(t, newFakeRefLookup(), ref)

	s.TryRegister(context.Background(), "t1")

	want := testBaseURL + webhookCallbackPathPrefix + ref
	if len(pix.registered) != 1 || pix.registered[0] != want {
		t.Fatalf("pix registered %v, want exactly [%s]", pix.registered, want)
	}
	if rec.rec != want {
		t.Fatalf("rec URL = %q, want %q", rec.rec, want)
	}
	if rec.cobr != want {
		t.Fatalf("cobr URL = %q, want %q", rec.cobr, want)
	}
	if got := svc.urls["CHECKOUT"]; got != want {
		t.Fatalf("checkout URL = %q, want %q", got, want)
	}
}

// The regression this exists to prevent: PIX already live, but a sibling channel is not.
// The gate must NOT be satisfied by the PIX channel alone.
func TestTryRegisterReRegistersWhenOnlyPixIsLive(t *testing.T) {
	t.Parallel()
	const liveRef = "LIVE-pix-only-ref"
	refs := newFakeRefLookup()
	refs.bind(liveRef, "t1")
	s, pix, rec, svc := multiChannelService(t, refs, strings.Repeat("N", 43))

	// C6 holds a live PIX registration; recurrence and checkout hold nothing.
	pix.getDefault = ports.WebhookRegistration{WebhookURL: testBaseURL + webhookCallbackPathPrefix + liveRef}

	s.TryRegister(context.Background(), "t1")

	if len(pix.registered) == 0 {
		t.Fatal("pix must be re-registered too: the mint supersedes the ref every channel shares")
	}
	want := testBaseURL + webhookCallbackPathPrefix + strings.Repeat("N", 43)
	for name, got := range map[string]string{"rec": rec.rec, "cobr": rec.cobr, "checkout": svc.urls["CHECKOUT"]} {
		if got != want {
			t.Fatalf("%s URL = %q, want %q", name, got, want)
		}
	}
}

// Every channel live on the same active ref — the steady state must stay a no-op, or the
// reconcile sweep would churn a fresh ref on every tick.
func TestTryRegisterIsNoOpWhenAllChannelsLive(t *testing.T) {
	t.Parallel()
	const liveRef = "ALL-channels-live-ref"
	refs := newFakeRefLookup()
	refs.bind(liveRef, "t1")
	s, pix, rec, svc := multiChannelService(t, refs, "SHOULD-NOT-BE-MINTED")

	live := testBaseURL + webhookCallbackPathPrefix + liveRef
	pix.getDefault = ports.WebhookRegistration{WebhookURL: live}
	rec.rec, rec.cobr = live, live
	svc.urls["CHECKOUT"] = live

	s.TryRegister(context.Background(), "t1")

	if len(pix.registered) != 0 {
		t.Fatalf("steady state must not re-register: %v", pix.registered)
	}
	if rec.rec != live || svc.urls["CHECKOUT"] != live {
		t.Fatal("steady state must leave existing registrations untouched")
	}
}

// A failing channel must not abort the others: partial success beats none, and the sweep
// retries the rest.
func TestTryRegisterContinuesAfterOneChannelFails(t *testing.T) {
	t.Parallel()
	const ref = "PARTIAL-failure-ref"
	s, _, rec, svc := multiChannelService(t, newFakeRefLookup(), ref)
	rec.registerErr = errors.New("psp unavailable")

	s.TryRegister(context.Background(), "t1")

	want := testBaseURL + webhookCallbackPathPrefix + ref
	if svc.urls["CHECKOUT"] != want {
		t.Fatalf("checkout must still be registered after rec failed: %q", svc.urls["CHECKOUT"])
	}
	if rec.rec != "" {
		t.Fatalf("rec should have failed, got %q", rec.rec)
	}
}

// Without the optional registrars wired, behaviour collapses to the single PIX channel —
// a deployment that has not adopted them is unaffected.
func TestTryRegisterSingleChannelWhenRegistrarsUnwired(t *testing.T) {
	t.Parallel()
	const ref = "SINGLE-channel-ref"
	creds := &fakeCredStore{cred: completeCred()}
	minter := &fakeMinter{ref: ref}
	pix := &fakeRegistrar{}
	logger, _ := newBufLogger()
	s := NewWebhookRegistrationService(creds, pix, minter, testBaseURL, logger).
		WithRefLookup(newFakeRefLookup())

	s.TryRegister(context.Background(), "t1")

	if len(pix.registered) != 1 {
		t.Fatalf("pix registrations = %d, want 1", len(pix.registered))
	}
	if want := testBaseURL + webhookCallbackPathPrefix + ref; pix.registered[0] != want {
		t.Fatalf("registered %q, want %q", pix.registered[0], want)
	}
}

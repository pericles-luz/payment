package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/domain/webhookref"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// Regression suite for the idempotency gate (SIN-69580). The gate used to skip whenever
// C6 held ANY URL under our origin. That marked a dead registration as done: a revoked or
// foreign ref 404s at the receiver, yet neither a self-serve write nor the reconcile sweep
// would ever replace it — the failure was permanent and silent. The gate must now skip
// only for a ref that is ACTIVE and owned by this tenant.

// fakeRefLookup resolves ref hashes to owning tenants. Refs absent from the map model an
// unknown or revoked ref (the durable store does not resolve revoked ones).
type fakeRefLookup struct {
	owners map[string]string // hex-free: keyed by the raw sum bytes as a string
	err    error
	calls  int
}

func newFakeRefLookup() *fakeRefLookup {
	return &fakeRefLookup{owners: map[string]string{}}
}

func (f *fakeRefLookup) bind(ref, tenantID string) {
	sum := webhookref.Sum(ref)
	f.owners[string(sum[:])] = tenantID
}

func (f *fakeRefLookup) LookupWebhookRef(_ context.Context, refSHA []byte) (string, bool, error) {
	f.calls++
	if f.err != nil {
		return "", false, f.err
	}
	owner, ok := f.owners[string(refSHA)]
	return owner, ok, nil
}

// gateFixture builds a service whose C6 double already holds registeredRef for the key.
func gateFixture(t *testing.T, registeredRef string, refs webhookRefLookup) (*WebhookRegistrationService, *fakeMinter, *fakeRegistrar) {
	t.Helper()
	creds := &fakeCredStore{cred: completeCred()}
	minter := &fakeMinter{ref: strings.Repeat("B", 43)}
	reg := &fakeRegistrar{
		getDefault: ports.WebhookRegistration{
			WebhookURL: testBaseURL + webhookCallbackPathPrefix + registeredRef,
		},
	}
	logger, _ := newBufLogger()
	s := NewWebhookRegistrationService(creds, reg, minter, testBaseURL, logger)
	if refs != nil {
		s = s.WithRefLookup(refs)
	}
	return s, minter, reg
}

// An active ref of this tenant means the registration is live — stay idempotent.
func TestGateSkipsWhenRegisteredRefIsActiveForTenant(t *testing.T) {
	t.Parallel()
	const active = "ACTIVE-ref-value"
	refs := newFakeRefLookup()
	refs.bind(active, "t1")
	s, minter, reg := gateFixture(t, active, refs)

	s.TryRegister(context.Background(), "t1")

	if minter.mints != 0 || len(reg.registered) != 0 {
		t.Fatalf("live registration must be a no-op: mints=%d puts=%d", minter.mints, len(reg.registered))
	}
}

// A revoked/unknown ref 404s at the receiver — the registration must be replaced.
func TestGateReRegistersWhenRegisteredRefIsRevoked(t *testing.T) {
	t.Parallel()
	refs := newFakeRefLookup() // nothing bound: models a revoked/superseded ref
	s, minter, reg := gateFixture(t, "REVOKED-ref-value", refs)

	s.TryRegister(context.Background(), "t1")

	if minter.mints != 1 {
		t.Fatalf("mints = %d, want 1 (stale registration must be replaced)", minter.mints)
	}
	if len(reg.registered) != 1 {
		t.Fatalf("PUTs = %d, want 1", len(reg.registered))
	}
	if want := testBaseURL + webhookCallbackPathPrefix + minter.ref; reg.registered[0] != want {
		t.Fatalf("registered %q, want the freshly minted ref %q", reg.registered[0], want)
	}
}

// A ref owned by ANOTHER tenant must never count as this tenant's registration.
func TestGateReRegistersWhenRefBelongsToAnotherTenant(t *testing.T) {
	t.Parallel()
	const foreign = "OTHER-tenants-ref"
	refs := newFakeRefLookup()
	refs.bind(foreign, "t2")
	s, minter, _ := gateFixture(t, foreign, refs)

	s.TryRegister(context.Background(), "t1")

	if minter.mints != 1 {
		t.Fatalf("mints = %d, want 1 (foreign ref must be replaced)", minter.mints)
	}
}

// A ref-store fault is ambiguous: skip instead of minting a fresh ref on every pass,
// which would churn refs once per sweep for as long as the fault lasts.
func TestGateSkipsWhenRefLookupFails(t *testing.T) {
	t.Parallel()
	refs := newFakeRefLookup()
	refs.err = errors.New("store unavailable")
	s, minter, reg := gateFixture(t, "any-ref-value", refs)

	s.TryRegister(context.Background(), "t1")

	if minter.mints != 0 || len(reg.registered) != 0 {
		t.Fatalf("ambiguous state must not mint: mints=%d puts=%d", minter.mints, len(reg.registered))
	}
}

// Without a ref lookup wired the gate keeps its historical origin-prefix behaviour, so a
// deployment that has not adopted the durable store is unaffected.
func TestGateFallsBackToPrefixCheckWithoutLookup(t *testing.T) {
	t.Parallel()
	s, minter, reg := gateFixture(t, "whatever-ref", nil)

	s.TryRegister(context.Background(), "t1")

	if minter.mints != 0 || len(reg.registered) != 0 {
		t.Fatalf("prefix-only fallback must stay idempotent: mints=%d puts=%d", minter.mints, len(reg.registered))
	}
}

// A URL outside our origin is stale regardless of the lookup — replace it.
func TestGateReRegistersForeignOrigin(t *testing.T) {
	t.Parallel()
	creds := &fakeCredStore{cred: completeCred()}
	minter := &fakeMinter{ref: strings.Repeat("C", 43)}
	reg := &fakeRegistrar{
		getResults: []ports.WebhookRegistration{{WebhookURL: "https://attacker.example/webhooks/c6/x"}},
		getErrs:    []error{nil},
		getDefErr:  shared.ErrNotFound,
	}
	logger, _ := newBufLogger()
	s := NewWebhookRegistrationService(creds, reg, minter, testBaseURL, logger).
		WithRefLookup(newFakeRefLookup())

	s.TryRegister(context.Background(), "t1")

	if minter.mints != 1 {
		t.Fatalf("mints = %d, want 1 (foreign origin must be replaced)", minter.mints)
	}
}

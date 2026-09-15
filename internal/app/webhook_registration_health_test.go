package app

import (
	"context"
	"errors"
	"strings"
	"testing"
)

const healthTenant = "t-health"

func healthURL(ref string) string { return testBaseURL + webhookCallbackPathPrefix + ref }

// The case that was silently wrong before this classifier existed: the PSP holds a URL, so
// the old report said "registrado", but the ref no longer resolves — every callback through
// it is answered 401. An operator reading "registrado" concluded the channel worked.
//
// This is not a hypothetical. A sync interrupted after its first channel left five channels
// in exactly this state and the report called all six registered (15/09/2026).
func TestClassifyWebhookRegistrationRevokedRefIsStaleNotLive(t *testing.T) {
	t.Parallel()
	refs := newFakeRefLookup() // nothing bound: models a revoked or unknown ref
	got := ClassifyWebhookRegistration(context.Background(), refs, testBaseURL, healthTenant,
		healthURL(strings.Repeat("R", 43)))
	if got != RegistrationHealthStale {
		t.Fatalf("a revoked ref must be %q, got %q", RegistrationHealthStale, got)
	}
	if got == RegistrationHealthLive {
		t.Fatal("reporting a revoked ref as live is the defect this exists to prevent")
	}
}

// An active ref owned by this tenant is the only thing that counts as reachable.
func TestClassifyWebhookRegistrationActiveRefIsLive(t *testing.T) {
	t.Parallel()
	ref := strings.Repeat("A", 43)
	refs := newFakeRefLookup()
	refs.bind(ref, healthTenant)

	got := ClassifyWebhookRegistration(context.Background(), refs, testBaseURL, healthTenant, healthURL(ref))
	if got != RegistrationHealthLive {
		t.Fatalf("want %q, got %q", RegistrationHealthLive, got)
	}
}

// A ref that resolves to a DIFFERENT tenant is stale, not live. Treating it as live would
// let one empresa's callbacks authenticate under another's channel.
func TestClassifyWebhookRegistrationForeignRefIsStale(t *testing.T) {
	t.Parallel()
	ref := strings.Repeat("F", 43)
	refs := newFakeRefLookup()
	refs.bind(ref, "someone-else")

	got := ClassifyWebhookRegistration(context.Background(), refs, testBaseURL, healthTenant, healthURL(ref))
	if got != RegistrationHealthStale {
		t.Fatalf("a ref owned by another tenant must be %q, got %q", RegistrationHealthStale, got)
	}
}

// A URL pointing somewhere else entirely — a stale origin after a cutover, say — is stale
// regardless of what the ref store says, and is decided without consulting it.
func TestClassifyWebhookRegistrationForeignOriginIsStale(t *testing.T) {
	t.Parallel()
	refs := newFakeRefLookup()
	got := ClassifyWebhookRegistration(context.Background(), refs, testBaseURL, healthTenant,
		"https://payment.someu.com.br/webhooks/c6/"+strings.Repeat("A", 43))
	if got != RegistrationHealthStale {
		t.Fatalf("want %q, got %q", RegistrationHealthStale, got)
	}
	if refs.calls != 0 {
		t.Fatalf("a foreign origin needs no store lookup, got %d", refs.calls)
	}
}

// An empty ref after the prefix is stale, not live — the prefix alone proves nothing.
func TestClassifyWebhookRegistrationEmptyRefIsStale(t *testing.T) {
	t.Parallel()
	got := ClassifyWebhookRegistration(context.Background(), newFakeRefLookup(), testBaseURL,
		healthTenant, healthURL(""))
	if got != RegistrationHealthStale {
		t.Fatalf("want %q, got %q", RegistrationHealthStale, got)
	}
}

// A store that cannot answer is UNKNOWN, kept distinct from stale on purpose: "obsoleta"
// tells an operator to reconverge, and reconverging on a guess churns the ref for nothing.
func TestClassifyWebhookRegistrationStoreErrorIsUnknown(t *testing.T) {
	t.Parallel()
	refs := newFakeRefLookup()
	refs.err = errors.New("cofre indisponivel")

	got := ClassifyWebhookRegistration(context.Background(), refs, testBaseURL, healthTenant,
		healthURL(strings.Repeat("A", 43)))
	if got != RegistrationHealthUnknown {
		t.Fatalf("want %q, got %q", RegistrationHealthUnknown, got)
	}
}

// With no ref store wired the classifier degrades to the origin-prefix check, so a
// deployment predating the durable store behaves exactly as it did before.
func TestClassifyWebhookRegistrationNilLookupDegradesToPrefix(t *testing.T) {
	t.Parallel()
	if got := ClassifyWebhookRegistration(context.Background(), nil, testBaseURL, healthTenant,
		healthURL(strings.Repeat("A", 43))); got != RegistrationHealthLive {
		t.Fatalf("matching origin with no store must be %q, got %q", RegistrationHealthLive, got)
	}
	if got := ClassifyWebhookRegistration(context.Background(), nil, testBaseURL, healthTenant,
		"https://elsewhere.test/webhooks/c6/x"); got != RegistrationHealthStale {
		t.Fatalf("foreign origin must still be %q, got %q", RegistrationHealthStale, got)
	}
}

// The gate and the operator tooling must never disagree about what "reachable" means, which
// is why registrationState delegates rather than keeping a second copy of the rule.
func TestRegistrationStateAgreesWithClassifier(t *testing.T) {
	t.Parallel()
	active, revoked := strings.Repeat("A", 43), strings.Repeat("R", 43)
	refs := newFakeRefLookup()
	refs.bind(active, healthTenant)

	s, _, _ := gateFixture(t, active, refs)
	cases := []struct {
		url  string
		want registrationState
	}{
		{healthURL(active), registrationLive},
		{healthURL(revoked), registrationStale},
		{"https://elsewhere.test/webhooks/c6/" + active, registrationStale},
	}
	for _, tc := range cases {
		if got := s.registrationState(context.Background(), healthTenant, tc.url); got != tc.want {
			t.Fatalf("registrationState(%q) = %v, want %v", tc.url, got, tc.want)
		}
	}
}

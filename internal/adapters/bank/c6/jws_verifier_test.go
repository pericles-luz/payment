package c6

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// --- test key + signing helpers -------------------------------------------------

type testKey struct {
	priv any
	pub  any
	alg  jose.SignatureAlgorithm
	kid  string
}

func newES256Key(t *testing.T, kid string) testKey {
	t.Helper()
	p, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa key: %v", err)
	}
	return testKey{priv: p, pub: p.Public(), alg: jose.ES256, kid: kid}
}

func newPS256Key(t *testing.T, kid string) testKey {
	t.Helper()
	p, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	return testKey{priv: p, pub: p.Public(), alg: jose.PS256, kid: kid}
}

// jwkSet builds a public JWKS from the given keys.
func jwkSet(keys ...testKey) *jose.JSONWebKeySet {
	set := &jose.JSONWebKeySet{}
	for _, k := range keys {
		set.Keys = append(set.Keys, jose.JSONWebKey{Key: k.pub, KeyID: k.kid, Algorithm: string(k.alg)})
	}
	return set
}

// signCompact produces a compact JWS over payload, embedding kid in the protected
// header (go-jose copies the signing JWK's KeyID into the protected header).
func signCompact(t *testing.T, k testKey, payload []byte) []byte {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: k.alg, Key: jose.JSONWebKey{Key: k.priv, KeyID: k.kid, Algorithm: string(k.alg)}},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	compact, err := obj.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return []byte(compact)
}

// --- fetcher test double --------------------------------------------------------

type fakeFetcher struct {
	mu    sync.Mutex
	sets  []*jose.JSONWebKeySet // returned in order; last one repeats
	err   error
	calls int
}

func (f *fakeFetcher) fetch(context.Context) (*jose.JSONWebKeySet, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	idx := f.calls - 1
	if idx >= len(f.sets) {
		idx = len(f.sets) - 1
	}
	return f.sets[idx], nil
}

func (f *fakeFetcher) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// fakeClock (manually-advanced clock) is declared in token_test.go and reused here.

const recPayload = `{"idRec":"RR1","status":"APROVADA"}`

// --- AC: happy paths ------------------------------------------------------------

func TestVerifyJWS_ValidES256(t *testing.T) {
	t.Parallel()
	k := newES256Key(t, "k-es")
	f := &fakeFetcher{sets: []*jose.JSONWebKeySet{jwkSet(k)}}
	v := newVerifier(f)

	payload, err := v.VerifyJWS(context.Background(), signCompact(t, k, []byte(recPayload)))
	if err != nil {
		t.Fatalf("VerifyJWS: %v", err)
	}
	if string(payload) != recPayload {
		t.Fatalf("payload = %q, want %q", payload, recPayload)
	}
	if f.callCount() != 1 {
		t.Fatalf("fetch calls = %d, want 1", f.callCount())
	}
}

func TestVerifyJWS_ValidPS256(t *testing.T) {
	t.Parallel()
	k := newPS256Key(t, "k-ps")
	f := &fakeFetcher{sets: []*jose.JSONWebKeySet{jwkSet(k)}}
	v := newVerifier(f)

	payload, err := v.VerifyJWS(context.Background(), signCompact(t, k, []byte(recPayload)))
	if err != nil {
		t.Fatalf("VerifyJWS: %v", err)
	}
	if string(payload) != recPayload {
		t.Fatalf("payload mismatch")
	}
}

func TestVerifyJWS_CachedNoRefetch(t *testing.T) {
	t.Parallel()
	k := newES256Key(t, "k-es")
	f := &fakeFetcher{sets: []*jose.JSONWebKeySet{jwkSet(k)}}
	v := newVerifier(f)
	tok := signCompact(t, k, []byte(recPayload))

	for i := 0; i < 3; i++ {
		if _, err := v.VerifyJWS(context.Background(), tok); err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
	}
	if f.callCount() != 1 {
		t.Fatalf("fetch calls = %d, want 1 (JWKS must be cached)", f.callCount())
	}
}

// --- AC#2: reject alg:none ------------------------------------------------------

func TestVerifyJWS_RejectsAlgNone(t *testing.T) {
	t.Parallel()
	k := newES256Key(t, "k-es")
	f := &fakeFetcher{sets: []*jose.JSONWebKeySet{jwkSet(k)}}
	v := newVerifier(f)

	// Hand-craft an unsigned token: {"alg":"none","kid":"k-es"} . payload . (empty sig)
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	header := b64([]byte(`{"alg":"none","kid":"k-es"}`))
	body := b64([]byte(recPayload))
	none := []byte(header + "." + body + ".")

	if _, err := v.VerifyJWS(context.Background(), none); err == nil {
		t.Fatal("expected alg:none to be rejected, got nil error")
	}
	if f.callCount() != 0 {
		t.Fatalf("fetch must not run for a rejected alg; calls = %d", f.callCount())
	}
}

// --- AC#3: reject symmetric MAC (HS256) — key-confusion defence -----------------

func TestVerifyJWS_RejectsHS256KeyConfusion(t *testing.T) {
	t.Parallel()
	k := newES256Key(t, "k-es")
	f := &fakeFetcher{sets: []*jose.JSONWebKeySet{jwkSet(k)}}
	v := newVerifier(f)

	// Attacker forges an HS256 token using a known kid, hoping the verifier will
	// treat the public key as an HMAC secret. The allowlist excludes HS*, so it must
	// be rejected at parse before any key is consulted.
	hsSigner, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.HS256, Key: []byte("pretend-this-is-the-public-key-bytes")},
		(&jose.SignerOptions{ExtraHeaders: map[jose.HeaderKey]any{"kid": "k-es"}}),
	)
	if err != nil {
		t.Fatalf("hs signer: %v", err)
	}
	obj, err := hsSigner.Sign([]byte(recPayload))
	if err != nil {
		t.Fatalf("hs sign: %v", err)
	}
	compact, _ := obj.CompactSerialize()

	if _, err := v.VerifyJWS(context.Background(), []byte(compact)); err == nil {
		t.Fatal("expected HS256 to be rejected (key-confusion), got nil error")
	}
	if f.callCount() != 0 {
		t.Fatalf("fetch must not run for a rejected alg; calls = %d", f.callCount())
	}
}

// --- AC#1: allowlist is explicit — even an unexpected asymmetric alg is rejected -

func TestVerifyJWS_RejectsRS256OutsideAllowlist(t *testing.T) {
	t.Parallel()
	rsaKey := newPS256Key(t, "k-rs") // reuse RSA key but sign RS256 (not in default allowlist)
	rsaKey.alg = jose.RS256
	f := &fakeFetcher{sets: []*jose.JSONWebKeySet{jwkSet(rsaKey)}}
	v := newVerifier(f) // default allowlist = {PS256, ES256}

	tok := signCompact(t, rsaKey, []byte(recPayload))
	if _, err := v.VerifyJWS(context.Background(), tok); err == nil {
		t.Fatal("expected RS256 (outside allowlist) to be rejected")
	}
}

// --- AC#4/#5: kid handling, rotation, fail-closed -------------------------------

func TestVerifyJWS_MissingKid(t *testing.T) {
	t.Parallel()
	k := newES256Key(t, "") // empty kid ⇒ no kid in protected header
	f := &fakeFetcher{sets: []*jose.JSONWebKeySet{jwkSet(k)}}
	v := newVerifier(f)

	if _, err := v.VerifyJWS(context.Background(), signCompact(t, k, []byte(recPayload))); err == nil ||
		!strings.Contains(err.Error(), "missing kid") {
		t.Fatalf("expected missing-kid error, got %v", err)
	}
}

func TestVerifyJWS_UnknownKidFailsClosed(t *testing.T) {
	t.Parallel()
	signing := newES256Key(t, "k-unknown")
	other := newES256Key(t, "k-known")
	f := &fakeFetcher{sets: []*jose.JSONWebKeySet{jwkSet(other)}} // JWKS lacks k-unknown
	v := newVerifier(f)

	_, err := v.VerifyJWS(context.Background(), signCompact(t, signing, []byte(recPayload)))
	if err == nil || !strings.Contains(err.Error(), "unknown kid") {
		t.Fatalf("expected unknown-kid error, got %v", err)
	}
	if f.callCount() != 1 {
		t.Fatalf("expected exactly one refetch attempt, got %d", f.callCount())
	}
}

func TestVerifyJWS_RotationPicksUpNewKid(t *testing.T) {
	t.Parallel()
	k1 := newES256Key(t, "k1")
	k2 := newES256Key(t, "k2") // rotated-in key, absent from the first JWKS
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	f := &fakeFetcher{sets: []*jose.JSONWebKeySet{jwkSet(k1), jwkSet(k1, k2)}}
	v := newVerifier(f, WithClock(clk.now), WithMinRefetch(time.Minute))

	if _, err := v.VerifyJWS(context.Background(), signCompact(t, k1, []byte(recPayload))); err != nil {
		t.Fatalf("k1 verify: %v", err)
	}
	clk.advance(2 * time.Minute) // past the refetch throttle
	if _, err := v.VerifyJWS(context.Background(), signCompact(t, k2, []byte(recPayload))); err != nil {
		t.Fatalf("k2 verify after rotation: %v", err)
	}
	if f.callCount() != 2 {
		t.Fatalf("expected 2 fetches (initial + rotation), got %d", f.callCount())
	}
}

func TestVerifyJWS_ThrottleSkipsRefetch(t *testing.T) {
	t.Parallel()
	k1 := newES256Key(t, "k1")
	k2 := newES256Key(t, "k2")
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	f := &fakeFetcher{sets: []*jose.JSONWebKeySet{jwkSet(k1), jwkSet(k1, k2)}}
	v := newVerifier(f, WithClock(clk.now), WithMinRefetch(time.Minute))

	if _, err := v.VerifyJWS(context.Background(), signCompact(t, k1, []byte(recPayload))); err != nil {
		t.Fatalf("k1 verify: %v", err)
	}
	// No clock advance: the unknown k2 must NOT trigger a refetch within the window.
	_, err := v.VerifyJWS(context.Background(), signCompact(t, k2, []byte(recPayload)))
	if err == nil || !strings.Contains(err.Error(), "unknown kid") {
		t.Fatalf("expected throttled unknown-kid, got %v", err)
	}
	if f.callCount() != 1 {
		t.Fatalf("throttle must prevent a 2nd fetch; calls = %d", f.callCount())
	}
}

func TestVerifyJWS_FetchError(t *testing.T) {
	t.Parallel()
	k := newES256Key(t, "k-es")
	f := &fakeFetcher{err: errors.New("network down")}
	v := newVerifier(f)

	_, err := v.VerifyJWS(context.Background(), signCompact(t, k, []byte(recPayload)))
	if err == nil || !strings.Contains(err.Error(), "jwks fetch") {
		t.Fatalf("expected jwks-fetch error, got %v", err)
	}
}

func TestVerifyJWS_BadSignatureFailsClosed(t *testing.T) {
	t.Parallel()
	signing := newES256Key(t, "k-es")
	imposter := newES256Key(t, "k-es") // same kid, different key material
	f := &fakeFetcher{sets: []*jose.JSONWebKeySet{jwkSet(imposter)}}
	v := newVerifier(f)

	_, err := v.VerifyJWS(context.Background(), signCompact(t, signing, []byte(recPayload)))
	if err == nil || !strings.Contains(err.Error(), "verification failed") {
		t.Fatalf("expected signature-verification failure, got %v", err)
	}
}

func TestVerifyJWS_CorruptedCompact(t *testing.T) {
	t.Parallel()
	v := newVerifier(&fakeFetcher{sets: []*jose.JSONWebKeySet{jwkSet(newES256Key(t, "k"))}})
	if _, err := v.VerifyJWS(context.Background(), []byte("not.a.jws")); err == nil {
		t.Fatal("expected parse error on garbage input")
	}
}

func TestVerifyJWS_MultipleSignaturesRejected(t *testing.T) {
	t.Parallel()
	k1 := newES256Key(t, "k1")
	k2 := newES256Key(t, "k2")
	signer, err := jose.NewMultiSigner([]jose.SigningKey{
		{Algorithm: k1.alg, Key: jose.JSONWebKey{Key: k1.priv, KeyID: k1.kid, Algorithm: string(k1.alg)}},
		{Algorithm: k2.alg, Key: jose.JSONWebKey{Key: k2.priv, KeyID: k2.kid, Algorithm: string(k2.alg)}},
	}, nil)
	if err != nil {
		t.Fatalf("multi signer: %v", err)
	}
	obj, err := signer.Sign([]byte(recPayload))
	if err != nil {
		t.Fatalf("multi sign: %v", err)
	}
	general := []byte(obj.FullSerialize()) // JSON general serialization carries N signatures

	f := &fakeFetcher{sets: []*jose.JSONWebKeySet{jwkSet(k1, k2)}}
	v := newVerifier(f)
	if _, err := v.VerifyJWS(context.Background(), general); err == nil ||
		!strings.Contains(err.Error(), "exactly one signature") {
		t.Fatalf("expected multi-signature rejection, got %v", err)
	}
}

// lookupKey must ignore a symmetric (oct) key sharing the kid and only pick the
// public asymmetric key.
func TestVerifyJWS_IgnoresSymmetricKeyInJWKS(t *testing.T) {
	t.Parallel()
	k := newES256Key(t, "k-es")
	set := jwkSet(k)
	set.Keys = append([]jose.JSONWebKey{{Key: []byte("symmetric-secret"), KeyID: "k-es", Algorithm: "HS256"}}, set.Keys...)
	f := &fakeFetcher{sets: []*jose.JSONWebKeySet{set}}
	v := newVerifier(f)

	if _, err := v.VerifyJWS(context.Background(), signCompact(t, k, []byte(recPayload))); err != nil {
		t.Fatalf("verify with symmetric decoy present: %v", err)
	}
}

func TestVerifyJWS_SymmetricOnlyKidFailsClosed(t *testing.T) {
	t.Parallel()
	k := newES256Key(t, "k-es")
	set := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: []byte("symmetric-secret"), KeyID: "k-es", Algorithm: "HS256"}}}
	f := &fakeFetcher{sets: []*jose.JSONWebKeySet{set}}
	v := newVerifier(f)

	if _, err := v.VerifyJWS(context.Background(), signCompact(t, k, []byte(recPayload))); err == nil ||
		!strings.Contains(err.Error(), "unknown kid") {
		t.Fatalf("expected unknown-kid when only a symmetric key matches, got %v", err)
	}
}

// --- options coverage -----------------------------------------------------------

func TestVerifierOptions_IgnoreInvalidValues(t *testing.T) {
	t.Parallel()
	v := newVerifier(&fakeFetcher{}, WithAlgorithms(), WithClock(nil), WithMinRefetch(0))
	if len(v.algs) != len(defaultRecVerifierAlgs) {
		t.Fatalf("empty WithAlgorithms must keep default allowlist")
	}
	if v.now == nil {
		t.Fatal("nil WithClock must keep default clock")
	}
	if v.minRefetch != defaultJWKSMinRefetch {
		t.Fatal("non-positive WithMinRefetch must keep default")
	}
}

func TestWithAlgorithms_Override(t *testing.T) {
	t.Parallel()
	// Restrict to ES256 only; a PS256 token must then be rejected at parse.
	k := newPS256Key(t, "k-ps")
	f := &fakeFetcher{sets: []*jose.JSONWebKeySet{jwkSet(k)}}
	v := newVerifier(f, WithAlgorithms(jose.ES256))
	if _, err := v.VerifyJWS(context.Background(), signCompact(t, k, []byte(recPayload))); err == nil {
		t.Fatal("PS256 must be rejected when allowlist is ES256-only")
	}
}

// --- httpJWKSFetcher + NewJWSVerifier -------------------------------------------

func TestHTTPJWKSFetcher_SuccessAndEndToEnd(t *testing.T) {
	t.Parallel()
	k := newES256Key(t, "k-es")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwkSet(k))
	}))
	defer srv.Close()

	v, err := NewJWSVerifier(srv.URL, srv.Client())
	if err != nil {
		t.Fatalf("NewJWSVerifier: %v", err)
	}
	payload, err := v.VerifyJWS(context.Background(), signCompact(t, k, []byte(recPayload)))
	if err != nil {
		t.Fatalf("end-to-end verify: %v", err)
	}
	if string(payload) != recPayload {
		t.Fatalf("payload mismatch end-to-end")
	}
}

func TestHTTPJWKSFetcher_Non2xx(t *testing.T) {
	t.Parallel()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	f := &httpJWKSFetcher{url: srv.URL, client: srv.Client()}
	if _, err := f.fetch(context.Background()); err == nil || !strings.Contains(err.Error(), "status 500") {
		t.Fatalf("expected status error, got %v", err)
	}
}

func TestHTTPJWKSFetcher_BadJSON(t *testing.T) {
	t.Parallel()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("{not json"))
	}))
	defer srv.Close()
	f := &httpJWKSFetcher{url: srv.URL, client: srv.Client()}
	if _, err := f.fetch(context.Background()); err == nil || !strings.Contains(err.Error(), "decode jwks") {
		t.Fatalf("expected decode error, got %v", err)
	}
}

func TestHTTPJWKSFetcher_EmptyKeys(t *testing.T) {
	t.Parallel()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer srv.Close()
	f := &httpJWKSFetcher{url: srv.URL, client: srv.Client()}
	if _, err := f.fetch(context.Background()); err == nil || !strings.Contains(err.Error(), "no keys") {
		t.Fatalf("expected empty-keys error, got %v", err)
	}
}

func TestHTTPJWKSFetcher_TransportError(t *testing.T) {
	t.Parallel()
	// Closed server ⇒ connection refused.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()
	f := &httpJWKSFetcher{url: url, client: &http.Client{Timeout: time.Second}}
	if _, err := f.fetch(context.Background()); err == nil {
		t.Fatal("expected transport error against a closed server")
	}
}

func TestNewJWSVerifier_RejectsNonHTTPS(t *testing.T) {
	t.Parallel()
	for _, u := range []string{"", "http://insecure.example/jwks", "://bad"} {
		if _, err := NewJWSVerifier(u, nil); err == nil {
			t.Fatalf("expected rejection for %q", u)
		}
	}
}

func TestNewJWSVerifier_NilClientBuildsDefault(t *testing.T) {
	t.Parallel()
	v, err := NewJWSVerifier("https://c6.example/jwks", nil)
	if err != nil {
		t.Fatalf("NewJWSVerifier: %v", err)
	}
	f, ok := v.fetcher.(*httpJWKSFetcher)
	if !ok || f.client == nil {
		t.Fatal("nil client must be replaced by a default HTTP client")
	}
}

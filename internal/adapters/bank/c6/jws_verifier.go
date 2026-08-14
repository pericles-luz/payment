package c6

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// JWS verifier for PIX Automático (Recorrência) reads. C6 returns rec/solicrec/cobr
// GETs as a JWS-signed document (Accept: application/jose) so the BACEN mandate is
// non-reputable; this is the concrete RecurrenceVerifier injected in production
// (SIN-66061), replacing the fail-secure nil seam from F1 (SIN-66035).
//
// Security bar (SIN-66038 §1), all fail-closed:
//   - Explicit asymmetric algorithm allowlist passed to ParseSigned — the verifier
//     never trusts the token's own `alg` header. `none` (unsigned) and HS* (symmetric
//     MAC) are absent from the allowlist, so a token asking for them is rejected at
//     parse time. Excluding HS* is the key-confusion defence: an attacker must not be
//     able to present the public key as an HMAC secret.
//   - Key selection is by `kid` read from the PROTECTED (signed) header only — never
//     the merged/unprotected header, which an attacker could set freely. An unknown
//     kid triggers a single throttled JWKS refetch (key rotation) and then fails
//     closed if still unknown.
//   - Any verification failure (parse, missing/unknown kid, signature mismatch, JWKS
//     fetch error) returns an error; signedRead maps it to shared.ErrUnavailable so a
//     never-trust-unverified-document invariant holds end to end.

// defaultRecVerifierAlgs is the secure-by-default asymmetric allowlist for the
// Recorrência JWS reads. Only public-key signature algorithms appear here; the
// exact algorithm C6/BACEN emits is confirmed in the F4 homologação capture
// (SIN-66034) and may be narrowed via WithAlgorithms. Symmetric MACs (HS*) and the
// unsigned `none` are intentionally NOT present.
var defaultRecVerifierAlgs = []jose.SignatureAlgorithm{jose.PS256, jose.ES256}

// jwksMaxBytes bounds how much of a JWKS response body is read, capping memory on a
// hostile or buggy endpoint (mirrors maxResponseBytes for the bank API).
const jwksMaxBytes = 1 << 20 // 1 MiB

// defaultJWKSMinRefetch throttles refetches when an unknown kid is seen, so a token
// stream carrying garbage kids cannot turn into a JWKS-fetch amplification.
const defaultJWKSMinRefetch = 1 * time.Minute

// jwksFetcher fetches the bank's current JSON Web Key Set. It is an internal seam so
// the verifier can be table-tested without HTTP (the concrete impl is httpJWKSFetcher).
type jwksFetcher interface {
	fetch(ctx context.Context) (*jose.JSONWebKeySet, error)
}

// JWSVerifier is the concrete RecurrenceVerifier. It verifies a compact JWS against
// C6's published JWKS, selecting the key by the signed `kid` and refetching the JWKS
// (throttled) when a kid is unknown to support key rotation.
type JWSVerifier struct {
	algs    []jose.SignatureAlgorithm
	fetcher jwksFetcher

	now        func() time.Time
	minRefetch time.Duration

	mu          sync.Mutex
	cached      *jose.JSONWebKeySet
	lastFetched time.Time
}

// compile-time assertion that JWSVerifier satisfies the adapter's seam.
var _ RecurrenceVerifier = (*JWSVerifier)(nil)

// VerifierOption configures an optional aspect of the verifier.
type VerifierOption func(*JWSVerifier)

// WithAlgorithms overrides the asymmetric signature allowlist. Passing an empty or
// nil slice is ignored (the secure default stands); callers must never widen the
// list to include symmetric or `none` algorithms.
func WithAlgorithms(algs ...jose.SignatureAlgorithm) VerifierOption {
	return func(v *JWSVerifier) {
		if len(algs) > 0 {
			v.algs = append([]jose.SignatureAlgorithm(nil), algs...)
		}
	}
}

// WithClock overrides the clock used to throttle JWKS refetches (tests).
func WithClock(now func() time.Time) VerifierOption {
	return func(v *JWSVerifier) {
		if now != nil {
			v.now = now
		}
	}
}

// WithMinRefetch overrides the minimum interval between JWKS refetches on an unknown
// kid. A non-positive value is ignored.
func WithMinRefetch(d time.Duration) VerifierOption {
	return func(v *JWSVerifier) {
		if d > 0 {
			v.minRefetch = d
		}
	}
}

// NewJWSVerifier builds a verifier that fetches C6's JWKS over HTTP. jwksURL must be
// an absolute https URL (secure-by-default, TLS-only — the public keys must come over
// an authenticated channel). When client is nil a TLS-1.2+ client is built. The
// returned verifier is safe for concurrent use.
func NewJWSVerifier(jwksURL string, client *http.Client, opts ...VerifierOption) (*JWSVerifier, error) {
	if err := requireHTTPS("rec_jwks_url", jwksURL); err != nil {
		return nil, err
	}
	if client == nil {
		client = jwksHTTPClient()
	}
	f := &httpJWKSFetcher{url: jwksURL, client: client}
	return newVerifier(f, opts...), nil
}

// newVerifier wires a verifier around an arbitrary fetcher (the test seam).
func newVerifier(f jwksFetcher, opts ...VerifierOption) *JWSVerifier {
	v := &JWSVerifier{
		algs:       defaultRecVerifierAlgs,
		fetcher:    f,
		now:        time.Now,
		minRefetch: defaultJWKSMinRefetch,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// VerifyJWS verifies a compact JWS and returns its decoded payload, or an error on
// any failure (fail-closed). It is the RecurrenceVerifier the c6 adapter calls.
func (v *JWSVerifier) VerifyJWS(ctx context.Context, compact []byte) ([]byte, error) {
	sig, err := jose.ParseSigned(string(compact), v.algs)
	if err != nil {
		// Covers alg: none (unsigned), HS* (symmetric MAC), and any algorithm outside
		// the allowlist — ParseSigned rejects them before any key is consulted.
		return nil, fmt.Errorf("c6 jws: parse: %w", err)
	}
	if len(sig.Signatures) != 1 {
		return nil, fmt.Errorf("c6 jws: expected exactly one signature, got %d", len(sig.Signatures))
	}
	// kid MUST come from the protected (signed) header: the merged Header carries
	// unprotected values an attacker can set, which must never steer key selection.
	kid := sig.Signatures[0].Protected.KeyID
	if kid == "" {
		return nil, errors.New("c6 jws: missing kid in protected header")
	}
	key, err := v.keyByID(ctx, kid)
	if err != nil {
		return nil, err
	}
	payload, err := sig.Verify(key)
	if err != nil {
		return nil, fmt.Errorf("c6 jws: signature verification failed: %w", err)
	}
	return payload, nil
}

// keyByID returns the public key for kid, refetching the JWKS once (throttled) when
// the kid is unknown so a rotated key is picked up. Fails closed on an unknown kid.
func (v *JWSVerifier) keyByID(ctx context.Context, kid string) (*jose.JSONWebKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if k := lookupKey(v.cached, kid); k != nil {
		return k, nil
	}
	// Unknown kid: refetch (rotation), but only if we have never fetched or enough
	// time has passed, so a flood of bogus kids cannot amplify into JWKS fetches.
	if v.cached == nil || v.now().Sub(v.lastFetched) >= v.minRefetch {
		set, err := v.fetcher.fetch(ctx)
		if err != nil {
			return nil, fmt.Errorf("c6 jws: jwks fetch: %w", err)
		}
		v.cached = set
		v.lastFetched = v.now()
		if k := lookupKey(v.cached, kid); k != nil {
			return k, nil
		}
	}
	return nil, fmt.Errorf("c6 jws: unknown kid %q", kid)
}

// lookupKey returns the first key in set matching kid that holds a public (asymmetric)
// key, or nil. A symmetric (oct) key in the JWKS is ignored defensively, even though
// the parse-time allowlist already bars symmetric verification.
func lookupKey(set *jose.JSONWebKeySet, kid string) *jose.JSONWebKey {
	if set == nil {
		return nil
	}
	for _, k := range set.Key(kid) {
		if k.IsPublic() && k.Valid() {
			key := k
			return &key
		}
	}
	return nil
}

// httpJWKSFetcher fetches a JWKS document over HTTPS.
type httpJWKSFetcher struct {
	url    string
	client *http.Client
}

func (f *httpJWKSFetcher) fetch(ctx context.Context) (*jose.JSONWebKeySet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, jwksMaxBytes))
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("jwks endpoint returned status %d", resp.StatusCode)
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("decode jwks: %w", err)
	}
	if len(set.Keys) == 0 {
		return nil, errors.New("jwks contained no keys")
	}
	return &set, nil
}

// jwksHTTPClient builds a TLS-1.2+ client for JWKS fetches with a bounded timeout and
// redirects disabled (a key endpoint must never be chased through a 3xx — SSRF
// defence, mirroring defaultHTTPClient).
func jwksHTTPClient() *http.Client {
	return &http.Client{
		Timeout: defaultTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			MaxIdleConns:        10,
			MaxIdleConnsPerHost: 4,
			IdleConnTimeout:     90 * time.Second,
			ForceAttemptHTTP2:   true,
		},
	}
}

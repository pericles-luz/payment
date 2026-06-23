package c6

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// defaultRefreshSkew is how long before real expiry a cached token is treated as
// stale, so a token is renewed proactively instead of failing an in-flight call
// at the boundary.
const defaultRefreshSkew = 30 * time.Second

// fallbackTokenTTL is used when the token endpoint omits expires_in. It is short
// so a missing TTL degrades to frequent refresh rather than using a token past
// its real lifetime.
const fallbackTokenTTL = 60 * time.Second

// cachedToken is an access token together with the instant it must be considered
// expired. The token lives only in memory and is never persisted (threat C1).
type cachedToken struct {
	accessToken string
	expiresAt   time.Time
}

// tokenState is the per-tenant cache slot. Its own mutex serializes refreshes for
// a single tenant (so concurrent calls for the same tenant make at most one token
// request) without serializing unrelated tenants.
type tokenState struct {
	mu  sync.Mutex
	tok cachedToken
}

// tokenManager issues and caches OAuth2 client_credentials access tokens per
// tenant. Credentials are resolved from the CredentialStore at fetch time and the
// client secret is sent only in the token request's Basic auth header — never
// logged, never stored, never placed in a URL (threat C1/C4).
type tokenManager struct {
	creds    ports.CredentialStore
	tokenURL string
	scope    string
	httpc    *http.Client
	now      func() time.Time
	skew     time.Duration

	mu      sync.Mutex
	entries map[string]*tokenState
}

func newTokenManager(creds ports.CredentialStore, tokenURL, scope string, httpc *http.Client, now func() time.Time) *tokenManager {
	return &tokenManager{
		creds:    creds,
		tokenURL: tokenURL,
		scope:    scope,
		httpc:    httpc,
		now:      now,
		skew:     defaultRefreshSkew,
		entries:  make(map[string]*tokenState),
	}
}

// stateFor returns the cache slot for a tenant, creating it on first use. The
// outer mutex is held only for the map lookup/insert, never across the HTTP call.
func (m *tokenManager) stateFor(tenantID string) *tokenState {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.entries[tenantID]
	if !ok {
		st = &tokenState{}
		m.entries[tenantID] = st
	}
	return st
}

// token returns a valid access token for the tenant, fetching or refreshing it as
// needed. Tokens are isolated per tenant: one tenant's token is never served to
// another, and a refresh for one tenant cannot block another.
func (m *tokenManager) token(ctx context.Context, tenantID string) (string, error) {
	st := m.stateFor(tenantID)
	st.mu.Lock()
	defer st.mu.Unlock()

	if st.tok.accessToken != "" && m.now().Before(st.tok.expiresAt.Add(-m.skew)) {
		return st.tok.accessToken, nil
	}

	// Resolve the tenant's credential lazily and only when a (re)fetch is needed.
	cred, err := m.creds.GetBankCredential(ctx, tenantID)
	if err != nil {
		return "", err
	}
	tok, err := m.fetch(ctx, cred)
	if err != nil {
		return "", err
	}
	st.tok = tok
	return tok.accessToken, nil
}

// invalidate drops any cached token for tenantID so the next token() call mints a
// fresh one under the tenant's current credential. It is the eviction half of the
// token-revocation-lag fix (ADR-0003): a rotated/revoked credential takes effect
// at once instead of after the cached bearer expires (≤ TTL; 60s fallback). Safe
// for an unknown tenant (no-op) and concurrency-safe against an in-flight refresh:
// it takes the outer lock only to find the slot, then the slot's own lock to zero
// it — the same outer-then-slot order token() uses, never both at once, so no
// lock-order inversion. A refresh already running for the old credential finishes
// into its slot; because the new credential is persisted before invalidate runs,
// any (re)fetch — that in-flight one or the next caller's — resolves the new
// secret from the store.
func (m *tokenManager) invalidate(tenantID string) {
	m.mu.Lock()
	st, ok := m.entries[tenantID]
	m.mu.Unlock()
	if !ok {
		return
	}
	st.mu.Lock()
	st.tok = cachedToken{}
	st.mu.Unlock()
}

// tokenResponse is the subset of the OAuth2 token response we consume.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

// fetch performs the OAuth2 client_credentials grant. The secret travels only in
// the Basic auth header. On any non-2xx the body is read solely to extract the
// safe machine code (via mapError); its raw contents are never surfaced.
func (m *tokenManager) fetch(ctx context.Context, cred ports.BankCredential) (cachedToken, error) {
	form := url.Values{"grant_type": {"client_credentials"}}
	if m.scope != "" {
		form.Set("scope", m.scope)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return cachedToken{}, transportError("token")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	// Client secret is sent only here, in the Authorization header — never logged.
	req.SetBasicAuth(cred.ClientID, cred.Secret)

	resp, err := m.httpc.Do(req)
	if err != nil {
		return cachedToken{}, transportError("token")
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if resp.StatusCode/100 != 2 {
		return cachedToken{}, mapError("token", resp.StatusCode, body)
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil || tr.AccessToken == "" {
		// A 2xx without a usable token is an upstream contract violation.
		return cachedToken{}, &Error{Op: "token", StatusCode: resp.StatusCode, sentinel: shared.ErrUnavailable}
	}

	ttl := time.Duration(tr.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = fallbackTokenTTL
	}
	return cachedToken{accessToken: tr.AccessToken, expiresAt: m.now().Add(ttl)}, nil
}

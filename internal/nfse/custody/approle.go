package custody

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// appRoleRenewMargin is how far ahead of the token's lease expiry
// AppRoleTokenSource re-logs-in. Re-authenticating early (instead of exactly at
// expiry) avoids a race where an in-flight VaultTransitSigner request picks up
// a token that expires between the cache read and the Vault round-trip.
const appRoleRenewMargin = 30 * time.Second

// AppRoleConfig configures AppRoleTokenSource. RoleID and SecretID are the
// AppRole credentials (ADR-0007 / runbook-nfse-kms-custody.md §5): the
// fiscalsigner AppRole role_id is fixed per-environment, secret_id is the
// runtime-injected credential (never baked into an image or committed).
// Neither value is ever logged or wrapped into an error.
type AppRoleConfig struct {
	// Address is the Vault API base URL (e.g. https://172.18.2.63:8200).
	Address string
	// RoleID identifies the AppRole (public, not sensitive on its own).
	RoleID string
	// SecretID is the AppRole secret (sensitive — read from env/secret
	// injection at process start, never from a flag or committed file).
	SecretID string
	// HTTPClient overrides the HTTP client (test hook / TLS config). A default
	// client with a 10s timeout is used when nil.
	HTTPClient *http.Client
	// Now overrides the clock (test hook). Defaults to time.Now.
	Now func() time.Time
}

// AppRoleTokenSource logs in against Vault's AppRole auth method and returns a
// func(ctx) (string, error) suitable for VaultTransitConfig.TokenSource. The
// returned func is safe for concurrent use: it caches the client token and
// only re-authenticates once the cached token is within appRoleRenewMargin of
// its lease expiry (or on first call). No login happens at construction time —
// the first Token() call performs it — so building the token source never
// blocks on Vault being reachable.
func AppRoleTokenSource(cfg AppRoleConfig) (func(context.Context) (string, error), error) {
	if strings.TrimSpace(cfg.Address) == "" {
		return nil, errors.New("custody: approle vault address required")
	}
	if strings.TrimSpace(cfg.RoleID) == "" {
		return nil, errors.New("custody: approle role_id required")
	}
	if strings.TrimSpace(cfg.SecretID) == "" {
		return nil, errors.New("custody: approle secret_id required")
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	src := &appRoleTokenSource{
		address:    strings.TrimRight(cfg.Address, "/"),
		roleID:     cfg.RoleID,
		secretID:   cfg.SecretID,
		httpClient: httpClient,
		now:        now,
	}
	return src.Token, nil
}

// appRoleTokenSource holds the AppRole credentials and the cached client
// token. It never exposes RoleID/SecretID/token outside Token() and login().
type appRoleTokenSource struct {
	address    string
	roleID     string
	secretID   string
	httpClient *http.Client
	now        func() time.Time

	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

// Token returns a valid client token, logging in (or re-logging-in) against
// Vault as needed. Errors are wrapped in ErrVaultTransport and never include
// the role_id, secret_id, or any token.
func (s *appRoleTokenSource) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.token != "" && s.now().Before(s.expiresAt.Add(-appRoleRenewMargin)) {
		return s.token, nil
	}

	token, ttl, err := s.login(ctx)
	if err != nil {
		return "", err
	}
	s.token = token
	s.expiresAt = s.now().Add(ttl)
	return s.token, nil
}

// appRoleLoginResponse decodes the subset of Vault's
// POST /v1/auth/approle/login response this adapter needs.
type appRoleLoginResponse struct {
	Auth struct {
		ClientToken   string `json:"client_token"`
		LeaseDuration int    `json:"lease_duration"`
	} `json:"auth"`
}

// login performs one AppRole login call and returns the client token plus its
// lease duration. It never logs the request body or the response.
func (s *appRoleTokenSource) login(ctx context.Context) (string, time.Duration, error) {
	reqBody, err := json.Marshal(map[string]string{
		"role_id":   s.roleID,
		"secret_id": s.secretID,
	})
	if err != nil {
		return "", 0, fmt.Errorf("%w: marshal approle login request", ErrVaultTransport)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.address+"/v1/auth/approle/login", bytes.NewReader(reqBody))
	if err != nil {
		return "", 0, fmt.Errorf("%w: build approle login request", ErrVaultTransport)
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := s.httpClient.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("%w: approle login request failed", ErrVaultTransport)
	}
	defer res.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(res.Body, 1<<16))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return "", 0, fmt.Errorf("%w: approle login -> HTTP %d", ErrVaultTransport, res.StatusCode)
	}

	var out appRoleLoginResponse
	if err := json.Unmarshal(payload, &out); err != nil {
		return "", 0, fmt.Errorf("%w: decode approle login response", ErrVaultTransport)
	}
	if out.Auth.ClientToken == "" {
		return "", 0, fmt.Errorf("%w: approle login returned empty client_token", ErrVaultTransport)
	}
	ttl := time.Duration(out.Auth.LeaseDuration) * time.Second
	if ttl <= appRoleRenewMargin {
		// Degenerate/very-short TTL (e.g. a misconfigured role): don't cache —
		// force a fresh login on the very next call rather than risk serving a
		// token that's already within (or past) the renew margin.
		ttl = 0
	}
	return out.Auth.ClientToken, ttl, nil
}

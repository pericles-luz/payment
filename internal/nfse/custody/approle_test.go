package custody

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// approleStub is an httptest.Server standing in for Vault's
// POST /v1/auth/approle/login endpoint.
type approleStub struct {
	*httptest.Server

	mu            sync.Mutex
	wantRoleID    string
	wantSecretID  string
	tokenPrefix   string
	leaseDuration int
	statusCode    int
	emptyToken    bool
	loginCount    int32
}

func newApproleStub(t *testing.T) *approleStub {
	t.Helper()
	s := &approleStub{
		wantRoleID:    "role-123",
		wantSecretID:  "secret-abc",
		tokenPrefix:   "t-",
		leaseDuration: 3600,
		statusCode:    http.StatusOK,
	}
	s.Server = httptest.NewServer(http.HandlerFunc(s.handle))
	t.Cleanup(s.Close)
	return s
}

func (s *approleStub) handle(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/v1/auth/approle/login" {
		http.NotFound(w, r)
		return
	}
	n := atomic.AddInt32(&s.loginCount, 1)

	var body struct {
		RoleID   string `json:"role_id"`
		SecretID string `json:"secret_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if body.RoleID != s.wantRoleID || body.SecretID != s.wantSecretID {
		http.Error(w, "invalid role_id/secret_id", http.StatusBadRequest)
		return
	}
	if s.statusCode != http.StatusOK {
		http.Error(w, "denied", s.statusCode)
		return
	}

	resp := appRoleLoginResponse{}
	if !s.emptyToken {
		resp.Auth.ClientToken = s.tokenPrefix + strconv.Itoa(int(n))
	}
	resp.Auth.LeaseDuration = s.leaseDuration
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *approleStub) logins() int {
	return int(atomic.LoadInt32(&s.loginCount))
}

func TestAppRoleTokenSource_ConstructorValidation(t *testing.T) {
	cases := []struct {
		name string
		cfg  AppRoleConfig
	}{
		{"missing address", AppRoleConfig{RoleID: "r", SecretID: "s"}},
		{"missing role_id", AppRoleConfig{Address: "https://vault:8200", SecretID: "s"}},
		{"missing secret_id", AppRoleConfig{Address: "https://vault:8200", RoleID: "r"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := AppRoleTokenSource(tc.cfg); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestAppRoleTokenSource_LoginAndCache(t *testing.T) {
	stub := newApproleStub(t)
	now := time.Now()
	clock := func() time.Time { return now }

	src, err := AppRoleTokenSource(AppRoleConfig{
		Address:  stub.URL,
		RoleID:   stub.wantRoleID,
		SecretID: stub.wantSecretID,
		Now:      func() time.Time { return clock() },
	})
	if err != nil {
		t.Fatalf("AppRoleTokenSource: %v", err)
	}

	tok1, err := src(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok1 != "t-1" {
		t.Fatalf("token = %q, want t-1", tok1)
	}
	if got := stub.logins(); got != 1 {
		t.Fatalf("logins = %d, want 1", got)
	}

	// Second call, well within the lease: must be served from cache, no new login.
	tok2, err := src(context.Background())
	if err != nil {
		t.Fatalf("Token (cached): %v", err)
	}
	if tok2 != tok1 {
		t.Fatalf("cached token changed: %q -> %q", tok1, tok2)
	}
	if got := stub.logins(); got != 1 {
		t.Fatalf("logins after cached call = %d, want 1 (no re-login)", got)
	}

	// Advance the clock past (lease - renewMargin): must re-login.
	now = now.Add(time.Duration(stub.leaseDuration)*time.Second - appRoleRenewMargin + time.Second)
	tok3, err := src(context.Background())
	if err != nil {
		t.Fatalf("Token (post-renew-margin): %v", err)
	}
	if tok3 == tok1 {
		t.Fatalf("expected a fresh token after crossing the renew margin, got the same one")
	}
	if got := stub.logins(); got != 2 {
		t.Fatalf("logins after renew-margin call = %d, want 2", got)
	}
}

func TestAppRoleTokenSource_ShortLeaseNeverCaches(t *testing.T) {
	stub := newApproleStub(t)
	stub.leaseDuration = 5 // below appRoleRenewMargin

	src, err := AppRoleTokenSource(AppRoleConfig{
		Address:  stub.URL,
		RoleID:   stub.wantRoleID,
		SecretID: stub.wantSecretID,
	})
	if err != nil {
		t.Fatalf("AppRoleTokenSource: %v", err)
	}

	if _, err := src(context.Background()); err != nil {
		t.Fatalf("Token: %v", err)
	}
	if _, err := src(context.Background()); err != nil {
		t.Fatalf("Token: %v", err)
	}
	if got := stub.logins(); got != 2 {
		t.Fatalf("logins = %d, want 2 (short lease must never be cached)", got)
	}
}

func TestAppRoleTokenSource_WrongCredentials(t *testing.T) {
	stub := newApproleStub(t)
	src, err := AppRoleTokenSource(AppRoleConfig{
		Address:  stub.URL,
		RoleID:   stub.wantRoleID,
		SecretID: "wrong-secret",
	})
	if err != nil {
		t.Fatalf("AppRoleTokenSource: %v", err)
	}
	_, err = src(context.Background())
	if !errors.Is(err, ErrVaultTransport) {
		t.Fatalf("err = %v, want wrapping ErrVaultTransport", err)
	}
	if strings.Contains(err.Error(), "wrong-secret") {
		t.Fatalf("error leaks the secret_id: %v", err)
	}
}

func TestAppRoleTokenSource_HTTPError(t *testing.T) {
	stub := newApproleStub(t)
	stub.statusCode = http.StatusInternalServerError
	src, err := AppRoleTokenSource(AppRoleConfig{
		Address:  stub.URL,
		RoleID:   stub.wantRoleID,
		SecretID: stub.wantSecretID,
	})
	if err != nil {
		t.Fatalf("AppRoleTokenSource: %v", err)
	}
	if _, err := src(context.Background()); !errors.Is(err, ErrVaultTransport) {
		t.Fatalf("err = %v, want wrapping ErrVaultTransport", err)
	}
}

func TestAppRoleTokenSource_EmptyClientToken(t *testing.T) {
	stub := newApproleStub(t)
	stub.emptyToken = true
	src, err := AppRoleTokenSource(AppRoleConfig{
		Address:  stub.URL,
		RoleID:   stub.wantRoleID,
		SecretID: stub.wantSecretID,
	})
	if err != nil {
		t.Fatalf("AppRoleTokenSource: %v", err)
	}
	if _, err := src(context.Background()); !errors.Is(err, ErrVaultTransport) {
		t.Fatalf("err = %v, want wrapping ErrVaultTransport", err)
	}
}

func TestAppRoleTokenSource_UnreachableAddress(t *testing.T) {
	src, err := AppRoleTokenSource(AppRoleConfig{
		Address:  "http://127.0.0.1:1", // reserved, connection refused
		RoleID:   "r",
		SecretID: "s",
	})
	if err != nil {
		t.Fatalf("AppRoleTokenSource: %v", err)
	}
	if _, err := src(context.Background()); !errors.Is(err, ErrVaultTransport) {
		t.Fatalf("err = %v, want wrapping ErrVaultTransport", err)
	}
}

package http

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/domain/account"
)

// newTenantAuth builds a StaticTokenAuth with the given token→tenant map and no
// admin/webhook credentials, for exercising the tenant auth choke-point.
func newTenantAuth(tenantTokens map[string]string) *StaticTokenAuth {
	return NewStaticTokenAuth(tenantTokens, nil, nil)
}

// TestAuthenticateTenantPrincipal proves the single choke-point resolves BOTH the
// tenant id (unchanged) and the owning account id, and that the account is the
// tenant's self-account derived server-side (dark-ship default, ADR-0009 §4 /
// SIN-69126 F1). A failed lookup denies with the same (zero,false) as
// AuthenticateTenant — no new enumeration oracle.
func TestAuthenticateTenantPrincipal(t *testing.T) {
	t.Parallel()
	auth := newTenantAuth(map[string]string{
		"tok-a": "tenant-a",
		"tok-b": "tenant-b",
	})
	tests := []struct {
		name        string
		token       string
		wantOK      bool
		wantTenant  string
		wantAccount string
	}{
		{name: "legacy token resolves to both ids (self-account)", token: "tok-a", wantOK: true, wantTenant: "tenant-a", wantAccount: "acct-tenant-a"},
		{name: "second tenant isolated to its own self-account", token: "tok-b", wantOK: true, wantTenant: "tenant-b", wantAccount: "acct-tenant-b"},
		{name: "unknown token denied", token: "nope", wantOK: false},
		{name: "empty token denied", token: "", wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p, ok := auth.AuthenticateTenantPrincipal(tt.token)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if !tt.wantOK {
				if p != (Principal{}) {
					t.Fatalf("denied lookup must return zero Principal, got %+v", p)
				}
				return
			}
			if p.TenantID != tt.wantTenant {
				t.Errorf("TenantID = %q, want %q", p.TenantID, tt.wantTenant)
			}
			if p.AccountID != tt.wantAccount {
				t.Errorf("AccountID = %q, want %q", p.AccountID, tt.wantAccount)
			}
			// The account MUST be the derived self-account, not the tenant id.
			if p.AccountID != account.SelfAccountID(tt.wantTenant) {
				t.Errorf("AccountID = %q, want self-account %q", p.AccountID, account.SelfAccountID(tt.wantTenant))
			}
		})
	}
}

// TestTenantAuthMiddlewareInjectsPrincipal proves the middleware injects BOTH
// ctxTenantID (unchanged, authoritative for isolation) and ctxAccountID (new,
// attribution) on an authenticated request, and denies an unauthenticated one
// with 401 before the handler runs (deny-by-default).
func TestTenantAuthMiddlewareInjectsPrincipal(t *testing.T) {
	t.Parallel()
	auth := newTenantAuth(map[string]string{"tok-a": "tenant-a"})

	var gotTenant, gotAccount string
	var handlerRan bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerRan = true
		gotTenant = tenantFromContext(r.Context())
		gotAccount = accountFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	h := tenantAuthMiddleware(auth)(next)

	t.Run("authenticated injects both ids", func(t *testing.T) {
		handlerRan, gotTenant, gotAccount = false, "", ""
		req := httptest.NewRequest(http.MethodGet, "/v1/x", nil)
		req.Header.Set("Authorization", "Bearer tok-a")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if !handlerRan {
			t.Fatal("handler did not run for authenticated request")
		}
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if gotTenant != "tenant-a" {
			t.Errorf("ctxTenantID = %q, want tenant-a", gotTenant)
		}
		if gotAccount != "acct-tenant-a" {
			t.Errorf("ctxAccountID = %q, want acct-tenant-a", gotAccount)
		}
	})

	t.Run("unauthenticated denied before handler", func(t *testing.T) {
		handlerRan = false
		req := httptest.NewRequest(http.MethodGet, "/v1/x", nil)
		// no Authorization header
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if handlerRan {
			t.Fatal("handler must not run for unauthenticated request")
		}
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})
}

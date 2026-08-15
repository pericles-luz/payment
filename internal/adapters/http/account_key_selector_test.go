package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
)

// fakeKeyAuth is a fixed-answer AccountKeyAuthenticator for the model (b) guard
// tests: a presented secret resolves to its owning account only if it is in the
// map, otherwise the uniform ("", false) — no oracle, mirroring the store.
type fakeKeyAuth struct{ byKey map[string]string }

func (f fakeKeyAuth) AuthenticateAccountKey(_ context.Context, secret string) (string, bool) {
	acct, ok := f.byKey[secret]
	return acct, ok
}

// The account-key path routes on the ak_ prefix (accountkey.HasSecretShape), so
// test keys must carry it. These are opaque plaintext secrets, not real entropy.
const (
	keyAcctA = "ak_key_for_account_A"
	keyAcctB = "ak_key_for_account_B"
)

// b2Resolver builds a StoreAccountResolver over a finder that maps the selectable
// tenants to their owning accounts (acct-A owns emp-a; acct-B owns emp-b; emp-self
// is unassigned → owner ""). It is the same read port model (a) uses, exercised
// here under the model (b) deny semantics.
func b2Resolver(t *testing.T) *StoreAccountResolver {
	t.Helper()
	finder := fakeTenantFinder{byID: map[string]*tenant.Tenant{
		"emp-a":    tenantWithAccount(t, "emp-a", "acct-A"),
		"emp-b":    tenantWithAccount(t, "emp-b", "acct-B"),
		"emp-self": tenantWithAccount(t, "emp-self", ""),
	}}
	return NewStoreAccountResolver(finder)
}

// TestAccountKeyChokepointGuard is the load-bearing §2 regression suite (ADR-0011 /
// SIN-69279). It exercises the account-key + selector path with the flag ON and
// proves every threat disposition is fail-closed: cross-account and unknown tenant
// are indistinguishable (same 404, no A01 oracle), a tenant token cannot select, a
// key without a selector never defaults into a tenant, and any resolver failure
// denies.
func TestAccountKeyChokepointGuard(t *testing.T) {
	t.Parallel()
	tenantAuth := newTenantAuth(map[string]string{"tok-a": "emp-a"})
	keyAuth := fakeKeyAuth{byKey: map[string]string{keyAcctA: "acct-A", keyAcctB: "acct-B"}}

	tests := []struct {
		name        string
		bearer      string
		selector    string // X-Client-Tenant; "" means header omitted
		resolver    AccountResolver
		wantStatus  int
		wantRan     bool
		wantTenant  string
		wantAccount string
	}{
		{
			name:        "happy path: key owns selected tenant → scoped to it",
			bearer:      keyAcctA,
			selector:    "emp-a",
			resolver:    b2Resolver(t),
			wantStatus:  http.StatusOK,
			wantRan:     true,
			wantTenant:  "emp-a",
			wantAccount: "acct-A",
		},
		{
			name:       "T1 cross-account selector → 404 (no oracle)",
			bearer:     keyAcctA,
			selector:   "emp-b", // owned by acct-B, caller is acct-A
			resolver:   b2Resolver(t),
			wantStatus: http.StatusNotFound,
			wantRan:    false,
		},
		{
			name:       "T2 unknown tenant → same 404 as cross-account",
			bearer:     keyAcctA,
			selector:   "ghost",
			resolver:   b2Resolver(t),
			wantStatus: http.StatusNotFound,
			wantRan:    false,
		},
		{
			name:       "unassigned (self-account) tenant → 404 (model (b) deny, not permissive)",
			bearer:     keyAcctA,
			selector:   "emp-self", // owner "" — model (a) would keep self-account; (b) denies
			resolver:   b2Resolver(t),
			wantStatus: http.StatusNotFound,
			wantRan:    false,
		},
		{
			name:       "T4 key without selector → 400 (never defaults a tenant)",
			bearer:     keyAcctA,
			selector:   "",
			resolver:   b2Resolver(t),
			wantStatus: http.StatusBadRequest,
			wantRan:    false,
		},
		{
			name:       "T7 resolver error → 404 (fail-closed)",
			bearer:     keyAcctA,
			selector:   "emp-a",
			resolver:   NewStoreAccountResolver(fakeTenantFinder{err: errFinder}),
			wantStatus: http.StatusNotFound,
			wantRan:    false,
		},
		{
			name:       "no resolver wired → 404 (cannot prove ownership, fail-closed)",
			bearer:     keyAcctA,
			selector:   "emp-a",
			resolver:   nil,
			wantStatus: http.StatusNotFound,
			wantRan:    false,
		},
		{
			name:       "bad account key (ak_ shape, unknown) → uniform 401",
			bearer:     "ak_not_a_real_key",
			selector:   "emp-a",
			resolver:   b2Resolver(t),
			wantStatus: http.StatusUnauthorized,
			wantRan:    false,
		},
		{
			name:       "T3 tenant token + selector → 400 (no selection authority)",
			bearer:     "tok-a",
			selector:   "emp-a",
			resolver:   b2Resolver(t),
			wantStatus: http.StatusBadRequest,
			wantRan:    false,
		},
		{
			name:        "tenant token without selector → unchanged model (a) 200",
			bearer:      "tok-a",
			selector:    "",
			resolver:    b2Resolver(t),
			wantStatus:  http.StatusOK,
			wantRan:     true,
			wantTenant:  "emp-a",
			wantAccount: "acct-A", // resolver upgrades self-account to the real parent
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var ran bool
			var gotTenant, gotAccount string
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ran = true
				gotTenant = tenantFromContext(r.Context())
				gotAccount = accountFromContext(r.Context())
				w.WriteHeader(http.StatusOK)
			})
			guard := accountKeyGuard{enabled: true, keyAuth: keyAuth}
			var h http.Handler
			if tt.resolver == nil {
				h = tenantAuthMiddlewareWithSelector(tenantAuth, guard)(next)
			} else {
				h = tenantAuthMiddlewareWithSelector(tenantAuth, guard, tt.resolver)(next)
			}

			req := httptest.NewRequest(http.MethodGet, "/v1/x", nil)
			req.Header.Set("Authorization", "Bearer "+tt.bearer)
			if tt.selector != "" {
				req.Header.Set(clientSelectorHeader, tt.selector)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if ran != tt.wantRan {
				t.Fatalf("handler ran = %v, want %v", ran, tt.wantRan)
			}
			if tt.wantRan {
				if gotTenant != tt.wantTenant {
					t.Errorf("ctxTenantID = %q, want %q", gotTenant, tt.wantTenant)
				}
				if gotAccount != tt.wantAccount {
					t.Errorf("ctxAccountID = %q, want %q", gotAccount, tt.wantAccount)
				}
			}
		})
	}
}

// TestAccountKeySelectorFlagOffIsNoOp proves the dark-ship default: with the guard
// disabled (flag off, the zero accountKeyGuard) the choke-point behaves EXACTLY as
// model (a) — an ak_ bearer is NOT treated as an account key (it is just an unknown
// tenant token → 401) and an X-Client-Tenant selector on a valid tenant token is
// silently IGNORED (200, no T3 rejection). Nothing about model (b) leaks when off.
func TestAccountKeySelectorFlagOffIsNoOp(t *testing.T) {
	t.Parallel()
	tenantAuth := newTenantAuth(map[string]string{"tok-a": "emp-a"})
	keyAuth := fakeKeyAuth{byKey: map[string]string{keyAcctA: "acct-A"}}
	resolver := b2Resolver(t)

	newHandler := func() (http.Handler, *bool, *string, *string) {
		var ran bool
		var gotTenant, gotAccount string
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ran = true
			gotTenant = tenantFromContext(r.Context())
			gotAccount = accountFromContext(r.Context())
			w.WriteHeader(http.StatusOK)
		})
		// enabled:false — even with a keyAuth present the guard is inert. This mirrors
		// how tenantAuthMiddleware (the plain wrapper) is installed when the flag is off.
		guard := accountKeyGuard{enabled: false, keyAuth: keyAuth}
		return tenantAuthMiddlewareWithSelector(tenantAuth, guard, resolver)(next), &ran, &gotTenant, &gotAccount
	}

	t.Run("ak_ bearer is not an account key → treated as unknown tenant token (401)", func(t *testing.T) {
		h, ran, _, _ := newHandler()
		req := httptest.NewRequest(http.MethodGet, "/v1/x", nil)
		req.Header.Set("Authorization", "Bearer "+keyAcctA)
		req.Header.Set(clientSelectorHeader, "emp-a")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401 (ak_ key must not authenticate when flag off)", rec.Code)
		}
		if *ran {
			t.Fatal("handler must not run")
		}
	})

	t.Run("selector on a valid tenant token is ignored → 200 model (a)", func(t *testing.T) {
		h, ran, tid, acct := newHandler()
		req := httptest.NewRequest(http.MethodGet, "/v1/x", nil)
		req.Header.Set("Authorization", "Bearer tok-a")
		req.Header.Set(clientSelectorHeader, "emp-b") // would be a cross-account probe if honored
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (selector must be ignored when flag off)", rec.Code)
		}
		if !*ran {
			t.Fatal("handler must run")
		}
		if *tid != "emp-a" {
			t.Errorf("ctxTenantID = %q, want emp-a (from token, selector ignored)", *tid)
		}
		if *acct != "acct-A" {
			t.Errorf("ctxAccountID = %q, want acct-A", *acct)
		}
	})
}

// TestAccountKeyGuardActiveFailsClosedWithoutKeyAuth proves the guard stays off when
// the flag is on but no key authenticator is wired (misconfiguration): active() is
// false, so an ak_ bearer falls through to the tenant-token path (401 here) rather
// than crashing on a nil authenticator — fail-closed, deny-by-default.
func TestAccountKeyGuardActiveFailsClosedWithoutKeyAuth(t *testing.T) {
	t.Parallel()
	if (accountKeyGuard{enabled: true, keyAuth: nil}).active() {
		t.Fatal("guard with nil keyAuth must not be active")
	}
	if (accountKeyGuard{enabled: false, keyAuth: fakeKeyAuth{}}).active() {
		t.Fatal("guard with flag off must not be active")
	}
	if !(accountKeyGuard{enabled: true, keyAuth: fakeKeyAuth{}}).active() {
		t.Fatal("guard with flag on and keyAuth wired must be active")
	}

	tenantAuth := newTenantAuth(map[string]string{"tok-a": "emp-a"})
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := tenantAuthMiddlewareWithSelector(tenantAuth, accountKeyGuard{enabled: true, keyAuth: nil}, b2Resolver(t))(next)
	req := httptest.NewRequest(http.MethodGet, "/v1/x", nil)
	req.Header.Set("Authorization", "Bearer "+keyAcctA) // ak_ shape, but no key auth wired
	req.Header.Set(clientSelectorHeader, "emp-a")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (ak_ key with no authenticator must not be honored)", rec.Code)
	}
}

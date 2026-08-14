package http

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
)

// fakeTenantFinder is a minimal tenantAccountFinder for exercising the resolver in
// isolation: it maps a tenant id to a prebuilt tenant, or returns errFinder for
// any id not present (the ErrNotFound analogue).
type fakeTenantFinder struct {
	byID map[string]*tenant.Tenant
	err  error
}

var errFinder = errors.New("not found")

func (f fakeTenantFinder) FindTenantByID(_ context.Context, id string) (*tenant.Tenant, error) {
	if f.err != nil {
		return nil, f.err
	}
	t, ok := f.byID[id]
	if !ok {
		return nil, errFinder
	}
	return t, nil
}

func tenantWithAccount(t *testing.T, id, acctID string) *tenant.Tenant {
	t.Helper()
	tn, err := tenant.New(id, "n-"+id, time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatalf("new tenant: %v", err)
	}
	if acctID != "" {
		if err := tn.AssignAccount(acctID); err != nil {
			t.Fatalf("assign: %v", err)
		}
	}
	return tn
}

// TestStoreAccountResolver covers the read port that turns a tenant id into its
// owning Account id: a bound tenant returns its real parent; an unbound
// (self-account) tenant returns ""; and every fail-safe path (nil receiver, nil
// finder, empty id, store error, missing tenant) returns "" so the choke-point
// keeps the self-account default and never widens scope.
func TestStoreAccountResolver(t *testing.T) {
	t.Parallel()
	bound := tenantWithAccount(t, "emp-1", "acct-x")
	unbound := tenantWithAccount(t, "emp-2", "")
	finder := fakeTenantFinder{byID: map[string]*tenant.Tenant{"emp-1": bound, "emp-2": unbound}}

	tests := []struct {
		name     string
		resolver *StoreAccountResolver
		tenantID string
		want     string
	}{
		{name: "bound tenant returns real parent", resolver: NewStoreAccountResolver(finder), tenantID: "emp-1", want: "acct-x"},
		{name: "self-account tenant returns empty", resolver: NewStoreAccountResolver(finder), tenantID: "emp-2", want: ""},
		{name: "missing tenant is fail-safe empty", resolver: NewStoreAccountResolver(finder), tenantID: "ghost", want: ""},
		{name: "empty tenant id is empty", resolver: NewStoreAccountResolver(finder), tenantID: "  ", want: ""},
		{name: "store error is fail-safe empty", resolver: NewStoreAccountResolver(fakeTenantFinder{err: errFinder}), tenantID: "emp-1", want: ""},
		{name: "nil finder is empty", resolver: NewStoreAccountResolver(nil), tenantID: "emp-1", want: ""},
		{name: "nil resolver is empty", resolver: nil, tenantID: "emp-1", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.resolver.ResolveAccountID(context.Background(), tt.tenantID); got != tt.want {
				t.Errorf("ResolveAccountID(%q) = %q, want %q", tt.tenantID, got, tt.want)
			}
		})
	}
}

// stubResolver is a fixed-answer AccountResolver for the middleware test.
type stubResolver struct{ account string }

func (s stubResolver) ResolveAccountID(context.Context, string) string { return s.account }

// TestTenantAuthMiddlewareResolvesParentAccount proves the optional resolver
// overrides the choke-point's self-account default with the real parent Account
// when it resolves one, and keeps the self-account default when the resolver
// returns "" (unassigned tenant / fail-safe). The tenant id is unaffected either
// way — the isolation boundary never moves.
func TestTenantAuthMiddlewareResolvesParentAccount(t *testing.T) {
	t.Parallel()
	auth := newTenantAuth(map[string]string{"tok-a": "tenant-a"})

	run := func(t *testing.T, resolver AccountResolver) (tenantID, accountID string) {
		t.Helper()
		next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			tenantID = tenantFromContext(r.Context())
			accountID = accountFromContext(r.Context())
		})
		h := tenantAuthMiddleware(auth, resolver)(next)
		req := httptest.NewRequest(http.MethodGet, "/v1/x", nil)
		req.Header.Set("Authorization", "Bearer tok-a")
		h.ServeHTTP(httptest.NewRecorder(), req)
		return tenantID, accountID
	}

	t.Run("resolver returns real parent → stamped", func(t *testing.T) {
		tid, acct := run(t, stubResolver{account: "acct-reseller"})
		if tid != "tenant-a" {
			t.Errorf("tenant = %q, want tenant-a", tid)
		}
		if acct != "acct-reseller" {
			t.Errorf("account = %q, want acct-reseller (parent override)", acct)
		}
	})

	t.Run("resolver returns empty → self-account default kept", func(t *testing.T) {
		tid, acct := run(t, stubResolver{account: ""})
		if tid != "tenant-a" {
			t.Errorf("tenant = %q, want tenant-a", tid)
		}
		if acct != "acct-tenant-a" {
			t.Errorf("account = %q, want acct-tenant-a (self-account default)", acct)
		}
	})

	t.Run("nil resolver element → self-account default kept", func(t *testing.T) {
		tid, acct := run(t, nil)
		if tid != "tenant-a" || acct != "acct-tenant-a" {
			t.Errorf("got (%q,%q), want (tenant-a, acct-tenant-a)", tid, acct)
		}
	})
}

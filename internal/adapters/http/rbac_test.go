package http_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/bank"
	httpadapter "github.com/ia-dev-sindireceita/payment/internal/adapters/http"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/messaging/inmemory"
	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/system"
	"github.com/ia-dev-sindireceita/payment/internal/app"
)

const (
	rbacTenantToken   = "ten-tok"
	rbacAdminToken    = "adm-tok"
	rbacOperatorToken = "ops-tok"
	rbacWebhookSecret = "wh-sec"
)

type rbacFixture struct {
	handler  http.Handler
	tenantID string
	creds    *secret.Store
}

// newRBACFixture wires a server with both an admin (full) and an operator
// (read-only) token plus the credential write path, so the role matrix and the
// per-tenant bank-credential write can be exercised end-to-end.
func newRBACFixture(t *testing.T) *rbacFixture {
	t.Helper()
	store := persistence.NewStore()
	creds := secret.NewStore(nil)
	stub := bank.NewStubProvider(creds)
	deps := app.Deps{
		Payments:    store,
		Tenants:     store,
		Pricing:     store,
		Ledger:      store,
		Processed:   store,
		Bus:         inmemory.NewBus(),
		Bank:        stub,
		Credentials: creds,
		CredWriter:  creds,
		Clock:       system.Clock{},
		IDs:         system.IDProvider{},
	}
	admin := app.NewAdminService(deps)
	tn, err := admin.CreateTenant(context.Background(), "Acme")
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	auth := httpadapter.NewStaticTokenAuthWithRoles(
		map[string]string{rbacTenantToken: tn.ID()},
		map[string]httpadapter.Role{
			rbacAdminToken:    httpadapter.RoleAdmin,
			rbacOperatorToken: httpadapter.RoleOperator,
		},
		rbacWebhookSecret,
	)
	srv := httpadapter.NewServer(httpadapter.Config{
		Charges:     app.NewChargeService(deps),
		Admin:       admin,
		Webhooks:    app.NewWebhookService(deps),
		TenantAuth:  auth,
		AdminAuth:   auth,
		WebhookAuth: auth,
	})
	return &rbacFixture{handler: srv.Router(), tenantID: tn.ID(), creds: creds}
}

// TestAdminRoleMatrix asserts allow/deny per role across the admin write routes
// plus the tenant token and the no-token cases (deny-by-default).
func TestAdminRoleMatrix(t *testing.T) {
	t.Parallel()
	f := newRBACFixture(t)
	credPath := "/admin/tenants/" + f.tenantID + "/bank-credential"

	type call struct {
		method, path string
		body         any
	}
	createTenant := call{http.MethodPost, "/admin/tenants", map[string]any{"name": "New Co"}}
	setPrice := call{http.MethodPost, "/admin/tenants/" + f.tenantID + "/pricing", map[string]any{"endpoint": "pix.create", "price_cents": 10}}
	setCred := call{http.MethodPut, credPath, map[string]any{"client_id": "cid", "secret": "shh"}}

	cases := []struct {
		name  string
		token string
		c     call
		want  int
	}{
		// Full admin: all writes allowed.
		{"admin creates tenant", rbacAdminToken, createTenant, http.StatusCreated},
		{"admin sets price", rbacAdminToken, setPrice, http.StatusOK},
		{"admin sets credential", rbacAdminToken, setCred, http.StatusOK},

		// Operator: authenticated but forbidden from every write (403).
		{"operator denied create", rbacOperatorToken, createTenant, http.StatusForbidden},
		{"operator denied price", rbacOperatorToken, setPrice, http.StatusForbidden},
		{"operator denied credential", rbacOperatorToken, setCred, http.StatusForbidden},

		// Tenant token must never reach the admin plane (401, not 403 — it has no
		// admin identity at all).
		{"tenant token denied create", rbacTenantToken, createTenant, http.StatusUnauthorized},
		{"tenant token denied credential", rbacTenantToken, setCred, http.StatusUnauthorized},

		// No credential at all → 401.
		{"anon denied create", "", createTenant, http.StatusUnauthorized},
		{"anon denied credential", "", setCred, http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := do(t, f.handler, tc.c.method, tc.c.path, tc.token, nil, tc.c.body)
			if rec.Code != tc.want {
				t.Fatalf("%s %s as %q: want %d, got %d (body=%s)", tc.c.method, tc.c.path, tc.token, tc.want, rec.Code, rec.Body.String())
			}
		})
	}
}

// TestSetBankCredentialEndpoint verifies the credential is persisted to the
// secret store and that the response never echoes the secret.
func TestSetBankCredentialEndpoint(t *testing.T) {
	t.Parallel()
	f := newRBACFixture(t)
	const secretVal = "do-not-echo-me"
	path := "/admin/tenants/" + f.tenantID + "/bank-credential"

	rec := do(t, f.handler, http.MethodPut, path, rbacAdminToken, nil,
		map[string]any{"client_id": "cid-9", "secret": secretVal})
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), secretVal) {
		t.Fatalf("response leaked the secret: %s", rec.Body.String())
	}

	got, err := f.creds.GetBankCredential(context.Background(), f.tenantID)
	if err != nil {
		t.Fatalf("read stored credential: %v", err)
	}
	if got.ClientID != "cid-9" || got.Secret != secretVal {
		t.Fatalf("credential not stored: %+v", got)
	}

	// Unknown tenant → 404 (tenant must exist; admin op names the tenant
	// explicitly and the repo stays tenant-scoped).
	rec = do(t, f.handler, http.MethodPut, "/admin/tenants/ghost/bank-credential", rbacAdminToken, nil,
		map[string]any{"client_id": "c", "secret": "s"})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404 for unknown tenant, got %d", rec.Code)
	}

	// Missing secret → 400 (boundary validation).
	rec = do(t, f.handler, http.MethodPut, path, rbacAdminToken, nil,
		map[string]any{"client_id": "cid"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for missing secret, got %d", rec.Code)
	}
}

// TestAuthenticateAdminRoles unit-tests the token→role resolution, including the
// drop of misconfigured (empty/unknown-role) entries.
func TestAuthenticateAdminRoles(t *testing.T) {
	t.Parallel()
	auth := httpadapter.NewStaticTokenAuthWithRoles(nil, map[string]httpadapter.Role{
		"admin1":  httpadapter.RoleAdmin,
		"ops1":    httpadapter.RoleOperator,
		"":        httpadapter.RoleAdmin,   // dropped: empty token
		"bogustk": httpadapter.Role("god"), // dropped: unknown role
	}, "")

	cases := []struct {
		token    string
		wantRole httpadapter.Role
		wantOK   bool
	}{
		{"admin1", httpadapter.RoleAdmin, true},
		{"ops1", httpadapter.RoleOperator, true},
		{"bogustk", "", false},
		{"unknown", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		role, ok := auth.AuthenticateAdmin(tc.token)
		if ok != tc.wantOK || role != tc.wantRole {
			t.Fatalf("AuthenticateAdmin(%q) = (%q,%v), want (%q,%v)", tc.token, role, ok, tc.wantRole, tc.wantOK)
		}
	}
}

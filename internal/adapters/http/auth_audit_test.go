package http_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"

	auditlog "github.com/ia-dev-sindireceita/payment/internal/adapters/audit/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/bank"
	httpadapter "github.com/ia-dev-sindireceita/payment/internal/adapters/http"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/messaging/inmemory"
	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/system"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
)

// wantOperatorID mirrors deriveOperatorID (unexported): SHA-256 of the token,
// first 8 bytes hex-encoded, "op-" prefixed.
func wantOperatorID(token string) string {
	sum := sha256.Sum256([]byte(token))
	return "op-" + hex.EncodeToString(sum[:8])
}

// TestAuthenticateAdminPrincipal verifies the principal carries the role and a
// stable, server-derived operator id that never equals the token.
func TestAuthenticateAdminPrincipal(t *testing.T) {
	t.Parallel()
	auth := httpadapter.NewStaticTokenAuthWithRoles(nil, map[string]httpadapter.Role{
		"adm": httpadapter.RoleAdmin,
		"ops": httpadapter.RoleOperator,
	}, nil)

	p, ok := auth.AuthenticateAdminPrincipal("adm")
	if !ok || p.Role != httpadapter.RoleAdmin {
		t.Fatalf("admin principal: ok=%v role=%q", ok, p.Role)
	}
	if p.OperatorID != wantOperatorID("adm") {
		t.Fatalf("operator id: want %q, got %q", wantOperatorID("adm"), p.OperatorID)
	}
	if p.OperatorID == "adm" {
		t.Fatal("operator id must not equal the token")
	}
	// Stable across calls.
	if p2, _ := auth.AuthenticateAdminPrincipal("adm"); p2.OperatorID != p.OperatorID {
		t.Fatalf("operator id not stable: %q vs %q", p.OperatorID, p2.OperatorID)
	}
	// Operator role resolves too.
	if p, ok := auth.AuthenticateAdminPrincipal("ops"); !ok || p.Role != httpadapter.RoleOperator {
		t.Fatalf("operator principal: ok=%v role=%q", ok, p.Role)
	}
	// Empty and unknown tokens are denied.
	if _, ok := auth.AuthenticateAdminPrincipal(""); ok {
		t.Fatal("empty token must be denied")
	}
	if _, ok := auth.AuthenticateAdminPrincipal("nope"); ok {
		t.Fatal("unknown token must be denied")
	}
}

// TestAdminWriteRecordsAuditWithOperator drives the full router and asserts the
// privileged write is recorded in the audit trail attributed to the operator id
// derived from the admin token (server-side), never the token itself.
func TestAdminWriteRecordsAuditWithOperator(t *testing.T) {
	t.Parallel()
	store := persistence.NewStore()
	creds := secret.NewStore(nil)
	log := auditlog.NewLog()
	deps := app.Deps{
		Payments:    store,
		Tenants:     store,
		Pricing:     store,
		Ledger:      store,
		Processed:   store,
		Bus:         inmemory.NewBus(),
		Bank:        bank.NewStubProvider(creds),
		Credentials: creds,
		CredWriter:  creds,
		Audit:       log,
		Clock:       system.Clock{},
		IDs:         system.IDProvider{},
	}
	admin := app.NewAdminService(deps)
	auth := httpadapter.NewStaticTokenAuth(nil, []string{adminToken}, nil)
	srv := httpadapter.NewServer(httpadapter.Config{
		Charges:     app.NewChargeService(deps),
		Admin:       admin,
		Webhooks:    app.NewWebhookService(deps),
		TenantAuth:  auth,
		AdminAuth:   auth,
		WebhookAuth: auth,
	})
	h := srv.Router()

	// Create a tenant, then write its bank credential — two privileged writes.
	rec := do(t, h, http.MethodPost, "/admin/tenants", adminToken, nil, map[string]any{"name": "Acme"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create tenant: %d", rec.Code)
	}
	var tv struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &tv)

	const secretVal = "live-secret-never-audited"
	rec = do(t, h, http.MethodPut, "/admin/tenants/"+tv.ID+"/bank-credential", adminToken, nil,
		map[string]any{"client_id": "cid", "secret": secretVal})
	if rec.Code != http.StatusOK {
		t.Fatalf("set credential: %d body=%s", rec.Code, rec.Body.String())
	}

	entries := log.Entries()
	if len(entries) != 2 {
		t.Fatalf("want 2 audit entries, got %d", len(entries))
	}
	wantOp := wantOperatorID(adminToken)
	for i, e := range entries {
		if e.OperatorID() != wantOp {
			t.Errorf("entry %d operator: want %q, got %q", i, wantOp, e.OperatorID())
		}
		if e.OperatorID() == adminToken {
			t.Errorf("entry %d leaked the admin token as operator id", i)
		}
	}
	if entries[0].Action() != audit.ActionCreateTenant || entries[1].Action() != audit.ActionSetBankCredential {
		t.Fatalf("unexpected actions: %q, %q", entries[0].Action(), entries[1].Action())
	}
	// The credential audit entry must name the tenant but not the secret.
	credEntry := entries[1]
	if credEntry.TenantID() != tv.ID {
		t.Fatalf("cred entry tenant: want %q, got %q", tv.ID, credEntry.TenantID())
	}
}

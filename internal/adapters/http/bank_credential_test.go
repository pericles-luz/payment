package http_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// TestSetBankCredentialAcceptsBank covers the multi-bank admin write path: the
// PUT endpoint accepts an explicit `bank` slug, persists the credential under the
// (tenant, bank) pair, and echoes the resolved bank without the secret (SIN-66015).
func TestSetBankCredentialAcceptsBank(t *testing.T) {
	t.Parallel()
	f := newRBACFixture(t)
	path := "/admin/tenants/" + f.tenantID + "/bank-credential"
	const secretVal = "do-not-echo-me"

	rec := do(t, f.handler, http.MethodPut, path, rbacAdminToken, nil,
		map[string]any{"bank": "c6", "client_id": "cid-bank", "secret": secretVal})
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), secretVal) {
		t.Fatalf("response leaked the secret: %s", rec.Body.String())
	}

	// The response echoes the resolved bank (non-secret) so the UX can confirm it.
	var view struct {
		TenantID string `json:"tenant_id"`
		Bank     string `json:"bank"`
		ClientID string `json:"client_id"`
		Status   string `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode view: %v", err)
	}
	if view.Bank != ports.BankIDC6 {
		t.Fatalf("want bank %q in response, got %q", ports.BankIDC6, view.Bank)
	}

	// The credential is stored under the explicit bank.
	got, err := f.creds.GetBankCredential(context.Background(), f.tenantID, ports.BankIDC6)
	if err != nil {
		t.Fatalf("read stored credential: %v", err)
	}
	if got.ClientID != "cid-bank" || got.Secret != secretVal {
		t.Fatalf("credential not stored under (tenant, c6): %+v", got)
	}
}

// TestSetBankCredentialDefaultsBank pins retro-compat: a legacy call with no
// `bank` field still succeeds and writes under the default bank (c6).
func TestSetBankCredentialDefaultsBank(t *testing.T) {
	t.Parallel()
	f := newRBACFixture(t)
	path := "/admin/tenants/" + f.tenantID + "/bank-credential"

	rec := do(t, f.handler, http.MethodPut, path, rbacAdminToken, nil,
		map[string]any{"client_id": "cid-legacy", "secret": "shh"})
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", rec.Code, rec.Body.String())
	}

	// Stored under the default bank — reachable both via the explicit c6 slug and
	// via the empty (default) selector.
	for _, bank := range []string{ports.BankIDC6, ""} {
		got, err := f.creds.GetBankCredential(context.Background(), f.tenantID, bank)
		if err != nil {
			t.Fatalf("read stored credential (bank=%q): %v", bank, err)
		}
		if got.ClientID != "cid-legacy" {
			t.Fatalf("default-bank credential not stored (bank=%q): %+v", bank, got)
		}
	}
}

// TestSetBankCredentialRejectsUnknownBank pins deny-by-default: a bank slug with
// no wired adapter is rejected at the boundary with a 400 and nothing is written.
func TestSetBankCredentialRejectsUnknownBank(t *testing.T) {
	t.Parallel()
	f := newRBACFixture(t)
	path := "/admin/tenants/" + f.tenantID + "/bank-credential"

	rec := do(t, f.handler, http.MethodPut, path, rbacAdminToken, nil,
		map[string]any{"bank": "nubank", "client_id": "cid", "secret": "shh"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for unknown bank, got %d (%s)", rec.Code, rec.Body.String())
	}
	// No credential was written for the rejected bank.
	if _, err := f.creds.GetBankCredential(context.Background(), f.tenantID, "nubank"); err == nil {
		t.Fatalf("unknown-bank credential must not be stored")
	}
}

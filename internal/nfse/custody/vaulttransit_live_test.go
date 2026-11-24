package custody

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"
)

// TestLiveVaultTwoTenantsImportAndSign runs the BYOK import and signing path
// against a REAL Vault, under FiscalSignerVaultPolicy, for TWO tenants through
// ONE login — the case the original templated policy could not serve and that
// no stub-based test caught. It also proves the policy still denies key export
// and every reconfiguration except deletion_allowed, and that a rotation
// crypto-shreds the replaced key through the app token.
//
// Skipped unless NFSE_VAULT_TEST_ADDR and NFSE_VAULT_TEST_ROOT_TOKEN point at a
// throwaway Vault (e.g. `docker run -p 8200:8200 -e VAULT_DEV_ROOT_TOKEN_ID=root
// hashicorp/vault`). It enables transit, writes the policy and mints a token
// carrying only that policy.
func TestLiveVaultTwoTenantsImportAndSign(t *testing.T) {
	addr := os.Getenv("NFSE_VAULT_TEST_ADDR")
	root := os.Getenv("NFSE_VAULT_TEST_ROOT_TOKEN")
	if addr == "" || root == "" {
		t.Skip("NFSE_VAULT_TEST_ADDR / NFSE_VAULT_TEST_ROOT_TOKEN not set; skipping live Vault suite")
	}
	ctx := context.Background()

	vaultCall(t, addr, root, http.MethodPost, "sys/mounts/transit", map[string]any{"type": "transit"}, 0) // 400 if already mounted
	vaultCall(t, addr, root, http.MethodPut, "sys/policies/acl/fiscalsigner", map[string]any{"policy": FiscalSignerVaultPolicy}, http.StatusNoContent)
	var tok struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	vaultJSON(t, addr, root, http.MethodPost, "auth/token/create", map[string]any{
		"policies": []string{"fiscalsigner"}, "no_default_policy": true, "ttl": "10m",
	}, &tok)
	appToken := tok.Auth.ClientToken

	certs := NewMemoryCertStore()
	v, err := NewVaultTransitSigner(VaultTransitConfig{Address: addr, Certs: certs, Token: appToken})
	if err != nil {
		t.Fatal(err)
	}

	suffix := time.Now().Format("150405")
	tenants := []struct{ companyID, cnpj string }{
		{"tenantA" + suffix + "_47064135000184", "47064135000184"},
		{"tenantB" + suffix + "_11222333000181", "11222333000181"},
	}
	for _, tn := range tenants {
		key, leaf := newVaultTestLeaf(t, tn.companyID, tn.cnpj, time.Hour, time.Now())
		if err := v.ImportA1Key(ctx, tn.companyID, leaf, key); err != nil {
			t.Fatalf("import %s: %v", tn.companyID, err)
		}
		if err := v.ImportA1Key(ctx, tn.companyID, leaf, key); err != nil {
			t.Fatalf("idempotent re-import %s: %v", tn.companyID, err)
		}
		if err := certs.PutA1(ctx, tn.companyID, []*x509.Certificate{leaf}, A1MetaFromLeaf(leaf, tn.cnpj)); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256([]byte("DPS " + tn.companyID))
		sig, err := v.SignDigest(ctx, tn.companyID, SerialHex(leaf), digest[:])
		if err != nil {
			t.Fatalf("sign %s through the shared login: %v", tn.companyID, err)
		}
		if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
			t.Errorf("signature for %s does not verify with its own certificate: %v", tn.companyID, err)
		}

		name := v.keyName(tn.companyID, SerialHex(leaf))
		// The policy must deny everything that could get the key out or
		// change its custody guarantees.
		vaultCall(t, addr, appToken, http.MethodGet, "transit/export/signing-key/"+name, nil, http.StatusForbidden)
		vaultCall(t, addr, appToken, http.MethodPost, "transit/keys/"+name+"/config", map[string]any{"exportable": true}, http.StatusForbidden)
		vaultCall(t, addr, appToken, http.MethodPost, "transit/keys/"+name+"/rotate", nil, http.StatusForbidden)
		vaultCall(t, addr, appToken, http.MethodPost, "transit/keys/"+name+"/import_version", map[string]any{"ciphertext": "x"}, http.StatusForbidden)
		// config is open ONLY for deletion_allowed: smuggling exportable next
		// to it must still be refused.
		vaultCall(t, addr, appToken, http.MethodPost, "transit/keys/"+name+"/config", map[string]any{"deletion_allowed": true, "exportable": true}, http.StatusForbidden)
		vaultCall(t, addr, appToken, http.MethodPost, "transit/keys/"+name+"/config", map[string]any{"allow_plaintext_backup": true}, http.StatusForbidden)
	}

	// Rotation: tenant A renews its certificate. The new key is imported, the
	// old one is crypto-shredded through the app token, and the old serial can
	// no longer sign.
	tn := tenants[0]
	oldKey, oldLeaf := newVaultTestLeaf(t, tn.companyID+"old", tn.cnpj, time.Hour, time.Now())
	if err := v.ImportA1Key(ctx, tn.companyID, oldLeaf, oldKey); err != nil {
		t.Fatalf("import old cert: %v", err)
	}
	if err := certs.PutA1(ctx, tn.companyID, []*x509.Certificate{oldLeaf}, A1MetaFromLeaf(oldLeaf, tn.cnpj)); err != nil {
		t.Fatal(err)
	}
	if err := v.RetireA1Key(ctx, tn.companyID, SerialHex(oldLeaf)); err != nil {
		t.Fatalf("retire old key through the app token: %v", err)
	}
	vaultCall(t, addr, root, http.MethodGet, "transit/keys/"+v.keyName(tn.companyID, SerialHex(oldLeaf)), nil, http.StatusNotFound)
	digest := sha256.Sum256([]byte("after rotation"))
	if _, err := v.SignDigest(ctx, tn.companyID, SerialHex(oldLeaf), digest[:]); err == nil {
		t.Error("the retired key still signs")
	}
	if err := v.RetireA1Key(ctx, tn.companyID, SerialHex(oldLeaf)); err != nil {
		t.Errorf("retiring an already-retired key must be idempotent: %v", err)
	}
}

func vaultCall(t *testing.T, addr, token, method, path string, body any, wantStatus int) {
	t.Helper()
	res := vaultDo(t, addr, token, method, path, body)
	res.Body.Close()
	if wantStatus != 0 && res.StatusCode != wantStatus {
		t.Errorf("%s %s = HTTP %d, want %d", method, path, res.StatusCode, wantStatus)
	}
}

func vaultJSON(t *testing.T, addr, token, method, path string, body, out any) {
	t.Helper()
	res := vaultDo(t, addr, token, method, path, body)
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		t.Fatalf("%s %s = HTTP %d", method, path, res.StatusCode)
	}
	if err := json.NewDecoder(res.Body).Decode(out); err != nil {
		t.Fatal(err)
	}
}

func vaultDo(t *testing.T, addr, token, method, path string, body any) *http.Response {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req, err := http.NewRequest(method, addr+"/v1/"+path, &buf)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Vault-Token", token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

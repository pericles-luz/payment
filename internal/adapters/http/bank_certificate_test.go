package http_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/bank"
	httpadapter "github.com/ia-dev-sindireceita/payment/internal/adapters/http"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/messaging/inmemory"
	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/system"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

type certFixture struct {
	handler  http.Handler
	tenantID string
	certs    *secret.CertStore
}

// newCertFixture wires a server with the admin token plus the bank-certificate
// write path so the PUT endpoint can be exercised end-to-end. The clock is the
// real system clock, so fixtures use a validity window around now.
func newCertFixture(t *testing.T) *certFixture {
	t.Helper()
	store := persistence.NewStore()
	creds := secret.NewStore(nil)
	certs := secret.NewCertStore()
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
		CertWriter:  certs,
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
		map[string]httpadapter.Role{rbacAdminToken: httpadapter.RoleAdmin},
		nil,
	)
	srv := httpadapter.NewServer(httpadapter.Config{
		Charges:     app.NewChargeService(deps),
		Admin:       admin,
		Webhooks:    app.NewWebhookService(deps),
		TenantAuth:  auth,
		AdminAuth:   auth,
		WebhookAuth: auth,
	})
	return &certFixture{handler: srv.Router(), tenantID: tn.ID(), certs: certs}
}

func httpCertKeyPEM(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(123),
		Subject:      pkix.Name{CommonName: "http.mtls.example"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM
}

// TestSetBankCertificateEndpointHappy covers the admin write path: PUT accepts the
// cert/key, persists under (tenant, bank), and echoes ONLY public metadata — the
// private key never appears in the response.
func TestSetBankCertificateEndpointHappy(t *testing.T) {
	t.Parallel()
	f := newCertFixture(t)
	path := "/admin/tenants/" + f.tenantID + "/bank-certificate"
	certPEM, keyPEM := httpCertKeyPEM(t)

	rec := do(t, f.handler, http.MethodPut, path, rbacAdminToken, nil,
		map[string]any{"bank": "c6", "cert_pem": certPEM, "key_pem": keyPEM})
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	// The private key must never be echoed back.
	keyBody := strings.TrimSpace(strings.Split(keyPEM, "-----")[2])
	if keyBody != "" && strings.Contains(rec.Body.String(), keyBody) {
		t.Fatalf("response leaked the private key: %s", rec.Body.String())
	}

	var view struct {
		Bank              string `json:"bank"`
		SubjectCN         string `json:"subject_cn"`
		FingerprintSHA256 string `json:"fingerprint_sha256"`
		NotAfter          string `json:"not_after"`
		Status            string `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode view: %v", err)
	}
	if view.Bank != ports.BankIDC6 || view.SubjectCN != "http.mtls.example" {
		t.Fatalf("unexpected view: %+v", view)
	}
	if view.FingerprintSHA256 == "" || view.NotAfter == "" || view.Status != "ok" {
		t.Fatalf("public metadata missing in view: %+v", view)
	}
	if _, err := f.certs.GetBankCertificateMeta(context.Background(), f.tenantID, ports.BankIDC6); err != nil {
		t.Fatalf("certificate not stored: %v", err)
	}
}

// TestSetBankCertificateEndpointRejectsUnknownBank pins deny-by-default at the
// boundary: an unknown bank is a 400 and nothing is written.
func TestSetBankCertificateEndpointRejectsUnknownBank(t *testing.T) {
	t.Parallel()
	f := newCertFixture(t)
	path := "/admin/tenants/" + f.tenantID + "/bank-certificate"
	certPEM, keyPEM := httpCertKeyPEM(t)

	rec := do(t, f.handler, http.MethodPut, path, rbacAdminToken, nil,
		map[string]any{"bank": "nubank", "cert_pem": certPEM, "key_pem": keyPEM})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d (%s)", rec.Code, rec.Body.String())
	}
}

// TestSetBankCertificateEndpointRejectsMalformed pins that a malformed certificate
// surfaces as a 400 (named validation error), never a 500.
func TestSetBankCertificateEndpointRejectsMalformed(t *testing.T) {
	t.Parallel()
	f := newCertFixture(t)
	path := "/admin/tenants/" + f.tenantID + "/bank-certificate"
	_, keyPEM := httpCertKeyPEM(t)

	rec := do(t, f.handler, http.MethodPut, path, rbacAdminToken, nil,
		map[string]any{"bank": "c6", "cert_pem": "not-a-cert", "key_pem": keyPEM})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for malformed cert, got %d (%s)", rec.Code, rec.Body.String())
	}
}

// TestSetBankCertificateEndpointRejectsUnknownField pins DisallowUnknownFields:
// an unexpected JSON field is a 400 (anti mass-assignment).
func TestSetBankCertificateEndpointRejectsUnknownField(t *testing.T) {
	t.Parallel()
	f := newCertFixture(t)
	path := "/admin/tenants/" + f.tenantID + "/bank-certificate"
	certPEM, keyPEM := httpCertKeyPEM(t)

	rec := do(t, f.handler, http.MethodPut, path, rbacAdminToken, nil,
		map[string]any{"bank": "c6", "cert_pem": certPEM, "key_pem": keyPEM, "extra": "x"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for unknown field, got %d (%s)", rec.Code, rec.Body.String())
	}
}

// TestSetBankCertificateEndpointRequiresAdmin pins deny-by-default authz: an
// operator (read-only) token cannot write a certificate.
func TestSetBankCertificateEndpointRequiresAdmin(t *testing.T) {
	t.Parallel()
	f := newCertFixture(t)
	path := "/admin/tenants/" + f.tenantID + "/bank-certificate"
	certPEM, keyPEM := httpCertKeyPEM(t)

	rec := do(t, f.handler, http.MethodPut, path, rbacTenantToken, nil,
		map[string]any{"bank": "c6", "cert_pem": certPEM, "key_pem": keyPEM})
	if rec.Code == http.StatusOK {
		t.Fatalf("non-admin token must not write a certificate, got 200")
	}
}

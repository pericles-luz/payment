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

	auditlog "github.com/ia-dev-sindireceita/payment/internal/adapters/audit/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/bank"
	httpadapter "github.com/ia-dev-sindireceita/payment/internal/adapters/http"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/messaging/inmemory"
	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/system"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// selfServeCertFixture wires a tenant-plane server with the self-serve certificate
// intake enabled, a real certificate store and a real (in-memory) audit log, plus a
// second tenant to prove cross-tenant isolation. It is the certificate sibling of
// selfServeFixture; tokenA/tokenB authenticate the two tenants and there is NO
// admin-addressable selector in the self-serve contract.
type selfServeCertFixture struct {
	handler          http.Handler
	tenantA, tenantB string
	tokenA, tokenB   string
	certs            *secret.CertStore
	audit            *auditlog.Log
}

const (
	selfCertTokenA = "self-cert-tok-a"
	selfCertTokenB = "self-cert-tok-b"
)

// newSelfServeCertFixtureFlag builds the fixture with the intake flag set as given,
// so the same wiring covers both the enabled behaviour and the flag-off inert case.
func newSelfServeCertFixtureFlag(t *testing.T, enabled bool) *selfServeCertFixture {
	t.Helper()
	store := persistence.NewStore()
	creds := secret.NewStore(nil)
	certs := secret.NewCertStore()
	stub := bank.NewStubProvider(creds)
	log := auditlog.NewLog()
	deps := app.Deps{
		Payments: store, Tenants: store, Pricing: store, Ledger: store, Processed: store,
		Bus: inmemory.NewBus(), Bank: stub, Credentials: creds, CredWriter: creds,
		CertWriter: certs, Audit: log, Clock: system.Clock{}, IDs: system.IDProvider{},
	}
	admin := app.NewAdminService(deps)
	mk := func(name string) string {
		tn, err := admin.CreateTenant(context.Background(), name)
		if err != nil {
			t.Fatalf("seed tenant %s: %v", name, err)
		}
		return tn.ID()
	}
	tenantA, tenantB := mk("Acme"), mk("Globex")
	auth := httpadapter.NewStaticTokenAuth(
		map[string]string{selfCertTokenA: tenantA, selfCertTokenB: tenantB},
		[]string{adminToken}, nil)
	srv := httpadapter.NewServer(httpadapter.Config{
		Charges:             app.NewChargeService(deps),
		Admin:               admin,
		Webhooks:            app.NewWebhookService(deps),
		TenantAuth:          auth,
		AdminAuth:           auth,
		WebhookAuth:         auth,
		SelfServeCredIntake: enabled,
	})
	return &selfServeCertFixture{
		handler: srv.Router(), tenantA: tenantA, tenantB: tenantB,
		tokenA: selfCertTokenA, tokenB: selfCertTokenB, certs: certs, audit: log,
	}
}

func newSelfServeCertFixture(t *testing.T) *selfServeCertFixture {
	return newSelfServeCertFixtureFlag(t, true)
}

const selfServeCertPath = "/v1/bank-certificate"

// selfCertPEM builds a self-signed leaf cert + matching EC key (PEM) with the given
// validity window, so a test can pin the expired / valid cases against the real
// system clock the fixture uses.
func selfCertPEM(t *testing.T, cn string, notBefore, notAfter time.Time) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(77),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
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

// validSelfCert returns a cert/key valid around now (the fixture uses the system
// clock), plus the raw base64 body of the private key so a test can assert it never
// leaks into a response or audit trail.
func validSelfCert(t *testing.T) (certPEM, keyPEM, keyBody string) {
	t.Helper()
	now := time.Now()
	certPEM, keyPEM = selfCertPEM(t, "selfserve.mtls.example", now.Add(-time.Hour), now.Add(24*time.Hour))
	keyBody = strings.TrimSpace(strings.Split(keyPEM, "-----")[2])
	return certPEM, keyPEM, keyBody
}

// TestSelfServeCertWritesOwnTenant is the happy path: a tenant PUTs its own
// certificate, gets 200 with a key-free public-metadata view, and the cert lands
// under (its tenant, c6) — the tenant coming from the token, not any request field.
func TestSelfServeCertWritesOwnTenant(t *testing.T) {
	t.Parallel()
	f := newSelfServeCertFixture(t)
	certPEM, keyPEM, keyBody := validSelfCert(t)

	rec := do(t, f.handler, http.MethodPut, selfServeCertPath, f.tokenA, nil,
		map[string]any{"bank": "c6", "cert_pem": certPEM, "key_pem": keyPEM})
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if keyBody != "" && strings.Contains(rec.Body.String(), keyBody) {
		t.Fatalf("response leaked the private key: %s", rec.Body.String())
	}
	var view struct {
		TenantID          string `json:"tenant_id"`
		Bank              string `json:"bank"`
		SubjectCN         string `json:"subject_cn"`
		FingerprintSHA256 string `json:"fingerprint_sha256"`
		NotAfter          string `json:"not_after"`
		Status            string `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode view: %v", err)
	}
	if view.TenantID != f.tenantA || view.Bank != ports.BankIDC6 || view.Status != "ok" {
		t.Fatalf("unexpected view: %+v", view)
	}
	if view.SubjectCN != "selfserve.mtls.example" || view.FingerprintSHA256 == "" || view.NotAfter == "" {
		t.Fatalf("public metadata missing in view: %+v", view)
	}
	if _, err := f.certs.GetBankCertificateMeta(context.Background(), f.tenantA, ports.BankIDC6); err != nil {
		t.Fatalf("certificate not stored under (A, c6): %v", err)
	}
	// The write emitted a certificate.set audit entry stamped origin=self-serve.
	entries := f.audit.Entries()
	last := entries[len(entries)-1]
	if last.Action() != audit.ActionSetBankCertificate || last.Origin() != audit.OriginSelfServe {
		t.Fatalf("audit entry = action %q origin %q, want certificate.set/self-serve", last.Action(), last.Origin())
	}
	if last.TenantID() != f.tenantA {
		t.Fatalf("audit tenant = %q, want %q", last.TenantID(), f.tenantA)
	}
}

// TestSelfServeCertDefaultsBankToC6 pins that an empty bank resolves to c6
// (retro-compat with the single-bank default), matching the admin path.
func TestSelfServeCertDefaultsBankToC6(t *testing.T) {
	t.Parallel()
	f := newSelfServeCertFixture(t)
	certPEM, keyPEM, _ := validSelfCert(t)
	rec := do(t, f.handler, http.MethodPut, selfServeCertPath, f.tokenA, nil,
		map[string]any{"cert_pem": certPEM, "key_pem": keyPEM})
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if _, err := f.certs.GetBankCertificateMeta(context.Background(), f.tenantA, ports.BankIDC6); err != nil {
		t.Fatalf("default-bank certificate not stored: %v", err)
	}
}

// TestSelfServeCertRejectsNonC6 pins the Q4 dedicated allow-list: a bank outside
// {c6} is rejected with 400 and NOTHING is written or echoed.
func TestSelfServeCertRejectsNonC6(t *testing.T) {
	t.Parallel()
	f := newSelfServeCertFixture(t)
	certPEM, keyPEM, _ := validSelfCert(t)
	rec := do(t, f.handler, http.MethodPut, selfServeCertPath, f.tokenA, nil,
		map[string]any{"bank": "nubank", "cert_pem": certPEM, "key_pem": keyPEM})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for non-c6 bank, got %d (%s)", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); strings.Contains(body, "nubank") {
		t.Fatalf("400 response echoed the input bank: %s", body)
	}
	if _, err := f.certs.GetBankCertificateMeta(context.Background(), f.tenantA, "nubank"); err == nil {
		t.Fatal("non-c6 certificate must not be stored")
	}
}

// TestSelfServeCertRejectsExpired pins that a certificate already expired at upload
// (NotAfter < now) is rejected with 400 and nothing is written — the boundary
// validates the material before it reaches the vault.
func TestSelfServeCertRejectsExpired(t *testing.T) {
	t.Parallel()
	f := newSelfServeCertFixture(t)
	now := time.Now()
	certPEM, keyPEM := selfCertPEM(t, "expired.mtls.example", now.Add(-48*time.Hour), now.Add(-time.Hour))
	rec := do(t, f.handler, http.MethodPut, selfServeCertPath, f.tokenA, nil,
		map[string]any{"bank": "c6", "cert_pem": certPEM, "key_pem": keyPEM})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for expired cert, got %d (%s)", rec.Code, rec.Body.String())
	}
	if _, err := f.certs.GetBankCertificateMeta(context.Background(), f.tenantA, ports.BankIDC6); err == nil {
		t.Fatal("expired certificate must not be stored")
	}
}

// TestSelfServeCertRejectsMismatchedKey pins that a cert whose private key does not
// match is rejected with 400 (X509KeyPair mismatch), never a 500, and not stored.
func TestSelfServeCertRejectsMismatchedKey(t *testing.T) {
	t.Parallel()
	f := newSelfServeCertFixture(t)
	certPEM, _, _ := validSelfCert(t)
	_, otherKey, _ := validSelfCert(t) // key from a different pair
	rec := do(t, f.handler, http.MethodPut, selfServeCertPath, f.tokenA, nil,
		map[string]any{"bank": "c6", "cert_pem": certPEM, "key_pem": otherKey})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for mismatched key, got %d (%s)", rec.Code, rec.Body.String())
	}
	if _, err := f.certs.GetBankCertificateMeta(context.Background(), f.tenantA, ports.BankIDC6); err == nil {
		t.Fatal("mismatched-key certificate must not be stored")
	}
}

// TestSelfServeCertRequiresAuth pins deny-by-default: no token → 401, and an admin
// token (wrong audience for the tenant plane) → 401. The certificate intake is a
// tenant-plane self-service, never reachable without a tenant identity.
func TestSelfServeCertRequiresAuth(t *testing.T) {
	t.Parallel()
	f := newSelfServeCertFixture(t)
	certPEM, keyPEM, _ := validSelfCert(t)
	body := map[string]any{"bank": "c6", "cert_pem": certPEM, "key_pem": keyPEM}
	if rec := do(t, f.handler, http.MethodPut, selfServeCertPath, "", nil, body); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: want 401, got %d", rec.Code)
	}
	if rec := do(t, f.handler, http.MethodPut, selfServeCertPath, adminToken, nil, body); rec.Code != http.StatusUnauthorized {
		t.Fatalf("admin token on tenant plane: want 401, got %d", rec.Code)
	}
}

// TestSelfServeCertCrossTenantIsolation is the server-enforced A01-by-construction
// regression: tenant A's token can only ever write (A, c6). There is NO parameter
// in the contract to address tenant B, so a write with A's token leaves B's
// certificate absent — the whole broken-access-control class is designed out.
func TestSelfServeCertCrossTenantIsolation(t *testing.T) {
	t.Parallel()
	f := newSelfServeCertFixture(t)
	certPEM, keyPEM, _ := validSelfCert(t)

	rec := do(t, f.handler, http.MethodPut, selfServeCertPath, f.tokenA, nil,
		map[string]any{"bank": "c6", "cert_pem": certPEM, "key_pem": keyPEM})
	if rec.Code != http.StatusOK {
		t.Fatalf("A write: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if _, err := f.certs.GetBankCertificateMeta(context.Background(), f.tenantA, ports.BankIDC6); err != nil {
		t.Fatalf("A certificate missing: %v", err)
	}
	// B's certificate was NOT touched by A's request (no selector exists to address B).
	if _, err := f.certs.GetBankCertificateMeta(context.Background(), f.tenantB, ports.BankIDC6); err == nil {
		t.Fatal("isolation breach: A's write created a certificate for B")
	}
	entries := f.audit.Entries()
	last := entries[len(entries)-1]
	if last.TenantID() != f.tenantA {
		t.Fatalf("audit attributed write to %q, want A (%q)", last.TenantID(), f.tenantA)
	}
}

// TestSelfServeCertCreateEqualsRotate is the no-oracle / idempotency assertion: the
// response to a CREATE and to a subsequent ROTATE (re-upload) with the same cert/key
// is byte-identical (derived purely from the public certificate) and never leaks the
// private key.
func TestSelfServeCertCreateEqualsRotate(t *testing.T) {
	t.Parallel()
	f := newSelfServeCertFixture(t)
	certPEM, keyPEM, keyBody := validSelfCert(t)
	body := map[string]any{"bank": "c6", "cert_pem": certPEM, "key_pem": keyPEM}

	create := do(t, f.handler, http.MethodPut, selfServeCertPath, f.tokenA, nil, body)
	rotate := do(t, f.handler, http.MethodPut, selfServeCertPath, f.tokenA, nil, body)
	if create.Code != http.StatusOK || rotate.Code != http.StatusOK {
		t.Fatalf("create=%d rotate=%d, want both 200", create.Code, rotate.Code)
	}
	if create.Body.String() != rotate.Body.String() {
		t.Fatalf("create/rotate responses differ (oracle):\n create=%q\n rotate=%q", create.Body.String(), rotate.Body.String())
	}
	if keyBody != "" && strings.Contains(rotate.Body.String(), keyBody) {
		t.Fatalf("response leaked the private key: %s", rotate.Body.String())
	}
}

// TestSelfServeCertRateLimited pins the dedicated inbound limiter: a flood past the
// small burst trips 429 with a Retry-After header. The bucket is per tenant and on a
// SEPARATE namespace from the credential intake, so it is the cert intake's own.
func TestSelfServeCertRateLimited(t *testing.T) {
	t.Parallel()
	f := newSelfServeCertFixture(t)
	certPEM, keyPEM, _ := validSelfCert(t)
	body := map[string]any{"bank": "c6", "cert_pem": certPEM, "key_pem": keyPEM}
	limitedAt := -1
	for i := 0; i < 20; i++ {
		rec := do(t, f.handler, http.MethodPut, selfServeCertPath, f.tokenA, nil, body)
		if i == 0 && rec.Code == http.StatusTooManyRequests {
			t.Fatal("first request must not be rate-limited")
		}
		if rec.Code == http.StatusTooManyRequests {
			if ra := rec.Header().Get("Retry-After"); ra == "" {
				t.Fatalf("429 missing Retry-After header")
			}
			limitedAt = i
			break
		}
	}
	if limitedAt < 1 {
		t.Fatalf("expected a 429 within the burst, tripped at %d", limitedAt)
	}
}

// TestSelfServeCertFlagOffInert pins the rollback path: with the flag off the route
// is not registered, so even a valid tenant token gets 404 — the feature is fully
// inert and nothing is written.
func TestSelfServeCertFlagOffInert(t *testing.T) {
	t.Parallel()
	f := newSelfServeCertFixtureFlag(t, false)
	certPEM, keyPEM, _ := validSelfCert(t)
	rec := do(t, f.handler, http.MethodPut, selfServeCertPath, f.tokenA, nil,
		map[string]any{"bank": "c6", "cert_pem": certPEM, "key_pem": keyPEM})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("flag off: want 404 (route absent), got %d (%s)", rec.Code, rec.Body.String())
	}
	if _, err := f.certs.GetBankCertificateMeta(context.Background(), f.tenantA, ports.BankIDC6); err == nil {
		t.Fatal("flag off must write nothing")
	}
}

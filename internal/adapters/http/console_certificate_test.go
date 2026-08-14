package http_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// genCertKeyPEM builds a self-signed leaf cert + matching EC key (PEM) valid in the
// given window. The console fixture's clock is fixed at Unix(1000), so a window that
// straddles it yields a "valid" certificate.
func genCertKeyPEM(t *testing.T, cn string, notBefore, notAfter time.Time) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
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

// certUploadFields names the cert/key file parts to include in a multipart upload.
// A nil value omits the field entirely (to exercise the missing-file path).
type certUploadFields struct {
	cert *string
	key  *string
}

// consoleCertPost submits a multipart certificate upload with CSRF attached.
func consoleCertPost(t *testing.T, h http.Handler, path, token string, f certUploadFields, csrf *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if csrf != nil {
		_ = mw.WriteField("csrf_token", csrf.Value)
	}
	writeFile := func(field string, content *string) {
		if content == nil {
			return
		}
		fw, err := mw.CreateFormFile(field, field+".pem")
		if err != nil {
			t.Fatalf("create form file: %v", err)
		}
		if _, err := fw.Write([]byte(*content)); err != nil {
			t.Fatalf("write part: %v", err)
		}
	}
	writeFile("cert_pem", f.cert)
	writeFile("key_pem", f.key)
	if err := mw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, path, &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if csrf != nil {
		req.AddCookie(csrf)
		req.Header.Set("X-CSRF-Token", csrf.Value)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestConsoleCertUploadHappy(t *testing.T) {
	t.Parallel()
	f := newConsoleFixture(t)
	csrf := csrfToken(t, f.handler, adminToken)
	certPEM, keyPEM := genCertKeyPEM(t, "mtls.t1", time.Unix(0, 0), time.Unix(1000, 0).Add(365*24*time.Hour))

	rec := consoleCertPost(t, f.handler, "/console/tenants/t1/banks/c6/certificate", adminToken,
		certUploadFields{cert: &certPEM, key: &keyPEM}, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("upload = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"Certificado salvo", "mtls.t1", "Válido", "Certificado salvo.", "cert-status"} {
		if !strings.Contains(body, want) {
			t.Fatalf("response missing %q: %s", want, body)
		}
	}
	// The private key must never appear in the rendered response.
	keyBody := strings.TrimSpace(strings.Split(keyPEM, "-----")[2])
	if keyBody != "" && strings.Contains(body, keyBody) {
		t.Fatalf("private key leaked into response")
	}
	// Persisted under (t1, c6).
	if _, err := f.certs.GetBankCertificateMeta(context.Background(), "t1", ports.BankIDC6); err != nil {
		t.Fatalf("certificate not stored: %v", err)
	}
}

func TestConsoleCertUploadMissingFiles(t *testing.T) {
	t.Parallel()
	f := newConsoleFixture(t)
	csrf := csrfToken(t, f.handler, adminToken)
	certPEM, keyPEM := genCertKeyPEM(t, "cn", time.Unix(0, 0), time.Unix(1000, 0).Add(time.Hour))

	// Missing key file → inline key_pem error, 422.
	rec := consoleCertPost(t, f.handler, "/console/tenants/t1/banks/c6/certificate", adminToken,
		certUploadFields{cert: &certPEM}, csrf)
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "chave privada") {
		t.Fatalf("missing key = %d: %s", rec.Code, rec.Body.String())
	}
	// Missing cert file → inline cert_pem error, 422.
	rec = consoleCertPost(t, f.handler, "/console/tenants/t1/banks/c6/certificate", adminToken,
		certUploadFields{key: &keyPEM}, csrf)
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "certificado") {
		t.Fatalf("missing cert = %d: %s", rec.Code, rec.Body.String())
	}
}

func TestConsoleCertUploadInvalidPEM(t *testing.T) {
	t.Parallel()
	f := newConsoleFixture(t)
	csrf := csrfToken(t, f.handler, adminToken)
	_, keyPEM := genCertKeyPEM(t, "cn", time.Unix(0, 0), time.Unix(1000, 0).Add(time.Hour))
	garbage := "not a pem"

	rec := consoleCertPost(t, f.handler, "/console/tenants/t1/banks/c6/certificate", adminToken,
		certUploadFields{cert: &garbage, key: &keyPEM}, csrf)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid PEM = %d, want 422: %s", rec.Code, rec.Body.String())
	}
	// Field-level inline error on the certificate input.
	if !strings.Contains(rec.Body.String(), `id="e-cert"`) {
		t.Fatalf("expected inline cert error: %s", rec.Body.String())
	}
}

func TestConsoleCertUploadExpiredRejected(t *testing.T) {
	t.Parallel()
	f := newConsoleFixture(t)
	csrf := csrfToken(t, f.handler, adminToken)
	// NotAfter before the fixture clock (Unix 1000) → expired at upload.
	certPEM, keyPEM := genCertKeyPEM(t, "old", time.Unix(0, 0), time.Unix(500, 0))

	rec := consoleCertPost(t, f.handler, "/console/tenants/t1/banks/c6/certificate", adminToken,
		certUploadFields{cert: &certPEM, key: &keyPEM}, csrf)
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "expirado") {
		t.Fatalf("expired upload = %d: %s", rec.Code, rec.Body.String())
	}
}

func TestConsoleCertUploadOversize(t *testing.T) {
	t.Parallel()
	f := newConsoleFixture(t)
	csrf := csrfToken(t, f.handler, adminToken)
	huge := strings.Repeat("A", (256<<10)+1024)
	small := "x"

	rec := consoleCertPost(t, f.handler, "/console/tenants/t1/banks/c6/certificate", adminToken,
		certUploadFields{cert: &huge, key: &small}, csrf)
	if rec.Code != http.StatusRequestEntityTooLarge || !strings.Contains(rec.Body.String(), "muito grande") {
		t.Fatalf("oversize = %d, want 413: %s", rec.Code, rec.Body.String())
	}
}

func TestConsoleCertUploadUnknownBank(t *testing.T) {
	t.Parallel()
	f := newConsoleFixture(t)
	csrf := csrfToken(t, f.handler, adminToken)
	certPEM, keyPEM := genCertKeyPEM(t, "cn", time.Unix(0, 0), time.Unix(1000, 0).Add(time.Hour))

	rec := consoleCertPost(t, f.handler, "/console/tenants/t1/banks/itau/certificate", adminToken,
		certUploadFields{cert: &certPEM, key: &keyPEM}, csrf)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown bank = %d, want 404", rec.Code)
	}
}

func TestConsoleCertUploadForbiddenForOperator(t *testing.T) {
	t.Parallel()
	f := newConsoleFixture(t)
	csrf := csrfToken(t, f.handler, operatorToken)
	certPEM, keyPEM := genCertKeyPEM(t, "cn", time.Unix(0, 0), time.Unix(1000, 0).Add(time.Hour))

	// Operator (read-only) must not be able to write a certificate (RBAC, 403).
	rec := consoleCertPost(t, f.handler, "/console/tenants/t1/banks/c6/certificate", operatorToken,
		certUploadFields{cert: &certPEM, key: &keyPEM}, csrf)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("operator write = %d, want 403", rec.Code)
	}
}

// TestConsoleBankDetailShowsCertCard pins that the bank detail screen renders the
// certificate card (upload control) for an admin.
func TestConsoleBankDetailShowsCertCard(t *testing.T) {
	t.Parallel()
	f := newConsoleFixture(t)
	if err := f.creds.SetBankCredential(context.Background(), "t1", ports.BankIDC6, "cid-1", "s3cr3t"); err != nil {
		t.Fatalf("seed cred: %v", err)
	}
	rec := consoleGet(t, f.handler, "/console/tenants/t1/banks/c6", adminToken)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "Certificado mTLS") || !strings.Contains(body, `name="cert_pem"`) {
		t.Fatalf("detail cert card missing (%d): %s", rec.Code, body)
	}
}

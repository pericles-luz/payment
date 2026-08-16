package secret_test

import (
	"context"
	"crypto/tls"
	"errors"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// TestCertStoreLoadTLSCertificate: the in-memory vault re-assembles a usable
// tls.Certificate for the stored (tenant, bank) pair, exact-match, with the leaf
// parseable and the private key present (so it can complete a handshake).
func TestCertStoreLoadTLSCertificate(t *testing.T) {
	t.Parallel()
	st := secret.NewCertStore()
	certPEM, keyPEM := certKeyPEM(t, "verz.client")
	if err := st.SetBankCertificate(context.Background(), ports.BankCertificate{
		TenantID: "tnt-1", BankID: "c6", CertPEM: certPEM, KeyPEM: keyPEM,
	}); err != nil {
		t.Fatalf("set: %v", err)
	}

	cert, err := st.LoadTLSCertificate(context.Background(), "tnt-1", "c6")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cert == nil || len(cert.Certificate) == 0 {
		t.Fatal("expected a populated tls.Certificate")
	}
	if cert.PrivateKey == nil {
		t.Fatal("expected the private key to back the certificate (needed for the handshake)")
	}
	// It must be a real key pair the TLS stack accepts.
	if _, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM)); err != nil {
		t.Fatalf("sanity: seeded material is not a valid pair: %v", err)
	}
}

// TestCertStoreLoadTLSCertificateEmptyBankDefaults: an empty bankID resolves to the
// default BankIDC6 (retro-compat), matching the write path.
func TestCertStoreLoadTLSCertificateEmptyBankDefaults(t *testing.T) {
	t.Parallel()
	st := secret.NewCertStore()
	certPEM, keyPEM := certKeyPEM(t, "verz.client")
	if err := st.SetBankCertificate(context.Background(), ports.BankCertificate{
		TenantID: "tnt-1", BankID: "", CertPEM: certPEM, KeyPEM: keyPEM,
	}); err != nil {
		t.Fatalf("set: %v", err)
	}
	if _, err := st.LoadTLSCertificate(context.Background(), "tnt-1", ""); err != nil {
		t.Fatalf("load with empty bank: %v", err)
	}
}

// TestCertStoreLoadTLSCertificateNotFound: a missing pair returns ErrNotFound (no
// fallback), and never resolves to another tenant's certificate (deny-by-default).
func TestCertStoreLoadTLSCertificateNotFound(t *testing.T) {
	t.Parallel()
	st := secret.NewCertStore()
	certPEM, keyPEM := certKeyPEM(t, "verz.client")
	if err := st.SetBankCertificate(context.Background(), ports.BankCertificate{
		TenantID: "tnt-1", BankID: "c6", CertPEM: certPEM, KeyPEM: keyPEM,
	}); err != nil {
		t.Fatalf("set: %v", err)
	}
	if _, err := st.LoadTLSCertificate(context.Background(), "tnt-OTHER", "c6"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want ErrNotFound for another tenant, got %v", err)
	}
	if _, err := st.LoadTLSCertificate(context.Background(), "tnt-1", "bank-other"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want ErrNotFound for another bank, got %v", err)
	}
}

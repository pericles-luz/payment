package secret_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

func certKeyPEM(t *testing.T, cn string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Unix(1700000000, 0).UTC(),
		NotAfter:     time.Unix(1700000000, 0).UTC().Add(24 * time.Hour),
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

func TestCertStoreSetGetMeta(t *testing.T) {
	t.Parallel()
	st := secret.NewCertStore()
	ctx := context.Background()
	certPEM, keyPEM := certKeyPEM(t, "cn-a")

	if err := st.SetBankCertificate(ctx, ports.BankCertificate{
		TenantID: "t1", BankID: "c6", CertPEM: certPEM, KeyPEM: keyPEM,
	}); err != nil {
		t.Fatalf("set: %v", err)
	}
	meta, err := st.GetBankCertificateMeta(ctx, "t1", "c6")
	if err != nil {
		t.Fatalf("get meta: %v", err)
	}
	if meta.SubjectCN != "cn-a" {
		t.Errorf("SubjectCN: want cn-a, got %q", meta.SubjectCN)
	}
	if meta.TenantID != "t1" || meta.BankID != "c6" {
		t.Errorf("identity: got (%q,%q)", meta.TenantID, meta.BankID)
	}
	if meta.FingerprintSHA256 == "" {
		t.Errorf("fingerprint must be populated")
	}
}

// TestCertStoreEmptyBankDefaultsToC6 pins retro-compat: an empty bank both stores
// and reads under the default bank slug.
func TestCertStoreEmptyBankDefaultsToC6(t *testing.T) {
	t.Parallel()
	st := secret.NewCertStore()
	ctx := context.Background()
	certPEM, keyPEM := certKeyPEM(t, "cn")

	if err := st.SetBankCertificate(ctx, ports.BankCertificate{
		TenantID: "t1", BankID: "", CertPEM: certPEM, KeyPEM: keyPEM,
	}); err != nil {
		t.Fatalf("set: %v", err)
	}
	for _, bank := range []string{"", ports.BankIDC6} {
		if _, err := st.GetBankCertificateMeta(ctx, "t1", bank); err != nil {
			t.Fatalf("get (bank=%q): %v", bank, err)
		}
	}
}

// TestCertStoreMissingReturnsNotFound pins deny-by-default: an unknown pair is a
// not-found, never a fallback to another tenant/bank.
func TestCertStoreMissingReturnsNotFound(t *testing.T) {
	t.Parallel()
	st := secret.NewCertStore()
	ctx := context.Background()
	certPEM, keyPEM := certKeyPEM(t, "cn")
	if err := st.SetBankCertificate(ctx, ports.BankCertificate{TenantID: "t1", BankID: "c6", CertPEM: certPEM, KeyPEM: keyPEM}); err != nil {
		t.Fatalf("set: %v", err)
	}
	// Different tenant — must not resolve to t1's cert.
	if _, err := st.GetBankCertificateMeta(ctx, "t2", "c6"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant read: want ErrNotFound, got %v", err)
	}
}

func TestCertStoreRejectsEmptyInputs(t *testing.T) {
	t.Parallel()
	st := secret.NewCertStore()
	ctx := context.Background()
	certPEM, keyPEM := certKeyPEM(t, "cn")

	cases := map[string]ports.BankCertificate{
		"no tenant": {TenantID: "", BankID: "c6", CertPEM: certPEM, KeyPEM: keyPEM},
		"no cert":   {TenantID: "t1", BankID: "c6", CertPEM: "", KeyPEM: keyPEM},
		"no key":    {TenantID: "t1", BankID: "c6", CertPEM: certPEM, KeyPEM: ""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := st.SetBankCertificate(ctx, c); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want ErrValidation, got %v", err)
			}
		})
	}
}

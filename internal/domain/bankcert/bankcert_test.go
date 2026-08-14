package bankcert_test

import (
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

	"github.com/ia-dev-sindireceita/payment/internal/domain/bankcert"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

// genCertKeyPEM builds a self-signed leaf certificate and its matching EC private
// key, both PEM-encoded, for the given CN and validity window. EC P-256 keeps the
// generation fast for table-driven tests.
func genCertKeyPEM(t *testing.T, cn string, notBefore, notAfter time.Time) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4242),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM
}

func TestParseCertHappy(t *testing.T) {
	t.Parallel()
	nb := time.Unix(1700000000, 0).UTC()
	na := nb.Add(365 * 24 * time.Hour)
	certPEM, _ := genCertKeyPEM(t, "payment.example", nb, na)

	got, err := bankcert.ParseCert(certPEM)
	if err != nil {
		t.Fatalf("ParseCert: %v", err)
	}
	if got.SubjectCN != "payment.example" {
		t.Errorf("SubjectCN: want %q, got %q", "payment.example", got.SubjectCN)
	}
	if got.SerialNumber != "4242" {
		t.Errorf("SerialNumber: want 4242, got %q", got.SerialNumber)
	}
	if len(got.FingerprintSHA256) != 64 { // hex of 32 bytes
		t.Errorf("FingerprintSHA256: want 64 hex chars, got %d (%q)", len(got.FingerprintSHA256), got.FingerprintSHA256)
	}
	if !got.NotBefore.Equal(nb) || !got.NotAfter.Equal(na) {
		t.Errorf("validity window: got [%s, %s], want [%s, %s]", got.NotBefore, got.NotAfter, nb, na)
	}
	if got.Issuer == "" {
		t.Errorf("Issuer should be populated for a self-signed cert")
	}
}

// TestParseCertFingerprintDeterministic pins that the SHA-256 fingerprint is a
// stable function of the certificate bytes.
func TestParseCertFingerprintDeterministic(t *testing.T) {
	t.Parallel()
	nb := time.Unix(1700000000, 0).UTC()
	certPEM, _ := genCertKeyPEM(t, "cn", nb, nb.Add(time.Hour))
	a, err := bankcert.ParseCert(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	b, err := bankcert.ParseCert(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	if a.FingerprintSHA256 != b.FingerprintSHA256 {
		t.Fatalf("fingerprint not deterministic: %q vs %q", a.FingerprintSHA256, b.FingerprintSHA256)
	}
}

func TestParseCertRejectsMalformed(t *testing.T) {
	t.Parallel()
	// A non-CERTIFICATE PEM block (a private key) must be rejected.
	_, keyPEM := genCertKeyPEM(t, "cn", time.Unix(1, 0), time.Unix(2, 0))
	// A CERTIFICATE block whose body is junk DER.
	junkDER := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not-a-der")}))

	cases := map[string]string{
		"empty":              "",
		"garbage":            "-----BEGIN nonsense",
		"wrong block type":   keyPEM,
		"valid pem junk der": junkDER,
	}
	for name, certPEM := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := bankcert.ParseCert(certPEM)
			if err == nil {
				t.Fatalf("want error for %s, got nil", name)
			}
			var ve *shared.ValidationError
			if !errors.As(err, &ve) || ve.Field != "cert_pem" {
				t.Fatalf("want ValidationError on cert_pem, got %v", err)
			}
		})
	}
}

func TestParseHappyMatchingPair(t *testing.T) {
	t.Parallel()
	nb := time.Unix(1700000000, 0).UTC()
	certPEM, keyPEM := genCertKeyPEM(t, "cn", nb, nb.Add(time.Hour))
	got, err := bankcert.Parse(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("Parse matching pair: %v", err)
	}
	if got.SubjectCN != "cn" {
		t.Fatalf("metadata not returned: %+v", got)
	}
}

func TestParseRejectsMismatchedPair(t *testing.T) {
	t.Parallel()
	nb := time.Unix(1700000000, 0).UTC()
	certPEM, _ := genCertKeyPEM(t, "a", nb, nb.Add(time.Hour))
	_, otherKey := genCertKeyPEM(t, "b", nb, nb.Add(time.Hour))

	_, err := bankcert.Parse(certPEM, otherKey)
	var ve *shared.ValidationError
	if !errors.As(err, &ve) || ve.Field != "key_pem" {
		t.Fatalf("want ValidationError on key_pem for mismatched pair, got %v", err)
	}
}

func TestParseRejectsMalformedKey(t *testing.T) {
	t.Parallel()
	nb := time.Unix(1700000000, 0).UTC()
	certPEM, _ := genCertKeyPEM(t, "a", nb, nb.Add(time.Hour))

	_, err := bankcert.Parse(certPEM, "-----BEGIN PRIVATE KEY-----\nbad\n-----END PRIVATE KEY-----")
	var ve *shared.ValidationError
	if !errors.As(err, &ve) || ve.Field != "key_pem" {
		t.Fatalf("want ValidationError on key_pem for malformed key, got %v", err)
	}
}

func TestParseRejectsMalformedCertBeforeKey(t *testing.T) {
	t.Parallel()
	// A malformed cert is rejected at the cert stage (cert_pem), regardless of key.
	_, err := bankcert.Parse("garbage", "garbage")
	var ve *shared.ValidationError
	if !errors.As(err, &ve) || ve.Field != "cert_pem" {
		t.Fatalf("want ValidationError on cert_pem, got %v", err)
	}
}

package custody

import (
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"
)

// provisionLeaf is a test helper: it mints a real self-signed test leaf via the
// LocalTestSigner so meta/store tests operate on genuine *x509.Certificate
// values rather than fabricated stubs.
func provisionLeaf(t *testing.T, companyID, cnpj string, validFor time.Duration) ([]*x509.Certificate, A1Meta) {
	t.Helper()
	s := NewLocalTestSigner()
	chain, meta, err := s.Provision(companyID, cnpj, validFor)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	return chain, meta
}

func TestSerialHex(t *testing.T) {
	if got := SerialHex(nil); got != "" {
		t.Errorf("SerialHex(nil) = %q, want empty", got)
	}
	chain, _ := provisionLeaf(t, "co-1", "11.222.333/0001-81", time.Hour)
	got := SerialHex(chain[0])
	if got == "" {
		t.Fatal("SerialHex on real leaf returned empty")
	}
	if got != strings.ToLower(got) {
		t.Errorf("serial not lowercase: %q", got)
	}
}

func TestHashCNPJ(t *testing.T) {
	// Formatting must not change the hash: digits are what matter.
	a := HashCNPJ("11.222.333/0001-81")
	b := HashCNPJ("11222333000181")
	if a != b {
		t.Errorf("formatted vs raw CNPJ hash differ: %s != %s", a, b)
	}
	if len(a) != 64 {
		t.Errorf("hash length = %d, want 64 hex chars", len(a))
	}
	// The raw CNPJ digits must never appear in the hash.
	if strings.Contains(a, "11222333000181") {
		t.Error("raw CNPJ leaked into hash")
	}
	if HashCNPJ("") == "" {
		t.Error("hash of empty string should still be a fixed 64-char digest")
	}
}

func TestA1MetaFromLeaf(t *testing.T) {
	nilMeta := A1MetaFromLeaf(nil, "11222333000181")
	if nilMeta.Serial != "" || !nilMeta.NotAfter.IsZero() {
		t.Errorf("nil leaf should yield empty serial/zero notAfter, got %+v", nilMeta)
	}
	if nilMeta.CNPJHash == "" {
		t.Error("nil leaf should still hash the CNPJ")
	}

	chain, _ := provisionLeaf(t, "co-1", "11222333000181", 48*time.Hour)
	meta := A1MetaFromLeaf(chain[0], "11222333000181")
	if meta.Serial == "" {
		t.Error("expected non-empty serial")
	}
	if meta.NotAfter.IsZero() {
		t.Error("expected non-zero notAfter")
	}
	if !strings.Contains(meta.Subject, "TEST NFS-e A1") {
		t.Errorf("unexpected subject %q", meta.Subject)
	}
}

func TestExpiresInDaysAndIsExpired(t *testing.T) {
	base := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	meta := A1Meta{NotAfter: base.Add(30 * 24 * time.Hour)}
	if d := meta.ExpiresInDays(base); d != 30 {
		t.Errorf("ExpiresInDays = %d, want 30", d)
	}
	if meta.IsExpired(base) {
		t.Error("should not be expired 30 days early")
	}
	after := base.Add(31 * 24 * time.Hour)
	if !meta.IsExpired(after) {
		t.Error("should be expired past notAfter")
	}
	if d := meta.ExpiresInDays(after); d >= 0 {
		t.Errorf("ExpiresInDays past expiry = %d, want negative", d)
	}
	// Exactly at notAfter counts as expired (fail-closed boundary).
	if !meta.IsExpired(meta.NotAfter) {
		t.Error("notAfter instant should be expired")
	}
}

func TestEncodeDecodeChainPEMRoundTrip(t *testing.T) {
	chain, _ := provisionLeaf(t, "co-1", "11222333000181", time.Hour)
	pemStr, err := EncodeChainPEM(chain)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !strings.Contains(pemStr, "BEGIN CERTIFICATE") {
		t.Error("PEM missing certificate header")
	}
	if strings.Contains(pemStr, "PRIVATE KEY") {
		t.Fatal("PEM must never contain a private key")
	}
	back, err := DecodeChainPEM(pemStr)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(back) != len(chain) {
		t.Fatalf("round trip length %d != %d", len(back), len(chain))
	}
	if back[0].SerialNumber.Cmp(chain[0].SerialNumber) != 0 {
		t.Error("serial changed across PEM round trip")
	}
}

func TestEncodeChainPEMErrors(t *testing.T) {
	if _, err := EncodeChainPEM(nil); !errors.Is(err, ErrEmptyChain) {
		t.Errorf("empty chain err = %v, want ErrEmptyChain", err)
	}
	if _, err := EncodeChainPEM([]*x509.Certificate{nil}); !errors.Is(err, ErrEmptyChain) {
		t.Errorf("nil element err = %v, want ErrEmptyChain", err)
	}
}

func TestDecodeChainPEMRejectsNonCert(t *testing.T) {
	priv := "-----BEGIN PRIVATE KEY-----\nZm9v\n-----END PRIVATE KEY-----\n"
	if _, err := DecodeChainPEM(priv); err == nil {
		t.Fatal("expected rejection of PRIVATE KEY block")
	}
	if _, err := DecodeChainPEM("not pem at all"); !errors.Is(err, ErrEmptyChain) {
		t.Errorf("garbage input err = %v, want ErrEmptyChain", err)
	}
	if _, err := DecodeChainPEM("-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n"); err == nil {
		t.Error("expected parse error for bogus certificate bytes")
	}
}

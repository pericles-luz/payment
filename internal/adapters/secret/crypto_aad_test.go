package secret_test

import (
	"bytes"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
)

func TestSealWithAADRoundTrip(t *testing.T) {
	t.Parallel()
	c, _ := secret.NewCipher(newKey(0x11))
	aad := secret.RowAAD("tenant-a", "c6")
	plain := []byte("c6-oauth-secret")
	sealed, err := c.SealWithAAD(plain, aad)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	out, err := c.OpenWithAAD(sealed, aad)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(out, plain) {
		t.Fatalf("round trip mismatch: %q", out)
	}
}

// TestOpenWithWrongAADFails is the core row-binding guarantee: a blob sealed for
// one row cannot be opened under another row's AAD.
func TestOpenWithWrongAADFails(t *testing.T) {
	t.Parallel()
	c, _ := secret.NewCipher(newKey(0x12))
	sealed, _ := c.SealWithAAD([]byte("secret"), secret.RowAAD("tenant-a", "c6"))
	if _, err := c.OpenWithAAD(sealed, secret.RowAAD("tenant-b", "c6")); err == nil {
		t.Fatal("blob bound to (tenant-a, c6) must not open under (tenant-b, c6)")
	}
	if _, err := c.OpenWithAAD(sealed, secret.RowAAD("tenant-a", "itau")); err == nil {
		t.Fatal("blob bound to bank c6 must not open under bank itau")
	}
	// And an AAD-bound blob must not open with no AAD (the legacy path).
	if _, err := c.Open(sealed); err == nil {
		t.Fatal("AAD-bound blob must not open with nil AAD")
	}
}

// TestSealNilAADInteropsWithOpen documents that Seal/Open (nil AAD) are the same
// as the *WithAAD forms with aad=nil — the compatibility path the re-seal tool
// uses to upgrade pre-row-binding blobs.
func TestSealNilAADInteropsWithOpen(t *testing.T) {
	t.Parallel()
	c, _ := secret.NewCipher(newKey(0x13))
	sealed, _ := c.Seal([]byte("legacy"))
	if _, err := c.OpenWithAAD(sealed, nil); err != nil {
		t.Fatalf("nil-AAD blob must open with OpenWithAAD(nil): %v", err)
	}
}

// TestRowAADUnambiguous proves the length-prefixing prevents the classic
// concatenation collision: ("ab","c") and ("a","bc") must yield distinct AAD.
func TestRowAADUnambiguous(t *testing.T) {
	t.Parallel()
	if bytes.Equal(secret.RowAAD("ab", "c"), secret.RowAAD("a", "bc")) {
		t.Fatal("RowAAD must not collide across different (tenant, bank) splits")
	}
	if !bytes.Equal(secret.RowAAD("t", "c6"), secret.RowAAD("t", "c6")) {
		t.Fatal("RowAAD must be deterministic for the same inputs")
	}
	if bytes.Equal(secret.RowAAD("t", "c6"), secret.RowAAD("t", "")) {
		t.Fatal("empty bank must differ from a set bank")
	}
}

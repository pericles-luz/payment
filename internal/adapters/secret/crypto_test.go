package secret_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
)

func newKey(b byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b
	}
	return k
}

func TestCipherRoundTrip(t *testing.T) {
	t.Parallel()
	c, err := secret.NewCipher(newKey(0x01))
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}
	plain := []byte("c6-client-secret-value")
	sealed, err := c.Seal(plain)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if bytes.Contains(sealed, plain) {
		t.Fatal("ciphertext contains plaintext")
	}
	out, err := c.Open(sealed)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(out, plain) {
		t.Fatalf("round trip mismatch: %q", out)
	}
}

func TestSealUsesFreshNonce(t *testing.T) {
	t.Parallel()
	c, _ := secret.NewCipher(newKey(0x02))
	plain := []byte("same")
	a, _ := c.Seal(plain)
	b, _ := c.Seal(plain)
	if bytes.Equal(a, b) {
		t.Fatal("sealing the same plaintext twice produced identical ciphertext (nonce reuse)")
	}
}

func TestNewCipherKeySize(t *testing.T) {
	t.Parallel()
	for _, n := range []int{0, 16, 24, 31, 33} {
		if _, err := secret.NewCipher(make([]byte, n)); !errors.Is(err, secret.ErrKeySize) {
			t.Fatalf("key size %d: want ErrKeySize, got %v", n, err)
		}
	}
}

func TestOpenRejectsTamper(t *testing.T) {
	t.Parallel()
	c, _ := secret.NewCipher(newKey(0x03))
	sealed, _ := c.Seal([]byte("authentic"))
	// Flip a bit in the tag/ciphertext region.
	sealed[len(sealed)-1] ^= 0xff
	if _, err := c.Open(sealed); err == nil {
		t.Fatal("tampered ciphertext must fail authentication")
	}
}

func TestOpenRejectsWrongKey(t *testing.T) {
	t.Parallel()
	enc, _ := secret.NewCipher(newKey(0x04))
	dec, _ := secret.NewCipher(newKey(0x05))
	sealed, _ := enc.Seal([]byte("secret"))
	if _, err := dec.Open(sealed); err == nil {
		t.Fatal("decrypting with the wrong key must fail")
	}
}

func TestOpenRejectsTooShort(t *testing.T) {
	t.Parallel()
	c, _ := secret.NewCipher(newKey(0x06))
	if _, err := c.Open([]byte{0x00}); !errors.Is(err, secret.ErrMalformed) {
		t.Fatalf("want ErrMalformed, got %v", err)
	}
}

package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// ErrKeySize is returned when a Cipher is built with a key that is not 32 bytes
// (AES-256).
var ErrKeySize = errors.New("secret: key must be 32 bytes (AES-256)")

// Cipher provides authenticated encryption (AES-256-GCM) for credential secrets
// at rest. The in-memory Store keeps secrets in process memory only (not "at
// rest"); when a persisted/vault-backed CredentialWriter is introduced it MUST
// wrap each secret with Seal so the durable column is ciphertext, never
// plaintext (threat C1/C4). The key is loaded from config/env (a KEK/derived
// DEK), never hard-coded.
//
// Output layout is nonce||ciphertext||tag (GCM appends the tag). A fresh random
// nonce is generated per Seal, so encrypting the same secret twice yields
// distinct ciphertexts and the nonce is never reused under one key.
type Cipher struct {
	aead cipher.AEAD
}

// NewCipher builds a Cipher from a 32-byte (AES-256) key.
func NewCipher(key []byte) (*Cipher, error) {
	if len(key) != 32 {
		return nil, ErrKeySize
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secret: new cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secret: new gcm: %w", err)
	}
	return &Cipher{aead: aead}, nil
}

// SealWithAAD encrypts plaintext and returns nonce||ciphertext||tag, additionally
// AUTHENTICATING (but not encrypting) aad. The aad is NOT stored in the returned
// blob: it must be supplied identically to OpenWithAAD or GCM authentication
// fails. Persistence adapters MUST pass RowAAD(tenantID, bankID) so a sealed blob
// is cryptographically bound to its storage row — a ciphertext copied to another
// (tenant, bank) row (confused-deputy / row relocation) then fails to open
// (defense in depth beyond the row lookup; SIN-69369, ADR-0007 C1/C4). Never log
// the plaintext argument.
func (c *Cipher) SealWithAAD(plaintext, aad []byte) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("secret: read nonce: %w", err)
	}
	// Seal appends the ciphertext+tag to the nonce prefix so the nonce travels
	// with the message; aad is folded into the GCM tag but not into the output.
	return c.aead.Seal(nonce, nonce, plaintext, aad), nil
}

// Seal is SealWithAAD with no row binding (aad=nil). Retained for callers that do
// not persist to a (tenant, bank) row; durable vault writers use SealWithAAD.
func (c *Cipher) Seal(plaintext []byte) ([]byte, error) {
	return c.SealWithAAD(plaintext, nil)
}

// ErrMalformed is returned when ciphertext is too short to contain a nonce.
var ErrMalformed = errors.New("secret: ciphertext too short")

// OpenWithAAD decrypts nonce||ciphertext||tag produced by SealWithAAD, verifying
// that aad matches the value bound at seal time. It returns an error if the data
// was tampered with, the wrong key is used, or the aad differs (all surface as
// GCM authentication failure), so a corrupted/forged/relocated credential is
// never silently accepted.
func (c *Cipher) OpenWithAAD(sealed, aad []byte) ([]byte, error) {
	ns := c.aead.NonceSize()
	if len(sealed) < ns {
		return nil, ErrMalformed
	}
	nonce, ciphertext := sealed[:ns], sealed[ns:]
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		// Do not wrap with any data-derived context; authentication failure is
		// reported generically.
		return nil, fmt.Errorf("secret: open: %w", err)
	}
	return plaintext, nil
}

// Open is OpenWithAAD with no row binding (aad=nil). Retained for symmetry with
// Seal; durable vault readers use OpenWithAAD.
func (c *Cipher) Open(sealed []byte) ([]byte, error) {
	return c.OpenWithAAD(sealed, nil)
}

// RowAAD builds the additional authenticated data that cryptographically binds a
// sealed vault blob to its storage row (tenant_id, bank_id). It is NOT secret and
// is NOT stored — it is reconstructed on read from the row's own key columns. The
// fields are length-prefixed under a fixed domain tag so no two distinct
// (tenant, bank) pairs can collide (e.g. ("ab","c") vs ("a","bc") yield different
// AAD), and so this binding can never be confused with some other AAD scheme.
func RowAAD(tenantID, bankID string) []byte {
	// Tag documents the binding scheme and version; bump if the layout ever changes.
	out := []byte("payment/bank-vault/row/v1")
	out = appendLenPrefixed(out, tenantID)
	out = appendLenPrefixed(out, bankID)
	return out
}

// appendLenPrefixed appends an 8-byte big-endian length followed by s, so that a
// concatenation of fields is unambiguous regardless of the fields' contents.
func appendLenPrefixed(dst []byte, s string) []byte {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(s)))
	dst = append(dst, n[:]...)
	return append(dst, s...)
}

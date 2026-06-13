package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
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

// Seal encrypts plaintext and returns nonce||ciphertext||tag. The returned bytes
// are safe to persist; recovering the plaintext requires the key. Never log the
// plaintext argument.
func (c *Cipher) Seal(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("secret: read nonce: %w", err)
	}
	// Seal appends the ciphertext+tag to the nonce prefix so the nonce travels
	// with the message.
	return c.aead.Seal(nonce, nonce, plaintext, nil), nil
}

// ErrMalformed is returned when ciphertext is too short to contain a nonce.
var ErrMalformed = errors.New("secret: ciphertext too short")

// Open decrypts nonce||ciphertext||tag produced by Seal. It returns an error if
// the data was tampered with or the wrong key is used (GCM authentication
// fails), so a corrupted/forged credential is never silently accepted.
func (c *Cipher) Open(sealed []byte) ([]byte, error) {
	ns := c.aead.NonceSize()
	if len(sealed) < ns {
		return nil, ErrMalformed
	}
	nonce, ciphertext := sealed[:ns], sealed[ns:]
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		// Do not wrap with any data-derived context; authentication failure is
		// reported generically.
		return nil, fmt.Errorf("secret: open: %w", err)
	}
	return plaintext, nil
}

package consoleauth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Password hashing uses argon2id (the CTO-mandated primitive, SIN-69265): a
// memory-hard KDF resistant to GPU/ASIC cracking. The plaintext is never stored;
// only the PHC-format encoded hash is. Verification is constant-time with respect
// to the derived key so it leaks nothing about how much of the password matched.
//
// Parameters follow the OWASP argon2id guidance (m=64 MiB, t=3, p=4). They are
// embedded in the encoded string so a stored hash carries the cost it was minted
// with — the parameters can be raised later without invalidating existing hashes.
const (
	argonTime    = 3         // iterations
	argonMemory  = 64 * 1024 // KiB (64 MiB)
	argonThreads = 4
	argonKeyLen  = 32 // derived key length (bytes)
	argonSaltLen = 16 // random salt length (bytes)
	// argonVersion is argon2's algorithm version (0x13 == 19), recorded in the
	// encoded string for forward-compatibility of the parser.
	argonVersion = argon2.Version
)

// HashPassword derives an argon2id hash of plain with a fresh random salt and
// returns it in the standard PHC string format
// ($argon2id$v=19$m=65536,t=3,p=4$<b64salt>$<b64hash>). An empty plaintext is
// rejected (ErrEmptyPassword); a CSPRNG failure is surfaced.
func HashPassword(plain string) (string, error) {
	if plain == "" {
		return "", ErrEmptyPassword
	}
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("consoleauth: read salt: %w", err)
	}
	key := argon2.IDKey([]byte(plain), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return encodeArgon2(salt, key), nil
}

// encodeArgon2 renders the salt+key in PHC string format with the fixed cost
// parameters. base64 is standard, unpadded (the PHC convention).
func encodeArgon2(salt, key []byte) string {
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argonVersion, argonMemory, argonTime, argonThreads,
		b64.EncodeToString(salt), b64.EncodeToString(key))
}

// VerifyPassword reports whether plain matches an argon2id PHC-encoded hash. It
// re-derives the key with the parameters carried in the encoded string and
// compares in constant time. A malformed or non-argon2id encoded value, or an
// empty plaintext, yields false (never a panic and never a partial match).
func VerifyPassword(encoded, plain string) bool {
	salt, key, ok := decodeArgon2(encoded)
	if !ok || plain == "" {
		return false
	}
	got := argon2.IDKey([]byte(plain), salt, argonTime, argonMemory, argonThreads, uint32(len(key)))
	return subtle.ConstantTimeCompare(got, key) == 1
}

// decodeArgon2 parses a PHC argon2id string, returning the salt and derived key.
// It accepts ONLY the argon2id variant and version 19 with the exact cost
// parameters this package mints — any deviation returns ok=false so a tampered or
// downgraded hash never verifies. It is total (any malformed input → ok=false).
func decodeArgon2(encoded string) (salt, key []byte, ok bool) {
	parts := strings.Split(encoded, "$")
	// ["", "argon2id", "v=19", "m=65536,t=3,p=4", saltB64, keyB64]
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return nil, nil, false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argonVersion {
		return nil, nil, false
	}
	var mem, iter, par int
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &iter, &par); err != nil {
		return nil, nil, false
	}
	if mem != argonMemory || iter != argonTime || par != argonThreads {
		return nil, nil, false
	}
	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return nil, nil, false
	}
	key, err = b64.DecodeString(parts[5])
	if err != nil || len(key) == 0 {
		return nil, nil, false
	}
	return salt, key, true
}

package custody

import (
	"crypto/aes"
	"encoding/binary"
	"errors"
)

// kwpWrap implements AES Key Wrap with Padding (RFC 5649), the format Vault's
// transit/keys/{name}/import expects for the target key after the ephemeral AES
// key is itself wrapped with RSA-OAEP (BYOK). Go's standard library has no KWP,
// and pulling Tink in for ~40 lines is not worth the dependency.
func kwpWrap(kek, plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, errors.New("custody: kwp: empty plaintext")
	}
	if uint64(len(plaintext)) > 0xFFFFFFFF {
		return nil, errors.New("custody: kwp: plaintext too long")
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	// Alternative IV: 0xA65959A6 || 32-bit message length indicator.
	var aiv [8]byte
	binary.BigEndian.PutUint32(aiv[:4], 0xA65959A6)
	binary.BigEndian.PutUint32(aiv[4:], uint32(len(plaintext)))

	padded := make([]byte, (len(plaintext)+7)/8*8)
	copy(padded, plaintext)
	defer zero(padded)

	if len(padded) == 8 {
		// One semiblock: a single AES-ECB encryption of AIV || P (§4.1).
		out := make([]byte, 16)
		copy(out, aiv[:])
		copy(out[8:], padded)
		block.Encrypt(out, out)
		return out, nil
	}

	// RFC 3394 wrapping process W with A initialised to the AIV.
	n := len(padded) / 8
	out := make([]byte, 8+len(padded))
	copy(out[8:], padded)
	a := aiv
	var b [16]byte
	for j := 0; j < 6; j++ {
		for i := 1; i <= n; i++ {
			copy(b[:8], a[:])
			copy(b[8:], out[i*8:i*8+8])
			block.Encrypt(b[:], b[:])
			t := uint64(n*j + i)
			binary.BigEndian.PutUint64(a[:], binary.BigEndian.Uint64(b[:8])^t)
			copy(out[i*8:i*8+8], b[8:])
		}
	}
	zero(b[:])
	copy(out[:8], a[:])
	return out, nil
}

// zero overwrites b. Best-effort scrubbing of key material: Go's GC may have
// copied the bytes elsewhere, so this narrows exposure rather than ending it.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

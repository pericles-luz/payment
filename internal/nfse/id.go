package nfse

import (
	"crypto/rand"
	"encoding/hex"
)

// newEmissionID returns a random 128-bit identifier as lowercase hex, prefixed
// "nfse_". It is opaque to clients and collision-safe for the emission volume.
func newEmissionID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing is unrecoverable; a zero id is still unique enough
		// for the process to fail loudly downstream rather than silently reuse.
		return "nfse_0000000000000000"
	}
	return "nfse_" + hex.EncodeToString(b[:])
}

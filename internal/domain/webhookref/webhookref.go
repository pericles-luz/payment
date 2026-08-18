// Package webhookref is the domain home of the opaque per-tenant C6 webhook
// callback reference (tenantRef). The C6 webhook contract carries NO message
// authenticity — no HMAC, signature or key-id (ADR-0002 / F4, SIN-64720) — so the
// unguessable per-tenant URL segment IS the credential (a capability URL): holding
// a valid ref authenticates the channel and binds it to exactly one tenant.
//
// This package centralises the ref crypto (mint / hash / structural validation) so
// there is ONE implementation shared by every layer: the HTTP adapter's bootstrap
// authenticator (auth.go) and the durable store's mint path (SIN-69559). It has no
// dependency on database/sql, net/http or any vendor SDK — it is pure domain crypto,
// safe to import from a use-case.
//
// SECURITY: the plaintext ref is a secret and is never stored, logged or compared in
// the clear. Only Sum(ref) — a SHA-256 — is persisted (in-memory map key or the
// durable store column). A structurally invalid ref (see Valid) is rejected BEFORE
// any lookup so a path-traversal / percent-encoded input can never reach the
// credential map (uniform failure, no enumeration oracle).
package webhookref

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// refBytes is the entropy of a minted ref: 32 bytes (256 bits) makes the capability
// URL infeasible to guess.
const refBytes = 32

// RefLen is the fixed length of a ref once base64url-encoded without padding:
// ceil(32*8/6) = 43 characters. Callers validate against this exact length.
const RefLen = 43

// Generate mints a fresh, unguessable per-tenant callback reference: 32 random bytes
// (256 bits) from the system CSPRNG encoded base64url without padding (43 chars). It
// returns an error only if the CSPRNG fails. The returned value is a secret: register
// its Sum and hand the plaintext to the caller exactly once (display-once).
func Generate() (string, error) {
	b := make([]byte, refBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Sum returns the raw SHA-256 of a ref, the value persisted as the credential key so
// the plaintext ref is never stored. It is a pure hash of the bytes; callers hex- or
// otherwise-encode it for their storage medium.
func Sum(ref string) [sha256.Size]byte {
	return sha256.Sum256([]byte(ref))
}

// Valid reports whether ref is structurally a tenantRef: exactly RefLen base64url
// characters ([A-Za-z0-9_-], no padding). Enforcing the fixed shape before any lookup
// rejects path-traversal / percent-encoded inputs uniformly and keeps a malformed ref
// from ever reaching the credential map or the durable store.
func Valid(ref string) bool {
	if len(ref) != RefLen {
		return false
	}
	for i := 0; i < len(ref); i++ {
		c := ref[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

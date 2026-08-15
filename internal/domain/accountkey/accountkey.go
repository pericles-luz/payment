// Package accountkey holds the AccountKey aggregate — the rotatable bearer secret
// that an Account (the API user / reseller above the tenant, ADR-0009) presents to
// authenticate as itself in the model (b) access path (ADR-0011, SIN-69274). It is
// the credential half of the "chave-de-Conta + seletor" model the board declared
// for Verz: one rotatable key per Account, scoped by the guard at the choke-point
// (§2 of the ADR) to exactly the tenants that Account owns.
//
// SHIPS DARK (SIN-69278 / phase B1): this package only defines the domain and is
// exercised by the store adapters. It is NOT yet wired into the choke-point
// (internal/adapters/http/auth.go) and no flag turns it on — that is phase B2.
//
// Security posture (ADR-0011 §3):
//   - The secret is opaque and >=256-bit of CSPRNG entropy — infeasible to guess or
//     brute-force, which is exactly why a single SHA-256 is the correct hash-at-rest
//     here. Argon2/bcrypt exist to slow brute-force of LOW-entropy human passwords;
//     they buy nothing for a 256-bit random secret and only add cost. This mirrors
//     the established repo pattern for high-entropy capability secrets (the webhook
//     ref and admin-token maps in auth.go are keyed by sha256).
//   - The plaintext is NEVER stored: an AccountKey holds only the hash. The plaintext
//     is returned exactly once, at mint time, and then discarded (display-once,
//     ADR-0010).
//   - Verification is constant-time (crypto/subtle) so a comparison never leaks how
//     many leading bytes matched.
//   - LogValue() redacts the hash so a stray structured-log call cannot emit it.
//
// Pure domain: it imports only the standard library crypto primitives (the same
// allowance consoleauth uses) — no database/sql, no net/http, no vendor SDK.
package accountkey

import (
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"log/slog"
	"strings"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

const (
	// secretBytes is the entropy of the opaque secret: 32 bytes = 256 bits, so a
	// key is infeasible to guess (ADR-0011 §3, "secret opaco >=256-bit").
	secretBytes = 32

	// secretPrefix tags the plaintext so the choke-point (phase B2) can cheaply tell
	// an account-key apart from a tenant token before authenticating, without a
	// timing side-channel. It is part of the plaintext and is included in the hash,
	// so it does not reduce the 256 bits of entropy that follow it (Stripe-style
	// `sk_`-prefixed keys). It carries no secret by itself.
	secretPrefix = "ak_"
)

// GenerateSecret mints a fresh opaque >=256-bit account-key secret, encoded
// base64url without padding (URL/paste-safe, no ambiguous characters) behind the
// account-key prefix. It returns an error only if the system CSPRNG fails — a
// caller MUST treat that as fatal and never fall back to a weaker source.
func GenerateSecret() (string, error) {
	b := make([]byte, secretBytes)
	if _, err := crand.Read(b); err != nil {
		return "", err
	}
	return secretPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// HasSecretShape reports whether a presented string has the account-key prefix. It
// is a cheap, non-secret discriminator for the choke-point (phase B2) to route a
// bearer value to the account-key authenticator; it says NOTHING about validity
// (an attacker can trivially craft the prefix). Authentication is still by hash.
func HasSecretShape(secret string) bool {
	return strings.HasPrefix(secret, secretPrefix)
}

// HashSecret returns the hex-encoded SHA-256 hash-at-rest of a plaintext secret.
// This is the ONLY representation of the secret that is ever persisted or held in
// memory by a store. A single SHA-256 is appropriate because the secret is
// high-entropy (see the package doc).
func HashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// AccountKey is the aggregate: an Account's bearer credential, at rest. It holds
// the hash of the secret — never the plaintext — plus its lifecycle state. Exactly
// one key per Account is active at a time; rotation supersedes the previous one
// (active=false, rotatedAt set) and mints a new active key.
type AccountKey struct {
	accountID string
	hash      string // hex sha256 of the plaintext secret; the plaintext is never held
	active    bool
	createdAt time.Time
	rotatedAt time.Time // zero until this key is superseded by a rotation
}

// New constructs an active AccountKey from an already-generated plaintext secret,
// hashing it at rest. It enforces the invariants: a key must belong to an account
// and must carry a non-empty secret. The plaintext is consumed here and not
// retained. Callers that also need the plaintext back should use Mint.
func New(accountID, secret string, now time.Time) (*AccountKey, error) {
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		return nil, shared.NewValidationError("account_id", "account id is required")
	}
	if secret == "" {
		return nil, shared.NewValidationError("secret", "secret is required")
	}
	return &AccountKey{
		accountID: accountID,
		hash:      HashSecret(secret),
		active:    true,
		createdAt: now,
	}, nil
}

// Mint generates a fresh secret and returns both the new active AccountKey (holding
// only the hash) and the plaintext to surface to the caller exactly once. It is the
// convenience a store uses on create/rotate: persist the AccountKey, return the
// plaintext. The plaintext MUST NOT be stored or logged.
func Mint(accountID string, now time.Time) (*AccountKey, string, error) {
	secret, err := GenerateSecret()
	if err != nil {
		return nil, "", err
	}
	k, err := New(accountID, secret, now)
	if err != nil {
		return nil, "", err
	}
	return k, secret, nil
}

// Rehydrate rebuilds an AccountKey from persisted state without re-running creation
// validation (used by persistence adapters). A zero rotatedAt means "never rotated".
func Rehydrate(accountID, hash string, active bool, createdAt, rotatedAt time.Time) *AccountKey {
	return &AccountKey{
		accountID: accountID,
		hash:      hash,
		active:    active,
		createdAt: createdAt,
		rotatedAt: rotatedAt,
	}
}

// AccountID returns the owning account id.
func (k *AccountKey) AccountID() string { return k.accountID }

// Hash returns the hex sha256 hash-at-rest. Adapters persist and index by this; it
// is not the secret and cannot be reversed to it, but it is still a credential
// derivative and must not be logged (LogValue redacts it).
func (k *AccountKey) Hash() string { return k.hash }

// Active reports whether this key currently authenticates. A superseded (rotated)
// key is inactive.
func (k *AccountKey) Active() bool { return k.active }

// CreatedAt returns the mint instant.
func (k *AccountKey) CreatedAt() time.Time { return k.createdAt }

// RotatedAt returns the instant this key was superseded, or the zero time if it is
// still the active key.
func (k *AccountKey) RotatedAt() time.Time { return k.rotatedAt }

// Supersede marks this key inactive as of now — the invalidation half of a rotation
// (ADR-0011 §3: a new key invalidates the previous immediately, the safer default).
// Superseding an already-inactive key is a no-op on the flag but still records the
// instant, which is harmless for an idempotent create==rotate.
func (k *AccountKey) Supersede(now time.Time) {
	k.active = false
	k.rotatedAt = now
}

// Verify reports whether the presented plaintext secret matches this key AND the key
// is active. The hash comparison is constant-time (crypto/subtle) so it never leaks,
// via timing, how many bytes of the hash matched. An inactive (superseded) key never
// verifies, so a rotated secret stops working immediately.
func (k *AccountKey) Verify(secret string) bool {
	want := HashSecret(secret)
	match := subtle.ConstantTimeCompare([]byte(want), []byte(k.hash)) == 1
	return match && k.active
}

// LogValue implements slog.LogValuer so structured logging of an AccountKey emits
// only non-secret descriptors. The hash is redacted so a stray log call can never
// leak the credential material (segredo-zero em log; ADR-0011 §3).
func (k *AccountKey) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("account_id", k.accountID),
		slog.String("hash", "[REDACTED]"),
		slog.Bool("active", k.active),
		slog.Time("created_at", k.createdAt),
		slog.Time("rotated_at", k.rotatedAt),
	)
}

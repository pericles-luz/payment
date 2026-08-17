// Package outboundwebhook holds the OutboundWebhookConfig aggregate — one Conta's
// (Account's) single outbound webhook endpoint: where the platform will POST that
// Conta's events (F2) and the HMAC signing secret those deliveries are signed with.
// It is the config half of "webhook de saída por Conta" (SIN-69486, model (b)
// ADR-0011); this phase (F0, SIN-69490) ships ONLY the durable, encrypted,
// account-scoped configuration — there is NO forwarding yet (that is F2) and the
// whole surface is dark behind a flag.
//
// One endpoint per Conta in v1 (a CEO decision — a simple aggregate keyed by
// accountID, upsert semantics), so this is deliberately NOT a collection.
//
// Security posture:
//   - The signing secret is opaque and >=256-bit of CSPRNG entropy. Unlike an
//     account key (a bearer we only ever VERIFY, so we can hash-at-rest), the signing
//     secret must be RECOVERABLE at delivery time to compute the HMAC over the F2
//     payload, so it is ENCRYPTED at rest (AES-256-GCM + AAD row-binding) by the
//     persistence adapter, never hashed — mirroring the bank credential / console
//     TOTP vaults (SIN-69366/69432). The aggregate holds the plaintext only
//     transiently (like consoleauth.Credential holds the TOTP secret); the durable
//     column is always ciphertext.
//   - The URL is NOT a secret (the operator sees it on the card to configure their
//     receiver) but is validated https-only at construction as defense-in-depth; the
//     dial-time SSRF enforcement lands in F2 (SIN-69486 gate).
//   - LogValue() redacts the signing secret so a stray structured-log call can never
//     emit it.
//
// Pure domain: it imports only the standard library plus the shared errors — no
// database/sql, no net/http, no vendor SDK.
package outboundwebhook

import (
	crand "crypto/rand"
	"encoding/base64"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

const (
	// secretBytes is the entropy of the opaque signing secret: 32 bytes = 256 bits,
	// so it is infeasible to guess — the correct strength for an HMAC signing key.
	secretBytes = 32

	// secretPrefix tags the plaintext so an operator (and a future receiver library)
	// can recognise a Sindireceita webhook signing secret at a glance (Stripe-style
	// `whsec_`). It is part of the plaintext and carries no secret by itself.
	secretPrefix = "whsec_"

	// maxURLLen bounds the stored URL so a pathological value cannot bloat the row or
	// a rendered page. Real webhook receiver URLs are far shorter.
	maxURLLen = 2048
)

// GenerateSigningSecret mints a fresh opaque >=256-bit signing secret, encoded
// base64url without padding (URL/paste-safe) behind the `whsec_` prefix. It returns
// an error only if the system CSPRNG fails — a caller MUST treat that as fatal and
// never fall back to a weaker source.
func GenerateSigningSecret() (string, error) {
	b := make([]byte, secretBytes)
	if _, err := crand.Read(b); err != nil {
		return "", err
	}
	return secretPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// ValidateURL enforces the endpoint invariants shared by the domain and the HTTP
// boundary (defense-in-depth): a non-empty, syntactically valid, absolute https URL
// with a host and no embedded credentials. It returns the trimmed, canonical string
// or a *shared.ValidationError. It is https-only on purpose — an outbound delivery
// carrying signed event data must never travel in cleartext. It does NOT perform
// SSRF/DNS checks (private-range, dial-time) — those are F2's dial-time concern
// (SIN-69486), enforced when a request is actually made, not at config time.
func ValidateURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", shared.NewValidationError("url", "webhook URL is required")
	}
	if len(raw) > maxURLLen {
		return "", shared.NewValidationError("url", "webhook URL is too long")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", shared.NewValidationError("url", "webhook URL is not a valid URL")
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return "", shared.NewValidationError("url", "webhook URL must use https")
	}
	if u.Host == "" {
		return "", shared.NewValidationError("url", "webhook URL must include a host")
	}
	if u.User != nil {
		// Credentials in the URL (user:pass@host) are a secret-in-URL smell and are
		// never needed for a webhook receiver — reject rather than store them.
		return "", shared.NewValidationError("url", "webhook URL must not embed credentials")
	}
	return raw, nil
}

// Config is the aggregate: one Conta's outbound webhook endpoint at rest. It holds
// the signing secret PLAINTEXT transiently (the persistence adapter seals it before
// it touches a column and hydrates it back on read); the plaintext is never persisted
// by the domain. Exactly one Config exists per Account (upsert on accountID).
type Config struct {
	accountID     string
	url           string
	signingSecret string // plaintext, held transiently; sealed at rest by the adapter
	enabled       bool
	createdAt     time.Time
	updatedAt     time.Time
}

// New constructs a Config, enforcing the invariants: a non-empty account id, a valid
// https URL and a non-empty signing secret (callers use GenerateSigningSecret). The
// signing secret is consumed here and held transiently. createdAt and updatedAt are
// both set to now (a fresh config).
func New(accountID, rawURL, signingSecret string, enabled bool, now time.Time) (*Config, error) {
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		return nil, shared.NewValidationError("account_id", "account id is required")
	}
	canonURL, err := ValidateURL(rawURL)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(signingSecret) == "" {
		return nil, shared.NewValidationError("signing_secret", "signing secret is required")
	}
	return &Config{
		accountID:     accountID,
		url:           canonURL,
		signingSecret: signingSecret,
		enabled:       enabled,
		createdAt:     now,
		updatedAt:     now,
	}, nil
}

// Rehydrate rebuilds a Config from persisted state without re-running creation
// validation (used by persistence adapters). The signing secret is the decrypted
// plaintext the adapter opened from its sealed column.
func Rehydrate(accountID, rawURL, signingSecret string, enabled bool, createdAt, updatedAt time.Time) *Config {
	return &Config{
		accountID:     accountID,
		url:           rawURL,
		signingSecret: signingSecret,
		enabled:       enabled,
		createdAt:     createdAt,
		updatedAt:     updatedAt,
	}
}

// SetURL updates the endpoint URL, re-validating the invariant, and stamps updatedAt.
// A validation error leaves the config unchanged.
func (c *Config) SetURL(rawURL string, now time.Time) error {
	canonURL, err := ValidateURL(rawURL)
	if err != nil {
		return err
	}
	c.url = canonURL
	c.updatedAt = now
	return nil
}

// SetEnabled toggles delivery on/off and stamps updatedAt. Disabling keeps the config
// (and its secret) intact so a later re-enable does not require re-provisioning.
func (c *Config) SetEnabled(enabled bool, now time.Time) {
	c.enabled = enabled
	c.updatedAt = now
}

// RotateSecret replaces the signing secret with a freshly minted one, returning the
// new plaintext to surface to the caller exactly once, and stamps updatedAt. The old
// secret is discarded — a rotation invalidates it immediately (the safer default,
// matching the account-key rotation posture).
func (c *Config) RotateSecret(now time.Time) (string, error) {
	s, err := GenerateSigningSecret()
	if err != nil {
		return "", err
	}
	c.signingSecret = s
	c.updatedAt = now
	return s, nil
}

// AccountID returns the owning Conta's id.
func (c *Config) AccountID() string { return c.accountID }

// URL returns the (validated, https) delivery endpoint. It is non-secret and may be
// rendered back to the operator.
func (c *Config) URL() string { return c.url }

// SigningSecret returns the plaintext HMAC signing secret held transiently. It is a
// credential: never render it into a page, log it, or place it in a URL. The
// persistence adapter seals it (AES-256-GCM) before it reaches a column.
func (c *Config) SigningSecret() string { return c.signingSecret }

// Enabled reports whether delivery is switched on. F0 stores this only; F2 consults
// it before forwarding.
func (c *Config) Enabled() bool { return c.enabled }

// CreatedAt returns the first-provisioned instant.
func (c *Config) CreatedAt() time.Time { return c.createdAt }

// UpdatedAt returns the last-write instant.
func (c *Config) UpdatedAt() time.Time { return c.updatedAt }

// LogValue implements slog.LogValuer so structured logging of a Config emits only
// non-secret descriptors. The signing secret is redacted so a stray log call can
// never leak the credential material.
func (c *Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("account_id", c.accountID),
		slog.String("url", c.url),
		slog.String("signing_secret", "[REDACTED]"),
		slog.Bool("enabled", c.enabled),
		slog.Time("created_at", c.createdAt),
		slog.Time("updated_at", c.updatedAt),
	)
}

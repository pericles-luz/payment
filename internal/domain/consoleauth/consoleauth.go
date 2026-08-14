// Package consoleauth is the pure domain of the self-contained console login
// (ADR-0001 Opção B, SIN-69265): the operator credential (username + argon2id
// password hash + TOTP secret), the RFC 6238 TOTP verifier, and the server-side
// session value object.
//
// It is transport- and storage-agnostic by construction — it imports no
// database/sql, no net/http and no vendor SDK. Persistence (session store,
// credential store, TOTP replay guard) lives behind ports the app layer declares
// and adapters satisfy; the HTTP adapter owns cookies, CSRF and rate limiting.
// Secrets (the password plaintext, the password hash, the TOTP secret) are held
// only as opaque values here and are NEVER rendered or logged by this package.
package consoleauth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"
)

// Errors surfaced by the domain. The verification helpers deliberately do NOT
// distinguish "no such user" from "wrong password/code": the app layer maps every
// authentication failure to a single generic error so the login surface is not a
// user-enumeration oracle (OWASP A07).
var (
	// ErrEmptyPassword is returned by HashPassword for an empty plaintext — a
	// credential must never be provisioned with a blank password.
	ErrEmptyPassword = errors.New("consoleauth: empty password")
)

// sessionIDBytes is the entropy of an opaque session id: 32 bytes (256 bits)
// makes an unauthenticated id infeasible to guess. The cookie carries ONLY this
// id; all session state lives server-side behind the SessionStore port.
const sessionIDBytes = 32

// GenerateSessionID mints a fresh, opaque 256-bit session id encoded base64url
// without padding (43 chars). It is the only value written to the session cookie.
// Returns an error only if the system CSPRNG fails.
func GenerateSessionID() (string, error) {
	b := make([]byte, sessionIDBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Credential is the single console operator's stored identity: the fixed
// username, the argon2id-encoded password hash (never the plaintext), and the
// base32 TOTP shared secret. It is provisioned once at bootstrap and then locked.
// All three fields are unexported so a Credential can only be built through
// NewCredential (fresh provisioning) or RehydrateCredential (load from a store),
// and the secret material never leaks through an accidental struct literal.
type Credential struct {
	username     string
	passwordHash string
	totpSecret   string
}

// NewCredential builds a credential from a username, an argon2id-encoded password
// hash (see HashPassword) and a base32 TOTP secret (see GenerateTOTPSecret).
func NewCredential(username, passwordHash, totpSecret string) Credential {
	return Credential{username: username, passwordHash: passwordHash, totpSecret: totpSecret}
}

// RehydrateCredential reconstructs a credential loaded from a store. It is a
// synonym for NewCredential kept as a distinct name so persistence adapters read
// clearly (load, not mint).
func RehydrateCredential(username, passwordHash, totpSecret string) Credential {
	return NewCredential(username, passwordHash, totpSecret)
}

// Username returns the operator's login name (non-secret).
func (c Credential) Username() string { return c.username }

// PasswordHash returns the argon2id-encoded hash for persistence. It is not the
// plaintext and is safe to store; it is still never logged.
func (c Credential) PasswordHash() string { return c.passwordHash }

// TOTPSecret returns the base32 TOTP shared secret. It IS secret — a persistence
// adapter must protect it at rest (encrypt) and never log it.
func (c Credential) TOTPSecret() string { return c.totpSecret }

// VerifyPassword reports whether plain matches the stored hash, in constant time
// with respect to the hash contents (see VerifyPassword). A malformed stored hash
// yields false.
func (c Credential) VerifyPassword(plain string) bool {
	return VerifyPassword(c.passwordHash, plain)
}

// Session is a server-side authenticated session. The opaque id is the only thing
// the browser cookie carries; the subject (operator username), the absolute
// expiry and the last-seen instant (idle timeout) all live here, server-side.
// Fields are unexported so a session is only built via NewSession / RehydrateSession
// and mutated via Touched — its lifetime invariants cannot be bypassed.
type Session struct {
	id         string
	subject    string
	createdAt  time.Time
	expiresAt  time.Time
	lastSeenAt time.Time
}

// NewSession mints a session for subject, valid from now until now+absolute
// (absolute expiry). lastSeenAt starts at now for the idle-timeout clock.
func NewSession(id, subject string, now time.Time, absolute time.Duration) Session {
	return Session{
		id:         id,
		subject:    subject,
		createdAt:  now,
		expiresAt:  now.Add(absolute),
		lastSeenAt: now,
	}
}

// RehydrateSession reconstructs a session loaded from a store.
func RehydrateSession(id, subject string, createdAt, expiresAt, lastSeenAt time.Time) Session {
	return Session{id: id, subject: subject, createdAt: createdAt, expiresAt: expiresAt, lastSeenAt: lastSeenAt}
}

// ID returns the opaque session id.
func (s Session) ID() string { return s.id }

// Subject returns the authenticated operator username.
func (s Session) Subject() string { return s.subject }

// CreatedAt returns when the session was minted.
func (s Session) CreatedAt() time.Time { return s.createdAt }

// ExpiresAt returns the absolute expiry (independent of activity).
func (s Session) ExpiresAt() time.Time { return s.expiresAt }

// LastSeenAt returns the last time the session was exercised (idle clock).
func (s Session) LastSeenAt() time.Time { return s.lastSeenAt }

// Valid reports whether the session is still usable at now: it must be before the
// absolute expiry AND, when idle > 0, within idle of the last-seen instant. Both
// bounds are enforced so a long-lived session cannot outlive either the absolute
// or the inactivity window.
func (s Session) Valid(now time.Time, idle time.Duration) bool {
	if !now.Before(s.expiresAt) {
		return false
	}
	if idle > 0 && now.Sub(s.lastSeenAt) > idle {
		return false
	}
	return true
}

// Touched returns a copy of the session with last-seen advanced to now, resetting
// the idle clock. The absolute expiry is unchanged — activity never extends the
// absolute lifetime.
func (s Session) Touched(now time.Time) Session {
	s.lastSeenAt = now
	return s
}

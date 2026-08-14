package app

import (
	"context"
	"crypto/subtle"
	"errors"
	"sync"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/consoleauth"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// ConsoleAuthService is the use-case layer for the self-contained console login
// (ADR-0001 Opção B, SIN-69265): first-access bootstrap provisioning, username +
// password + TOTP verification with a single-use replay guard and brute-force
// lockout, and the server-side session lifecycle (create / authenticate+touch /
// revoke). It depends only on narrow storage ports (accept-narrow); the HTTP
// adapter owns cookies, CSRF and per-IP rate limiting on top.
//
// Every authentication failure collapses to one generic ErrInvalidCredentials so
// the login surface cannot be used to enumerate users or probe which factor was
// wrong (OWASP A07). Secrets (password plaintext, hash, TOTP secret) are only ever
// held as opaque domain values and are never logged.
type ConsoleAuthService struct {
	creds    ConsoleCredentialStore
	sessions SessionStore
	replay   TOTPReplayStore
	clock    ports.Clock

	username       string
	issuer         string
	bootstrapToken string
	absoluteTTL    time.Duration
	idleTTL        time.Duration

	lockout *loginLockout
}

// ConsoleAuthConfig configures a ConsoleAuthService. Username defaults to
// "pericles.luz" and the TTLs/lockout to secure defaults when left zero, so a
// caller only has to supply the stores, clock and bootstrap token.
type ConsoleAuthConfig struct {
	// Username is the single fixed operator login (config, not hard-coded in the
	// domain). Empty ⇒ defaultConsoleUsername.
	Username string
	// Issuer labels the otpauth URI shown at bootstrap (the authenticator app entry
	// name). Empty ⇒ defaultConsoleIssuer.
	Issuer string
	// BootstrapToken gates first-access provisioning: /console/bootstrap only mints a
	// credential when the caller presents this exact token AND none is provisioned
	// yet. Empty ⇒ bootstrap is DISABLED entirely (failure-closed): no token, no
	// provisioning, so the feature can never become an anonymous land-grab.
	BootstrapToken string
	// AbsoluteTTL bounds a session's total lifetime regardless of activity. Zero ⇒
	// defaultAbsoluteTTL.
	AbsoluteTTL time.Duration
	// IdleTTL revokes a session after this much inactivity (reset on each
	// authenticated request). Zero ⇒ defaultIdleTTL.
	IdleTTL time.Duration
	// MaxFailures / LockoutWindow configure the per-username brute-force lockout.
	// Zero ⇒ defaultMaxFailures / defaultLockoutWindow.
	MaxFailures   int
	LockoutWindow time.Duration
}

const (
	defaultConsoleUsername = "pericles.luz"
	defaultConsoleIssuer   = "Pagamentos Admin"
	defaultAbsoluteTTL     = 12 * time.Hour
	defaultIdleTTL         = 30 * time.Minute
	defaultMaxFailures     = 5
	defaultLockoutWindow   = 15 * time.Minute
)

// ConsoleCredentialStore persists the single operator credential provisioned at
// bootstrap. Get reports whether one exists (ok=false ⇒ not provisioned yet);
// Save writes it once. The TOTP secret it round-trips is secret — a durable
// adapter MUST encrypt it at rest.
type ConsoleCredentialStore interface {
	GetCredential(ctx context.Context) (consoleauth.Credential, bool, error)
	SaveCredential(ctx context.Context, c consoleauth.Credential) error
}

// SessionStore is the server-side session persistence. The cookie carries only
// the opaque id; every other field lives here. Get reports ok=false for an
// unknown id; Touch advances last-seen (idle clock); Delete revokes (logout /
// expiry cleanup).
type SessionStore interface {
	Create(ctx context.Context, s consoleauth.Session) error
	Get(ctx context.Context, id string) (consoleauth.Session, bool, error)
	Touch(ctx context.Context, id string, lastSeen time.Time) error
	Delete(ctx context.Context, id string) error
}

// TOTPReplayStore records the last TOTP step consumed for a subject so a code
// cannot be replayed within its validity window. LastStep returns 0 when none was
// recorded (the zero step is never a valid unix/period counter for a real clock).
type TOTPReplayStore interface {
	LastStep(ctx context.Context, subject string) (int64, error)
	SetLastStep(ctx context.Context, subject string, step int64) error
}

// Console auth errors. They are intentionally coarse on the login path (one
// generic invalid-credentials error) and specific on the bootstrap path (the
// operator provisioning the box needs to know WHY it was refused).
var (
	// ErrInvalidCredentials is the single generic login failure (bad user, bad
	// password, bad/replayed TOTP, or a locked account) — no enumeration oracle.
	ErrInvalidCredentials = errors.New("credenciais inválidas")
	// ErrConsoleAuthUnavailable is returned when the service was wired without the
	// stores it needs (a misconfiguration in production; some tests omit it).
	ErrConsoleAuthUnavailable = errors.New("console auth not configured")
	// ErrBootstrapDisabled is returned when no bootstrap token is configured, so
	// first-access provisioning is switched off entirely (failure-closed).
	ErrBootstrapDisabled = errors.New("bootstrap desabilitado")
	// ErrBootstrapForbidden is returned when the presented bootstrap token does not
	// match the configured one.
	ErrBootstrapForbidden = errors.New("bootstrap não autorizado")
	// ErrBootstrapLocked is returned when a credential is already provisioned: the
	// one-time bootstrap has been consumed and cannot be re-run (anti-takeover).
	ErrBootstrapLocked = errors.New("credencial já provisionada")
)

// dummyArgon2Hash is a real argon2id hash of a random throwaway password. It is
// verified against on the "no credential provisioned" and "wrong username" paths
// so the login handler spends the same argon2 work whether or not the operator
// exists — closing the timing side-channel that would otherwise reveal whether a
// credential is set (OWASP A07). It can never match a real login (its plaintext is
// unknown), so it is safe.
var dummyArgon2Hash = func() string {
	h, err := consoleauth.HashPassword("consoleauth-timing-equalizer-not-a-real-password")
	if err != nil {
		// HashPassword only fails on CSPRNG failure at init; fall back to a
		// syntactically valid constant so VerifyPassword still does argon2 work.
		return "$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	}
	return h
}()

// NewConsoleAuthService builds the service from its stores and config, applying
// secure defaults. A nil creds or sessions store leaves the service inert: Login
// and Authenticate fail closed (ErrConsoleAuthUnavailable / no session), so wiring
// it is always safe.
func NewConsoleAuthService(creds ConsoleCredentialStore, sessions SessionStore, replay TOTPReplayStore, clock ports.Clock, cfg ConsoleAuthConfig) *ConsoleAuthService {
	if cfg.Username == "" {
		cfg.Username = defaultConsoleUsername
	}
	if cfg.Issuer == "" {
		cfg.Issuer = defaultConsoleIssuer
	}
	if cfg.AbsoluteTTL <= 0 {
		cfg.AbsoluteTTL = defaultAbsoluteTTL
	}
	if cfg.IdleTTL <= 0 {
		cfg.IdleTTL = defaultIdleTTL
	}
	if cfg.MaxFailures <= 0 {
		cfg.MaxFailures = defaultMaxFailures
	}
	if cfg.LockoutWindow <= 0 {
		cfg.LockoutWindow = defaultLockoutWindow
	}
	return &ConsoleAuthService{
		creds:          creds,
		sessions:       sessions,
		replay:         replay,
		clock:          clock,
		username:       cfg.Username,
		issuer:         cfg.Issuer,
		bootstrapToken: cfg.BootstrapToken,
		absoluteTTL:    cfg.AbsoluteTTL,
		idleTTL:        cfg.IdleTTL,
		lockout:        newLoginLockout(cfg.MaxFailures, cfg.LockoutWindow),
	}
}

// BootstrapEnabled reports whether first-access provisioning is switched on (a
// bootstrap token is configured). When false the HTTP adapter renders the
// bootstrap route as disabled (failure-closed).
func (s *ConsoleAuthService) BootstrapEnabled() bool { return s.bootstrapToken != "" }

// Username returns the fixed operator login (for pre-filling the login form).
func (s *ConsoleAuthService) Username() string { return s.username }

// Provisioned reports whether the operator credential has been set. A store error
// is treated as "provisioned" (fail-safe: never advertise the box as un-bootstrapped
// on a transient read failure, which would invite a takeover attempt).
func (s *ConsoleAuthService) Provisioned(ctx context.Context) bool {
	if s.creds == nil {
		return false
	}
	_, ok, err := s.creds.GetCredential(ctx)
	if err != nil {
		return true
	}
	return ok
}

// BootstrapResult is the one-time output of first-access provisioning: the
// generated password and the otpauth provisioning URI, shown to the operator
// EXACTLY once and never persisted in plaintext or logged.
type BootstrapResult struct {
	Username   string
	Password   string
	TOTPSecret string
	OTPAuthURI string
}

// Bootstrap provisions the operator credential on first access, gated by the
// deploy bootstrap token. It fails closed at every step: no token configured
// (ErrBootstrapDisabled), wrong token (ErrBootstrapForbidden, constant-time
// compare), or already provisioned (ErrBootstrapLocked). On success it generates a
// random password + TOTP secret, stores the password HASH + secret, and returns
// the plaintext password and otpauth URI once. It then cannot be re-run — the
// stored credential makes every future call ErrBootstrapLocked.
func (s *ConsoleAuthService) Bootstrap(ctx context.Context, token string) (BootstrapResult, error) {
	if s.creds == nil {
		return BootstrapResult{}, ErrConsoleAuthUnavailable
	}
	if s.bootstrapToken == "" {
		return BootstrapResult{}, ErrBootstrapDisabled
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(s.bootstrapToken)) != 1 {
		return BootstrapResult{}, ErrBootstrapForbidden
	}
	if _, ok, err := s.creds.GetCredential(ctx); err != nil {
		return BootstrapResult{}, err
	} else if ok {
		return BootstrapResult{}, ErrBootstrapLocked
	}

	password, err := generateBootstrapPassword()
	if err != nil {
		return BootstrapResult{}, err
	}
	secret, err := consoleauth.GenerateTOTPSecret()
	if err != nil {
		return BootstrapResult{}, err
	}
	hash, err := consoleauth.HashPassword(password)
	if err != nil {
		return BootstrapResult{}, err
	}
	cred := consoleauth.NewCredential(s.username, hash, secret)
	if err := s.creds.SaveCredential(ctx, cred); err != nil {
		return BootstrapResult{}, err
	}
	return BootstrapResult{
		Username:   s.username,
		Password:   password,
		TOTPSecret: secret,
		OTPAuthURI: consoleauth.OTPAuthURI(s.issuer, s.username, secret),
	}, nil
}

// Login verifies username + password + TOTP and, on success, creates and returns
// a fresh server-side session id (rotated per login — anti-fixation, since the id
// is brand new). Every failure returns the single generic ErrInvalidCredentials
// and records a lockout strike for the username; too many strikes within the
// window lock the account temporarily (brute-force defence). The TOTP replay guard
// is advanced ONLY on a fully successful login, so a wrong password never consumes
// a step.
func (s *ConsoleAuthService) Login(ctx context.Context, username, password, code string) (string, error) {
	if s.creds == nil || s.sessions == nil {
		return "", ErrConsoleAuthUnavailable
	}
	now := s.clock.Now()
	// Lockout key is the presented username (attacker-controlled), which is fine:
	// the only real username is s.username, so strikes concentrate there and a
	// flood on random usernames cannot lock the real account out of proportion.
	if s.lockout.locked(username, now) {
		return "", ErrInvalidCredentials
	}

	cred, ok, err := s.creds.GetCredential(ctx)
	if err != nil {
		return "", ErrConsoleAuthUnavailable
	}

	// Always spend argon2 work (real hash when provisioned, dummy otherwise) so the
	// response time does not reveal whether a credential exists.
	userMatch := ok && subtle.ConstantTimeCompare([]byte(username), []byte(cred.Username())) == 1
	passOK := false
	if userMatch {
		passOK = cred.VerifyPassword(password)
	} else {
		_ = consoleauth.VerifyPassword(dummyArgon2Hash, password)
	}

	if !userMatch || !passOK {
		s.lockout.strike(username, now)
		return "", ErrInvalidCredentials
	}

	step, totpOK := consoleauth.VerifyTOTP(cred.TOTPSecret(), code, now)
	if !totpOK || !s.totpFresh(ctx, cred.Username(), step) {
		s.lockout.strike(username, now)
		return "", ErrInvalidCredentials
	}

	// Success: consume the TOTP step (single-use), reset lockout, mint the session.
	if err := s.replaySet(ctx, cred.Username(), step); err != nil {
		return "", err
	}
	s.lockout.reset(username)

	id, err := consoleauth.GenerateSessionID()
	if err != nil {
		return "", err
	}
	sess := consoleauth.NewSession(id, cred.Username(), now, s.absoluteTTL)
	if err := s.sessions.Create(ctx, sess); err != nil {
		return "", err
	}
	return id, nil
}

// totpFresh reports whether step has not already been consumed for subject (replay
// guard). With no replay store it degrades to "always fresh" — acceptable only in
// tests; production always wires one. A store error fails closed (treated as
// replayed) so a transient fault never opens the replay window.
func (s *ConsoleAuthService) totpFresh(ctx context.Context, subject string, step int64) bool {
	if s.replay == nil {
		return true
	}
	last, err := s.replay.LastStep(ctx, subject)
	if err != nil {
		return false
	}
	return step > last
}

func (s *ConsoleAuthService) replaySet(ctx context.Context, subject string, step int64) error {
	if s.replay == nil {
		return nil
	}
	return s.replay.SetLastStep(ctx, subject, step)
}

// Authenticate validates a session id from the cookie and, when still valid,
// advances its idle clock (touch) and returns the subject. An unknown, expired or
// idle-timed-out session returns ok=false; an expired/idle one is proactively
// revoked so a stale id cannot linger. This is the read side the console auth
// middleware calls on every protected request.
func (s *ConsoleAuthService) Authenticate(ctx context.Context, sessionID string) (subject string, ok bool) {
	if s == nil || s.sessions == nil || sessionID == "" {
		return "", false
	}
	sess, found, err := s.sessions.Get(ctx, sessionID)
	if err != nil || !found {
		return "", false
	}
	now := s.clock.Now()
	if !sess.Valid(now, s.idleTTL) {
		_ = s.sessions.Delete(ctx, sessionID)
		return "", false
	}
	// Advance the idle clock. A touch failure does not deny an otherwise-valid
	// request (the absolute expiry still bounds the session); it just skips the
	// idle refresh this round.
	_ = s.sessions.Touch(ctx, sessionID, now)
	return sess.Subject(), true
}

// Logout revokes a session id (idempotent — an unknown id is a no-op success).
func (s *ConsoleAuthService) Logout(ctx context.Context, sessionID string) error {
	if s.sessions == nil || sessionID == "" {
		return nil
	}
	return s.sessions.Delete(ctx, sessionID)
}

// loginLockout is a process-local, per-key brute-force limiter: it counts recent
// failures and, once they reach the threshold within the window, reports the key
// as locked until the window elapses from the last strike. It is in-memory (like
// the session store in this first delivery) and safe for concurrent use.
type loginLockout struct {
	mu       sync.Mutex
	max      int
	window   time.Duration
	failures map[string]lockoutEntry
}

type lockoutEntry struct {
	count int
	until time.Time // when the current strike streak's window expires
}

func newLoginLockout(max int, window time.Duration) *loginLockout {
	return &loginLockout{max: max, window: window, failures: map[string]lockoutEntry{}}
}

// locked reports whether key is currently locked out at now.
func (l *loginLockout) locked(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.failures[key]
	if !ok {
		return false
	}
	if now.After(e.until) {
		// Window elapsed — the streak is stale; clear it.
		delete(l.failures, key)
		return false
	}
	return e.count >= l.max
}

// strike records a failure for key, extending the window from now.
func (l *loginLockout) strike(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.failures[key]
	if !ok || now.After(e.until) {
		e = lockoutEntry{}
	}
	e.count++
	e.until = now.Add(l.window)
	l.failures[key] = e
}

// reset clears any strikes for key (a successful login).
func (l *loginLockout) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, key)
}

// generateBootstrapPassword mints a strong random password for first-access
// provisioning, encoded base64url (URL/paste-safe, no ambiguous padding). The
// underlying id is 256 bits of entropy; 24 chars of it is ~144 bits, far beyond
// any brute-force reach. It is shown once and then only its argon2id hash is kept.
func generateBootstrapPassword() (string, error) {
	id, err := consoleauth.GenerateSessionID() // 32 random bytes, base64url
	if err != nil {
		return "", err
	}
	return id[:24], nil
}

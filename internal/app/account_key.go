package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// ErrAccountKeyAlreadyRotated is returned by RotateAccountKey when a mint is
// replayed under an Idempotency-Key that already minted a key for the same account
// within the dedup window. It is NOT an error in the failure sense — it is the
// idempotent, display-once outcome: the guard collapses the retry so it does NOT
// mint a second key (which would invalidate the key the first response already
// delivered), and it deliberately does NOT return the plaintext again (ADR-0010
// display-once — "nunca retornado 2x"). A caller that lost the original response
// must rotate again with a FRESH Idempotency-Key to obtain a new secret. The HTTP
// adapter maps this sentinel to 409 Conflict.
var ErrAccountKeyAlreadyRotated = errors.New("account key already rotated for this idempotency key")

// accountKeyMinter is the narrow slice of ports.AccountKeyStore the rotation
// use-case needs: mint a fresh key for an account (create==rotate, invalidating any
// previous key) and return the plaintext ONCE. Declared here (accept-narrow) so the
// service depends on an interface, not the whole store; satisfied by both the
// in-memory and sqlite AccountKeyStore adapters.
type accountKeyMinter interface {
	PutKey(ctx context.Context, accountID string) (plaintext string, err error)
}

// accountKeyIdempotencyTTL bounds how long a used Idempotency-Key is remembered.
// A rotation is a rare, deliberate action; a double-submit (buggy client retry or a
// lost-response retry) is inherently same-process/same-minute, so a short window
// closes the realistic double-mint race while keeping the guard tiny. It is process
// -local (see accountKeyGuard): a cross-instance/cross-restart replay is not
// collapsed, but the WORST case there is a redundant rotation the Account can see
// and repeat — never a leaked or twice-shown secret.
const accountKeyIdempotencyTTL = 15 * time.Minute

// AccountKeyService is the use-case that mints/rotates an Account's rotatable bearer
// key (model (b), ADR-0011 §3 / SIN-69280). It backs two write surfaces — the
// Account self-rotating via /v1 with its existing key, and the admin plane
// bootstrapping the FIRST key for an Account — with the SAME create==rotate path, so
// the invariants (mint-new + invalidate-previous, display-once, no double-mint) hold
// identically regardless of who calls it.
//
// The secret plaintext is returned by this service to its caller exactly once and is
// NEVER stored, logged, or cached: the idempotency guard remembers only that a key
// was used, not the secret it minted (see accountKeyIdempotencyGuard). That is what
// makes "nunca retornado 2x" true even under retries.
type AccountKeyService struct {
	keys  accountKeyMinter
	clock ports.Clock
	guard *accountKeyIdempotencyGuard
	// audit + ids are the OPTIONAL audit sink (SIN-69386). When wired (production, via
	// WithAccountKeyAudit) every successful mint appends one account-scoped
	// account.key_mint entry from THIS shared choke-point, so both write surfaces
	// (JSON admin bootstrap + HTML console) are covered uniformly without either
	// handler carrying audit logic. When nil (the pre-existing constructor calls and
	// their tests) the service behaves exactly as before — no audit — so the change is
	// purely additive.
	audit ports.AuditLog
	ids   ports.IDProvider
}

// AccountKeyOption configures optional AccountKeyService collaborators without
// breaking the existing two-argument constructor (mirrors the GenerateBatchOption
// pattern). Today the only option wires the audit sink.
type AccountKeyOption func(*AccountKeyService)

// WithAccountKeyAudit wires the account-key mint audit trail (SIN-69386): every
// successful mint emits one account-scoped audit.ActionMintAccountKey entry from the
// shared RotateAccountKey choke-point. Both the audit sink and an id provider are
// required to attribute and identify the entry; production passes the durable
// audit_log store and the system id provider. Passing this opts the service into
// fail-closed audit (an append failure fails the mint, matching the console's other
// audited mutations); omitting it keeps the prior no-audit behaviour.
func WithAccountKeyAudit(a ports.AuditLog, ids ports.IDProvider) AccountKeyOption {
	return func(s *AccountKeyService) {
		s.audit = a
		s.ids = ids
	}
}

// NewAccountKeyService wires the service over the account-key store and a clock. The
// store is required (a nil store yields a service that always errors, so a
// misconfiguration fails closed rather than silently succeeding). The clock is the
// caller's to supply (production wires the system clock; tests inject a
// deterministic one) and drives the idempotency-guard TTL. Optional collaborators
// (e.g. the audit sink, WithAccountKeyAudit) are supplied as options so the existing
// two-argument callers keep compiling unchanged.
func NewAccountKeyService(keys ports.AccountKeyStore, clock ports.Clock, opts ...AccountKeyOption) *AccountKeyService {
	s := &AccountKeyService{
		keys:  keys,
		clock: clock,
		guard: newAccountKeyIdempotencyGuard(accountKeyIdempotencyTTL),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// RotateAccountKey mints a fresh account-key for accountID and returns the plaintext
// ONCE (create==rotate: any previous key is invalidated immediately). Both write
// surfaces call this — the caller has already authenticated and resolved the
// authoritative accountID server-side (the Account's own key, or the admin-plane
// path id), so this method never derives identity from client input.
//
// idemKey is MANDATORY (the routes reject an empty one at the boundary; the service
// also rejects it, defense-in-depth). It dedups retries: the FIRST call under a
// given (account, idemKey) mints and returns the plaintext; a REPEAT within the TTL
// returns ErrAccountKeyAlreadyRotated with NO plaintext — no second mint (so a key
// the first response already delivered is not invalidated out from under the caller)
// and no second display of the secret (display-once, ADR-0010).
//
// The guard is held across the mint so two concurrent double-submits cannot both
// miss the cache and both mint. A mint FAILURE is not remembered, so a transient
// store error does not poison the idempotency key — a retry can still succeed.
func (s *AccountKeyService) RotateAccountKey(ctx context.Context, accountID, idemKey string) (string, error) {
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		return "", shared.NewValidationError("account_id", "account id is required")
	}
	idemKey = strings.TrimSpace(idemKey)
	if idemKey == "" {
		return "", shared.NewValidationError("idempotency_key", "idempotency key is required")
	}
	if s.keys == nil {
		return "", ErrAccountKeysUnavailable
	}

	gkey := accountID + "\x00" + idemKey
	s.guard.mu.Lock()
	defer s.guard.mu.Unlock()
	now := s.clock.Now()
	s.guard.pruneLocked(now)
	if _, seen := s.guard.seen[gkey]; seen {
		// Replay: never mint again, never re-show the secret (display-once).
		return "", ErrAccountKeyAlreadyRotated
	}
	plaintext, err := s.keys.PutKey(ctx, accountID)
	if err != nil {
		return "", err // do NOT record a failed mint; a retry must be able to succeed
	}
	// Audit the emission from THIS shared choke-point (SIN-69386) so both write
	// surfaces (JSON admin bootstrap + HTML console) are covered uniformly. It runs
	// only on a real mint — the replay path returned above BEFORE PutKey, so a 409
	// never reaches here and never emits a second entry. The entry records who
	// (operator, from the transport-set context), which Conta (accountID) and when —
	// NEVER the plaintext (the constructor has no secret parameter; display-once).
	// Fail-closed and BEFORE recording the idempotency key: an append failure returns
	// an error without consuming the key, so no mint is silently left un-audited and a
	// retry can still succeed (matching the console's other audited mutations).
	if err := s.appendMintAudit(ctx, accountID); err != nil {
		return "", err
	}
	// Record ONLY that this key was consumed (never the plaintext) so the next
	// replay collapses without ever holding the secret at rest.
	s.guard.seen[gkey] = s.clock.Now()
	return plaintext, nil
}

// appendMintAudit emits the account-scoped account.key_mint audit entry for a
// successful mint (SIN-69386). It is a no-op when the audit sink is not wired (the
// pre-existing two-argument constructor, so a stripped-down deployment/test keeps its
// prior behaviour). The operator id is read from the context set by whichever
// transport authenticated the caller — the admin token pseudonym, the console
// session subject, or the self-serve account id — so the same choke-point attributes
// all three surfaces without knowing which one called it.
func (s *AccountKeyService) appendMintAudit(ctx context.Context, accountID string) error {
	if s.audit == nil || s.ids == nil {
		return nil
	}
	entry, err := audit.NewAccountKeyMintEntry(s.ids.NewID(), OperatorIDFromContext(ctx), accountID, s.clock.Now())
	if err != nil {
		return fmt.Errorf("build account-key mint audit entry: %w", err)
	}
	if err := s.audit.Append(ctx, entry); err != nil {
		return fmt.Errorf("append account-key mint audit entry: %w", err)
	}
	return nil
}

// ErrAccountKeysUnavailable is returned when the account-key store is not wired. It
// mirrors the other "store not configured" sentinels so a stripped-down deployment
// fails closed with a clear error instead of a nil-pointer panic.
var ErrAccountKeysUnavailable = errors.New("account key store not configured")

// accountKeyIdempotencyGuard is the process-local, TTL-bounded dedup store for
// account-key rotation (SIN-69280), keyed by "<accountID>\x00<idemKey>". It stores
// only the instant a key was consumed — NEVER the minted plaintext — so a replay can
// be collapsed without the secret ever living at rest (display-once). The mutex is
// held across the guarded mint (see RotateAccountKey), so no separate reservation
// state is needed. It mirrors the invoiceBatchGuard pattern (SIN-69184).
type accountKeyIdempotencyGuard struct {
	mu   sync.Mutex
	ttl  time.Duration
	seen map[string]time.Time
}

func newAccountKeyIdempotencyGuard(ttl time.Duration) *accountKeyIdempotencyGuard {
	return &accountKeyIdempotencyGuard{ttl: ttl, seen: make(map[string]time.Time)}
}

// pruneLocked drops entries older than the TTL. The caller MUST hold g.mu.
func (g *accountKeyIdempotencyGuard) pruneLocked(now time.Time) {
	for k, at := range g.seen {
		if now.Sub(at) > g.ttl {
			delete(g.seen, k)
		}
	}
}

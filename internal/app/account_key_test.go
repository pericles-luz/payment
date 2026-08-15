package app

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/domain/accountkey"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// akClock is a deterministic, advanceable clock local to the account-key rotation
// tests (the shared app_test clocks live in the external test package).
type akClock struct{ now time.Time }

func (c *akClock) Now() time.Time          { return c.now }
func (c *akClock) advance(d time.Duration) { c.now = c.now.Add(d) }

// akEpoch is a fixed instant for the deterministic mutable clock the rotation
// use-case tests advance to exercise the idempotency-guard TTL.
func akEpoch() time.Time { return time.Unix(1700000000, 0).UTC() }

// TestRotateAccountKeyMintsAndAuthenticates is the happy path: a first rotation
// mints a plaintext that (a) carries the account-key shape and (b) authenticates
// back to the account through the SAME store — proving the service returns a live,
// usable secret, not a placeholder.
func TestRotateAccountKeyMintsAndAuthenticates(t *testing.T) {
	t.Parallel()
	store := persistence.NewAccountKeyStore(&akClock{now: akEpoch()})
	svc := NewAccountKeyService(store, &akClock{now: akEpoch()})

	secret, err := svc.RotateAccountKey(context.Background(), "acct-A", "idem-1")
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if !accountkey.HasSecretShape(secret) {
		t.Fatalf("minted secret lacks the account-key shape: %q", secret)
	}
	acct, ok := store.AuthenticateAccountKey(context.Background(), secret)
	if !ok || acct != "acct-A" {
		t.Fatalf("minted secret does not authenticate to acct-A: acct=%q ok=%v", acct, ok)
	}
}

// TestRotateAccountKeyIdempotentReplay proves the display-once + no-double-mint
// contract: a repeat under the SAME Idempotency-Key returns ErrAccountKeyAlreadyRotated
// with NO plaintext, and the FIRST key still authenticates (the retry did not mint a
// second key that would have invalidated it).
func TestRotateAccountKeyIdempotentReplay(t *testing.T) {
	t.Parallel()
	store := persistence.NewAccountKeyStore(&akClock{now: akEpoch()})
	svc := NewAccountKeyService(store, &akClock{now: akEpoch()})

	first, err := svc.RotateAccountKey(context.Background(), "acct-A", "idem-1")
	if err != nil {
		t.Fatalf("first rotate: %v", err)
	}
	replay, err := svc.RotateAccountKey(context.Background(), "acct-A", "idem-1")
	if !errors.Is(err, ErrAccountKeyAlreadyRotated) {
		t.Fatalf("want ErrAccountKeyAlreadyRotated on replay, got err=%v secret=%q", err, replay)
	}
	if replay != "" {
		t.Fatalf("display-once violated: replay returned a secret %q", replay)
	}
	// The first key survives the collapsed replay (no second mint invalidated it).
	if acct, ok := store.AuthenticateAccountKey(context.Background(), first); !ok || acct != "acct-A" {
		t.Fatalf("first key stopped authenticating after replay: acct=%q ok=%v", acct, ok)
	}
}

// TestRotateAccountKeyFreshKeyRotates proves create==rotate: a DIFFERENT
// Idempotency-Key mints a new secret and invalidates the previous one immediately.
func TestRotateAccountKeyFreshKeyRotates(t *testing.T) {
	t.Parallel()
	store := persistence.NewAccountKeyStore(&akClock{now: akEpoch()})
	svc := NewAccountKeyService(store, &akClock{now: akEpoch()})

	first, err := svc.RotateAccountKey(context.Background(), "acct-A", "idem-1")
	if err != nil {
		t.Fatalf("first rotate: %v", err)
	}
	second, err := svc.RotateAccountKey(context.Background(), "acct-A", "idem-2")
	if err != nil {
		t.Fatalf("second rotate: %v", err)
	}
	if first == second {
		t.Fatalf("rotation returned the same secret twice")
	}
	if _, ok := store.AuthenticateAccountKey(context.Background(), first); ok {
		t.Fatalf("previous key still authenticates after rotation (not invalidated)")
	}
	if acct, ok := store.AuthenticateAccountKey(context.Background(), second); !ok || acct != "acct-A" {
		t.Fatalf("new key does not authenticate: acct=%q ok=%v", acct, ok)
	}
}

// TestRotateAccountKeyTTLExpiryAllowsReuse proves the idempotency guard is
// TTL-bounded: once the window elapses, the same Idempotency-Key is no longer a
// replay and a fresh mint proceeds (it can never wedge a key permanently).
func TestRotateAccountKeyTTLExpiryAllowsReuse(t *testing.T) {
	t.Parallel()
	clock := &akClock{now: akEpoch()}
	store := persistence.NewAccountKeyStore(clock)
	svc := NewAccountKeyService(store, clock)

	if _, err := svc.RotateAccountKey(context.Background(), "acct-A", "idem-1"); err != nil {
		t.Fatalf("first rotate: %v", err)
	}
	// Within the TTL: still a replay.
	if _, err := svc.RotateAccountKey(context.Background(), "acct-A", "idem-1"); !errors.Is(err, ErrAccountKeyAlreadyRotated) {
		t.Fatalf("want replay within TTL, got %v", err)
	}
	clock.advance(accountKeyIdempotencyTTL + time.Second)
	// After the TTL: the key is forgotten, so this mints again rather than replaying.
	if _, err := svc.RotateAccountKey(context.Background(), "acct-A", "idem-1"); err != nil {
		t.Fatalf("want fresh mint after TTL, got %v", err)
	}
}

// TestRotateAccountKeyValidation covers the boundary rejections: an empty account id
// or an empty Idempotency-Key is a validation error (the routes also enforce the
// key, defense-in-depth), and a nil store fails closed.
func TestRotateAccountKeyValidation(t *testing.T) {
	t.Parallel()
	store := persistence.NewAccountKeyStore(&akClock{now: akEpoch()})
	svc := NewAccountKeyService(store, &akClock{now: akEpoch()})

	if _, err := svc.RotateAccountKey(context.Background(), "  ", "idem-1"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty account id: want validation error, got %v", err)
	}
	if _, err := svc.RotateAccountKey(context.Background(), "acct-A", "  "); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty idempotency key: want validation error, got %v", err)
	}
	nilSvc := NewAccountKeyService(nil, &akClock{now: akEpoch()})
	if _, err := nilSvc.RotateAccountKey(context.Background(), "acct-A", "idem-1"); !errors.Is(err, ErrAccountKeysUnavailable) {
		t.Fatalf("nil store: want ErrAccountKeysUnavailable, got %v", err)
	}
}

// TestRotateAccountKeyFailedMintNotRemembered proves a failed mint does NOT poison
// the Idempotency-Key: a transient store error surfaces, and a retry under the SAME
// key still succeeds (the guard remembers only successful mints).
func TestRotateAccountKeyFailedMintNotRemembered(t *testing.T) {
	t.Parallel()
	m := &flakyMinter{failuresLeft: 1}
	svc := NewAccountKeyService(m, &akClock{now: akEpoch()})

	if _, err := svc.RotateAccountKey(context.Background(), "acct-A", "idem-1"); !errors.Is(err, errFlakyMint) {
		t.Fatalf("want the injected mint error, got %v", err)
	}
	secret, err := svc.RotateAccountKey(context.Background(), "acct-A", "idem-1")
	if err != nil {
		t.Fatalf("retry after transient failure should succeed, got %v", err)
	}
	if secret == "" {
		t.Fatalf("retry returned an empty secret")
	}
}

// errFlakyMint is the injected transient failure for the flaky store.
var errFlakyMint = errors.New("injected mint failure")

// flakyMinter is a ports.AccountKeyStore test double that fails PutKey a fixed number
// of times before succeeding — used ONLY to exercise the use-case's not-cache-a-
// failure behaviour, not persistence (the happy paths run against the real in-memory
// store, per the no-mock-the-DB rule).
type flakyMinter struct {
	failuresLeft int
	minted       int
}

func (m *flakyMinter) PutKey(_ context.Context, _ string) (string, error) {
	if m.failuresLeft > 0 {
		m.failuresLeft--
		return "", errFlakyMint
	}
	m.minted++
	return "ak_flaky_" + strconv.Itoa(m.minted), nil
}

func (m *flakyMinter) Rotate(ctx context.Context, accountID string) (string, error) {
	return m.PutKey(ctx, accountID)
}

func (m *flakyMinter) AuthenticateAccountKey(_ context.Context, _ string) (string, bool) {
	return "", false
}

var _ ports.AccountKeyStore = (*flakyMinter)(nil)

package inmemory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/domain/accountkey"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

// akClock is a minimal, advanceable clock so a test can give the mint and the
// rotation distinct instants.
type akClock struct{ t time.Time }

func (c *akClock) Now() time.Time { return c.t }

func TestAccountKeyPutAuthenticate(t *testing.T) {
	t.Parallel()
	s := inmemory.NewAccountKeyStore(&akClock{t: time.Unix(0, 0).UTC()})
	ctx := context.Background()

	secret, err := s.PutKey(ctx, "acct-1")
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if !accountkey.HasSecretShape(secret) {
		t.Fatalf("returned secret lacks the account-key prefix: %q", secret)
	}
	got, ok := s.AuthenticateAccountKey(ctx, secret)
	if !ok || got != "acct-1" {
		t.Fatalf("authenticate = (%q, %v), want (acct-1, true)", got, ok)
	}
}

func TestAccountKeyPutRequiresAccountID(t *testing.T) {
	t.Parallel()
	s := inmemory.NewAccountKeyStore(&akClock{t: time.Unix(0, 0).UTC()})
	if _, err := s.PutKey(context.Background(), ""); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation for empty account id, got %v", err)
	}
}

func TestAccountKeyUnknownAndEmptySecret(t *testing.T) {
	t.Parallel()
	s := inmemory.NewAccountKeyStore(&akClock{t: time.Unix(0, 0).UTC()})
	ctx := context.Background()
	if _, ok := s.AuthenticateAccountKey(ctx, "ak_never-issued"); ok {
		t.Fatal("unknown secret must not authenticate")
	}
	if _, ok := s.AuthenticateAccountKey(ctx, ""); ok {
		t.Fatal("empty secret must not authenticate")
	}
}

// TestAccountKeyRotateInvalidatesPrevious proves rotation: the old secret stops
// working the instant a new one is minted, and the new one authenticates.
func TestAccountKeyRotateInvalidatesPrevious(t *testing.T) {
	t.Parallel()
	clock := &akClock{t: time.Unix(0, 0).UTC()}
	s := inmemory.NewAccountKeyStore(clock)
	ctx := context.Background()

	first, err := s.PutKey(ctx, "acct-1")
	if err != nil {
		t.Fatalf("first put: %v", err)
	}
	clock.t = time.Unix(3600, 0).UTC()
	second, err := s.Rotate(ctx, "acct-1")
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if first == second {
		t.Fatal("rotation must mint a distinct secret")
	}
	if _, ok := s.AuthenticateAccountKey(ctx, first); ok {
		t.Fatal("rotated-out secret must no longer authenticate")
	}
	if got, ok := s.AuthenticateAccountKey(ctx, second); !ok || got != "acct-1" {
		t.Fatalf("new secret authenticate = (%q, %v), want (acct-1, true)", got, ok)
	}
}

// TestAccountKeyCreateEqualsRotate proves PutKey is idempotent in the create==rotate
// sense: calling it on an account that already has a key replaces the key exactly
// like Rotate does (previous invalidated, new active).
func TestAccountKeyCreateEqualsRotate(t *testing.T) {
	t.Parallel()
	s := inmemory.NewAccountKeyStore(&akClock{t: time.Unix(0, 0).UTC()})
	ctx := context.Background()

	first, err := s.PutKey(ctx, "acct-1")
	if err != nil {
		t.Fatalf("first put: %v", err)
	}
	second, err := s.PutKey(ctx, "acct-1") // second create == rotate
	if err != nil {
		t.Fatalf("second put: %v", err)
	}
	if first == second {
		t.Fatal("a second PutKey must mint a distinct secret (create==rotate)")
	}
	if _, ok := s.AuthenticateAccountKey(ctx, first); ok {
		t.Fatal("first secret must be invalidated by the second PutKey")
	}
	if _, ok := s.AuthenticateAccountKey(ctx, second); !ok {
		t.Fatal("second secret must authenticate")
	}
}

// TestAccountKeyIsolationBetweenAccounts proves one account's secret never resolves
// to another account.
func TestAccountKeyIsolationBetweenAccounts(t *testing.T) {
	t.Parallel()
	s := inmemory.NewAccountKeyStore(&akClock{t: time.Unix(0, 0).UTC()})
	ctx := context.Background()

	sa, err := s.PutKey(ctx, "acct-a")
	if err != nil {
		t.Fatalf("put a: %v", err)
	}
	sb, err := s.PutKey(ctx, "acct-b")
	if err != nil {
		t.Fatalf("put b: %v", err)
	}
	if got, _ := s.AuthenticateAccountKey(ctx, sa); got != "acct-a" {
		t.Fatalf("secret a resolved to %q", got)
	}
	if got, _ := s.AuthenticateAccountKey(ctx, sb); got != "acct-b" {
		t.Fatalf("secret b resolved to %q", got)
	}
}

package tenant_test

import (
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
)

// A freshly created tenant is a self-account (empty owner) — the dark-ship default
// that preserves the flat legacy behaviour (ADR-0009 §4).
func TestNewTenantIsSelfAccount(t *testing.T) {
	t.Parallel()
	tn, err := tenant.New("t1", "Acme", time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if tn.AccountID() != "" {
		t.Fatalf("want empty (self) account, got %q", tn.AccountID())
	}
}

func TestRehydrateWithAccount(t *testing.T) {
	t.Parallel()
	now := time.Unix(2, 0).UTC()
	// A backfilled tenant carries its owner.
	owned := tenant.RehydrateWithAccount("t1", "Acme", true, now, "acct-t1")
	if owned.AccountID() != "acct-t1" {
		t.Fatalf("want acct-t1, got %q", owned.AccountID())
	}
	if !owned.Active() || owned.ID() != "t1" || owned.Name() != "Acme" || !owned.CreatedAt().Equal(now) {
		t.Fatal("rehydrate-with-account field mismatch")
	}
	// A legacy row with NULL account_id reads back as a self-account; whitespace is trimmed.
	legacy := tenant.RehydrateWithAccount("t2", "Beta", true, now, "  ")
	if legacy.AccountID() != "" {
		t.Fatalf("want empty (self) account, got %q", legacy.AccountID())
	}
}

// AssignAccount is set-once: it binds from empty, is idempotent for the same id,
// and rejects re-parenting to a different account — the immutability invariant
// (ADR-0009 §3.2) that prevents attribution/billing drift.
func TestAssignAccountImmutable(t *testing.T) {
	t.Parallel()
	now := time.Unix(3, 0).UTC()

	t.Run("binds from empty", func(t *testing.T) {
		t.Parallel()
		tn, _ := tenant.New("t1", "Acme", now)
		if err := tn.AssignAccount(" acct-1 "); err != nil {
			t.Fatalf("assign: %v", err)
		}
		if tn.AccountID() != "acct-1" {
			t.Fatalf("want acct-1 (trimmed), got %q", tn.AccountID())
		}
	})

	t.Run("idempotent for same account", func(t *testing.T) {
		t.Parallel()
		tn, _ := tenant.New("t1", "Acme", now)
		if err := tn.AssignAccount("acct-1"); err != nil {
			t.Fatalf("first assign: %v", err)
		}
		if err := tn.AssignAccount("acct-1"); err != nil {
			t.Fatalf("re-assign same must be a no-op, got: %v", err)
		}
		if tn.AccountID() != "acct-1" {
			t.Fatalf("owner changed unexpectedly: %q", tn.AccountID())
		}
	})

	t.Run("rejects re-parent to different account", func(t *testing.T) {
		t.Parallel()
		tn, _ := tenant.New("t1", "Acme", now)
		if err := tn.AssignAccount("acct-1"); err != nil {
			t.Fatalf("first assign: %v", err)
		}
		err := tn.AssignAccount("acct-2")
		if !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("want ErrValidation on re-parent, got %v", err)
		}
		if tn.AccountID() != "acct-1" {
			t.Fatalf("owner must be unchanged after rejected re-parent, got %q", tn.AccountID())
		}
	})

	t.Run("rejects blank account", func(t *testing.T) {
		t.Parallel()
		tn, _ := tenant.New("t1", "Acme", now)
		if err := tn.AssignAccount("   "); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("want ErrValidation on blank, got %v", err)
		}
	})
}

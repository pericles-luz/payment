package sqlite_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/account"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
)

func TestAccountRoundTrip(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	now := time.Unix(1, 0).UTC()

	a, _ := account.New("a1", "Verz", now)
	if err := s.SaveAccount(ctx, a); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := s.FindAccountByID(ctx, "a1")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if got.Name() != "Verz" || !got.Active() {
		t.Fatal("account mismatch")
	}
	if _, err := s.FindAccountByID(ctx, "missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want not found, got %v", err)
	}

	// Upsert (deactivate) is retry-safe.
	a.Deactivate()
	if err := s.SaveAccount(ctx, a); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, _ = s.FindAccountByID(ctx, "a1")
	if got.Active() {
		t.Fatal("expected inactive after update")
	}
}

// A tenant bound to an account round-trips its owner; a self-account (empty owner)
// tenant round-trips as empty (NULL in the DB). And an admin upsert that only
// toggles active must NOT clobber the immutable, backfilled owner.
func TestTenantAccountRoundTrip(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	now := time.Unix(2, 0).UTC()

	// Owner account must exist first (FK tenants.account_id -> accounts.id).
	acc, _ := account.New("acct-owned", "Verz", now)
	if err := s.SaveAccount(ctx, acc); err != nil {
		t.Fatalf("save account: %v", err)
	}

	// Owned tenant.
	owned, _ := tenant.New("t-owned", "Acme", now)
	if err := owned.AssignAccount("acct-owned"); err != nil {
		t.Fatalf("assign: %v", err)
	}
	if err := s.SaveTenant(ctx, owned); err != nil {
		t.Fatalf("save owned tenant: %v", err)
	}
	got, err := s.FindTenantByID(ctx, "t-owned")
	if err != nil {
		t.Fatalf("find owned: %v", err)
	}
	if got.AccountID() != "acct-owned" {
		t.Fatalf("want acct-owned, got %q", got.AccountID())
	}

	// Self-account tenant persists a NULL owner and reads back empty.
	self, _ := tenant.New("t-self", "Beta", now)
	if err := s.SaveTenant(ctx, self); err != nil {
		t.Fatalf("save self tenant: %v", err)
	}
	got, _ = s.FindTenantByID(ctx, "t-self")
	if got.AccountID() != "" {
		t.Fatalf("want empty (self) owner, got %q", got.AccountID())
	}

	// Immutability at the persistence boundary: an admin deactivate upsert (which
	// carries no owner on the reloaded/rebuilt aggregate) must not wipe account_id.
	reloaded, _ := s.FindTenantByID(ctx, "t-owned")
	reloaded.Deactivate()
	if err := s.SaveTenant(ctx, reloaded); err != nil {
		t.Fatalf("deactivate upsert: %v", err)
	}
	got, _ = s.FindTenantByID(ctx, "t-owned")
	if got.AccountID() != "acct-owned" {
		t.Fatalf("owner clobbered by upsert: got %q", got.AccountID())
	}
	if got.Active() {
		t.Fatal("expected inactive after deactivate upsert")
	}

	// ListTenants also surfaces owners.
	all, err := s.ListTenants(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	owners := map[string]string{}
	for _, tn := range all {
		owners[tn.ID()] = tn.AccountID()
	}
	if owners["t-owned"] != "acct-owned" || owners["t-self"] != "" {
		t.Fatalf("list owners mismatch: %+v", owners)
	}
}

// A non-existent owner is rejected by the FK (a tenant cannot point at a
// non-existent account).
func TestTenantAccountForeignKeyEnforced(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	now := time.Unix(3, 0).UTC()

	orphan, _ := tenant.New("t-orphan", "Gamma", now)
	if err := orphan.AssignAccount("acct-ghost"); err != nil {
		t.Fatalf("assign: %v", err)
	}
	if err := s.SaveTenant(ctx, orphan); err == nil {
		t.Fatal("want FK violation for tenant pointing at non-existent account")
	}
}

package audit_test

import (
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/account"
	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
)

// TestEntryAccountIDDerivesSelfAccount checks that an audit entry's account
// attribution (SIN-69127) is the audited tenant's self-account, derived through the
// single source of truth (account.SelfAccountID) so it matches migration 0008's
// backfill ('acct-'||tenant_id) exactly. It holds for every constructor since they
// all require a tenant and derive the same way.
func TestEntryAccountIDDerivesSelfAccount(t *testing.T) {
	t.Parallel()
	at := time.Unix(100, 0).UTC()

	plain, err := audit.NewEntry("a1", "op", audit.ActionCreateTenant, "ten-1", at)
	if err != nil {
		t.Fatalf("new entry: %v", err)
	}
	if got, want := plain.AccountID(), account.SelfAccountID("ten-1"); got != want {
		t.Fatalf("account id = %q, want %q", got, want)
	}
	if plain.AccountID() != "acct-ten-1" {
		t.Fatalf("account id = %q, want acct-ten-1", plain.AccountID())
	}

	// A different constructor (credential.set) attributes to the same self-account.
	cred, err := audit.NewCredentialSetEntry("c1", "op", "ten-2", "c6", at)
	if err != nil {
		t.Fatalf("credential entry: %v", err)
	}
	if cred.AccountID() != "acct-ten-2" {
		t.Fatalf("credential account id = %q, want acct-ten-2", cred.AccountID())
	}
}

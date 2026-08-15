package audit_test

import (
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/account"
	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

func TestNewAccountActionEntry(t *testing.T) {
	t.Parallel()
	at := time.Unix(1700000000, 0).UTC()

	for _, act := range []audit.Action{audit.ActionRenameAccount, audit.ActionSuspendAccount, audit.ActionActivateAccount} {
		e, err := audit.NewAccountActionEntry("  id-1  ", "  op  ", act, "  reseller-1  ", at)
		if err != nil {
			t.Fatalf("action %s: %v", act, err)
		}
		if e.ID() != "id-1" || e.OperatorID() != "op" {
			t.Fatalf("not trimmed: id=%q op=%q", e.ID(), e.OperatorID())
		}
		if e.Action() != act {
			t.Fatalf("action = %q, want %q", e.Action(), act)
		}
		// Account-scoped: explicit account id, empty tenant, admin origin.
		if e.AccountID() != "reseller-1" || e.TenantID() != "" {
			t.Fatalf("account=%q tenant=%q", e.AccountID(), e.TenantID())
		}
		if e.Origin() != audit.OriginAdmin {
			t.Fatalf("origin = %q", e.Origin())
		}
	}
}

func TestNewAccountActionEntry_Invariants(t *testing.T) {
	t.Parallel()
	at := time.Unix(1, 0).UTC()
	// Blank id, blank account, and a non-account action all reject.
	if _, err := audit.NewAccountActionEntry("", "op", audit.ActionRenameAccount, "a", at); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("blank id: %v", err)
	}
	if _, err := audit.NewAccountActionEntry("id", "op", audit.ActionRenameAccount, "  ", at); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("blank account: %v", err)
	}
	// A tenant-scoped or unknown action must not be accepted by the account constructor.
	for _, bad := range []audit.Action{audit.ActionRenameTenant, audit.ActionSuspendTenant, audit.ActionSetBankCredential, audit.Action("bogus")} {
		if _, err := audit.NewAccountActionEntry("id", "op", bad, "a", at); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("action %s should reject, got %v", bad, err)
		}
	}
}

func TestNewBankConfigRemovedEntry(t *testing.T) {
	t.Parallel()
	at := time.Unix(2, 0).UTC()
	e, err := audit.NewBankConfigRemovedEntry("  id  ", "op", "  t1  ", "  c6  ", at)
	if err != nil {
		t.Fatalf("valid: %v", err)
	}
	if e.Action() != audit.ActionRemoveBankConfig {
		t.Fatalf("action = %q", e.Action())
	}
	if e.TenantID() != "t1" || e.BankID() != "c6" {
		t.Fatalf("tenant=%q bank=%q", e.TenantID(), e.BankID())
	}
	// Tenant-scoped: account_id derived from tenant (no explicit override).
	if e.AccountID() != account.SelfAccountID("t1") {
		t.Fatalf("account = %q, want %q", e.AccountID(), account.SelfAccountID("t1"))
	}
	// Invariants.
	if _, err := audit.NewBankConfigRemovedEntry("", "op", "t1", "c6", at); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("blank id: %v", err)
	}
	if _, err := audit.NewBankConfigRemovedEntry("id", "op", "  ", "c6", at); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("blank tenant: %v", err)
	}
	if _, err := audit.NewBankConfigRemovedEntry("id", "op", "t1", "  ", at); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("blank bank: %v", err)
	}
}

// TestAccountActionEntry_ValidForDurability confirms the new actions pass the
// closed-vocabulary check so NewEntry (used by the tenant-scoped rename/lifecycle
// paths) also accepts them.
func TestAccountActionEntry_ValidForDurability(t *testing.T) {
	t.Parallel()
	at := time.Unix(3, 0).UTC()
	// The tenant-scoped rename uses the generic NewEntry with ActionRenameTenant.
	if _, err := audit.NewEntry("id", "op", audit.ActionRenameTenant, "t1", at); err != nil {
		t.Fatalf("rename_tenant via NewEntry: %v", err)
	}
}

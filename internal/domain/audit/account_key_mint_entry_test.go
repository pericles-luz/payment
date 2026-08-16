package audit_test

import (
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

// TestNewAccountKeyMintEntryAccountScoped proves the mint audit entry is
// account-scoped exactly like the rename/suspend entries (ADR-0012 pattern): the
// AccountID is the explicit target and the tenant id is empty — a mint targets an
// Account, not a tenant. It also records who/when and the closed action string.
func TestNewAccountKeyMintEntryAccountScoped(t *testing.T) {
	t.Parallel()
	at := time.Unix(1700000000, 0).UTC()
	e, err := audit.NewAccountKeyMintEntry("aud-1", "console:alice", "acct-verz", at)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if e.Action() != audit.ActionMintAccountKey {
		t.Fatalf("action = %q, want %q", e.Action(), audit.ActionMintAccountKey)
	}
	if e.AccountID() != "acct-verz" {
		t.Fatalf("account id = %q, want acct-verz", e.AccountID())
	}
	if e.TenantID() != "" {
		t.Fatalf("tenant id = %q, want empty (account-scoped)", e.TenantID())
	}
	if e.OperatorID() != "console:alice" {
		t.Fatalf("operator id = %q, want console:alice", e.OperatorID())
	}
	if !e.At().Equal(at) {
		t.Fatalf("at = %v, want %v", e.At(), at)
	}
	// Never a secret: the entry carries no secret-bearing field (tx_id/bank_id are
	// zero for a mint), so a plaintext key can never ride along in the trail.
	if e.TxID() != "" || e.BankID() != "" {
		t.Fatalf("unexpected non-empty subject/bank field: tx=%q bank=%q", e.TxID(), e.BankID())
	}
	if e.Origin() != audit.OriginAdmin {
		t.Fatalf("origin = %q, want admin (default surface)", e.Origin())
	}
}

// TestNewAccountKeyMintEntryValidation rejects a missing id or account id (a mint
// with no target is meaningless) and allows an empty operator (a non-attributed
// internal caller), matching the sibling constructors.
func TestNewAccountKeyMintEntryValidation(t *testing.T) {
	t.Parallel()
	at := time.Unix(1700000000, 0).UTC()

	if _, err := audit.NewAccountKeyMintEntry("  ", "op", "acct-1", at); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("blank id: want validation error, got %v", err)
	}
	if _, err := audit.NewAccountKeyMintEntry("aud-1", "op", "   ", at); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("blank account id: want validation error, got %v", err)
	}
	// Empty operator is allowed (non-attributed internal caller).
	e, err := audit.NewAccountKeyMintEntry("aud-1", "", "acct-1", at)
	if err != nil {
		t.Fatalf("empty operator should be allowed: %v", err)
	}
	if e.OperatorID() != "" {
		t.Fatalf("operator id = %q, want empty", e.OperatorID())
	}
}

// TestActionMintAccountKeyString pins the persisted action string so an existing
// forensic query keyed on "account.key_mint" never silently breaks.
func TestActionMintAccountKeyString(t *testing.T) {
	t.Parallel()
	if got := string(audit.ActionMintAccountKey); got != "account.key_mint" {
		t.Fatalf("action string = %q, want account.key_mint", got)
	}
}

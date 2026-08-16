package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/domain/accountkey"
	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
)

// capturingAudit is an in-package fake ports.AuditLog that records appended entries
// (or fails on demand) so the shared mint choke-point can be asserted directly. It is
// NOT a database mock — it stands in for the audit OUTPUT port, which is exactly what
// the service depends on; the durable behaviour is covered by the sqlite adapter's
// own tests.
type capturingAudit struct {
	entries []audit.Entry
	failErr error
}

func (c *capturingAudit) Append(_ context.Context, e audit.Entry) error {
	if c.failErr != nil {
		return c.failErr
	}
	c.entries = append(c.entries, e)
	return nil
}

// The deterministic id provider (seqIDs) is shared with client_provisioning_test.go
// in this package.

// TestRotateAccountKeyEmitsMintAudit: a real mint through the shared choke-point
// emits exactly ONE account-scoped account.key_mint entry attributing who (the
// operator set by the transport), which Conta and when — and NEVER the secret. Both
// write surfaces (JSON admin + console) call this same method, so proving it here
// proves uniform coverage.
func TestRotateAccountKeyEmitsMintAudit(t *testing.T) {
	t.Parallel()
	store := persistence.NewAccountKeyStore(&akClock{now: akEpoch()})
	sink := &capturingAudit{}
	svc := NewAccountKeyService(store, &akClock{now: akEpoch()}, WithAccountKeyAudit(sink, &seqIDs{}))

	ctx := WithOperatorID(context.Background(), "console:bob")
	secret, err := svc.RotateAccountKey(ctx, "acct-A", "idem-1")
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if !accountkey.HasSecretShape(secret) {
		t.Fatalf("minted secret lacks shape: %q", secret)
	}
	if len(sink.entries) != 1 {
		t.Fatalf("want exactly 1 audit entry, got %d", len(sink.entries))
	}
	e := sink.entries[0]
	if e.Action() != audit.ActionMintAccountKey {
		t.Fatalf("action = %q, want %q", e.Action(), audit.ActionMintAccountKey)
	}
	if e.AccountID() != "acct-A" {
		t.Fatalf("account id = %q, want acct-A", e.AccountID())
	}
	if e.TenantID() != "" {
		t.Fatalf("tenant id = %q, want empty (account-scoped, ADR-0012)", e.TenantID())
	}
	if e.OperatorID() != "console:bob" {
		t.Fatalf("operator id = %q, want console:bob", e.OperatorID())
	}
	if !e.At().Equal(akEpoch()) {
		t.Fatalf("at = %v, want service clock %v", e.At(), akEpoch())
	}
	// The secret must never ride along in any recorded field.
	if strings.Contains(e.OperatorID()+e.AccountID()+e.TxID()+e.BankID(), secret) {
		t.Fatalf("audit entry leaked the minted secret")
	}
}

// TestRotateAccountKeyReplayEmitsNoSecondAudit: an idempotent replay (409, no mint)
// must NOT emit a second audit entry — the trail records mints, and a replay minted
// nothing.
func TestRotateAccountKeyReplayEmitsNoSecondAudit(t *testing.T) {
	t.Parallel()
	store := persistence.NewAccountKeyStore(&akClock{now: akEpoch()})
	sink := &capturingAudit{}
	svc := NewAccountKeyService(store, &akClock{now: akEpoch()}, WithAccountKeyAudit(sink, &seqIDs{}))

	if _, err := svc.RotateAccountKey(context.Background(), "acct-A", "idem-1"); err != nil {
		t.Fatalf("first rotate: %v", err)
	}
	if _, err := svc.RotateAccountKey(context.Background(), "acct-A", "idem-1"); !errors.Is(err, ErrAccountKeyAlreadyRotated) {
		t.Fatalf("replay: want ErrAccountKeyAlreadyRotated, got %v", err)
	}
	if len(sink.entries) != 1 {
		t.Fatalf("replay emitted a second audit entry: got %d, want 1", len(sink.entries))
	}
}

// TestRotateAccountKeyAuditFailClosed: an audit-append failure fails the mint
// (fail-closed, matching the console's other audited mutations) AND does not consume
// the idempotency key — a subsequent attempt under the same key can still succeed, so
// no mint is permanently lost to a transient audit outage.
func TestRotateAccountKeyAuditFailClosed(t *testing.T) {
	t.Parallel()
	store := persistence.NewAccountKeyStore(&akClock{now: akEpoch()})
	sink := &capturingAudit{failErr: errors.New("audit store down")}
	svc := NewAccountKeyService(store, &akClock{now: akEpoch()}, WithAccountKeyAudit(sink, &seqIDs{}))

	secret, err := svc.RotateAccountKey(context.Background(), "acct-A", "idem-1")
	if err == nil {
		t.Fatalf("want fail-closed error when audit append fails")
	}
	if secret != "" {
		t.Fatalf("fail-closed must not return a secret, got %q", secret)
	}
	// The idempotency key was NOT consumed: with audit now healthy, the same key mints.
	sink.failErr = nil
	secret2, err := svc.RotateAccountKey(context.Background(), "acct-A", "idem-1")
	if err != nil {
		t.Fatalf("retry after audit recovery should succeed, got %v", err)
	}
	if !accountkey.HasSecretShape(secret2) {
		t.Fatalf("retry secret lacks shape: %q", secret2)
	}
	if len(sink.entries) != 1 {
		t.Fatalf("want 1 entry from the successful retry, got %d", len(sink.entries))
	}
}

// TestRotateAccountKeyNoAuditWiredStillMints: the pre-existing two-argument
// constructor (no audit) keeps working unchanged — the audit is purely additive and
// its absence never blocks a mint.
func TestRotateAccountKeyNoAuditWiredStillMints(t *testing.T) {
	t.Parallel()
	store := persistence.NewAccountKeyStore(&akClock{now: akEpoch()})
	svc := NewAccountKeyService(store, &akClock{now: akEpoch()})

	secret, err := svc.RotateAccountKey(context.Background(), "acct-A", "idem-1")
	if err != nil {
		t.Fatalf("rotate without audit: %v", err)
	}
	if !accountkey.HasSecretShape(secret) {
		t.Fatalf("minted secret lacks shape: %q", secret)
	}
}

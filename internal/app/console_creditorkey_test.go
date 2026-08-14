package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	auditlog "github.com/ia-dev-sindireceita/payment/internal/adapters/audit/inmemory"
	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// countingEvictor records how many times the credential cache is evicted so the
// test can assert a creditor-key write does NOT trigger an OAuth token eviction
// (the key is not part of the OAuth identity).
type countingEvictor struct{ n int }

func (c *countingEvictor) InvalidateToken(string) { c.n++ }

// newCreditorConsole wires a ConsoleService over real in-memory adapters plus an
// audit log and a counting evictor, and seeds tenant "t1" with a bank credential.
func newCreditorConsole(t *testing.T) (*app.ConsoleService, *auditlog.Log, *countingEvictor, *secret.Store) {
	t.Helper()
	store := persistence.NewStore()
	if err := store.SaveTenant(context.Background(), tenant.Rehydrate("t1", "Acme", true, time.Unix(100, 0).UTC())); err != nil {
		t.Fatalf("seed: %v", err)
	}
	creds := secret.NewStore(map[string]ports.BankCredential{
		"t1": {TenantID: "t1", BankID: ports.BankIDC6, ClientID: "client-1", Secret: "secret-1"},
	})
	log := auditlog.NewLog()
	ev := &countingEvictor{}
	svc := app.NewConsoleService(app.ConsoleDeps{
		Tenants:         store,
		Pricing:         store,
		Ledger:          store,
		CredWriter:      creds,
		CreditorWriter:  creds,
		CredReader:      creds,
		CredInvalidator: ev,
		Audit:           log,
		Clock:           fixedClock{t: time.Unix(1000, 0).UTC()},
		IDs:             &seqIDs{},
	})
	return svc, log, ev, creds
}

func TestConsoleSetCreditorKey_StoresAndAudits(t *testing.T) {
	t.Parallel()
	svc, log, ev, creds := newCreditorConsole(t)
	ctx := app.WithOperatorID(context.Background(), "op-xyz")

	const key = "recebedor@acme.com.br"
	if err := svc.SetCreditorKey(ctx, "t1", key); err != nil {
		t.Fatalf("set creditor key: %v", err)
	}

	got, err := creds.GetBankCredential(ctx, "t1", ports.BankIDC6)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.CreditorKey != key {
		t.Errorf("key = %q, want %q", got.CreditorKey, key)
	}
	if got.Secret != "secret-1" {
		t.Errorf("secret clobbered: %q", got.Secret)
	}

	entries := log.Entries()
	if len(entries) != 1 {
		t.Fatalf("want 1 audit entry, got %d", len(entries))
	}
	e := entries[0]
	if e.Action() != audit.ActionSetCreditorKey {
		t.Errorf("action = %q", e.Action())
	}
	if e.OperatorID() != "op-xyz" {
		t.Errorf("operator = %q, want op-xyz", e.OperatorID())
	}
	if e.TenantID() != "t1" || e.BankID() != ports.BankIDC6 {
		t.Errorf("entry tenant/bank = %q/%q", e.TenantID(), e.BankID())
	}
	// The creditor key is NOT part of the OAuth identity → no token eviction.
	if ev.n != 0 {
		t.Errorf("token eviction count = %d, want 0 (creditor key is not the OAuth secret)", ev.n)
	}
}

func TestConsoleSetCreditorKey_UnknownTenant(t *testing.T) {
	t.Parallel()
	svc, log, _, _ := newCreditorConsole(t)
	err := svc.SetCreditorKey(context.Background(), "ghost", "recebedor@acme.com.br")
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if log.Len() != 0 {
		t.Errorf("no audit entry expected on failure, got %d", log.Len())
	}
}

func TestConsoleSetCreditorKey_InvalidKeyNotAudited(t *testing.T) {
	t.Parallel()
	svc, log, _, _ := newCreditorConsole(t)
	err := svc.SetCreditorKey(context.Background(), "t1", "not-a-pix-key")
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want validation error, got %v", err)
	}
	if log.Len() != 0 {
		t.Errorf("invalid key must not be audited, got %d entries", log.Len())
	}
}

// TestConsoleSetCreditorKey_NoCredentialRejected covers a tenant that exists but
// has no bank credential yet: the write is refused (ErrNotFound from the adapter)
// rather than creating a half-credential carrying a routing target but no identity.
func TestConsoleSetCreditorKey_NoCredentialRejected(t *testing.T) {
	t.Parallel()
	store := persistence.NewStore()
	if err := store.SaveTenant(context.Background(), tenant.Rehydrate("t2", "NoCred Ltda", true, time.Unix(100, 0).UTC())); err != nil {
		t.Fatalf("seed: %v", err)
	}
	creds := secret.NewStore(map[string]ports.BankCredential{})
	log := auditlog.NewLog()
	svc := app.NewConsoleService(app.ConsoleDeps{
		Tenants:        store,
		Pricing:        store,
		Ledger:         store,
		CredWriter:     creds,
		CreditorWriter: creds,
		CredReader:     creds,
		Audit:          log,
		Clock:          fixedClock{t: time.Unix(1000, 0).UTC()},
		IDs:            &seqIDs{},
	})

	err := svc.SetCreditorKey(context.Background(), "t2", "recebedor@acme.com.br")
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("tenant without a credential: want ErrNotFound, got %v", err)
	}
	if log.Len() != 0 {
		t.Errorf("no audit entry expected when the write is refused, got %d", log.Len())
	}
}

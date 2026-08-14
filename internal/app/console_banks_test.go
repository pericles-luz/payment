package app_test

import (
	"context"
	"errors"
	"testing"

	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

func TestConsoleListBanks_EmptyThenConfigured(t *testing.T) {
	t.Parallel()
	svc, store, creds := newConsole()
	ctx := context.Background()
	seedTenant(t, store, "t1", "Acme", true, 100)

	// Brand-new tenant: no configured bank → empty list, C6 addable.
	banks, err := svc.ListBanks(ctx, "t1")
	if err != nil || len(banks) != 0 {
		t.Fatalf("empty list = %d (%v), want 0", len(banks), err)
	}
	addable, err := svc.AddableBankSlugs(ctx, "t1")
	if err != nil || len(addable) != 1 || addable[0] != ports.BankIDC6 {
		t.Fatalf("addable = %v (%v), want [c6]", addable, err)
	}

	// Configure C6 → it appears as a configured bank and is no longer addable.
	if err := creds.SetBankCredential(ctx, "t1", ports.BankIDC6, "cid-1", "s3cr3t"); err != nil {
		t.Fatalf("seed cred: %v", err)
	}
	banks, err = svc.ListBanks(ctx, "t1")
	if err != nil || len(banks) != 1 {
		t.Fatalf("configured list = %d (%v), want 1", len(banks), err)
	}
	if banks[0].Slug != ports.BankIDC6 || !banks[0].CredentialSet || banks[0].ClientID != "cid-1" {
		t.Fatalf("bank row = %+v", banks[0])
	}
	if addable, _ := svc.AddableBankSlugs(ctx, "t1"); len(addable) != 0 {
		t.Fatalf("addable after configure = %v, want []", addable)
	}
}

func TestConsoleGetBank(t *testing.T) {
	t.Parallel()
	svc, store, creds := newConsole()
	ctx := context.Background()
	seedTenant(t, store, "t1", "Acme", true, 100)

	// Known but unconfigured → pendente, no client id.
	info, err := svc.GetBank(ctx, "t1", "c6")
	if err != nil || info.CredentialSet {
		t.Fatalf("pending bank = %+v (%v)", info, err)
	}
	// Unknown bank → ErrNotFound (deny-by-default).
	if _, err := svc.GetBank(ctx, "t1", "nubank"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("unknown bank err = %v, want ErrNotFound", err)
	}
	// Configured → client id + creditor key echoed (non-secret), never the secret.
	creds.Set("t1", ports.BankCredential{BankID: ports.BankIDC6, ClientID: "cid-1", Secret: "s3cr3t", CreditorKey: "pix-key-1"})
	info, err = svc.GetBank(ctx, "t1", "C6") // case-insensitive slug
	if err != nil || !info.CredentialSet || info.ClientID != "cid-1" || info.CreditorKey != "pix-key-1" {
		t.Fatalf("configured bank = %+v (%v)", info, err)
	}
}

func TestConsoleSetBankCredentialFor(t *testing.T) {
	t.Parallel()
	svc, store, creds := newConsole()
	ctx := context.Background()
	seedTenant(t, store, "t1", "Acme", true, 100)

	if err := svc.SetBankCredentialFor(ctx, "t1", "c6", "cid-1", "s3cr3t"); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, err := creds.GetBankCredential(ctx, "t1", ports.BankIDC6)
	if err != nil || got.ClientID != "cid-1" || got.Secret != "s3cr3t" {
		t.Fatalf("stored = %+v (%v)", got, err)
	}
	// Unknown bank slug → validation error, nothing written.
	if err := svc.SetBankCredentialFor(ctx, "t1", "nubank", "c", "s"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unknown slug err = %v, want ErrValidation", err)
	}
	// Missing tenant → not found.
	if err := svc.SetBankCredentialFor(ctx, "missing", "c6", "c", "s"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("missing tenant err = %v, want ErrNotFound", err)
	}
	// Empty secret → validation error (writer-side).
	if err := svc.SetBankCredentialFor(ctx, "t1", "c6", "c", ""); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty secret err = %v, want ErrValidation", err)
	}
}

func TestConsoleBanks_MissingTenant(t *testing.T) {
	t.Parallel()
	svc, _, _ := newConsole()
	ctx := context.Background()
	if _, err := svc.ListBanks(ctx, "missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("ListBanks missing = %v", err)
	}
	if _, err := svc.AddableBankSlugs(ctx, "missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("AddableBankSlugs missing = %v", err)
	}
	if _, err := svc.GetBank(ctx, "missing", "c6"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("GetBank missing = %v", err)
	}
}

// TestConsoleBanks_NilReaderDegrades asserts the screens still work when no
// credential reader is wired: every bank reads as pendente, none configured.
func TestConsoleBanks_NilReaderDegrades(t *testing.T) {
	t.Parallel()
	store := persistence.NewStore()
	creds := secret.NewStore(map[string]ports.BankCredential{})
	svc := app.NewConsoleService(app.ConsoleDeps{
		Tenants: store, Pricing: store, Ledger: store,
		CredWriter: creds, Clock: fixedClock{}, IDs: &seqIDs{},
		// CredReader intentionally nil.
	})
	ctx := context.Background()
	seedTenant(t, store, "t1", "Acme", true, 100)
	banks, err := svc.ListBanks(ctx, "t1")
	if err != nil || len(banks) != 0 {
		t.Fatalf("nil-reader list = %d (%v), want 0 configured", len(banks), err)
	}
	addable, err := svc.AddableBankSlugs(ctx, "t1")
	if err != nil || len(addable) != len(ports.KnownBankIDs()) {
		t.Fatalf("nil-reader addable = %v (%v)", addable, err)
	}
	info, err := svc.GetBank(ctx, "t1", "c6")
	if err != nil || info.CredentialSet {
		t.Fatalf("nil-reader GetBank = %+v (%v)", info, err)
	}
}

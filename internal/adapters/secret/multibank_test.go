package secret_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// TestStoreCompositeKeyingAndCrossBankIsolation pins the ADR-0007 core: the store
// is keyed by the EXACT (tenantID, bankID) pair. A credential for one bank is
// never resolvable through another bank, and two banks for the same tenant
// coexist without one overwriting the other (threat T2).
func TestStoreCompositeKeyingAndCrossBankIsolation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := secret.NewStore(map[string]ports.BankCredential{
		"t1-c6":   {TenantID: "t1", BankID: "c6", ClientID: "c6-cid", Secret: "c6-sec"},
		"t1-itau": {TenantID: "t1", BankID: "itau", ClientID: "itau-cid", Secret: "itau-sec"},
	})

	// Each bank resolves its OWN credential — no overwrite, no aliasing.
	c6, err := store.GetBankCredential(ctx, "t1", "c6")
	if err != nil || c6.ClientID != "c6-cid" || c6.Secret != "c6-sec" || c6.BankID != "c6" {
		t.Fatalf("(t1,c6) resolve: %+v err=%v", c6, err)
	}
	itau, err := store.GetBankCredential(ctx, "t1", "itau")
	if err != nil || itau.ClientID != "itau-cid" || itau.Secret != "itau-sec" || itau.BankID != "itau" {
		t.Fatalf("(t1,itau) resolve: %+v err=%v", itau, err)
	}

	// A bank the tenant did NOT configure has NO fallback to another bank (threat
	// T1): exact-match lookup, ErrNotFound — never another bank's credential.
	if got, err := store.GetBankCredential(ctx, "t1", "bradesco"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("(t1,bradesco) must be ErrNotFound with empty cred, got %+v err=%v", got, err)
	}
}

// TestStoreCrossTenantIsolationWithinBank pins that the bank dimension never
// relaxes the tenant scope: a (tenantA, bank) credential is unreachable as
// (tenantB, bank) (threat T2).
func TestStoreCrossTenantIsolationWithinBank(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := secret.NewStore(map[string]ports.BankCredential{
		"a": {TenantID: "tenantA", BankID: "c6", ClientID: "a-cid", Secret: "a-sec"},
	})
	if _, err := store.GetBankCredential(ctx, "tenantB", "c6"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("tenantB must not resolve tenantA's (·,c6) credential, got %v", err)
	}
}

// TestStoreDefaultBankID pins the retro-compatible default: a credential stored
// with an empty bankID, and a lookup with an empty bankID, both resolve to the
// canonical "c6" slot — so legacy single-bank config and pre-multi-bank call sites
// keep working unchanged.
func TestStoreDefaultBankID(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	// Value carries no BankID and no TenantID: NewStore stamps the tenant from the
	// map key and defaults the bank to c6.
	store := secret.NewStore(map[string]ports.BankCredential{
		"t1": {ClientID: "cid", Secret: "sec"},
	})

	// Empty bankID resolves to c6.
	byEmpty, err := store.GetBankCredential(ctx, "t1", "")
	if err != nil || byEmpty.BankID != "c6" || byEmpty.TenantID != "t1" {
		t.Fatalf("empty-bank lookup: %+v err=%v", byEmpty, err)
	}
	// Explicit c6 resolves the SAME slot.
	byC6, err := store.GetBankCredential(ctx, "t1", "c6")
	if err != nil || byC6.ClientID != "cid" {
		t.Fatalf("c6 lookup: %+v err=%v", byC6, err)
	}
}

// TestStoreSetBankCredentialPerBank pins the writer path: SetBankCredential keys
// by (tenant, bank); writing a second bank for the same tenant does not disturb
// the first, and an empty bankID writes the default c6 slot.
func TestStoreSetBankCredentialPerBank(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := secret.NewStore(nil)

	if err := store.SetBankCredential(ctx, "t1", "c6", "c6-cid", "c6-sec"); err != nil {
		t.Fatalf("set c6: %v", err)
	}
	if err := store.SetBankCredential(ctx, "t1", "itau", "itau-cid", "itau-sec"); err != nil {
		t.Fatalf("set itau: %v", err)
	}
	// An empty bankID writes the default c6 slot (retro-compat) — it OVERWRITES the
	// earlier explicit c6 write, proving "" and "c6" are the same slot.
	if err := store.SetBankCredential(ctx, "t1", "", "c6-cid2", "c6-sec2"); err != nil {
		t.Fatalf("set default: %v", err)
	}

	c6, err := store.GetBankCredential(ctx, "t1", "c6")
	if err != nil || c6.ClientID != "c6-cid2" || c6.Secret != "c6-sec2" {
		t.Fatalf("c6 after default write: %+v err=%v", c6, err)
	}
	itau, err := store.GetBankCredential(ctx, "t1", "itau")
	if err != nil || itau.ClientID != "itau-cid" {
		t.Fatalf("itau undisturbed: %+v err=%v", itau, err)
	}
}

// TestStoreSetBankCredentialValidation pins that empty required inputs are
// rejected WITHOUT echoing the secret value (threat C1/C4).
func TestStoreSetBankCredentialValidation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := secret.NewStore(nil)
	cases := []struct{ name, tenant, bank, client, secret string }{
		{"empty tenant", "", "c6", "cid", "sec"},
		{"empty client", "t1", "c6", "", "sec"},
		{"empty secret", "t1", "c6", "cid", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := store.SetBankCredential(ctx, tc.tenant, tc.bank, tc.client, tc.secret)
			if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want ErrValidation, got %v", err)
			}
		})
	}
}

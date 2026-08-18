package secret_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

func TestStoreIsolatesPerTenant(t *testing.T) {
	t.Parallel()
	store := secret.NewStore(map[string]ports.BankCredential{
		"t1": {TenantID: "t1", ClientID: "c1", Secret: "s1"},
	})
	ctx := context.Background()

	got, err := store.GetBankCredential(ctx, "t1", ports.BankIDC6)
	if err != nil {
		t.Fatalf("t1: %v", err)
	}
	if got.ClientID != "c1" || got.Secret != "s1" {
		t.Fatal("credential mismatch")
	}

	// A different tenant has no credential (isolation).
	if _, err := store.GetBankCredential(ctx, "t2", ports.BankIDC6); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want not found, got %v", err)
	}

	// Set assigns per tenant and stamps the tenant id.
	store.Set("t2", ports.BankCredential{ClientID: "c2", Secret: "s2"})
	got2, err := store.GetBankCredential(ctx, "t2", ports.BankIDC6)
	if err != nil {
		t.Fatalf("t2: %v", err)
	}
	if got2.TenantID != "t2" || got2.ClientID != "c2" {
		t.Fatal("set mismatch")
	}
}

func TestStoreListTenantsWithC6Credential(t *testing.T) {
	ctx := context.Background()

	// Empty store.
	st := secret.NewStore(nil)
	ids, err := st.ListTenantsWithC6Credential(ctx)
	if err != nil {
		t.Fatalf("empty list: %v", err)
	}
	if len(ids) != 0 {
		t.Fatalf("expected empty, got %v", ids)
	}

	// Seed two C6 tenants.
	st.Set("tnt-1", ports.BankCredential{BankID: ports.BankIDC6, ClientID: "cid-1", Secret: "s1"})
	st.Set("tnt-2", ports.BankCredential{BankID: ports.BankIDC6, ClientID: "cid-2", Secret: "s2"})

	ids, err = st.ListTenantsWithC6Credential(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("expected 2, got %v", ids)
	}
	got := map[string]bool{}
	for _, id := range ids {
		got[id] = true
	}
	for _, want := range []string{"tnt-1", "tnt-2"} {
		if !got[want] {
			t.Errorf("missing %q", want)
		}
	}
}

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

	got, err := store.GetBankCredential(ctx, "t1")
	if err != nil {
		t.Fatalf("t1: %v", err)
	}
	if got.ClientID != "c1" || got.Secret != "s1" {
		t.Fatal("credential mismatch")
	}

	// A different tenant has no credential (isolation).
	if _, err := store.GetBankCredential(ctx, "t2"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want not found, got %v", err)
	}

	// Set assigns per tenant and stamps the tenant id.
	store.Set("t2", ports.BankCredential{ClientID: "c2", Secret: "s2"})
	got2, err := store.GetBankCredential(ctx, "t2")
	if err != nil {
		t.Fatalf("t2: %v", err)
	}
	if got2.TenantID != "t2" || got2.ClientID != "c2" {
		t.Fatal("set mismatch")
	}
}

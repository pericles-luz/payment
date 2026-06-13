package secret_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

func TestSetBankCredentialValidation(t *testing.T) {
	t.Parallel()
	store := secret.NewStore(nil)
	ctx := context.Background()

	cases := []struct {
		name                       string
		tenantID, clientID, secret string
	}{
		{"empty tenant", "", "cid", "shh"},
		{"empty client", "t1", "", "shh"},
		{"empty secret", "t1", "cid", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := store.SetBankCredential(ctx, tc.tenantID, tc.clientID, tc.secret)
			if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want ErrValidation, got %v", err)
			}
		})
	}
}

func TestSetBankCredentialStoresAndOverwrites(t *testing.T) {
	t.Parallel()
	store := secret.NewStore(nil)
	ctx := context.Background()

	if err := store.SetBankCredential(ctx, "t1", "cid", "shh"); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := store.GetBankCredential(ctx, "t1")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got.TenantID != "t1" || got.ClientID != "cid" || got.Secret != "shh" {
		t.Fatalf("stored mismatch: %+v", got)
	}

	// Overwrite replaces both client id and secret.
	if err := store.SetBankCredential(ctx, "t1", "cid2", "shh2"); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	got, _ = store.GetBankCredential(ctx, "t1")
	if got.ClientID != "cid2" || got.Secret != "shh2" {
		t.Fatalf("overwrite not applied: %+v", got)
	}

	// Isolation: another tenant remains absent.
	if _, err := store.GetBankCredential(ctx, "t2"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want not found for t2, got %v", err)
	}
}

// Compile-time assertion that the adapter satisfies the write port.
var _ ports.CredentialWriter = (*secret.Store)(nil)

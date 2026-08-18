package inmemory_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/domain/webhookref"
)

// TestInMemoryWebhookRefSupersede proves the in-memory adapter matches the durable one's
// SUPERSEDE semantics (SIN-69588 / B1): a second ref for the same tenant drops the first,
// and one tenant's supersede never touches another's ref.
func TestInMemoryWebhookRefSupersede(t *testing.T) {
	t.Parallel()
	s := inmemory.NewWebhookRefStore()
	ctx := context.Background()

	ref1, _ := webhookref.Generate()
	ref2, _ := webhookref.Generate()
	refB, _ := webhookref.Generate()
	for _, p := range []struct {
		ref, tenant string
	}{{ref1, "tenant-1"}, {refB, "tenant-b"}, {ref2, "tenant-1"}} {
		if err := s.PutWebhookRef(ctx, sum(p.ref), p.tenant); err != nil {
			t.Fatalf("put %s: %v", p.tenant, err)
		}
	}
	if _, ok, _ := s.LookupWebhookRef(ctx, sum(ref1)); ok {
		t.Fatal("superseded ref1 must not resolve")
	}
	if got, ok, _ := s.LookupWebhookRef(ctx, sum(ref2)); !ok || got != "tenant-1" {
		t.Fatalf("active ref2 = (%q, %v), want (tenant-1, true)", got, ok)
	}
	if got, ok, _ := s.LookupWebhookRef(ctx, sum(refB)); !ok || got != "tenant-b" {
		t.Fatalf("tenant-b ref must survive, got (%q, %v)", got, ok)
	}
}

// TestInMemoryWebhookRefRevoke proves RevokeWebhookRefs drops the tenant's active refs,
// returns the count, and is idempotent; and it validates an empty tenant id.
func TestInMemoryWebhookRefRevoke(t *testing.T) {
	t.Parallel()
	s := inmemory.NewWebhookRefStore()
	ctx := context.Background()

	ref, _ := webhookref.Generate()
	if err := s.PutWebhookRef(ctx, sum(ref), "tenant-1"); err != nil {
		t.Fatalf("put: %v", err)
	}
	n, err := s.RevokeWebhookRefs(ctx, "tenant-1")
	if err != nil || n != 1 {
		t.Fatalf("revoke = (%d, %v), want (1, nil)", n, err)
	}
	if _, ok, _ := s.LookupWebhookRef(ctx, sum(ref)); ok {
		t.Fatal("revoked ref must not resolve")
	}
	if n, err := s.RevokeWebhookRefs(ctx, "tenant-1"); err != nil || n != 0 {
		t.Fatalf("idempotent revoke = (%d, %v), want (0, nil)", n, err)
	}
	if _, err := s.RevokeWebhookRefs(ctx, ""); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation for empty tenant, got %v", err)
	}
}

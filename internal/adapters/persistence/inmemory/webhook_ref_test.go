package inmemory_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/domain/webhookref"
)

func sum(ref string) []byte {
	s := webhookref.Sum(ref)
	return s[:]
}

// TestInMemoryWebhookRefPutLookup covers the happy path and tenant isolation.
func TestInMemoryWebhookRefPutLookup(t *testing.T) {
	t.Parallel()
	s := inmemory.NewWebhookRefStore()
	ctx := context.Background()

	refA, _ := webhookref.Generate()
	refB, _ := webhookref.Generate()
	if err := s.PutWebhookRef(ctx, sum(refA), "tenant-a"); err != nil {
		t.Fatalf("put a: %v", err)
	}
	if err := s.PutWebhookRef(ctx, sum(refB), "tenant-b"); err != nil {
		t.Fatalf("put b: %v", err)
	}
	if got, ok, err := s.LookupWebhookRef(ctx, sum(refA)); !ok || err != nil || got != "tenant-a" {
		t.Fatalf("lookup a = (%q, %v, %v)", got, ok, err)
	}
	if got, ok, err := s.LookupWebhookRef(ctx, sum(refB)); !ok || err != nil || got != "tenant-b" {
		t.Fatalf("lookup b = (%q, %v, %v)", got, ok, err)
	}
}

// TestInMemoryWebhookRefMiss covers the non-oracle miss and the empty-hash guard.
func TestInMemoryWebhookRefMiss(t *testing.T) {
	t.Parallel()
	s := inmemory.NewWebhookRefStore()
	ctx := context.Background()
	if got, ok, err := s.LookupWebhookRef(ctx, sum("unknown")); ok || err != nil || got != "" {
		t.Fatalf("unknown lookup = (%q, %v, %v), want ('', false, nil)", got, ok, err)
	}
	if _, ok, err := s.LookupWebhookRef(ctx, nil); ok || err != nil {
		t.Fatalf("nil lookup = (%v, %v), want (false, nil)", ok, err)
	}
}

// TestInMemoryWebhookRefValidation rejects an empty hash or tenant id.
func TestInMemoryWebhookRefValidation(t *testing.T) {
	t.Parallel()
	s := inmemory.NewWebhookRefStore()
	ctx := context.Background()
	if err := s.PutWebhookRef(ctx, nil, "tenant-a"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation for empty hash, got %v", err)
	}
	if err := s.PutWebhookRef(ctx, sum("x"), ""); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation for empty tenant, got %v", err)
	}
}

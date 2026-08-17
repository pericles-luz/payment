package inmemory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/outboundwebhook"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

// Compile-time check that the in-memory adapter satisfies the app port (the same one
// the durable sqlite vault implements).
var _ app.OutboundWebhookStore = (*inmemory.OutboundWebhookStore)(nil)

func TestOutboundWebhookStoreRoundTrip(t *testing.T) {
	t.Parallel()
	s := inmemory.NewOutboundWebhookStore()
	ctx := context.Background()
	now := time.Unix(1700000000, 0).UTC()

	if _, err := s.GetOutboundWebhook(ctx, "acct-1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("get missing = %v; want ErrNotFound", err)
	}
	cfg, _ := outboundwebhook.New("acct-1", "https://e.com/h", "whsec_1", true, now)
	if err := s.UpsertOutboundWebhook(ctx, cfg); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got, err := s.GetOutboundWebhook(ctx, "acct-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.URL() != "https://e.com/h" || got.SigningSecret() != "whsec_1" || !got.Enabled() {
		t.Errorf("round-trip mismatch: %+v", got)
	}
}

func TestOutboundWebhookStoreGetReturnsFreshAggregate(t *testing.T) {
	t.Parallel()
	s := inmemory.NewOutboundWebhookStore()
	ctx := context.Background()
	now := time.Unix(1700000000, 0).UTC()
	cfg, _ := outboundwebhook.New("acct-1", "https://e.com/h", "whsec_1", false, now)
	_ = s.UpsertOutboundWebhook(ctx, cfg)

	got1, _ := s.GetOutboundWebhook(ctx, "acct-1")
	// Mutating the returned aggregate must NOT leak into the store (no shared pointer).
	_ = got1.SetURL("https://mutated.example.com/h", now.Add(time.Hour))
	got2, _ := s.GetOutboundWebhook(ctx, "acct-1")
	if got2.URL() != "https://e.com/h" {
		t.Errorf("store leaked a pointer: url now %q", got2.URL())
	}
}

func TestOutboundWebhookStoreUpsertUpdatesAndDelete(t *testing.T) {
	t.Parallel()
	s := inmemory.NewOutboundWebhookStore()
	ctx := context.Background()
	now := time.Unix(1700000000, 0).UTC()
	c1, _ := outboundwebhook.New("acct-1", "https://a.example.com/h", "whsec_1", true, now)
	_ = s.UpsertOutboundWebhook(ctx, c1)
	c2, _ := outboundwebhook.New("acct-1", "https://b.example.com/h", "whsec_2", false, now)
	_ = s.UpsertOutboundWebhook(ctx, c2)
	got, _ := s.GetOutboundWebhook(ctx, "acct-1")
	if got.URL() != "https://b.example.com/h" || got.Enabled() {
		t.Errorf("update not applied: %+v", got)
	}
	// Idempotent delete.
	if err := s.DeleteOutboundWebhook(ctx, "acct-1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.GetOutboundWebhook(ctx, "acct-1"); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("get after delete = %v; want ErrNotFound", err)
	}
	if err := s.DeleteOutboundWebhook(ctx, "acct-1"); err != nil {
		t.Fatalf("second delete (idempotent): %v", err)
	}
}

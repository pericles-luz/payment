package inmemory_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/messaging/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

func TestBusPublishDelivers(t *testing.T) {
	t.Parallel()
	bus := inmemory.NewBus()
	ctx := context.Background()
	var received []ports.Message
	_ = bus.Subscribe(ctx, "topic", func(_ context.Context, m ports.Message) error {
		received = append(received, m)
		return nil
	})
	// Second subscriber to ensure fan-out.
	var count int
	_ = bus.Subscribe(ctx, "topic", func(_ context.Context, _ ports.Message) error {
		count++
		return nil
	})

	msg := ports.Message{TenantID: "t1", Type: "topic", Payload: []byte("x")}
	if err := bus.Publish(ctx, "topic", msg); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if len(received) != 1 || received[0].TenantID != "t1" {
		t.Fatal("first subscriber did not receive")
	}
	if count != 1 {
		t.Fatal("second subscriber did not receive")
	}

	// Publishing to an unknown topic is a no-op.
	if err := bus.Publish(ctx, "other", msg); err != nil {
		t.Fatalf("publish unknown: %v", err)
	}
}

func TestBusPropagatesHandlerError(t *testing.T) {
	t.Parallel()
	bus := inmemory.NewBus()
	ctx := context.Background()
	sentinel := errors.New("boom")
	_ = bus.Subscribe(ctx, "topic", func(_ context.Context, _ ports.Message) error {
		return sentinel
	})
	if err := bus.Publish(ctx, "topic", ports.Message{}); !errors.Is(err, sentinel) {
		t.Fatalf("want sentinel, got %v", err)
	}
}

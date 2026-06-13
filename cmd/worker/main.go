// Command worker is the async consumer entrypoint. It subscribes to platform
// events on the MessageBus port and processes them with idempotent handlers,
// shutting down gracefully on signal. The bus adapter (RabbitMQ in production,
// in-memory for local/dev) is chosen here without the domain knowing.
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/messaging/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("worker: %v", err)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// In-memory bus for the foundation scaffold; swap for the RabbitMQ adapter
	// (internal/adapters/messaging/rabbitmq) when a broker is configured.
	bus := inmemory.NewBus()

	handler := func(ctx context.Context, m ports.Message) error {
		// Idempotent processing belongs here (dedupe by m.IdempotencyKey).
		log.Printf("worker: event type=%s tenant=%s", m.Type, m.TenantID)
		return nil
	}
	for _, topic := range []string{app.TopicPaymentCreated, app.TopicPaymentPaid} {
		if err := bus.Subscribe(ctx, topic, handler); err != nil {
			return err
		}
	}

	log.Print("worker: started; waiting for events")
	<-ctx.Done()
	log.Print("worker: shutdown signal received")
	return nil
}

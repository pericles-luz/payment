// Package inmemory provides an in-process MessageBus used for tests and local
// development (the fallback bus when RabbitMQ is not configured). It delivers
// published messages synchronously to subscribed handlers.
package inmemory

import (
	"context"
	"sync"

	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// Bus is an in-memory implementation of ports.MessageBus. Handlers registered
// for a topic receive every message published to that topic, in order.
type Bus struct {
	mu       sync.RWMutex
	handlers map[string][]ports.MessageHandler
}

// NewBus returns an empty in-memory bus.
func NewBus() *Bus {
	return &Bus{handlers: make(map[string][]ports.MessageHandler)}
}

// Subscribe registers a handler for a topic.
func (b *Bus) Subscribe(ctx context.Context, topic string, h ports.MessageHandler) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.handlers[topic] = append(b.handlers[topic], h)
	return nil
}

// Publish delivers a message to all handlers subscribed to the topic. The first
// handler error is returned (after attempting all handlers).
func (b *Bus) Publish(ctx context.Context, topic string, m ports.Message) error {
	b.mu.RLock()
	hs := make([]ports.MessageHandler, len(b.handlers[topic]))
	copy(hs, b.handlers[topic])
	b.mu.RUnlock()

	var firstErr error
	for _, h := range hs {
		if err := h(ctx, m); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

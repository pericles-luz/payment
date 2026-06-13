// Package rabbitmq provides a MessageBus adapter backed by RabbitMQ
// (rabbitmq/amqp091-go). The AMQP channel is accessed through a small interface
// seam so the publish/consume logic is unit-testable without a live broker; an
// in-memory bus is the fallback for tests/dev (see ../inmemory).
package rabbitmq

import (
	"context"
	"fmt"
	"sync"

	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// Header keys carried on every AMQP message.
const (
	headerTenantID       = "x-tenant-id"
	headerType           = "x-type"
	headerIdempotencyKey = "x-idempotency-key"

	// ExchangeName is the topic exchange used for all platform events.
	ExchangeName = "payments"
)

// channel is the subset of *amqp.Channel the adapter needs. The seam keeps the
// adapter testable with a fake channel.
type channel interface {
	PublishWithContext(ctx context.Context, exchange, key string, mandatory, immediate bool, msg amqp.Publishing) error
	QueueDeclare(name string, durable, autoDelete, exclusive, noWait bool, args amqp.Table) (amqp.Queue, error)
	QueueBind(name, key, exchange string, noWait bool, args amqp.Table) error
	Consume(queue, consumer string, autoAck, exclusive, noLocal, noWait bool, args amqp.Table) (<-chan amqp.Delivery, error)
}

// Bus implements ports.MessageBus over an AMQP channel.
type Bus struct {
	ch channel
	wg sync.WaitGroup
}

// NewBus builds a Bus over the given AMQP channel seam.
func NewBus(ch channel) *Bus {
	return &Bus{ch: ch}
}

// toPublishing maps a domain message to an AMQP publishing (durable, persistent).
func toPublishing(m ports.Message) amqp.Publishing {
	return amqp.Publishing{
		ContentType:  "application/json",
		DeliveryMode: amqp.Persistent,
		MessageId:    m.IdempotencyKey,
		Type:         m.Type,
		Headers: amqp.Table{
			headerTenantID:       m.TenantID,
			headerType:           m.Type,
			headerIdempotencyKey: m.IdempotencyKey,
		},
		Body: m.Payload,
	}
}

// fromDelivery maps an AMQP delivery back to a domain message.
func fromDelivery(d amqp.Delivery) ports.Message {
	get := func(k string) string {
		if v, ok := d.Headers[k]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
		return ""
	}
	return ports.Message{
		TenantID:       get(headerTenantID),
		Type:           get(headerType),
		IdempotencyKey: get(headerIdempotencyKey),
		Payload:        d.Body,
	}
}

// Publish sends a message to the topic exchange with the topic as routing key.
func (b *Bus) Publish(ctx context.Context, topic string, m ports.Message) error {
	if err := b.ch.PublishWithContext(ctx, ExchangeName, topic, false, false, toPublishing(m)); err != nil {
		return fmt.Errorf("amqp publish: %w", err)
	}
	return nil
}

// Subscribe declares a durable queue for the topic, binds it to the exchange and
// dispatches deliveries to the handler in a background goroutine until the
// delivery channel closes or ctx is canceled. Successful handling acks; a handler
// error nacks with requeue for redelivery (handlers must be idempotent).
func (b *Bus) Subscribe(ctx context.Context, topic string, h ports.MessageHandler) error {
	q, err := b.ch.QueueDeclare(queueName(topic), true, false, false, false, nil)
	if err != nil {
		return fmt.Errorf("queue declare: %w", err)
	}
	if err := b.ch.QueueBind(q.Name, topic, ExchangeName, false, nil); err != nil {
		return fmt.Errorf("queue bind: %w", err)
	}
	deliveries, err := b.ch.Consume(q.Name, "", false, false, false, false, nil)
	if err != nil {
		return fmt.Errorf("consume: %w", err)
	}
	b.wg.Add(1)
	go b.dispatch(ctx, deliveries, h)
	return nil
}

func (b *Bus) dispatch(ctx context.Context, deliveries <-chan amqp.Delivery, h ports.MessageHandler) {
	defer b.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case d, ok := <-deliveries:
			if !ok {
				return
			}
			if err := h(ctx, fromDelivery(d)); err != nil {
				_ = d.Nack(false, true)
				continue
			}
			_ = d.Ack(false)
		}
	}
}

// Wait blocks until all dispatch goroutines have finished (graceful shutdown).
func (b *Bus) Wait() {
	b.wg.Wait()
}

func queueName(topic string) string { return ExchangeName + "." + topic }

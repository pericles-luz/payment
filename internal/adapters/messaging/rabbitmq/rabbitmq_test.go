package rabbitmq_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/messaging/rabbitmq"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// fakeAck implements amqp.Acknowledger, counting ack/nack calls.
type fakeAck struct {
	mu    sync.Mutex
	acks  int
	nacks int
}

func (f *fakeAck) Ack(uint64, bool) error { f.mu.Lock(); f.acks++; f.mu.Unlock(); return nil }
func (f *fakeAck) Nack(uint64, bool, bool) error {
	f.mu.Lock()
	f.nacks++
	f.mu.Unlock()
	return nil
}
func (f *fakeAck) Reject(uint64, bool) error { return nil }

// fakeChannel implements the (unexported) channel seam the adapter depends on.
type fakeChannel struct {
	published   []amqp.Publishing
	deliveries  chan amqp.Delivery
	declareErr  error
	bindErr     error
	consumeErr  error
	publishErr  error
	boundKey    string
	consumedSub string
}

func (c *fakeChannel) PublishWithContext(_ context.Context, _, key string, _, _ bool, msg amqp.Publishing) error {
	if c.publishErr != nil {
		return c.publishErr
	}
	c.boundKey = key
	c.published = append(c.published, msg)
	return nil
}

func (c *fakeChannel) QueueDeclare(name string, _, _, _, _ bool, _ amqp.Table) (amqp.Queue, error) {
	if c.declareErr != nil {
		return amqp.Queue{}, c.declareErr
	}
	return amqp.Queue{Name: name}, nil
}

func (c *fakeChannel) QueueBind(_, _, _ string, _ bool, _ amqp.Table) error { return c.bindErr }

func (c *fakeChannel) Consume(queue, _ string, _, _, _, _ bool, _ amqp.Table) (<-chan amqp.Delivery, error) {
	if c.consumeErr != nil {
		return nil, c.consumeErr
	}
	c.consumedSub = queue
	return c.deliveries, nil
}

func TestPublishMapsMessage(t *testing.T) {
	t.Parallel()
	ch := &fakeChannel{}
	bus := rabbitmq.NewBus(ch)
	err := bus.Publish(context.Background(), "payment.created", ports.Message{
		TenantID:       "t1",
		Type:           "payment.created",
		IdempotencyKey: "k1",
		Payload:        []byte(`{"a":1}`),
	})
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if len(ch.published) != 1 {
		t.Fatalf("expected 1 published, got %d", len(ch.published))
	}
	p := ch.published[0]
	if ch.boundKey != "payment.created" {
		t.Fatalf("routing key mismatch: %s", ch.boundKey)
	}
	if p.Headers["x-tenant-id"] != "t1" || p.Headers["x-idempotency-key"] != "k1" {
		t.Fatalf("headers mismatch: %+v", p.Headers)
	}
	if string(p.Body) != `{"a":1}` || p.ContentType != "application/json" {
		t.Fatal("body/content-type mismatch")
	}
}

func TestPublishError(t *testing.T) {
	t.Parallel()
	ch := &fakeChannel{publishErr: errors.New("down")}
	bus := rabbitmq.NewBus(ch)
	if err := bus.Publish(context.Background(), "t", ports.Message{}); err == nil {
		t.Fatal("expected publish error")
	}
}

func TestSubscribeDispatchesAckAndNack(t *testing.T) {
	t.Parallel()
	deliveries := make(chan amqp.Delivery, 2)
	ch := &fakeChannel{deliveries: deliveries}
	bus := rabbitmq.NewBus(ch)

	ack := &fakeAck{}
	var handled int
	var mu sync.Mutex
	err := bus.Subscribe(context.Background(), "payment.created", func(_ context.Context, m ports.Message) error {
		mu.Lock()
		handled++
		n := handled
		mu.Unlock()
		if m.TenantID != "t1" {
			t.Errorf("tenant mismatch: %s", m.TenantID)
		}
		if n == 2 {
			return errors.New("handler fail") // second delivery nacks
		}
		return nil
	})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	mkDelivery := func() amqp.Delivery {
		return amqp.Delivery{
			Acknowledger: ack,
			Headers:      amqp.Table{"x-tenant-id": "t1", "x-type": "payment.created", "x-idempotency-key": "k"},
			Body:         []byte("{}"),
		}
	}
	deliveries <- mkDelivery()
	deliveries <- mkDelivery()
	close(deliveries)

	bus.Wait()

	ack.mu.Lock()
	defer ack.mu.Unlock()
	if ack.acks != 1 {
		t.Fatalf("expected 1 ack, got %d", ack.acks)
	}
	if ack.nacks != 1 {
		t.Fatalf("expected 1 nack, got %d", ack.nacks)
	}
}

func TestSubscribeCancelStopsDispatch(t *testing.T) {
	t.Parallel()
	deliveries := make(chan amqp.Delivery)
	ch := &fakeChannel{deliveries: deliveries}
	bus := rabbitmq.NewBus(ch)
	ctx, cancel := context.WithCancel(context.Background())
	if err := bus.Subscribe(ctx, "topic", func(context.Context, ports.Message) error { return nil }); err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	cancel()
	bus.Wait() // returns once the dispatch goroutine observes ctx.Done
}

func TestSubscribeErrors(t *testing.T) {
	t.Parallel()
	h := func(context.Context, ports.Message) error { return nil }
	t.Run("declare", func(t *testing.T) {
		bus := rabbitmq.NewBus(&fakeChannel{declareErr: errors.New("x")})
		if err := bus.Subscribe(context.Background(), "t", h); err == nil {
			t.Fatal("want declare error")
		}
	})
	t.Run("bind", func(t *testing.T) {
		bus := rabbitmq.NewBus(&fakeChannel{bindErr: errors.New("x")})
		if err := bus.Subscribe(context.Background(), "t", h); err == nil {
			t.Fatal("want bind error")
		}
	})
	t.Run("consume", func(t *testing.T) {
		bus := rabbitmq.NewBus(&fakeChannel{consumeErr: errors.New("x")})
		if err := bus.Subscribe(context.Background(), "t", h); err == nil {
			t.Fatal("want consume error")
		}
	})
}

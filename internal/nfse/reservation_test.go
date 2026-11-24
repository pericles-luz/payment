package nfse

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// blockingTransmitter parks every Transmit until release is closed, so a test
// can hold one emission mid-flight while a concurrent one arrives.
type blockingTransmitter struct {
	mu      sync.Mutex
	calls   int
	entered chan struct{}
	release chan struct{}
	receipt Receipt
}

func newBlockingTransmitter() *blockingTransmitter {
	return &blockingTransmitter{entered: make(chan struct{}, 8), release: make(chan struct{}), receipt: Receipt{ChaveAcesso: "abc"}}
}

func (b *blockingTransmitter) Transmit(context.Context, string, []byte) (Receipt, error) {
	b.mu.Lock()
	b.calls++
	b.mu.Unlock()
	b.entered <- struct{}{}
	<-b.release
	return b.receipt, nil
}

func TestEmitConcurrentSameKeyTransmitsOnce(t *testing.T) {
	tx := newBlockingTransmitter()
	e, _ := provisionEmitter(t, testCNPJ, 24*time.Hour, tx)
	cmd := validCommand()
	cmd.IdempotencyKey = "idem-race"

	type result struct {
		em  Emission
		err error
	}
	first := make(chan result, 1)
	go func() {
		em, err := e.Emit(context.Background(), cmd)
		first <- result{em, err}
	}()
	<-tx.entered // the first request is now mid-transmit

	if _, err := e.Emit(context.Background(), cmd); !errors.Is(err, ErrEmissionInFlight) {
		t.Fatalf("concurrent Emit = %v, want ErrEmissionInFlight", err)
	}

	close(tx.release)
	r := <-first
	if r.err != nil {
		t.Fatalf("first Emit: %v", r.err)
	}
	replay, err := e.Emit(context.Background(), cmd)
	if err != nil || replay.ID != r.em.ID {
		t.Fatalf("replay after finish = %+v, %v; want id %s", replay, err, r.em.ID)
	}
	if tx.calls != 1 {
		t.Errorf("transmitted %d times, want 1", tx.calls)
	}
}

func TestEmitReleasesKeyOnTransportError(t *testing.T) {
	tx := &fakeTransmitter{err: &TransportError{Op: "do", Err: errors.New("timeout")}}
	e, _ := provisionEmitter(t, testCNPJ, 24*time.Hour, tx)
	cmd := validCommand()
	cmd.IdempotencyKey = "idem-retry"

	if _, err := e.Emit(context.Background(), cmd); err == nil {
		t.Fatal("first Emit should fail")
	}
	tx.err = nil
	tx.receipt = Receipt{ChaveAcesso: "abc"}
	em, err := e.Emit(context.Background(), cmd)
	if err != nil || em.Status != StatusAuthorized {
		t.Fatalf("retry = %+v, %v; want authorised", em, err)
	}
	if tx.calls != 2 {
		t.Errorf("calls = %d, want 2 (retry must transmit)", tx.calls)
	}
}

func TestEmitReleasesKeyOnPreTransmitFailure(t *testing.T) {
	tx := &fakeTransmitter{receipt: Receipt{ChaveAcesso: "abc"}}
	e, _ := provisionEmitter(t, testCNPJ, 24*time.Hour, tx)
	cmd := validCommand()
	cmd.IdempotencyKey = "idem-nocert"
	cmd.CompanyID = "tenant-without-cert"
	if _, err := e.Emit(context.Background(), cmd); !errors.Is(err, ErrNoCertificate) {
		t.Fatalf("Emit = %v, want ErrNoCertificate", err)
	}
	cmd.CompanyID = testCompany
	if _, err := e.Emit(context.Background(), cmd); err != nil {
		t.Fatalf("retry with cert = %v; key must have been released", err)
	}
}

// failingSaveStore lets Reserve through and fails every Save, simulating a DB
// outage right after the ADN answered.
type failingSaveStore struct {
	*MemoryStore
	released bool
}

func (f *failingSaveStore) Save(context.Context, Emission) error { return errors.New("db down") }
func (f *failingSaveStore) Release(ctx context.Context, h, k, id string) error {
	f.released = true
	return f.MemoryStore.Release(ctx, h, k, id)
}

func TestEmitKeepsReservationWhenSaveFailsAfterADNAnswer(t *testing.T) {
	tx := &fakeTransmitter{receipt: Receipt{ChaveAcesso: "abc"}}
	e, _ := provisionEmitter(t, testCNPJ, 24*time.Hour, tx)
	store := &failingSaveStore{MemoryStore: NewMemoryStore()}
	e.store = store
	cmd := validCommand()
	cmd.IdempotencyKey = "idem-savefail"

	if _, err := e.Emit(context.Background(), cmd); err == nil {
		t.Fatal("Emit should surface the Save failure")
	}
	if store.released {
		t.Fatal("reservation released after the ADN authorised: a retry would re-send the DPS")
	}
	if _, err := e.Emit(context.Background(), cmd); !errors.Is(err, ErrEmissionInFlight) {
		t.Errorf("retry within TTL = %v, want ErrEmissionInFlight", err)
	}
	if tx.calls != 1 {
		t.Errorf("calls = %d, want 1", tx.calls)
	}
}

func TestEmitTakesOverStaleReservation(t *testing.T) {
	tx := &fakeTransmitter{receipt: Receipt{ChaveAcesso: "abc"}}
	clock := testNow
	e, _ := provisionEmitter(t, testCNPJ, 24*time.Hour, tx, WithClock(func() time.Time { return clock }))
	cmd := validCommand()
	cmd.IdempotencyKey = "idem-stale"
	// A reservation left behind by a crashed request.
	if _, ok, err := e.store.Reserve(context.Background(), Emission{
		ID: "nfse_crashed", TenantID: cmd.TenantID, IdempotencyKey: cmd.IdempotencyKey,
		Status: StatusPending, CreatedAt: clock,
	}, clock.Add(-reservationTTL)); err != nil || !ok {
		t.Fatalf("seed reservation: ok=%v err=%v", ok, err)
	}
	if _, err := e.Emit(context.Background(), cmd); !errors.Is(err, ErrEmissionInFlight) {
		t.Fatalf("Emit within TTL = %v, want ErrEmissionInFlight", err)
	}
	clock = clock.Add(reservationTTL + time.Second)
	em, err := e.Emit(context.Background(), cmd)
	if err != nil || em.Status != StatusAuthorized || em.ID == "nfse_crashed" {
		t.Fatalf("Emit after TTL = %+v, %v; want a fresh authorised emission", em, err)
	}
	if _, err := e.Status(context.Background(), cmd.TenantID, "nfse_crashed"); !errors.Is(err, ErrNotFound) {
		t.Errorf("stale reservation still readable: %v", err)
	}
}

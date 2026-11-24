package nfse

import (
	"context"
	"errors"
	"testing"
	"time"
)

func sampleEmission(id, keyHash, idem string) Emission {
	return Emission{
		ID:                id,
		TenantID:          keyHash,
		IdempotencyKey:    idem,
		EmitterCNPJ:       "47064135000184",
		Competencia:       Competencia{Year: 2026, Month: 6},
		ServiceValueCents: 15000,
		Status:            StatusAuthorized,
		ChaveAcesso:       "123",
		CreatedAt:         time.Now().UTC(),
	}
}

func TestMemoryStoreSaveGet(t *testing.T) {
	ctx := context.Background()
	m := NewMemoryStore()
	e := sampleEmission("nfse_1", "keyA", "")
	if err := m.Save(ctx, e); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := m.GetByID(ctx, "keyA", "nfse_1")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.ChaveAcesso != "123" {
		t.Errorf("got %+v", got)
	}
}

func TestMemoryStoreTenantIsolation(t *testing.T) {
	ctx := context.Background()
	m := NewMemoryStore()
	if err := m.Save(ctx, sampleEmission("nfse_1", "keyA", "")); err != nil {
		t.Fatal(err)
	}
	// keyB must not see keyA's record — reported as not found (no oracle).
	if _, err := m.GetByID(ctx, "keyB", "nfse_1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant GetByID = %v, want ErrNotFound", err)
	}
	if _, err := m.GetByID(ctx, "keyA", "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing id = %v, want ErrNotFound", err)
	}
}

func TestMemoryStoreIdempotency(t *testing.T) {
	ctx := context.Background()
	m := NewMemoryStore()
	e := sampleEmission("nfse_1", "keyA", "idem-1")
	if err := m.Save(ctx, e); err != nil {
		t.Fatal(err)
	}
	got, err := m.GetByIdempotencyKey(ctx, "keyA", "idem-1")
	if err != nil {
		t.Fatalf("GetByIdempotencyKey: %v", err)
	}
	if got.ID != "nfse_1" {
		t.Errorf("got %s", got.ID)
	}
	// Empty key never matches.
	if _, err := m.GetByIdempotencyKey(ctx, "keyA", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty key = %v", err)
	}
	// Wrong tenant never matches.
	if _, err := m.GetByIdempotencyKey(ctx, "keyB", "idem-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant idem = %v", err)
	}
	// Unknown key.
	if _, err := m.GetByIdempotencyKey(ctx, "keyA", "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown idem = %v", err)
	}
}

func TestMemoryStoreReserve(t *testing.T) {
	ctx := context.Background()
	m := NewMemoryStore()
	now := time.Now().UTC()
	pending := sampleEmission("nfse_1", "keyA", "idem-1")
	pending.Status = StatusPending
	pending.CreatedAt = now

	if _, ok, err := m.Reserve(ctx, Emission{TenantID: "keyA"}, now); !errors.Is(err, ErrEmptyIdempotencyKey) || ok {
		t.Fatalf("empty key = ok %v, %v", ok, err)
	}
	if _, ok, err := m.Reserve(ctx, pending, now.Add(-time.Minute)); err != nil || !ok {
		t.Fatalf("first Reserve = ok %v, %v", ok, err)
	}
	second := pending
	second.ID = "nfse_2"
	if _, _, err := m.Reserve(ctx, second, now.Add(-time.Minute)); !errors.Is(err, ErrEmissionInFlight) {
		t.Fatalf("live reservation = %v, want ErrEmissionInFlight", err)
	}
	// Another tenant's identical key is independent.
	other := second
	other.TenantID = "keyB"
	if _, ok, err := m.Reserve(ctx, other, now.Add(-time.Minute)); err != nil || !ok {
		t.Fatalf("other tenant Reserve = ok %v, %v", ok, err)
	}

	// Release by a non-holder id is a no-op; by the holder it frees the key.
	if err := m.Release(ctx, "keyA", "idem-1", "nfse_2"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.Reserve(ctx, second, now.Add(-time.Minute)); !errors.Is(err, ErrEmissionInFlight) {
		t.Fatalf("after foreign Release = %v, want still in flight", err)
	}
	if err := m.Release(ctx, "keyA", "idem-1", "nfse_1"); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := m.Reserve(ctx, second, now.Add(-time.Minute)); err != nil || !ok {
		t.Fatalf("after Release = ok %v, %v", ok, err)
	}

	// A finished emission replays and survives Release.
	done := second
	done.Status = StatusAuthorized
	if err := m.Save(ctx, done); err != nil {
		t.Fatal(err)
	}
	if err := m.Release(ctx, "keyA", "idem-1", "nfse_2"); err != nil {
		t.Fatal(err)
	}
	third := pending
	third.ID = "nfse_3"
	prior, ok, err := m.Reserve(ctx, third, now.Add(time.Hour))
	if err != nil || ok || prior.ID != "nfse_2" {
		t.Fatalf("replay = %+v ok %v, %v; want nfse_2", prior, ok, err)
	}
}

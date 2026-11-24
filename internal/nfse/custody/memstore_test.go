package custody

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"
	"time"
)

func TestMemoryCertStorePutGetDelete(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryCertStore()
	chain, meta := provisionLeaf(t, "co-1", "11222333000181", time.Hour)

	if err := store.PutA1(ctx, "co-1", chain, meta); err != nil {
		t.Fatalf("put: %v", err)
	}

	gotChain, gotMeta, err := store.Get(ctx, "co-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(gotChain) != 1 || gotChain[0].SerialNumber.Cmp(chain[0].SerialNumber) != 0 {
		t.Error("stored chain mismatch")
	}
	if gotMeta.Serial != meta.Serial {
		t.Errorf("meta serial mismatch: %s != %s", gotMeta.Serial, meta.Serial)
	}

	if err := store.Delete(ctx, "co-1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, _, err := store.Get(ctx, "co-1"); !errors.Is(err, ErrCertNotFound) {
		t.Errorf("get after delete = %v, want ErrCertNotFound", err)
	}
	// Deleting an absent tenant is a no-op.
	if err := store.Delete(ctx, "co-1"); err != nil {
		t.Errorf("delete of absent tenant should be no-op, got %v", err)
	}
}

func TestMemoryCertStoreValidation(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryCertStore()
	chain, meta := provisionLeaf(t, "co-1", "11222333000181", time.Hour)

	if err := store.PutA1(ctx, "", chain, meta); !errors.Is(err, ErrEmptyCompanyID) {
		t.Errorf("put empty company = %v, want ErrEmptyCompanyID", err)
	}
	if err := store.PutA1(ctx, "co-1", nil, meta); !errors.Is(err, ErrEmptyChain) {
		t.Errorf("put empty chain = %v, want ErrEmptyChain", err)
	}
	if err := store.PutA1(ctx, "co-1", []*x509.Certificate{nil}, meta); !errors.Is(err, ErrEmptyChain) {
		t.Errorf("put nil element = %v, want ErrEmptyChain", err)
	}
	if _, _, err := store.Get(ctx, ""); !errors.Is(err, ErrEmptyCompanyID) {
		t.Errorf("get empty company = %v, want ErrEmptyCompanyID", err)
	}
	if err := store.Delete(ctx, ""); !errors.Is(err, ErrEmptyCompanyID) {
		t.Errorf("delete empty company = %v, want ErrEmptyCompanyID", err)
	}
	if _, _, err := store.Get(ctx, "nobody"); !errors.Is(err, ErrCertNotFound) {
		t.Errorf("get absent = %v, want ErrCertNotFound", err)
	}
}

// TestMemoryCertStoreStaleSeriesObserver covers the SIN-67763 re-import hook:
// replacing an on-file certificate with a DIFFERENT serial fires the stale-series
// observer with the OLD serial (so its a1_cert_expiry_days child can be dropped),
// while a first import and a same-serial re-Put leave the observer untouched.
func TestMemoryCertStoreStaleSeriesObserver(t *testing.T) {
	ctx := context.Background()
	type call struct{ company, serial string }
	var got []call
	store := NewMemoryCertStore(WithStaleSeriesObserver(func(company, serial string) {
		got = append(got, call{company, serial})
	}))

	chainA, metaA := provisionLeaf(t, "co-1", "11222333000181", time.Hour)
	chainB, metaB := provisionLeaf(t, "co-1", "11222333000181", time.Hour)
	if metaA.Serial == metaB.Serial {
		t.Fatal("test precondition: the two provisioned leaves must have different serials")
	}

	// First import: nothing on file, so no stale series to retire.
	if err := store.PutA1(ctx, "co-1", chainA, metaA); err != nil {
		t.Fatalf("put A: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("first import fired observer %v, want no calls", got)
	}

	// Same-serial re-Put (metadata refresh): the live series must stay put.
	if err := store.PutA1(ctx, "co-1", chainA, metaA); err != nil {
		t.Fatalf("re-put A: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("same-serial re-put fired observer %v, want no calls", got)
	}

	// Re-import onto serial B: the OLD serial (A) must be retired exactly once.
	if err := store.PutA1(ctx, "co-1", chainB, metaB); err != nil {
		t.Fatalf("put B: %v", err)
	}
	if len(got) != 1 || got[0] != (call{"co-1", metaA.Serial}) {
		t.Fatalf("re-import fired %v, want one call {co-1, %s}", got, metaA.Serial)
	}
}

// TestMemoryCertStoreNoObserverIsOptional proves the hook is optional: a store
// built without it re-imports without panicking.
func TestMemoryCertStoreNoObserverIsOptional(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryCertStore()
	chainA, metaA := provisionLeaf(t, "co-1", "11222333000181", time.Hour)
	chainB, metaB := provisionLeaf(t, "co-1", "11222333000181", time.Hour)
	if err := store.PutA1(ctx, "co-1", chainA, metaA); err != nil {
		t.Fatalf("put A: %v", err)
	}
	if err := store.PutA1(ctx, "co-1", chainB, metaB); err != nil {
		t.Fatalf("put B (no observer): %v", err)
	}
}

// TestMemoryCertStoreDefensiveCopy proves that mutating the caller's slice after
// PutA1 does not corrupt stored state, and that the slice returned by Get is a
// copy the caller cannot use to corrupt the store.
func TestMemoryCertStoreDefensiveCopy(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryCertStore()
	chain, meta := provisionLeaf(t, "co-1", "11222333000181", time.Hour)

	input := make([]*x509.Certificate, len(chain))
	copy(input, chain)
	if err := store.PutA1(ctx, "co-1", input, meta); err != nil {
		t.Fatalf("put: %v", err)
	}
	input[0] = nil // mutate caller slice

	got, _, err := store.Get(ctx, "co-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got[0] == nil {
		t.Error("store did not defensively copy the input chain")
	}
	got[0] = nil // mutate returned slice
	again, _, err := store.Get(ctx, "co-1")
	if err != nil || again[0] == nil {
		t.Error("mutating returned slice corrupted stored state")
	}
}

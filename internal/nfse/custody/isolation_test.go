package custody

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

// TestTenantIsolationSigner encodes the attack SecEng required as a regression
// (SIN-67486 §3, AC #6): tenant A must never be able to sign with tenant B's
// key, and the failure must be fail-closed. At the signer boundary the
// (companyID, certSerial) pair is the guard: presenting B's serial under A's
// company id (or vice versa) resolves to no key.
func TestTenantIsolationSigner(t *testing.T) {
	ctx := context.Background()
	s := NewLocalTestSigner()
	_, metaA, err := s.Provision("tenant-A", "11222333000181", time.Hour)
	if err != nil {
		t.Fatalf("provision A: %v", err)
	}
	_, metaB, err := s.Provision("tenant-B", "44555666000199", time.Hour)
	if err != nil {
		t.Fatalf("provision B: %v", err)
	}
	if metaA.Serial == metaB.Serial {
		t.Fatal("test precondition: serials collided")
	}
	digest := sha256.Sum256([]byte("DPS for tenant B"))

	// A tries to sign using B's serial -> denied, fail-closed.
	if _, err := s.SignDigest(ctx, "tenant-A", metaB.Serial, digest[:]); !errors.Is(err, ErrNotProvisioned) {
		t.Fatalf("cross-tenant sign (A with B serial) = %v, want ErrNotProvisioned", err)
	}
	// B tries to sign using A's serial -> denied, fail-closed.
	if _, err := s.SignDigest(ctx, "tenant-B", metaA.Serial, digest[:]); !errors.Is(err, ErrNotProvisioned) {
		t.Fatalf("cross-tenant sign (B with A serial) = %v, want ErrNotProvisioned", err)
	}
	// Each tenant CAN sign with its own key (proves the deny is specific, not blanket).
	if _, err := s.SignDigest(ctx, "tenant-A", metaA.Serial, digest[:]); err != nil {
		t.Errorf("tenant A own sign should succeed: %v", err)
	}
	if _, err := s.SignDigest(ctx, "tenant-B", metaB.Serial, digest[:]); err != nil {
		t.Errorf("tenant B own sign should succeed: %v", err)
	}
}

// TestTenantIsolationCertStore proves the store is tenant-scoped: tenant A's
// Get never returns tenant B's chain, and Delete of one tenant does not touch
// the other.
func TestTenantIsolationCertStore(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryCertStore()
	chainA, metaA := provisionLeaf(t, "tenant-A", "11222333000181", time.Hour)
	chainB, metaB := provisionLeaf(t, "tenant-B", "44555666000199", time.Hour)

	if err := store.PutA1(ctx, "tenant-A", chainA, metaA); err != nil {
		t.Fatal(err)
	}
	if err := store.PutA1(ctx, "tenant-B", chainB, metaB); err != nil {
		t.Fatal(err)
	}

	gotA, gA, err := store.Get(ctx, "tenant-A")
	if err != nil {
		t.Fatal(err)
	}
	if gotA[0].SerialNumber.Cmp(chainA[0].SerialNumber) != 0 || gA.Serial != metaA.Serial {
		t.Error("tenant A Get returned the wrong tenant's cert")
	}

	// Deleting A must not affect B (crypto-shred is per tenant).
	if err := store.Delete(ctx, "tenant-A"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Get(ctx, "tenant-A"); !errors.Is(err, ErrCertNotFound) {
		t.Errorf("tenant A should be shredded, got %v", err)
	}
	if _, gB, err := store.Get(ctx, "tenant-B"); err != nil || gB.Serial != metaB.Serial {
		t.Errorf("tenant B collateral-damaged by A delete: err=%v", err)
	}
}

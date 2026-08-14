package consoleauth_test

import (
	"context"
	"testing"
	"time"

	adapter "github.com/ia-dev-sindireceita/payment/internal/adapters/consoleauth"
	domain "github.com/ia-dev-sindireceita/payment/internal/domain/consoleauth"
)

func TestMemStoreCredential(t *testing.T) {
	t.Parallel()
	m := adapter.NewMemStore()
	ctx := context.Background()

	if _, ok, err := m.GetCredential(ctx); err != nil || ok {
		t.Fatalf("empty store: ok=%v err=%v, want ok=false", ok, err)
	}
	cred := domain.NewCredential("pericles.luz", "$hash$", "SECRET")
	if err := m.SaveCredential(ctx, cred); err != nil {
		t.Fatalf("SaveCredential: %v", err)
	}
	got, ok, err := m.GetCredential(ctx)
	if err != nil || !ok {
		t.Fatalf("after save: ok=%v err=%v", ok, err)
	}
	if got.Username() != "pericles.luz" || got.TOTPSecret() != "SECRET" {
		t.Fatalf("credential round-trip mismatch: %+v", got)
	}
}

func TestMemStoreSessionLifecycle(t *testing.T) {
	t.Parallel()
	m := adapter.NewMemStore()
	ctx := context.Background()
	start := time.Unix(1000, 0).UTC()
	sess := domain.NewSession("sid", "pericles.luz", start, time.Hour)

	if err := m.Create(ctx, sess); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, ok, err := m.Get(ctx, "sid")
	if err != nil || !ok {
		t.Fatalf("Get after create: ok=%v err=%v", ok, err)
	}
	if !got.LastSeenAt().Equal(start) {
		t.Fatalf("last-seen = %v, want %v", got.LastSeenAt(), start)
	}

	// Touch advances last-seen.
	later := start.Add(5 * time.Minute)
	if err := m.Touch(ctx, "sid", later); err != nil {
		t.Fatalf("Touch: %v", err)
	}
	got, _, _ = m.Get(ctx, "sid")
	if !got.LastSeenAt().Equal(later) {
		t.Fatalf("touch did not advance last-seen: %v", got.LastSeenAt())
	}
	// Touch of an unknown id is a no-op (no error).
	if err := m.Touch(ctx, "missing", later); err != nil {
		t.Fatalf("Touch unknown: %v", err)
	}

	// Delete revokes; a second delete is idempotent.
	if err := m.Delete(ctx, "sid"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok, _ := m.Get(ctx, "sid"); ok {
		t.Fatal("session should be gone after delete")
	}
	if err := m.Delete(ctx, "sid"); err != nil {
		t.Fatalf("idempotent delete: %v", err)
	}
}

func TestMemStoreReplay(t *testing.T) {
	t.Parallel()
	m := adapter.NewMemStore()
	ctx := context.Background()

	if last, err := m.LastStep(ctx, "pericles.luz"); err != nil || last != 0 {
		t.Fatalf("initial last step = %d err=%v, want 0", last, err)
	}
	if err := m.SetLastStep(ctx, "pericles.luz", 42); err != nil {
		t.Fatalf("SetLastStep: %v", err)
	}
	if last, _ := m.LastStep(ctx, "pericles.luz"); last != 42 {
		t.Fatalf("last step = %d, want 42", last)
	}
	// Distinct subjects are independent.
	if last, _ := m.LastStep(ctx, "other"); last != 0 {
		t.Fatalf("other subject last step = %d, want 0", last)
	}
}

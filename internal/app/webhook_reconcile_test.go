package app_test

import (
	"context"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/app"
)

// stubEnumerator implements ports.CredentialEnumerator for tests.
type stubEnumerator struct {
	ids []string
	err error
}

func (s *stubEnumerator) ListTenantsWithC6Credential(_ context.Context) ([]string, error) {
	return s.ids, s.err
}

// TestWebhookReconcileWorker_FlagOff verifies Sweep is a no-op when disabled.
func TestWebhookReconcileWorker_FlagOff(t *testing.T) {
	enum := &stubEnumerator{ids: []string{"tnt-a"}}
	// registrar is nil — safe because TryRegister guards on ready() which checks for nil
	worker := app.NewWebhookReconcileWorker(false, enum, nil, nil)
	n, err := worker.Sweep(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 eligible with flag off, got %d", n)
	}
}

// TestWebhookReconcileWorker_EnumeratorError surfaces enumerator errors.
func TestWebhookReconcileWorker_EnumeratorError(t *testing.T) {
	enum := &stubEnumerator{err: context.DeadlineExceeded}
	// registrar nil is safe: we error before calling TryRegister
	worker := app.NewWebhookReconcileWorker(true, enum, nil, nil)
	_, err := worker.Sweep(context.Background())
	if err == nil {
		t.Fatal("expected error from enumerator, got nil")
	}
}

// TestWebhookReconcileWorker_EmptySet succeeds with zero eligible tenants.
func TestWebhookReconcileWorker_EmptySet(t *testing.T) {
	enum := &stubEnumerator{ids: nil}
	worker := app.NewWebhookReconcileWorker(true, enum, nil, nil)
	n, err := worker.Sweep(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 eligible, got %d", n)
	}
}

// TestWebhookReconcileWorker_EligibleCount returns the count from the enumerator even
// when the WebhookRegistrationService is nil (TryRegister no-ops on nil).
func TestWebhookReconcileWorker_EligibleCount(t *testing.T) {
	enum := &stubEnumerator{ids: []string{"tnt-a", "tnt-b"}}
	// registrar nil → TryRegister is a silent no-op (ready() returns false)
	worker := app.NewWebhookReconcileWorker(true, enum, nil, nil)
	n, err := worker.Sweep(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 eligible, got %d", n)
	}
}

// TestWebhookReconcileWorker_CtxCancelled stops mid-sweep on context cancellation
// without blocking or leaking (the sweep exits early when ctx.Err() is non-nil).
func TestWebhookReconcileWorker_CtxCancelled(t *testing.T) {
	enum := &stubEnumerator{ids: []string{"tnt-a", "tnt-b", "tnt-c"}}
	worker := app.NewWebhookReconcileWorker(true, enum, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled
	// Sweep should return without hanging even though ctx is done.
	n, err := worker.Sweep(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// eligible is returned (set before the loop), only the loop body may be cut short
	if n != 3 {
		t.Fatalf("expected 3 eligible (set before loop), got %d", n)
	}
}

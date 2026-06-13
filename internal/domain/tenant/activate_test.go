package tenant_test

import (
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
)

func TestActivateDeactivate(t *testing.T) {
	t.Parallel()
	tn, err := tenant.New("t1", "Acme", time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if !tn.Active() {
		t.Fatalf("new tenant should be active")
	}
	tn.Deactivate()
	if tn.Active() {
		t.Fatalf("deactivate failed")
	}
	tn.Activate()
	if !tn.Active() {
		t.Fatalf("activate failed")
	}
	// Idempotent: activating an active tenant stays active.
	tn.Activate()
	if !tn.Active() {
		t.Fatalf("activate not idempotent")
	}
}

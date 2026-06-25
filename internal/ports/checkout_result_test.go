package ports_test

import (
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// TestCheckoutResultAmountReconciled mirrors the charge/PIX reconciliation contract for
// the checkout session (roteiro 12 settlement): only an exact capture of the authorized
// total reconciles; a partial/over capture or a non-positive total fails closed.
func TestCheckoutResultAmountReconciled(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		expected int64
		received int64
		want     bool
	}{
		{"exact match settles", 1250, 1250, true},
		{"partial capture does not reconcile", 1250, 500, false},
		{"overcapture does not reconcile", 1250, 1300, false},
		{"open session does not reconcile", 1250, 0, false},
		{"degenerate zero-total never reconciles", 0, 0, false},
		{"zero-total with capture never reconciles", 0, 100, false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := ports.CheckoutResult{
				Status:              "paid",
				AmountCents:         tc.expected,
				ReceivedAmountCents: tc.received,
			}
			if got := r.AmountReconciled(); got != tc.want {
				t.Fatalf("AmountReconciled(total=%d, received=%d): want %v, got %v",
					tc.expected, tc.received, tc.want, got)
			}
		})
	}
}

package outboundqueue_test

import (
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/outboundqueue"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

var f2Now = time.Date(2026, 8, 17, 16, 0, 0, 0, time.UTC)

func mustDelivery(t *testing.T) *outboundqueue.Delivery {
	t.Helper()
	d, err := outboundqueue.NewDelivery("d-1", "acct-verz", "ten-1", "ek-1", "tx-1", "payment.paid", f2Now)
	if err != nil {
		t.Fatalf("new delivery: %v", err)
	}
	return d
}

// DeadLetterFromDelivery copies the delivery's tenant/event fields into a park carrying an
// F2 reason, so an undeliverable event is inspectable/replayable (never forwarded to a
// guessed Conta).
func TestDeadLetterFromDeliveryCarriesFields(t *testing.T) {
	t.Parallel()
	for _, reason := range []outboundqueue.Reason{
		outboundqueue.ReasonEndpointInactive,
		outboundqueue.ReasonDeliveryExhausted,
	} {
		dl, err := outboundqueue.DeadLetterFromDelivery("dl-1", mustDelivery(t), reason, f2Now)
		if err != nil {
			t.Fatalf("reason %s: %v", reason, err)
		}
		if dl.TenantID() != "ten-1" || dl.EventKey() != "ek-1" || dl.TxID() != "tx-1" ||
			dl.EventType() != "payment.paid" {
			t.Fatalf("fields not carried: %+v", dl)
		}
		if dl.Reason() != reason {
			t.Fatalf("reason = %q, want %q", dl.Reason(), reason)
		}
	}
}

// The helper rejects a nil delivery and any reason that is not an F2 delivery-failure
// reason (so a caller cannot mislabel a park, e.g. as the F1-only 'unresolvable').
func TestDeadLetterFromDeliveryValidatesInputs(t *testing.T) {
	t.Parallel()
	if _, err := outboundqueue.DeadLetterFromDelivery("dl-1", nil, outboundqueue.ReasonEndpointInactive, f2Now); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("nil delivery: err = %v, want validation", err)
	}
	if _, err := outboundqueue.DeadLetterFromDelivery("dl-1", mustDelivery(t), outboundqueue.ReasonUnresolvable, f2Now); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("F1 reason via F2 helper: err = %v, want validation", err)
	}
	if _, err := outboundqueue.DeadLetterFromDelivery("dl-1", mustDelivery(t), outboundqueue.Reason("bogus"), f2Now); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unknown reason: err = %v, want validation", err)
	}
}

// The F2 reasons are accepted by the DeadLetter constructor (they are in the known set),
// and the F2 delivered status is defined.
func TestF2ReasonsAndStatusKnown(t *testing.T) {
	t.Parallel()
	for _, reason := range []outboundqueue.Reason{
		outboundqueue.ReasonEndpointInactive,
		outboundqueue.ReasonDeliveryExhausted,
	} {
		if _, err := outboundqueue.NewDeadLetter("dl", "ten", "ek", "tx", "payment.paid", reason, f2Now); err != nil {
			t.Fatalf("reason %s should be accepted: %v", reason, err)
		}
	}
	if outboundqueue.StatusDelivered != "delivered" {
		t.Fatalf("StatusDelivered = %q", outboundqueue.StatusDelivered)
	}
}

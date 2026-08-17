package audit_test

import (
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

// The F2 per-attempt delivery entry is account-scoped, records the result action and
// carries the inbound event_key as the subject txID (join key), never a payload/secret.
func TestNewOutboundDeliveryEntryAccountScoped(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 8, 17, 16, 0, 0, 0, time.UTC)
	for _, action := range []audit.Action{
		audit.ActionOutboundWebhookDelivered,
		audit.ActionOutboundWebhookDeadLettered,
	} {
		e, err := audit.NewOutboundDeliveryEntry("evt-1", "system:outbound-forward", action, "acct-9", "ek-1", at)
		if err != nil {
			t.Fatalf("action %s: %v", action, err)
		}
		if e.Action() != action {
			t.Errorf("action = %q; want %q", e.Action(), action)
		}
		if e.AccountID() != "acct-9" {
			t.Errorf("account id = %q; want acct-9", e.AccountID())
		}
		if e.TenantID() != "" {
			t.Errorf("tenant id = %q; want empty (account-scoped)", e.TenantID())
		}
		if e.TxID() != "ek-1" {
			t.Errorf("txID(event_key) = %q; want ek-1", e.TxID())
		}
		if e.OperatorID() != "system:outbound-forward" {
			t.Errorf("operator = %q", e.OperatorID())
		}
	}
}

func TestNewOutboundDeliveryEntryInvariants(t *testing.T) {
	t.Parallel()
	at := time.Now()
	if _, err := audit.NewOutboundDeliveryEntry("", "op", audit.ActionOutboundWebhookDelivered, "acct-1", "ek", at); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("empty id: err = %v; want validation", err)
	}
	if _, err := audit.NewOutboundDeliveryEntry("id", "op", audit.ActionOutboundWebhookDelivered, "", "ek", at); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("empty account: err = %v; want validation", err)
	}
	// A config or foreign action must be refused (deny-by-default; delivery constructor
	// only takes the two per-attempt result actions).
	if _, err := audit.NewOutboundDeliveryEntry("id", "op", audit.ActionSetOutboundWebhook, "acct-1", "ek", at); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("config action via delivery constructor: err = %v; want validation", err)
	}
	if _, err := audit.NewOutboundDeliveryEntry("id", "op", audit.ActionCreateTenant, "acct-1", "ek", at); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("foreign action: err = %v; want validation", err)
	}
	// An empty event_key is allowed (an event that carried no key).
	if _, err := audit.NewOutboundDeliveryEntry("id", "op", audit.ActionOutboundWebhookDelivered, "acct-1", "", at); err != nil {
		t.Errorf("empty event_key should be allowed: %v", err)
	}
}

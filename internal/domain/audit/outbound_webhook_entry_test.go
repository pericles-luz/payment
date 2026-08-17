package audit_test

import (
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

func TestNewOutboundWebhookEntryAccountScoped(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	for _, action := range []audit.Action{
		audit.ActionSetOutboundWebhook,
		audit.ActionRotateOutboundWebhookSecret,
		audit.ActionRemoveOutboundWebhook,
	} {
		e, err := audit.NewOutboundWebhookEntry("evt-1", "op-1", action, "acct-9", at)
		if err != nil {
			t.Fatalf("action %s: %v", action, err)
		}
		if e.Action() != action {
			t.Errorf("action = %q; want %q", e.Action(), action)
		}
		// Account-scoped: the account is the explicit target, tenant is empty.
		if e.AccountID() != "acct-9" {
			t.Errorf("account id = %q; want acct-9", e.AccountID())
		}
		if e.TenantID() != "" {
			t.Errorf("tenant id = %q; want empty (account-scoped)", e.TenantID())
		}
		if e.OperatorID() != "op-1" {
			t.Errorf("operator = %q; want op-1", e.OperatorID())
		}
	}
}

func TestNewOutboundWebhookEntryInvariants(t *testing.T) {
	t.Parallel()
	at := time.Now()
	if _, err := audit.NewOutboundWebhookEntry("", "op", audit.ActionSetOutboundWebhook, "acct-1", at); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("empty id: err = %v; want validation", err)
	}
	if _, err := audit.NewOutboundWebhookEntry("id", "op", audit.ActionSetOutboundWebhook, "", at); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("empty account: err = %v; want validation", err)
	}
	// A non-webhook action must be refused (deny-by-default, no tenant-scoped smuggling).
	if _, err := audit.NewOutboundWebhookEntry("id", "op", audit.ActionCreateTenant, "acct-1", at); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("foreign action: err = %v; want validation", err)
	}
}

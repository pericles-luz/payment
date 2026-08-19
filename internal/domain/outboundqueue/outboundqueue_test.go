package outboundqueue_test

import (
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/outboundqueue"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

var testNow = time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)

func TestNewDeliveryValidation(t *testing.T) {
	tests := []struct {
		name                                               string
		id, accountID, tenantID, eventKey, txID, eventType string
		wantErr                                            bool
	}{
		{"ok", "d1", "acct-1", "ten-1", "ek-1", "tx-1", "payment.paid", false},
		{"ok empty txid allowed", "d1", "acct-1", "ten-1", "ek-1", "", "payment.paid", false},
		{"missing id", "", "acct-1", "ten-1", "ek-1", "tx-1", "payment.paid", true},
		{"missing account", "d1", "", "ten-1", "ek-1", "tx-1", "payment.paid", true},
		{"whitespace account", "d1", "   ", "ten-1", "ek-1", "tx-1", "payment.paid", true},
		{"missing tenant", "d1", "acct-1", "", "ek-1", "tx-1", "payment.paid", true},
		{"missing event key", "d1", "acct-1", "ten-1", "", "tx-1", "payment.paid", true},
		{"missing event type", "d1", "acct-1", "ten-1", "ek-1", "tx-1", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := outboundqueue.NewDelivery(tt.id, tt.accountID, tt.tenantID, tt.eventKey, tt.txID, tt.eventType, outboundqueue.Detail{}, testNow)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if !errors.Is(err, shared.ErrValidation) {
					t.Fatalf("expected ErrValidation, got %v", err)
				}
				if d != nil {
					t.Fatalf("expected nil delivery on error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if d.Status() != outboundqueue.StatusPending {
				t.Fatalf("expected pending status, got %q", d.Status())
			}
		})
	}
}

func TestDeliveryTrimsAndAccessors(t *testing.T) {
	d, err := outboundqueue.NewDelivery("  d1 ", " acct-1 ", " ten-1 ", " ek-1 ", " tx-1 ", " payment.paid ", outboundqueue.Detail{}, testNow)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.ID() != "d1" || d.AccountID() != "acct-1" || d.TenantID() != "ten-1" ||
		d.EventKey() != "ek-1" || d.TxID() != "tx-1" || d.EventType() != "payment.paid" {
		t.Fatalf("fields not trimmed: %+v", d)
	}
	if !d.CreatedAt().Equal(testNow) {
		t.Fatalf("createdAt mismatch: %v", d.CreatedAt())
	}
}

func TestRehydrateDelivery(t *testing.T) {
	d := outboundqueue.RehydrateDelivery("d1", "acct-1", "ten-1", "ek-1", "tx-1", "payment.paid", outboundqueue.StatusPending, testNow, outboundqueue.Detail{})
	if d.ID() != "d1" || d.AccountID() != "acct-1" || d.Status() != outboundqueue.StatusPending {
		t.Fatalf("rehydrate mismatch: %+v", d)
	}
}

func TestNewDeadLetterValidation(t *testing.T) {
	tests := []struct {
		name                                    string
		id, tenantID, eventKey, txID, eventType string
		reason                                  outboundqueue.Reason
		wantErr                                 bool
	}{
		{"ok", "dl1", "ten-1", "ek-1", "tx-1", "payment.paid", outboundqueue.ReasonUnresolvable, false},
		{"ok empty txid", "dl1", "ten-1", "ek-1", "", "payment.paid", outboundqueue.ReasonUnresolvable, false},
		{"missing id", "", "ten-1", "ek-1", "tx-1", "payment.paid", outboundqueue.ReasonUnresolvable, true},
		{"missing tenant", "dl1", "", "ek-1", "tx-1", "payment.paid", outboundqueue.ReasonUnresolvable, true},
		{"missing event key", "dl1", "ten-1", "", "tx-1", "payment.paid", outboundqueue.ReasonUnresolvable, true},
		{"missing event type", "dl1", "ten-1", "ek-1", "tx-1", "", outboundqueue.ReasonUnresolvable, true},
		{"empty reason", "dl1", "ten-1", "ek-1", "tx-1", "payment.paid", outboundqueue.Reason(""), true},
		{"unknown reason", "dl1", "ten-1", "ek-1", "tx-1", "payment.paid", outboundqueue.Reason("bogus"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dl, err := outboundqueue.NewDeadLetter(tt.id, tt.tenantID, tt.eventKey, tt.txID, tt.eventType, tt.reason, testNow)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if !errors.Is(err, shared.ErrValidation) {
					t.Fatalf("expected ErrValidation, got %v", err)
				}
				if dl != nil {
					t.Fatalf("expected nil dead-letter on error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if dl.Reason() != tt.reason {
				t.Fatalf("reason mismatch: %q", dl.Reason())
			}
		})
	}
}

func TestDeadLetterAccessors(t *testing.T) {
	dl, err := outboundqueue.NewDeadLetter(" dl1 ", " ten-1 ", " ek-1 ", " tx-1 ", " payment.paid ", outboundqueue.ReasonUnresolvable, testNow)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dl.ID() != "dl1" || dl.TenantID() != "ten-1" || dl.EventKey() != "ek-1" ||
		dl.TxID() != "tx-1" || dl.EventType() != "payment.paid" {
		t.Fatalf("fields not trimmed: %+v", dl)
	}
	if !dl.CreatedAt().Equal(testNow) {
		t.Fatalf("createdAt mismatch")
	}
}

func TestRehydrateDeadLetter(t *testing.T) {
	dl := outboundqueue.RehydrateDeadLetter("dl1", "ten-1", "ek-1", "tx-1", "payment.paid", outboundqueue.ReasonUnresolvable, testNow)
	if dl.ID() != "dl1" || dl.Reason() != outboundqueue.ReasonUnresolvable {
		t.Fatalf("rehydrate mismatch: %+v", dl)
	}
}

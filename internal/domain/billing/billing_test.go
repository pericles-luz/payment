package billing_test

import (
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/billing"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

func TestNewEndpointPricing(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, tenant, endpoint string
		price                  int64
		wantErr                bool
	}{
		{name: "valid", tenant: "t1", endpoint: "pix.create", price: 50},
		{name: "free endpoint", tenant: "t1", endpoint: "pix.create", price: 0},
		{name: "missing tenant", tenant: "", endpoint: "pix.create", price: 50, wantErr: true},
		{name: "missing endpoint", tenant: "t1", endpoint: "", price: 50, wantErr: true},
		{name: "negative price", tenant: "t1", endpoint: "pix.create", price: -1, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p, err := billing.NewEndpointPricing(tt.tenant, tt.endpoint, tt.price)
			if tt.wantErr {
				if !errors.Is(err, shared.ErrValidation) {
					t.Fatalf("want ErrValidation, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected: %v", err)
			}
			if p.TenantID() != tt.tenant || p.Endpoint() != tt.endpoint || p.PriceCents() != tt.price {
				t.Fatal("field mismatch")
			}
		})
	}
}

func TestNewLedgerEntry(t *testing.T) {
	t.Parallel()
	at := time.Unix(100, 0).UTC()
	tests := []struct {
		name, id, tenant, endpoint string
		price                      int64
		wantErr                    bool
	}{
		{name: "valid", id: "l1", tenant: "t1", endpoint: "pix.create", price: 50},
		{name: "missing id", id: "", tenant: "t1", endpoint: "pix.create", price: 50, wantErr: true},
		{name: "missing tenant", id: "l1", tenant: "", endpoint: "pix.create", price: 50, wantErr: true},
		{name: "missing endpoint", id: "l1", tenant: "t1", endpoint: "", price: 50, wantErr: true},
		{name: "negative price", id: "l1", tenant: "t1", endpoint: "pix.create", price: -5, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e, err := billing.NewLedgerEntry(tt.id, tt.tenant, tt.endpoint, "ref1", tt.price, at)
			if tt.wantErr {
				if !errors.Is(err, shared.ErrValidation) {
					t.Fatalf("want ErrValidation, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected: %v", err)
			}
			if e.ID() != tt.id || e.TenantID() != tt.tenant || e.Endpoint() != tt.endpoint {
				t.Fatal("field mismatch")
			}
			if e.PriceCents() != tt.price || e.Reference() != "ref1" || !e.At().Equal(at) {
				t.Fatal("value mismatch")
			}
			// No account option → self-account (empty), NULL-safe default.
			if e.AccountID() != "" {
				t.Fatalf("default account = %q, want empty", e.AccountID())
			}
		})
	}
}

// TestLedgerEntryWithAccount covers the account attribution option (SIN-69127):
// WithAccount stamps and trims the owning account; omitting it leaves the
// self-account (empty), and blank input is normalised to empty.
func TestLedgerEntryWithAccount(t *testing.T) {
	t.Parallel()
	at := time.Unix(100, 0).UTC()

	e, err := billing.NewLedgerEntry("l1", "t1", "pix.create", "ref", 50, at, billing.WithAccount("  acct-t1  "))
	if err != nil {
		t.Fatalf("with account: %v", err)
	}
	if e.AccountID() != "acct-t1" {
		t.Fatalf("account = %q, want acct-t1 (trimmed)", e.AccountID())
	}

	blank, err := billing.NewLedgerEntry("l2", "t1", "pix.create", "ref", 50, at, billing.WithAccount("   "))
	if err != nil {
		t.Fatalf("blank account: %v", err)
	}
	if blank.AccountID() != "" {
		t.Fatalf("blank account = %q, want empty (self-account)", blank.AccountID())
	}
}

package c6

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// The carteira is environment-dependent (C6 documents 15 in production, 21 in sandbox), so
// it must come from configuration. Hardcoding it would register every charge against the
// production carteira from a sandbox deployment — accepted by the bank, wrong in effect.
func TestBillingSchemeComesFromConfig(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	p, err := New(Config{
		BaseURL:       ps.URL,
		TokenURL:      ps.URL + "/oauth/token",
		HTTPClient:    ps.Client(),
		BillingScheme: "21",
	}, oneTenant("t1", "c", "s"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := p.CreateBoleto(context.Background(), "t1", ports.BoletoRequest{
		TenantID: "t1", BoletoID: "b", AmountCents: 100, Currency: "BRL",
		DueDate: time.Unix(1_800_000_000, 0), Payer: fullBoletoPayer(),
		Description: "Compra de produto X",
	}); err != nil {
		t.Fatalf("CreateBoleto: %v", err)
	}
	var sent struct {
		PaymentMethod struct {
			BankSlip struct {
				BillingScheme string `json:"billing_scheme"`
			} `json:"bank_slip"`
		} `json:"payment_method"`
	}
	if err := json.Unmarshal(ps.body(), &sent); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if got := sent.PaymentMethod.BankSlip.BillingScheme; got != "21" {
		t.Fatalf("billing_scheme = %q, want the configured 21", got)
	}
}

// The contract expresses expiry as whole days after the due date, while the port carries an
// instant. A window that is absent or non-positive is not expressible, so the key is
// omitted rather than sent as zero/negative (which the strict schema rejects).
func TestDaysAfterDueDateMapping(t *testing.T) {
	t.Parallel()
	due := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)

	cases := []struct {
		name       string
		validUntil time.Time
		want       *int
	}{
		{"unset omits the key", time.Time{}, nil},
		{"before due omits the key", due.AddDate(0, 0, -3), nil},
		{"same day omits the key", due, nil},
		{"ten days after", due.AddDate(0, 0, 10), intPtr(10)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := daysAfterDueDate(due, tc.validUntil)
			switch {
			case tc.want == nil && got != nil:
				t.Fatalf("want nil, got %d", *got)
			case tc.want != nil && got == nil:
				t.Fatalf("want %d, got nil", *tc.want)
			case tc.want != nil && *got != *tc.want:
				t.Fatalf("want %d, got %d", *tc.want, *got)
			}
		})
	}
}

func intPtr(i int) *int { return &i }

// A registration without the mandatory description or neighborhood must fail at OUR
// boundary, with a message naming the field — not as an opaque 400 from the bank.
func TestCreateBoletoRequiresContractMandatoryFields(t *testing.T) {
	t.Parallel()
	base := func() ports.BoletoRequest {
		return ports.BoletoRequest{
			TenantID: "t1", BoletoID: "b", AmountCents: 100, Currency: "BRL",
			DueDate: time.Unix(1_800_000_000, 0), Payer: fullBoletoPayer(),
			Description: "Compra de produto X",
		}
	}
	cases := []struct {
		name   string
		mutate func(*ports.BoletoRequest)
	}{
		{"missing description", func(r *ports.BoletoRequest) { r.Description = "  " }},
		{"description too long", func(r *ports.BoletoRequest) { r.Description = string(make([]byte, 101)) }},
		{"missing neighborhood", func(r *ports.BoletoRequest) { r.Payer.Address.Neighborhood = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ps := newProductServer(t)
			p := ps.provider(t, oneTenant("t1", "c", "s"))
			req := base()
			tc.mutate(&req)
			if _, err := p.CreateBoleto(context.Background(), "t1", req); err == nil {
				t.Fatal("want a validation error")
			} else if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want ErrValidation, got %v", err)
			}
			if len(ps.body()) > 0 {
				t.Fatalf("nothing may reach the bank: %s", ps.body())
			}
		})
	}
}

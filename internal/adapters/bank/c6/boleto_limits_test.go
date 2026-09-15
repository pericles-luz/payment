package c6

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// baseLimitRequest is a registration that satisfies every contract limit, so each subtest
// can violate exactly one field and attribute the rejection to it.
func baseLimitRequest() ports.BoletoRequest {
	return ports.BoletoRequest{
		TenantID:    "t1",
		BoletoID:    "3f2a9c1d7e4b48a0b5c6d7e8f9a0b1c2",
		AmountCents: 1234,
		Currency:    "BRL",
		DueDate:     time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		Payer:       fullBoletoPayer(),
		Description: "Compra de produto X",
	}
}

// Every limit in the Bolepix contract is a CHARACTER count, and measuring bytes instead
// silently refuses ordinary Portuguese before it ever reaches the bank. This is the
// regression guard: a description of exactly 100 characters that occupies well over 100
// bytes must be ACCEPTED.
func TestBankSlipLimitsCountRunesNotBytes(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	p := ps.provider(t, oneTenant("t1", "c", "s"))

	// 100 accented characters => 200 bytes. A byte-based check rejects this; the contract
	// does not.
	desc := strings.Repeat("ç", 100)
	if len(desc) <= maxDescriptionLen {
		t.Fatalf("fixture must exceed the limit in BYTES to be meaningful, got %d", len(desc))
	}
	req := baseLimitRequest()
	req.Description = desc
	if _, err := p.CreateBoleto(context.Background(), "t1", req); err != nil {
		t.Fatalf("a 100-character description must be accepted, got %v", err)
	}

	// And one character past the limit must still be refused.
	req.Description = strings.Repeat("ç", 101)
	if _, err := p.CreateBoleto(context.Background(), "t1", req); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("101 characters must be refused, got %v", err)
	}
}

// Each contract limit is refused locally, with the offending field named, rather than
// forwarded to the bank as an opaque 400 whose problem+json this adapter discards.
func TestBankSlipFieldLimits(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		mutate func(*ports.BoletoRequest)
		want   string
	}{
		{"amount over the bank ceiling", func(r *ports.BoletoRequest) {
			r.AmountCents = 5_000_000_01
		}, "amount"},
		{"payer name too long", func(r *ports.BoletoRequest) {
			r.Payer.Name = strings.Repeat("a", 41)
		}, "payer.name"},
		{"street and number over the combined line", func(r *ports.BoletoRequest) {
			// 38 chars of street plus ", 1234" composes to 44 — over the 40-char line even
			// though the street alone fits.
			r.Payer.Address.Street = strings.Repeat("a", 38)
			r.Payer.Address.Number = 1234
		}, "street and number"},
		{"neighborhood too long", func(r *ports.BoletoRequest) {
			r.Payer.Address.Neighborhood = strings.Repeat("a", 41)
		}, "neighborhood"},
		{"city too long", func(r *ports.BoletoRequest) {
			r.Payer.Address.City = strings.Repeat("a", 41)
		}, "city"},
		{"masked tax id", func(r *ports.BoletoRequest) {
			r.Payer.TaxID = "123.456.789-01"
		}, "tax_id"},
		{"tax id of the wrong width", func(r *ports.BoletoRequest) {
			r.Payer.TaxID = "1234567890"
		}, "tax_id"},
		{"zip with a mask", func(r *ports.BoletoRequest) {
			r.Payer.Address.ZipCode = "70000-00"
		}, "zip_code"},
		{"uf that is not two letters", func(r *ports.BoletoRequest) {
			r.Payer.Address.State = "DFF"
		}, "state"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ps := newProductServer(t)
			p := ps.provider(t, oneTenant("t1", "c", "s"))
			req := baseLimitRequest()
			tc.mutate(&req)

			_, err := p.CreateBoleto(context.Background(), "t1", req)
			if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want ErrValidation, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error must name the offending field %q, got %q", tc.want, err.Error())
			}
			// Complete mediation: the rejection happens before anything is sent.
			if body := ps.body(); len(body) != 0 {
				t.Fatalf("nothing must reach the bank on a local rejection, sent %s", body)
			}
		})
	}
}

// A lowercase UF is unambiguous, so it is normalized to the contract's [A-Z]{2} rather
// than refused — refusing it would be pedantry, not safety.
func TestBankSlipUppercasesUF(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	p := ps.provider(t, oneTenant("t1", "c", "s"))

	req := baseLimitRequest()
	req.Payer.Address.State = "df"
	if _, err := p.CreateBoleto(context.Background(), "t1", req); err != nil {
		t.Fatalf("CreateBoleto: %v", err)
	}
	if !strings.Contains(string(ps.body()), `"state":"DF"`) {
		t.Fatalf("UF must be normalized to uppercase on the wire, got %s", ps.body())
	}
}

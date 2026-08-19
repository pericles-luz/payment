package c6

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// --- Boleto: fees, read reconciliation and the absent amendment endpoint ---

// The real /v1/bank_slips discount object has a portal-gated inner schema (undiscovered by
// blind probing — SIN-65888), so CreateBoleto intentionally OMITS it until captured (CTO
// decision on SIN-65953; tracked as a child follow-up). Even when the port request carries
// discount tiers, the bank_slips body must not emit a `discount`/`discounts` key (the
// strict C6 schema would 400). Fine/interest/amount still transport. (This replaces the
// prior "carries discounts on create" assertion, obsoleted by the DTO split — CTO §4.)
// The published contract exposes exactly ONE discount tier (first_discount_*), so a single
// tier maps and a second one is refused instead of being dropped: silently discarding a
// tier would change what the payer owes.
func TestCreateBoletoDiscountTier(t *testing.T) {
	t.Parallel()

	t.Run("single_tier_maps_into_fees", func(t *testing.T) {
		t.Parallel()
		ps := newProductServer(t)
		p := ps.provider(t, oneTenant("t1", "client-1", "secret-1"))

		if _, err := p.CreateBoleto(context.Background(), "t1", ports.BoletoRequest{
			TenantID: "t1", BoletoID: "bol_1", AmountCents: 100000, Currency: "BRL",
			FineBps: 200, MonthlyInterestBps: 100,
			Payer:       fullBoletoPayer(),
			Description: "Compra de produto X",
			Discounts:   []ports.BoletoDiscountTier{{DaysBeforeDue: 10, Bps: 1000}},
		}); err != nil {
			t.Fatalf("CreateBoleto: %v", err)
		}
		var sent struct {
			Fees struct {
				DiscountType          string      `json:"discount_type"`
				FirstDiscountValue    json.Number `json:"first_discount_value"`
				FirstDiscountDeadline int         `json:"first_discount_deadline"`
			} `json:"fees"`
		}
		if err := json.Unmarshal(ps.body(), &sent); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if sent.Fees.FirstDiscountValue.String() != "10.00" || sent.Fees.FirstDiscountDeadline != 10 {
			t.Fatalf("discount tier not mapped: %+v (body=%s)", sent.Fees, ps.body())
		}
		if sent.Fees.DiscountType == "" {
			t.Fatalf("discount_type must accompany the value: %s", ps.body())
		}
		// The invented top-level array must be gone.
		var raw map[string]json.RawMessage
		_ = json.Unmarshal(ps.body(), &raw)
		if _, ok := raw["discounts"]; ok {
			t.Fatalf("discounts is not a contract field: %s", ps.body())
		}
	})

	t.Run("second_tier_is_refused", func(t *testing.T) {
		t.Parallel()
		ps := newProductServer(t)
		p := ps.provider(t, oneTenant("t1", "client-1", "secret-1"))

		_, err := p.CreateBoleto(context.Background(), "t1", ports.BoletoRequest{
			TenantID: "t1", BoletoID: "bol_1", AmountCents: 100000, Currency: "BRL",
			Payer:       fullBoletoPayer(),
			Description: "Compra de produto X",
			Discounts: []ports.BoletoDiscountTier{
				{DaysBeforeDue: 10, Bps: 1000},
				{DaysBeforeDue: 0, FixedCents: 500},
			},
		})
		if !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("a second tier must be refused, got %v", err)
		}
	})
}

func TestGetBoletoSuccess(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	p := ps.provider(t, oneTenant("t1", "client-1", "secret-1"))

	res, err := p.GetBoleto(context.Background(), "t1", "bol_1")
	if err != nil {
		t.Fatalf("GetBoleto: %v", err)
	}
	if res.BoletoID != "bol_1" || res.Status != "REGISTERED" {
		t.Fatalf("unexpected result: %+v", res)
	}
	if res.FineBps != 200 || res.MonthlyInterestBps != 100 {
		t.Fatalf("registered rates not reconciled: %+v", res)
	}
	if len(res.Discounts) != 1 || res.Discounts[0].Bps != 500 {
		t.Fatalf("discounts not reconciled: %+v", res.Discounts)
	}
	if ps.lastAuthHeader != "Bearer tok-client-1" {
		t.Fatalf("bearer not attached: %q", ps.lastAuthHeader)
	}
}

func TestGetBoletoNotFoundMapping(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	ps.boletoGet = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":"NOT_FOUND"}`))
	}
	p := ps.provider(t, oneTenant("t1", "c", "s"))
	if _, err := p.GetBoleto(context.Background(), "t1", "nope"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("404 should map to ErrNotFound, got %v", err)
	}
}

func TestGetBoletoMissingCredential(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	p := ps.provider(t, &fakeCreds{creds: map[string]ports.BankCredential{}})
	if _, err := p.GetBoleto(context.Background(), "unknown", "b"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("missing credential should propagate ErrNotFound, got %v", err)
	}
	if ps.tokenCount() != 0 {
		t.Fatalf("token must not be hit without a credential, hits=%d", ps.tokenCount())
	}
}

// roteiro grupo 4: baixa/cancelamento via DELETE; bearer attached, status reconciled.
func TestCancelBoletoSuccess(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	p := ps.provider(t, oneTenant("t1", "client-1", "secret-1"))

	res, err := p.CancelBoleto(context.Background(), "t1", "bol_1")
	if err != nil {
		t.Fatalf("CancelBoleto: %v", err)
	}
	if res.Status != "CANCELLED" {
		t.Fatalf("status = %q, want CANCELLED", res.Status)
	}
	if ps.lastAuthHeader != "Bearer tok-client-1" {
		t.Fatalf("bearer not attached: %q", ps.lastAuthHeader)
	}
}

func TestCancelBoletoNotFoundMapping(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	ps.boletoCancel = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":"NOT_FOUND"}`))
	}
	p := ps.provider(t, oneTenant("t1", "c", "s"))
	if _, err := p.CancelBoleto(context.Background(), "t1", "nope"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("404 should map to ErrNotFound, got %v", err)
	}
}

// roteiro grupo 5: alteração via PUT carries the new params; bearer + idempotency.
// The contract has no amendment endpoint, so UpdateBoleto fails closed. The alternative —
// PUTting a speculative path — would look like it amended a registered charge while the
// bank knew nothing about it, leaving our state and the bank's divergent on money.
func TestUpdateBoletoIsUnsupported(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	p := ps.provider(t, oneTenant("t1", "client-1", "secret-1"))

	_, err := p.UpdateBoleto(context.Background(), "t1", "bol_1", ports.BoletoRequest{
		TenantID: "t1", BoletoID: "bol_1", AmountCents: 2000, Currency: "BRL",
	})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation, got %v", err)
	}
	if ps.body() != nil && len(ps.body()) > 0 {
		t.Fatalf("no request may reach the bank: %s", ps.body())
	}
}

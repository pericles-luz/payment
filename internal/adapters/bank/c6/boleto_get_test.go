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

// --- Boleto: register OMITS the portal-gated discount, read reconciles legacy tiers ---

// The real /v1/bank_slips discount object has a portal-gated inner schema (undiscovered by
// blind probing — SIN-65888), so CreateBoleto intentionally OMITS it until captured (CTO
// decision on SIN-65953; tracked as a child follow-up). Even when the port request carries
// discount tiers, the bank_slips body must not emit a `discount`/`discounts` key (the
// strict C6 schema would 400). Fine/interest/amount still transport. (This replaces the
// prior "carries discounts on create" assertion, obsoleted by the DTO split — CTO §4.)
func TestCreateBoletoOmitsPortalGatedDiscount(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	p := ps.provider(t, oneTenant("t1", "client-1", "secret-1"))

	if _, err := p.CreateBoleto(context.Background(), "t1", ports.BoletoRequest{
		TenantID: "t1", BoletoID: "bol_1", AmountCents: 100000, Currency: "BRL",
		FineBps: 200, MonthlyInterestBps: 100,
		Payer: fullBoletoPayer(),
		Discounts: []ports.BoletoDiscountTier{
			{DaysBeforeDue: 10, Bps: 1000},
			{DaysBeforeDue: 0, FixedCents: 500},
		},
	}); err != nil {
		t.Fatalf("CreateBoleto: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(ps.body(), &raw); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	for _, gone := range []string{"discount", "discounts"} {
		if _, ok := raw[gone]; ok {
			t.Fatalf("portal-gated %q must be omitted from the bank_slips body: %s", gone, ps.body())
		}
	}
	// Sanity: the rest of the rate set still transports (the omission is discount-specific).
	if _, ok := raw["fine"]; !ok {
		t.Fatalf("fine must still transport alongside the discount omission: %s", ps.body())
	}
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
func TestUpdateBoletoSuccess(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	p := ps.provider(t, oneTenant("t1", "client-1", "secret-1"))

	res, err := p.UpdateBoleto(context.Background(), "t1", "bol_1", ports.BoletoRequest{
		TenantID: "t1", BoletoID: "bol_1", AmountCents: 2000, Currency: "BRL",
		FineBps: 150, MonthlyInterestBps: 80, IdempotencyKey: "upd-key",
	})
	if err != nil {
		t.Fatalf("UpdateBoleto: %v", err)
	}
	if res.AmountCents != 2000 || res.FineBps != 150 {
		t.Fatalf("amended params not reconciled: %+v", res)
	}
	var sent struct {
		Amount  int64 `json:"amount"`
		FineBps int64 `json:"fine_bps"`
	}
	if err := json.Unmarshal(ps.body(), &sent); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if sent.Amount != 2000 || sent.FineBps != 150 {
		t.Fatalf("update body not transported: %s", ps.body())
	}
	if ps.idemKey() != "upd-key" {
		t.Fatalf("idempotency key not forwarded: %q", ps.idemKey())
	}
}

func TestUpdateBoletoNotFoundMapping(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	ps.boletoUpdate = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":"NOT_FOUND"}`))
	}
	p := ps.provider(t, oneTenant("t1", "c", "s"))
	if _, err := p.UpdateBoleto(context.Background(), "t1", "nope", ports.BoletoRequest{
		TenantID: "t1", BoletoID: "nope", AmountCents: 1, Currency: "BRL", IdempotencyKey: "k",
	}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("404 should map to ErrNotFound, got %v", err)
	}
}

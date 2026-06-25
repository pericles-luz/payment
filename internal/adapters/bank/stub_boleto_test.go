package bank

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// roteiro 6.a: register a boleto with its parameters, then read it back by id; the
// registered fine/interest/discount echo for reconciliation.
func TestStubGetBoleto(t *testing.T) {
	t.Parallel()
	s := newStub(t)
	ctx := context.Background()
	due := time.Unix(1_800_000_000, 0).UTC()

	if _, err := s.CreateBoleto(ctx, "t1", ports.BoletoRequest{
		TenantID: "t1", BoletoID: "bol_1", AmountCents: 100000, Currency: "BRL",
		DueDate: due, FineBps: 200, MonthlyInterestBps: 100,
		Discounts: []ports.BoletoDiscountTier{{DaysBeforeDue: 0, Bps: 500}},
	}); err != nil {
		t.Fatalf("CreateBoleto: %v", err)
	}

	got, err := s.GetBoleto(ctx, "t1", "bol_1")
	if err != nil {
		t.Fatalf("GetBoleto: %v", err)
	}
	if got.BoletoID != "bol_1" || got.Status != "REGISTERED" || got.AmountCents != 100000 {
		t.Fatalf("unexpected: %+v", got)
	}
	if got.FineBps != 200 || got.MonthlyInterestBps != 100 || !got.DueDate.Equal(due) {
		t.Fatalf("registered params not reconciled: %+v", got)
	}
	if len(got.Discounts) != 1 || got.Discounts[0].Bps != 500 {
		t.Fatalf("discounts not reconciled: %+v", got.Discounts)
	}
}

// An unknown id within a known tenant is not-found; a boleto registered by one
// tenant is invisible to another (tenant isolation).
func TestStubGetBoletoIsolation(t *testing.T) {
	t.Parallel()
	s := newStub(t)
	ctx := context.Background()

	if _, err := s.CreateBoleto(ctx, "t1", ports.BoletoRequest{TenantID: "t1", BoletoID: "bol_1", AmountCents: 100, Currency: "BRL"}); err != nil {
		t.Fatalf("CreateBoleto: %v", err)
	}
	if _, err := s.GetBoleto(ctx, "t1", "nope"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("unknown id: want ErrNotFound, got %v", err)
	}
	// Another tenant cannot read t1's boleto, and a tenant without a credential is
	// rejected before any lookup.
	if _, err := s.GetBoleto(ctx, "other", "bol_1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant: want ErrNotFound, got %v", err)
	}
}

// roteiro grupo 4: baixa marca CANCELLED (idempotente); unknown/cross-tenant → 404.
func TestStubCancelBoleto(t *testing.T) {
	t.Parallel()
	s := newStub(t)
	ctx := context.Background()
	if _, err := s.CreateBoleto(ctx, "t1", ports.BoletoRequest{TenantID: "t1", BoletoID: "bol_1", AmountCents: 100, Currency: "BRL"}); err != nil {
		t.Fatalf("CreateBoleto: %v", err)
	}

	res, err := s.CancelBoleto(ctx, "t1", "bol_1")
	if err != nil || res.Status != "CANCELLED" {
		t.Fatalf("cancel: status=%q err=%v", res.Status, err)
	}
	// GET now reflects cancellation; a second cancel is idempotent.
	got, _ := s.GetBoleto(ctx, "t1", "bol_1")
	if got.Status != "CANCELLED" {
		t.Fatalf("get after cancel: %q", got.Status)
	}
	if _, err := s.CancelBoleto(ctx, "t1", "bol_1"); err != nil {
		t.Fatalf("second cancel must be idempotent: %v", err)
	}
	// unknown id and cross-tenant cancel → not found (no oracle).
	if _, err := s.CancelBoleto(ctx, "t1", "nope"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("unknown cancel: want ErrNotFound, got %v", err)
	}
	if _, err := s.CancelBoleto(ctx, "other", "bol_1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant cancel: want ErrNotFound, got %v", err)
	}
}

// roteiro grupo 5: alteração amends mutable params; unknown/cross-tenant → 404.
func TestStubUpdateBoleto(t *testing.T) {
	t.Parallel()
	s := newStub(t)
	ctx := context.Background()
	due := time.Unix(1_800_000_000, 0).UTC()
	if _, err := s.CreateBoleto(ctx, "t1", ports.BoletoRequest{
		TenantID: "t1", BoletoID: "bol_1", AmountCents: 100000, Currency: "BRL",
		DueDate: due, FineBps: 200, MonthlyInterestBps: 100,
	}); err != nil {
		t.Fatalf("CreateBoleto: %v", err)
	}

	newDue := due.Add(48 * time.Hour)
	validUntil := newDue.Add(120 * time.Hour)
	res, err := s.UpdateBoleto(ctx, "t1", "bol_1", ports.BoletoRequest{
		TenantID: "t1", BoletoID: "bol_1", AmountCents: 90000, Currency: "BRL",
		DueDate: newDue, ValidUntil: validUntil, FineBps: 150, MonthlyInterestBps: 50,
	})
	if err != nil {
		t.Fatalf("UpdateBoleto: %v", err)
	}
	if res.AmountCents != 90000 || res.FineBps != 150 || !res.DueDate.Equal(newDue) || !res.ValidUntil.Equal(validUntil) {
		t.Fatalf("amended fields not applied: %+v", res)
	}
	// Identity preserved; GET reflects the amendment.
	got, _ := s.GetBoleto(ctx, "t1", "bol_1")
	if got.TxID != "tx_bol_1" || got.AmountCents != 90000 {
		t.Fatalf("get after update: %+v", got)
	}
	if _, err := s.UpdateBoleto(ctx, "t1", "nope", ports.BoletoRequest{TenantID: "t1", BoletoID: "nope"}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("unknown update: want ErrNotFound, got %v", err)
	}
	if _, err := s.UpdateBoleto(ctx, "other", "bol_1", ports.BoletoRequest{TenantID: "other", BoletoID: "bol_1"}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant update: want ErrNotFound, got %v", err)
	}
}

// Registration is idempotent on (tenant, id): a repeat returns the same record.
func TestStubCreateBoletoIdempotent(t *testing.T) {
	t.Parallel()
	s := newStub(t)
	ctx := context.Background()
	req := ports.BoletoRequest{TenantID: "t1", BoletoID: "bol_1", AmountCents: 100, Currency: "BRL"}

	first, err := s.CreateBoleto(ctx, "t1", req)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	again, err := s.CreateBoleto(ctx, "t1", req)
	if err != nil {
		t.Fatalf("repeat: %v", err)
	}
	if first.TxID != again.TxID {
		t.Fatalf("idempotent create returned different tx: %s vs %s", first.TxID, again.TxID)
	}
}

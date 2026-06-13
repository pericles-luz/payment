package bank_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/bank"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

func TestStubChargeLifecycle(t *testing.T) {
	t.Parallel()
	creds := secret.NewStore(map[string]ports.BankCredential{"t1": {ClientID: "c", Secret: "s"}})
	p := bank.NewStubProvider(creds)
	ctx := context.Background()

	res, err := p.CreateCharge(ctx, "t1", ports.ChargeRequest{TenantID: "t1", PaymentID: "pay1", AmountCents: 100, Currency: "BRL"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if res.TxID != "tx_pay1" || res.Status != "pending" {
		t.Fatalf("unexpected result: %+v", res)
	}

	got, err := p.GetCharge(ctx, "t1", res.TxID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != "pending" {
		t.Fatal("expected pending")
	}

	p.MarkSettled("t1", res.TxID)
	got, _ = p.GetCharge(ctx, "t1", res.TxID)
	if got.Status != "paid" {
		t.Fatal("expected paid after settle")
	}
}

func TestStubRequiresCredential(t *testing.T) {
	t.Parallel()
	creds := secret.NewStore(nil)
	p := bank.NewStubProvider(creds)
	_, err := p.CreateCharge(context.Background(), "nocred", ports.ChargeRequest{PaymentID: "p"})
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want not found without credential, got %v", err)
	}
}

func TestStubGetUnknownCharge(t *testing.T) {
	t.Parallel()
	p := bank.NewStubProvider(secret.NewStore(nil))
	if _, err := p.GetCharge(context.Background(), "t1", "missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want not found, got %v", err)
	}
}

package bank_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/bank"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

func newCobvStub(t *testing.T) *bank.StubProvider {
	t.Helper()
	creds := secret.NewStore(map[string]ports.BankCredential{
		"t1": {ClientID: "c", Secret: "s"},
		"t2": {ClientID: "c2", Secret: "s2"},
	})
	return bank.NewStubProvider(creds)
}

func cobvReq() ports.PixDueChargeRequest {
	return ports.PixDueChargeRequest{
		TenantID: "t1", AmountCents: 1000, Currency: "BRL",
		DueDate: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), ValidityDays: 5,
		FineBps: 200, MonthlyInterestBps: 100, DiscountBps: 500,
		DebtorTaxID: "12345678901", DebtorName: "Maria",
		CreditorKey: "acme@pix.example", IdempotencyKey: "cobv-1",
	}
}

func TestStubCobvCreateAndGet(t *testing.T) {
	t.Parallel()
	p := newCobvStub(t)
	ctx := context.Background()

	res, err := p.CreateDueCharge(ctx, "t1", cobvReq())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if res.TxID == "" || res.Status != "ATIVA" || res.QRCodePayload == "" || res.QRCodeLocation == "" {
		t.Fatalf("unexpected result: %+v", res)
	}
	if res.ExpectedAmountCents != 1000 || res.ValidityDays != 5 || res.FineBps != 200 || res.DiscountBps != 500 {
		t.Fatalf("params not echoed: %+v", res)
	}

	got, err := p.GetDueCharge(ctx, "t1", res.TxID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.TxID != res.TxID {
		t.Fatalf("get txid mismatch: %q vs %q", got.TxID, res.TxID)
	}
}

func TestStubCobvIdempotent(t *testing.T) {
	t.Parallel()
	p := newCobvStub(t)
	ctx := context.Background()
	a, err := p.CreateDueCharge(ctx, "t1", cobvReq())
	if err != nil {
		t.Fatalf("create a: %v", err)
	}
	b, err := p.CreateDueCharge(ctx, "t1", cobvReq())
	if err != nil {
		t.Fatalf("create b: %v", err)
	}
	if a.TxID != b.TxID {
		t.Fatalf("same anchor must resolve to same txid: %q vs %q", a.TxID, b.TxID)
	}
}

func TestStubCobvRejectsBadInput(t *testing.T) {
	t.Parallel()
	p := newCobvStub(t)
	ctx := context.Background()
	bad := cobvReq()
	bad.AmountCents = 0
	if _, err := p.CreateDueCharge(ctx, "t1", bad); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("zero amount must be ErrValidation, got %v", err)
	}
	bad = cobvReq()
	bad.IdempotencyKey = ""
	bad.TxID = ""
	if _, err := p.CreateDueCharge(ctx, "t1", bad); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty anchor must be ErrValidation, got %v", err)
	}
}

func TestStubCobvGetUnknown(t *testing.T) {
	t.Parallel()
	p := newCobvStub(t)
	if _, err := p.GetDueCharge(context.Background(), "t1", "missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("unknown txid must be ErrNotFound, got %v", err)
	}
}

// OWASP A01: one tenant can never read or amend another tenant's cobv charge.
func TestStubCobvIsolation(t *testing.T) {
	t.Parallel()
	p := newCobvStub(t)
	ctx := context.Background()
	res, err := p.CreateDueCharge(ctx, "t1", cobvReq())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := p.GetDueCharge(ctx, "t2", res.TxID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant get must be ErrNotFound, got %v", err)
	}
	req := cobvReq()
	req.AmountCents = 2000
	if _, err := p.UpdateDueCharge(ctx, "t2", res.TxID, req); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant amend must be ErrNotFound, got %v", err)
	}
}

func TestStubCobvUpdate(t *testing.T) {
	t.Parallel()
	p := newCobvStub(t)
	ctx := context.Background()
	res, err := p.CreateDueCharge(ctx, "t1", cobvReq())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	req := cobvReq()
	req.AmountCents = 2500
	req.ValidityDays = 10
	upd, err := p.UpdateDueCharge(ctx, "t1", res.TxID, req)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if upd.TxID != res.TxID {
		t.Fatalf("amend must preserve identity: %q vs %q", upd.TxID, res.TxID)
	}
	if upd.ExpectedAmountCents != 2500 || upd.ValidityDays != 10 {
		t.Fatalf("amended params not applied: %+v", upd)
	}
	got, _ := p.GetDueCharge(ctx, "t1", res.TxID)
	if got.ExpectedAmountCents != 2500 {
		t.Fatalf("amend not persisted: %+v", got)
	}
}

func TestStubCobvUpdateUnknown(t *testing.T) {
	t.Parallel()
	p := newCobvStub(t)
	req := cobvReq()
	if _, err := p.UpdateDueCharge(context.Background(), "t1", "missing", req); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("amend of unknown txid must be ErrNotFound, got %v", err)
	}
}

// A created cobv charge is reconcilable via the bank's generic charge-read so the
// webhook can reconcile-before-settle it (roteiro 7.8).
func TestStubCobvReconcilableForWebhook(t *testing.T) {
	t.Parallel()
	p := newCobvStub(t)
	ctx := context.Background()
	res, err := p.CreateDueCharge(ctx, "t1", cobvReq())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Before payment: the bank reports the charge as not-yet-paid.
	got, err := p.GetCharge(ctx, "t1", res.TxID)
	if err != nil {
		t.Fatalf("get charge: %v", err)
	}
	if got.Status == "paid" || got.AmountReconciled() {
		t.Fatalf("unpaid charge must not reconcile: %+v", got)
	}
	// After the bank settles it, the reconcile read reports paid + money matches.
	p.MarkSettled("t1", res.TxID)
	got, _ = p.GetCharge(ctx, "t1", res.TxID)
	if got.Status != "paid" || !got.AmountReconciled() {
		t.Fatalf("settled charge must reconcile: %+v", got)
	}
}

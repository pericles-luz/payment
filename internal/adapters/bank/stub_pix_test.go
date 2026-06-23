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

func newPixStub(t *testing.T) *bank.StubProvider {
	t.Helper()
	creds := secret.NewStore(map[string]ports.BankCredential{"t1": {ClientID: "c", Secret: "s"}})
	return bank.NewStubProvider(creds)
}

func TestStubPixCreateAndGet(t *testing.T) {
	t.Parallel()
	p := newPixStub(t)
	now := time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)
	p.SetClock(func() time.Time { return now })
	ctx := context.Background()

	res, err := p.CreateImmediateCharge(ctx, "t1", ports.ChargeRequest{
		TenantID: "t1", PaymentID: "pay1", IdempotencyKey: "idem1", AmountCents: 1050, Currency: "BRL",
	}, 30*time.Minute)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if res.TxID == "" || res.Status != "ATIVA" {
		t.Fatalf("unexpected result: %+v", res)
	}
	if res.QRCodePayload == "" || res.QRCodeLocation == "" {
		t.Fatalf("QR material missing: %+v", res)
	}
	if res.ExpectedAmountCents != 1050 {
		t.Fatalf("expected amount: %d", res.ExpectedAmountCents)
	}
	if want := now.Add(30 * time.Minute); !res.ExpiresAt.Equal(want) {
		t.Fatalf("ExpiresAt: want %v got %v", want, res.ExpiresAt)
	}

	got, err := p.GetImmediateCharge(ctx, "t1", res.TxID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.TxID != res.TxID {
		t.Fatalf("get txid mismatch: %q vs %q", got.TxID, res.TxID)
	}
}

func TestStubPixCreateDefaultExpiry(t *testing.T) {
	t.Parallel()
	p := newPixStub(t)
	now := time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)
	p.SetClock(func() time.Time { return now })

	res, err := p.CreateImmediateCharge(context.Background(), "t1", ports.ChargeRequest{
		TenantID: "t1", PaymentID: "pay1", AmountCents: 100, Currency: "BRL",
	}, 0)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if want := now.Add(time.Hour); !res.ExpiresAt.Equal(want) {
		t.Fatalf("default expiry: want %v got %v", want, res.ExpiresAt)
	}
}

func TestStubPixCreateIdempotent(t *testing.T) {
	t.Parallel()
	p := newPixStub(t)
	ctx := context.Background()
	req := ports.ChargeRequest{TenantID: "t1", PaymentID: "pay1", IdempotencyKey: "idem1", AmountCents: 500, Currency: "BRL"}

	first, err := p.CreateImmediateCharge(ctx, "t1", req, time.Hour)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := p.CreateImmediateCharge(ctx, "t1", req, time.Hour)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if first.TxID != second.TxID {
		t.Fatalf("re-submit changed txid: %q vs %q", first.TxID, second.TxID)
	}
}

func TestStubPixCreateRejectsInvalid(t *testing.T) {
	t.Parallel()
	p := newPixStub(t)
	ctx := context.Background()

	// Non-positive amount.
	if _, err := p.CreateImmediateCharge(ctx, "t1", ports.ChargeRequest{
		TenantID: "t1", PaymentID: "pay1", AmountCents: 0, Currency: "BRL",
	}, time.Hour); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation for zero amount, got %v", err)
	}
	// Empty anchor (no idempotency key, no payment id).
	if _, err := p.CreateImmediateCharge(ctx, "t1", ports.ChargeRequest{
		TenantID: "t1", AmountCents: 100, Currency: "BRL",
	}, time.Hour); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation for empty anchor, got %v", err)
	}
}

func TestStubPixRequiresCredential(t *testing.T) {
	t.Parallel()
	p := bank.NewStubProvider(secret.NewStore(nil))
	ctx := context.Background()
	if _, err := p.CreateImmediateCharge(ctx, "nocred", ports.ChargeRequest{
		PaymentID: "p", AmountCents: 100, Currency: "BRL",
	}, time.Hour); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want ErrNotFound without credential, got %v", err)
	}
	if _, err := p.GetImmediateCharge(ctx, "nocred", "tx"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want ErrNotFound without credential, got %v", err)
	}
	if _, err := p.ListImmediateCharges(ctx, "nocred", ports.PixListFilter{
		Start: time.Now().Add(-time.Hour), End: time.Now(),
	}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want ErrNotFound without credential, got %v", err)
	}
}

func TestStubPixGetUnknown(t *testing.T) {
	t.Parallel()
	p := newPixStub(t)
	if _, err := p.GetImmediateCharge(context.Background(), "t1", "missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestStubPixListByDateAndPagination(t *testing.T) {
	t.Parallel()
	p := newPixStub(t)
	ctx := context.Background()
	base := time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)

	// Create three charges at increasing instants.
	for i, key := range []string{"k1", "k2", "k3"} {
		p.SetClock(func() time.Time { return base.Add(time.Duration(i) * time.Minute) })
		if _, err := p.CreateImmediateCharge(ctx, "t1", ports.ChargeRequest{
			TenantID: "t1", PaymentID: key, IdempotencyKey: key, AmountCents: int64(100 * (i + 1)), Currency: "BRL",
		}, time.Hour); err != nil {
			t.Fatalf("create %s: %v", key, err)
		}
	}

	// Window covering all three.
	full, err := p.ListImmediateCharges(ctx, "t1", ports.PixListFilter{
		Start: base.Add(-time.Minute), End: base.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if full.TotalItems != 3 || len(full.Charges) != 3 {
		t.Fatalf("expected 3 charges, got %+v", full)
	}
	// Ascending by creation instant.
	if full.Charges[0].ExpectedAmountCents != 100 || full.Charges[2].ExpectedAmountCents != 300 {
		t.Fatalf("ordering wrong: %+v", full.Charges)
	}

	// Narrow window excludes the first charge.
	narrow, err := p.ListImmediateCharges(ctx, "t1", ports.PixListFilter{
		Start: base.Add(30 * time.Second), End: base.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("list narrow: %v", err)
	}
	if narrow.TotalItems != 2 {
		t.Fatalf("narrow window: want 2, got %d", narrow.TotalItems)
	}

	// Pagination: page size 2 => 2 pages.
	page0, err := p.ListImmediateCharges(ctx, "t1", ports.PixListFilter{
		Start: base.Add(-time.Minute), End: base.Add(time.Hour), Page: 0, PageSize: 2,
	})
	if err != nil {
		t.Fatalf("page0: %v", err)
	}
	if len(page0.Charges) != 2 || page0.TotalPages != 2 || page0.TotalItems != 3 {
		t.Fatalf("page0: %+v", page0)
	}
	page1, err := p.ListImmediateCharges(ctx, "t1", ports.PixListFilter{
		Start: base.Add(-time.Minute), End: base.Add(time.Hour), Page: 1, PageSize: 2,
	})
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	if len(page1.Charges) != 1 {
		t.Fatalf("page1: want 1 charge, got %d", len(page1.Charges))
	}
	// Out-of-range page is empty.
	page9, err := p.ListImmediateCharges(ctx, "t1", ports.PixListFilter{
		Start: base.Add(-time.Minute), End: base.Add(time.Hour), Page: 9, PageSize: 2,
	})
	if err != nil {
		t.Fatalf("page9: %v", err)
	}
	if len(page9.Charges) != 0 {
		t.Fatalf("page9 should be empty, got %d", len(page9.Charges))
	}
}

func TestStubPixListTenantIsolation(t *testing.T) {
	t.Parallel()
	creds := secret.NewStore(map[string]ports.BankCredential{
		"t1": {ClientID: "c1", Secret: "s"},
		"t2": {ClientID: "c2", Secret: "s"},
	})
	p := bank.NewStubProvider(creds)
	ctx := context.Background()
	base := time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)
	p.SetClock(func() time.Time { return base })

	if _, err := p.CreateImmediateCharge(ctx, "t1", ports.ChargeRequest{
		TenantID: "t1", PaymentID: "p1", IdempotencyKey: "k1", AmountCents: 100, Currency: "BRL",
	}, time.Hour); err != nil {
		t.Fatalf("create t1: %v", err)
	}

	// t2 lists the same window and sees nothing (cross-tenant isolation).
	list, err := p.ListImmediateCharges(ctx, "t2", ports.PixListFilter{
		Start: base.Add(-time.Hour), End: base.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("list t2: %v", err)
	}
	if list.TotalItems != 0 {
		t.Fatalf("tenant isolation breached: t2 saw %d charges", list.TotalItems)
	}
}

func TestStubPixListMissingWindow(t *testing.T) {
	t.Parallel()
	p := newPixStub(t)
	if _, err := p.ListImmediateCharges(context.Background(), "t1", ports.PixListFilter{
		End: time.Now(),
	}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation for missing start, got %v", err)
	}
}

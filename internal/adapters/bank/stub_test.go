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

// TestStubIdempotencyKeyDedup is the double-submit regression for F3b: when the
// same idempotency key is replayed, the bank returns the original charge and does
// NOT create a second one — even when the PaymentID differs (a retry that lost the
// local reservation race). This proves PSP-level dedup is keyed by the forwarded
// idempotency key, the defense-in-depth the real C6 adapter must preserve.
func TestStubIdempotencyKeyDedup(t *testing.T) {
	t.Parallel()
	creds := secret.NewStore(map[string]ports.BankCredential{"t1": {ClientID: "c", Secret: "s"}})
	p := bank.NewStubProvider(creds)
	ctx := context.Background()

	first, err := p.CreateCharge(ctx, "t1", ports.ChargeRequest{TenantID: "t1", PaymentID: "payA", AmountCents: 100, Currency: "BRL", IdempotencyKey: "idem-1"})
	if err != nil {
		t.Fatalf("first charge: %v", err)
	}
	// Double-submit: same key, different payment id (the retry generated a new id).
	second, err := p.CreateCharge(ctx, "t1", ports.ChargeRequest{TenantID: "t1", PaymentID: "payB", AmountCents: 100, Currency: "BRL", IdempotencyKey: "idem-1"})
	if err != nil {
		t.Fatalf("second charge: %v", err)
	}
	if second.TxID != first.TxID {
		t.Fatalf("replay must return the original charge: first=%s second=%s", first.TxID, second.TxID)
	}
	if got := p.ChargeCount(); got != 1 {
		t.Fatalf("idempotent replay must not create a second charge: ChargeCount=%d", got)
	}

	// A distinct key is a distinct charge (dedup is per key, not global).
	if _, err := p.CreateCharge(ctx, "t1", ports.ChargeRequest{TenantID: "t1", PaymentID: "payC", AmountCents: 100, Currency: "BRL", IdempotencyKey: "idem-2"}); err != nil {
		t.Fatalf("third charge: %v", err)
	}
	if got := p.ChargeCount(); got != 2 {
		t.Fatalf("distinct key must create a new charge: ChargeCount=%d", got)
	}

	// The same key under a different tenant must not collide (tenant-scoped).
	creds2 := secret.NewStore(map[string]ports.BankCredential{"t2": {ClientID: "c", Secret: "s"}})
	p2 := bank.NewStubProvider(creds2)
	if _, err := p2.CreateCharge(ctx, "t2", ports.ChargeRequest{TenantID: "t2", PaymentID: "payA", AmountCents: 100, Currency: "BRL", IdempotencyKey: "idem-1"}); err != nil {
		t.Fatalf("cross-tenant same key: %v", err)
	}
}

func TestStubMarkSettledReconcilesFullAmount(t *testing.T) {
	t.Parallel()
	creds := secret.NewStore(map[string]ports.BankCredential{"t1": {ClientID: "c", Secret: "s"}})
	p := bank.NewStubProvider(creds)
	ctx := context.Background()

	res, err := p.CreateCharge(ctx, "t1", ports.ChargeRequest{TenantID: "t1", PaymentID: "pay1", AmountCents: 100, Currency: "BRL"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if res.ExpectedAmountCents != 100 || res.ReceivedAmountCents != 0 {
		t.Fatalf("pending charge: %+v", res)
	}
	p.MarkSettled("t1", res.TxID)
	got, _ := p.GetCharge(ctx, "t1", res.TxID)
	if got.ReceivedAmountCents != 100 || !got.AmountReconciled() {
		t.Fatalf("full settlement must reconcile: %+v", got)
	}
}

func TestStubMarkSettledWithReceivedDiverges(t *testing.T) {
	t.Parallel()
	creds := secret.NewStore(map[string]ports.BankCredential{"t1": {ClientID: "c", Secret: "s"}})
	p := bank.NewStubProvider(creds)
	ctx := context.Background()

	res, _ := p.CreateCharge(ctx, "t1", ports.ChargeRequest{TenantID: "t1", PaymentID: "pay1", AmountCents: 100})
	p.MarkSettledWithReceived("t1", res.TxID, 60)
	got, _ := p.GetCharge(ctx, "t1", res.TxID)
	if got.Status != "paid" {
		t.Fatalf("status: %q", got.Status)
	}
	if got.ReceivedAmountCents != 60 || got.AmountReconciled() {
		t.Fatalf("partial settlement must NOT reconcile: %+v", got)
	}
}

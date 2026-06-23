package bank

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// fakePix is a controllable ports.PixProvider for the settlement-bridge tests. It
// records the GetImmediateCharge args and returns a canned result/error.
type fakePix struct {
	res         ports.PixChargeResult
	err         error
	gotTenant   string
	gotTxID     string
	getCalls    int
	createCalls int
}

func (f *fakePix) CreateImmediateCharge(_ context.Context, _ string, _ ports.ChargeRequest, _ time.Duration) (ports.PixChargeResult, error) {
	f.createCalls++
	return f.res, f.err
}

func (f *fakePix) GetImmediateCharge(_ context.Context, tenantID, txID string) (ports.PixChargeResult, error) {
	f.getCalls++
	f.gotTenant, f.gotTxID = tenantID, txID
	if f.err != nil {
		return ports.PixChargeResult{}, f.err
	}
	return f.res, nil
}

// ListImmediateCharges satisfies ports.PixProvider. The settlement bridge never
// lists (it only overrides the reconcile read), so this is an unused stub.
func (f *fakePix) ListImmediateCharges(_ context.Context, _ string, _ ports.PixListFilter) (ports.PixChargeList, error) {
	return ports.PixChargeList{}, f.err
}

// fakeBank is a controllable ports.BankProvider used as the embedded generic
// surface. GetCharge must NEVER be called through the bridge (the bridge overrides
// it); a call here flips genericGetCalled so the test can assert it stayed off the
// /charges path.
type fakeBank struct {
	createCalls      int
	genericGetCalled bool
	createRes        ports.ChargeResult
}

func (f *fakeBank) CreateCharge(_ context.Context, _ string, _ ports.ChargeRequest) (ports.ChargeResult, error) {
	f.createCalls++
	return f.createRes, nil
}

func (f *fakeBank) GetCharge(_ context.Context, _, _ string) (ports.ChargeResult, error) {
	f.genericGetCalled = true
	return ports.ChargeResult{}, errors.New("generic /charges GetCharge must not be the settlement reconcile source")
}

func TestPixSettlementGetChargeReconcilesViaPix(t *testing.T) {
	t.Parallel()
	pix := &fakePix{res: ports.PixChargeResult{
		TxID:                "txid-cob",
		Status:              "CONCLUIDA",
		ExpectedAmountCents: 10000,
		ReceivedAmountCents: 10000,
	}}
	generic := &fakeBank{}
	p := NewPixSettlementProvider(generic, pix)

	res, err := p.GetCharge(context.Background(), "t1", "txid-cob")
	if err != nil {
		t.Fatalf("GetCharge: %v", err)
	}
	// Routed through the PIX read, not the generic /charges read.
	if pix.getCalls != 1 {
		t.Fatalf("PIX read should be hit exactly once, got %d", pix.getCalls)
	}
	if generic.genericGetCalled {
		t.Fatal("settlement reconcile must NOT call the generic /charges GetCharge")
	}
	if pix.gotTenant != "t1" || pix.gotTxID != "txid-cob" {
		t.Fatalf("args not forwarded: tenant=%q txid=%q", pix.gotTenant, pix.gotTxID)
	}
	// BACEN CONCLUIDA is translated to the generic settled status the webhook gate expects.
	if res.Status != "paid" {
		t.Fatalf("CONCLUIDA must map to %q, got %q", "paid", res.Status)
	}
	if res.TxID != "txid-cob" || res.ExpectedAmountCents != 10000 || res.ReceivedAmountCents != 10000 {
		t.Fatalf("unexpected mapping: %+v", res)
	}
	if !res.AmountReconciled() {
		t.Fatal("a fully-paid CONCLUIDA charge must reconcile")
	}
}

func TestPixSettlementGetChargeStatusCaseInsensitive(t *testing.T) {
	t.Parallel()
	pix := &fakePix{res: ports.PixChargeResult{Status: "concluida", ExpectedAmountCents: 1, ReceivedAmountCents: 1}}
	p := NewPixSettlementProvider(&fakeBank{}, pix)

	res, err := p.GetCharge(context.Background(), "t1", "x")
	if err != nil {
		t.Fatalf("GetCharge: %v", err)
	}
	if res.Status != "paid" {
		t.Fatalf("lowercase concluida must still map to paid, got %q", res.Status)
	}
}

func TestPixSettlementGetChargeAmountDivergenceNotReconciled(t *testing.T) {
	t.Parallel()
	// CONCLUIDA but received < expected (partial / adjusted payment): paid status,
	// but the money half must refuse to settle.
	pix := &fakePix{res: ports.PixChargeResult{Status: "CONCLUIDA", ExpectedAmountCents: 10000, ReceivedAmountCents: 6000}}
	p := NewPixSettlementProvider(&fakeBank{}, pix)

	res, err := p.GetCharge(context.Background(), "t1", "x")
	if err != nil {
		t.Fatalf("GetCharge: %v", err)
	}
	if res.Status != "paid" {
		t.Fatalf("status: want paid, got %q", res.Status)
	}
	if res.AmountReconciled() {
		t.Fatal("a partially-paid charge must NOT reconcile")
	}
}

func TestPixSettlementGetChargeUnpaidStatusPassthrough(t *testing.T) {
	t.Parallel()
	// An unpaid (ATIVA) charge: status passes through unchanged so it never reads as
	// settled, and with zero received it cannot reconcile (fail-secure).
	pix := &fakePix{res: ports.PixChargeResult{Status: "ATIVA", ExpectedAmountCents: 10000, ReceivedAmountCents: 0}}
	p := NewPixSettlementProvider(&fakeBank{}, pix)

	res, err := p.GetCharge(context.Background(), "t1", "x")
	if err != nil {
		t.Fatalf("GetCharge: %v", err)
	}
	if res.Status != "ATIVA" {
		t.Fatalf("non-CONCLUIDA status must pass through unchanged, got %q", res.Status)
	}
	if res.AmountReconciled() {
		t.Fatal("an unpaid charge must not reconcile")
	}
}

func TestPixSettlementGetChargeFailSecureOnMissingAmount(t *testing.T) {
	t.Parallel()
	// Fail-secure: a CONCLUIDA charge whose read carried no amount (expected 0)
	// reconciles to zero and is refused, never settled open.
	pix := &fakePix{res: ports.PixChargeResult{Status: "CONCLUIDA", ExpectedAmountCents: 0, ReceivedAmountCents: 0}}
	p := NewPixSettlementProvider(&fakeBank{}, pix)

	res, err := p.GetCharge(context.Background(), "t1", "x")
	if err != nil {
		t.Fatalf("GetCharge: %v", err)
	}
	if res.AmountReconciled() {
		t.Fatal("a missing-amount charge must fail secure (not reconcile)")
	}
}

func TestPixSettlementGetChargePropagatesPixError(t *testing.T) {
	t.Parallel()
	pix := &fakePix{err: errors.New("pix read failed")}
	p := NewPixSettlementProvider(&fakeBank{}, pix)

	if _, err := p.GetCharge(context.Background(), "t1", "x"); err == nil {
		t.Fatal("expected the PIX read error to propagate")
	}
}

// TestPixSettlementCreateChargeDelegatesToGeneric proves charge creation is
// untouched by the bridge — it is served by the embedded generic BankProvider, not
// the PIX provider (the routing decision scopes only the settlement reconcile read).
func TestPixSettlementCreateChargeDelegatesToGeneric(t *testing.T) {
	t.Parallel()
	generic := &fakeBank{createRes: ports.ChargeResult{TxID: "tx_generic", Status: "pending"}}
	pix := &fakePix{}
	p := NewPixSettlementProvider(generic, pix)

	res, err := p.CreateCharge(context.Background(), "t1", ports.ChargeRequest{TenantID: "t1", PaymentID: "p", AmountCents: 1, Currency: "BRL"})
	if err != nil {
		t.Fatalf("CreateCharge: %v", err)
	}
	if generic.createCalls != 1 {
		t.Fatalf("create should delegate to the generic provider once, got %d", generic.createCalls)
	}
	if pix.createCalls != 0 {
		t.Fatalf("create must NOT route to the PIX provider, got %d", pix.createCalls)
	}
	if res.TxID != "tx_generic" {
		t.Fatalf("unexpected create result: %+v", res)
	}
}

// invalidatingBank is a generic provider that also caches credentials and so
// implements ports.CredentialInvalidator (like the real C6 adapter).
type invalidatingBank struct {
	fakeBank
	evicted []string
}

func (b *invalidatingBank) InvalidateToken(tenantID string) {
	b.evicted = append(b.evicted, tenantID)
}

// TestPixSettlementForwardsInvalidateToken: the decorator forwards credential
// eviction to a wrapped provider that supports it (ADR-0003).
func TestPixSettlementForwardsInvalidateToken(t *testing.T) {
	t.Parallel()
	generic := &invalidatingBank{}
	p := NewPixSettlementProvider(generic, &fakePix{})

	// The assembled provider must be recognisable as a CredentialInvalidator.
	inv, ok := any(p).(ports.CredentialInvalidator)
	if !ok {
		t.Fatal("PixSettlementProvider must satisfy ports.CredentialInvalidator")
	}
	inv.InvalidateToken("t1")
	if len(generic.evicted) != 1 || generic.evicted[0] != "t1" {
		t.Fatalf("eviction not forwarded to wrapped provider: %v", generic.evicted)
	}
}

// TestPixSettlementInvalidateTokenNoopWhenUnsupported: forwarding is a safe no-op
// when the wrapped provider holds no credential cache.
func TestPixSettlementInvalidateTokenNoopWhenUnsupported(t *testing.T) {
	t.Parallel()
	p := NewPixSettlementProvider(&fakeBank{}, &fakePix{})
	// Must not panic; the wrapped fakeBank is not a CredentialInvalidator.
	p.InvalidateToken("t1")
}

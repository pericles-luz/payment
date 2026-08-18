package app_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/payment"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// newCobvHarness wires a PixDueChargeService with the stub as the cobv provider and
// a seeded, priced, credentialed tenant. The harness clock is 1970, so any 2026 due
// date is comfortably in the future.
func newCobvHarness(t *testing.T) (*app.PixDueChargeService, *harness, string) {
	t.Helper()
	h := newHarness(t)
	h.deps.PixDueCharge = h.bank
	admin := app.NewAdminService(h.deps)
	tn, err := admin.CreateTenant(context.Background(), "Acme")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	h.deps.Credentials.(*secret.Store).Set(tn.ID(), ports.BankCredential{ClientID: "cid", Secret: "shh"})
	if _, err := admin.SetEndpointPrice(context.Background(), tn.ID(), app.PixCobVCreateEndpoint, 50); err != nil {
		t.Fatalf("price: %v", err)
	}
	return app.NewPixDueChargeService(h.deps), h, tn.ID()
}

func cobvInput(tenantID string) app.DueChargeInput {
	return app.DueChargeInput{
		TenantID: tenantID, AmountCents: 1000, Currency: "BRL",
		DueDate: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), ValidityDays: 5,
		FineBps: 200, MonthlyInterestBps: 100, DiscountBps: 500,
		DebtorTaxID: "12345678901", DebtorName: "Maria",
		CreditorKey: "acme@pix.example", IdempotencyKey: "k1",
	}
}

// roteiro 7.5: create cobv reserves a payment, bills once, sets the txid.
func TestCobvCreateSuccess(t *testing.T) {
	t.Parallel()
	svc, h, tenantID := newCobvHarness(t)

	p, res, err := svc.CreateDueCharge(context.Background(), cobvInput(tenantID))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if p.Status() != payment.StatusPending || p.TxID() == "" {
		t.Fatalf("payment not created: %+v", p)
	}
	if res.TxID != p.TxID() || res.Status != "ATIVA" || res.QRCodePayload == "" {
		t.Fatalf("unexpected result: %+v", res)
	}
	if h.store.LedgerLen() != 1 {
		t.Fatalf("expected 1 ledger entry, got %d", h.store.LedgerLen())
	}
}

func TestCobvCreateIdempotent(t *testing.T) {
	t.Parallel()
	svc, h, tenantID := newCobvHarness(t)
	in := cobvInput(tenantID)

	p1, _, err := svc.CreateDueCharge(context.Background(), in)
	if err != nil {
		t.Fatalf("create 1: %v", err)
	}
	p2, _, err := svc.CreateDueCharge(context.Background(), in)
	if err != nil {
		t.Fatalf("create 2: %v", err)
	}
	if p1.ID() != p2.ID() {
		t.Fatalf("idempotent retry must return same payment: %q vs %q", p1.ID(), p2.ID())
	}
	if h.store.LedgerLen() != 1 {
		t.Fatalf("idempotent retry must not bill again, got %d", h.store.LedgerLen())
	}
}

func TestCobvCreateValidation(t *testing.T) {
	t.Parallel()
	svc, _, tenantID := newCobvHarness(t)
	cases := []struct {
		name   string
		mutate func(*app.DueChargeInput)
	}{
		{"missing idempotency", func(in *app.DueChargeInput) { in.IdempotencyKey = "" }},
		{"zero amount", func(in *app.DueChargeInput) { in.AmountCents = 0 }},
		{"past due date", func(in *app.DueChargeInput) { in.DueDate = time.Date(1969, 1, 1, 0, 0, 0, 0, time.UTC) }},
		{"fine over cap", func(in *app.DueChargeInput) { in.FineBps = 100000 }},
		{"bad debtor", func(in *app.DueChargeInput) { in.DebtorTaxID = "123" }},
		{"missing creditor key", func(in *app.DueChargeInput) { in.CreditorKey = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			in := cobvInput(tenantID)
			tc.mutate(&in)
			if _, _, err := svc.CreateDueCharge(context.Background(), in); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("%s: want ErrValidation, got %v", tc.name, err)
			}
		})
	}
}

// An invalid request must not reserve a payment (no orphan reservation).
func TestCobvInvalidDoesNotReserve(t *testing.T) {
	t.Parallel()
	svc, h, tenantID := newCobvHarness(t)
	in := cobvInput(tenantID)
	in.FineBps = 100000 // over cap
	if _, _, err := svc.CreateDueCharge(context.Background(), in); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation, got %v", err)
	}
	if _, err := h.store.FindPaymentByIdempotencyKey(context.Background(), tenantID, in.IdempotencyKey); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("invalid request must not reserve a payment, got %v", err)
	}
}

func TestCobvCreateInactiveTenant(t *testing.T) {
	t.Parallel()
	svc, h, tenantID := newCobvHarness(t)
	tn, err := h.store.FindTenantByID(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("find tenant: %v", err)
	}
	tn.Deactivate()
	if err := h.store.SaveTenant(context.Background(), tn); err != nil {
		t.Fatalf("save tenant: %v", err)
	}
	if _, _, err := svc.CreateDueCharge(context.Background(), cobvInput(tenantID)); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("inactive tenant must be ErrValidation, got %v", err)
	}
}

// TestCobvCreateNoPriceIsFree pins the SIN-69512 charge-time contract: a tenant
// without a configured cobv price is served for free (billed 0 cents), not
// rejected; the payment IS reserved and a single 0-cent ledger entry is written.
//
// Rule-3 disclosure: this test previously required ErrNotFound and no reservation
// for the unpriced case — the exact behavior the CEO reframed in
// SIN-69508/SIN-69512. Its assertion is updated to the new mandated contract; CTO
// ratifies at the review gate.
func TestCobvCreateNoPriceIsFree(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.deps.PixDueCharge = h.bank
	admin := app.NewAdminService(h.deps)
	tn, err := admin.CreateTenant(context.Background(), "Acme")
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	h.deps.Credentials.(*secret.Store).Set(tn.ID(), ports.BankCredential{ClientID: "cid", Secret: "shh"})
	svc := app.NewPixDueChargeService(h.deps)
	p, _, err := svc.CreateDueCharge(context.Background(), cobvInput(tn.ID()))
	if err != nil {
		t.Fatalf("unpriced cobv should succeed (free), got %v", err)
	}
	if p == nil || p.TxID() == "" {
		t.Fatal("cobv not created for unpriced (free) endpoint")
	}
	// The payment IS reserved under the free contract.
	if _, err := h.store.FindPaymentByIdempotencyKey(context.Background(), tn.ID(), "k1"); err != nil {
		t.Fatalf("free create must reserve a payment, got %v", err)
	}
	entries, err := h.store.ListLedgerEntries(context.Background(), tn.ID())
	if err != nil {
		t.Fatalf("list ledger: %v", err)
	}
	if len(entries) != 1 || entries[0].PriceCents() != 0 {
		t.Fatalf("want 1 ledger entry billed 0 cents, got %+v", entries)
	}
}

func TestCobvCreateUnknownTenant(t *testing.T) {
	t.Parallel()
	svc, _, _ := newCobvHarness(t)
	if _, _, err := svc.CreateDueCharge(context.Background(), cobvInput("nope")); err == nil {
		t.Fatal("want error for unknown tenant")
	}
}

// Concurrent creates with the same idempotency key bill exactly once and resolve to
// one payment (the unique index serialises racers in reservePayment).
func TestCobvCreateConcurrentSameKey(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.deps.PixDueCharge = h.bank
	h.deps.UoW = h.store // real transactional boundary so the unique index serialises racers
	admin := app.NewAdminService(h.deps)
	tn, err := admin.CreateTenant(context.Background(), "Acme")
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	h.deps.Credentials.(*secret.Store).Set(tn.ID(), ports.BankCredential{ClientID: "cid", Secret: "shh"})
	if _, err := admin.SetEndpointPrice(context.Background(), tn.ID(), app.PixCobVCreateEndpoint, 40); err != nil {
		t.Fatalf("price: %v", err)
	}
	svc := app.NewPixDueChargeService(h.deps)
	in := cobvInput(tn.ID())

	const n = 8
	var wg sync.WaitGroup
	ids := make([]string, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p, _, err := svc.CreateDueCharge(context.Background(), in)
			errs[i] = err
			if p != nil {
				ids[i] = p.ID()
			}
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d failed: %v", i, err)
		}
	}
	for i := 1; i < n; i++ {
		if ids[i] != ids[0] {
			t.Fatalf("idempotency violated: id[%d]=%q != id[0]=%q", i, ids[i], ids[0])
		}
	}
	if got := h.store.LedgerLen(); got != 1 {
		t.Fatalf("concurrent same-key creates must bill once: ledger len = %d, want 1", got)
	}
}

// roteiro 7.6: reconcile read by txid; unknown txid is not-found.
func TestCobvGet(t *testing.T) {
	t.Parallel()
	svc, _, tenantID := newCobvHarness(t)
	_, res, err := svc.CreateDueCharge(context.Background(), cobvInput(tenantID))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := svc.GetDueCharge(context.Background(), tenantID, res.TxID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.TxID != res.TxID {
		t.Fatalf("get txid mismatch: %q vs %q", got.TxID, res.TxID)
	}
	if _, err := svc.GetDueCharge(context.Background(), tenantID, "missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("unknown txid must be ErrNotFound, got %v", err)
	}
	if _, err := svc.GetDueCharge(context.Background(), tenantID, "  "); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("blank txid must be ErrValidation, got %v", err)
	}
}

// roteiro 7.7: amend updates params without billing again.
func TestCobvUpdate(t *testing.T) {
	t.Parallel()
	svc, h, tenantID := newCobvHarness(t)
	_, res, err := svc.CreateDueCharge(context.Background(), cobvInput(tenantID))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	before := h.store.LedgerLen()

	in := cobvInput(tenantID)
	in.AmountCents = 2500
	in.IdempotencyKey = "upd-1"
	upd, err := svc.UpdateDueCharge(context.Background(), tenantID, res.TxID, in)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if upd.ExpectedAmountCents != 2500 {
		t.Fatalf("amended amount not applied: %+v", upd)
	}
	if h.store.LedgerLen() != before {
		t.Fatalf("amend must not bill again: before=%d after=%d", before, h.store.LedgerLen())
	}
}

func TestCobvUpdateValidation(t *testing.T) {
	t.Parallel()
	svc, _, tenantID := newCobvHarness(t)
	_, res, err := svc.CreateDueCharge(context.Background(), cobvInput(tenantID))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	in := cobvInput(tenantID)
	in.IdempotencyKey = ""
	if _, err := svc.UpdateDueCharge(context.Background(), tenantID, res.TxID, in); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing idempotency on amend must be ErrValidation, got %v", err)
	}
	in = cobvInput(tenantID)
	if _, err := svc.UpdateDueCharge(context.Background(), tenantID, "  ", in); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("blank txid on amend must be ErrValidation, got %v", err)
	}
}

// A provider failure on create must not leave a billed payment behind.
func TestCobvBankErrorDoesNotBill(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.deps.PixDueCharge = errCobvProvider{}
	admin := app.NewAdminService(h.deps)
	tn, _ := admin.CreateTenant(context.Background(), "Acme")
	h.deps.Credentials.(*secret.Store).Set(tn.ID(), ports.BankCredential{ClientID: "cid", Secret: "shh"})
	if _, err := admin.SetEndpointPrice(context.Background(), tn.ID(), app.PixCobVCreateEndpoint, 50); err != nil {
		t.Fatalf("price: %v", err)
	}
	svc := app.NewPixDueChargeService(h.deps)

	if _, _, err := svc.CreateDueCharge(context.Background(), cobvInput(tn.ID())); err == nil {
		t.Fatal("expected provider error")
	}
	if h.store.LedgerLen() != 0 {
		t.Fatalf("provider failure must not bill, got %d ledger entries", h.store.LedgerLen())
	}
}

// Fault-injection: each repository failure on the cobv create path surfaces as an
// error (and the financial-integrity ordering never bills on a failed write). Uses
// the shared faultRepo so the tenant resolves active and priced by default.
func TestCobvCreateFaultInjection(t *testing.T) {
	t.Parallel()
	cobvDeps := func(f *faultRepo) app.Deps {
		d := depsWith(f)
		d.PixDueCharge = d.Bank.(ports.PixDueChargeProvider) // stub satisfies the cobv port
		return d
	}
	cases := []struct {
		name string
		repo *faultRepo
	}{
		{"tenant lookup fails", &faultRepo{findTenant: errInjected}},
		{"price lookup fails", &faultRepo{getPrice: errInjected}},
		{"idempotency lookup fails", &faultRepo{findByIdem: errInjected}},
		{"save payment fails", &faultRepo{savePayment: errInjected}},
		{"append ledger fails", &faultRepo{appendLedger: errInjected}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			svc := app.NewPixDueChargeService(cobvDeps(tc.repo))
			if _, _, err := svc.CreateDueCharge(context.Background(), cobvInput("t1")); err == nil {
				t.Fatalf("%s: expected error", tc.name)
			}
		})
	}
}

// errCobvProvider fails every cobv create so the no-bill path can be exercised.
type errCobvProvider struct{}

func (errCobvProvider) CreateDueCharge(context.Context, string, ports.PixDueChargeRequest) (ports.PixDueChargeResult, error) {
	return ports.PixDueChargeResult{}, errors.New("bank down")
}

func (errCobvProvider) GetDueCharge(context.Context, string, string) (ports.PixDueChargeResult, error) {
	return ports.PixDueChargeResult{}, errors.New("bank down")
}

func (errCobvProvider) UpdateDueCharge(context.Context, string, string, ports.PixDueChargeRequest) (ports.PixDueChargeResult, error) {
	return ports.PixDueChargeResult{}, errors.New("bank down")
}

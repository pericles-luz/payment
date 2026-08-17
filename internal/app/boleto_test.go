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

// boletoDueDate is a fixed, non-zero vencimento for the harness (the fixedClock is
// Unix(1000)); the domain only requires a non-zero due date.
var boletoDueDate = time.Unix(1_800_000_000, 0).UTC()

// newBoletoHarness wires a BoletoService with the stub as the boleto provider plus a
// seeded, priced, credentialed tenant.
func newBoletoHarness(t *testing.T) (*app.BoletoService, *harness, string) {
	t.Helper()
	h := newHarness(t)
	h.deps.Boleto = h.bank
	admin := app.NewAdminService(h.deps)
	tn, err := admin.CreateTenant(context.Background(), "Acme")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	h.deps.Credentials.(*secret.Store).Set(tn.ID(), ports.BankCredential{ClientID: "cid", Secret: "shh"})
	if _, err := admin.SetEndpointPrice(context.Background(), tn.ID(), app.BoletoCreateEndpoint, 40); err != nil {
		t.Fatalf("price: %v", err)
	}
	return app.NewBoletoService(h.deps), h, tn.ID()
}

func baseBoletoInput(tenantID, idemKey string) app.RegisterBoletoInput {
	return app.RegisterBoletoInput{
		TenantID:           tenantID,
		AmountCents:        100000,
		Currency:           "BRL",
		DueDate:            boletoDueDate,
		FineBps:            200,
		MonthlyInterestBps: 100,
		IdempotencyKey:     idemKey,
	}
}

// roteiro grupos 1–3: register the boleto variants (fine+interest, fine only,
// interest only, fixed/percent fine, until-due discount, tiered discount).
func TestRegisterBoletoVariants(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		mut  func(*app.RegisterBoletoInput)
	}{
		{"1a_fine_and_interest", func(in *app.RegisterBoletoInput) {}},
		{"1b_no_fine_no_interest", func(in *app.RegisterBoletoInput) { in.FineBps = 0; in.MonthlyInterestBps = 0 }},
		{"2a_interest_only", func(in *app.RegisterBoletoInput) { in.FineBps = 0 }},
		{"2b_fine_only", func(in *app.RegisterBoletoInput) { in.MonthlyInterestBps = 0 }},
		{"2c_fine_fixed", func(in *app.RegisterBoletoInput) { in.FineBps = 0; in.FineFixedCents = 1500 }},
		{"3a_discount_until_due", func(in *app.RegisterBoletoInput) {
			in.Discounts = []app.DiscountTierInput{{DaysBeforeDue: 0, Bps: 500}}
		}},
		{"3a_discount_fixed", func(in *app.RegisterBoletoInput) {
			in.Discounts = []app.DiscountTierInput{{DaysBeforeDue: 0, FixedCents: 2500}}
		}},
		{"3b_discount_tiered", func(in *app.RegisterBoletoInput) {
			in.Discounts = []app.DiscountTierInput{
				{DaysBeforeDue: 10, Bps: 1000},
				{DaysBeforeDue: 5, Bps: 500},
				{DaysBeforeDue: 0, Bps: 200},
			}
		}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			svc, h, tenantID := newBoletoHarness(t)
			in := baseBoletoInput(tenantID, "k-"+tc.name)
			tc.mut(&in)
			p, res, err := svc.RegisterBoleto(context.Background(), in)
			if err != nil {
				t.Fatalf("register: %v", err)
			}
			if p.Status() != payment.StatusPending || p.TxID() == "" {
				t.Fatalf("payment not created: %+v", p)
			}
			if p.Amount().Cents() != 100000 {
				t.Fatalf("principal: want 100000 got %d", p.Amount().Cents())
			}
			if res.BoletoID != p.ID() || res.Status != "REGISTERED" || res.QRCode == "" || res.Barcode == "" {
				t.Fatalf("unexpected result: %+v", res)
			}
			if h.store.LedgerLen() != 1 {
				t.Fatalf("expected 1 ledger entry, got %d", h.store.LedgerLen())
			}
			// The boleto is reconcilable by id (roteiro 6.a).
			got, err := svc.GetBoleto(context.Background(), tenantID, res.BoletoID)
			if err != nil {
				t.Fatalf("get: %v", err)
			}
			if got.BoletoID != res.BoletoID {
				t.Fatalf("get mismatch: %+v", got)
			}
		})
	}
}

func TestRegisterBoletoIdempotent(t *testing.T) {
	t.Parallel()
	svc, h, tenantID := newBoletoHarness(t)
	in := baseBoletoInput(tenantID, "k1")

	var events int
	var mu sync.Mutex
	_ = h.bus.Subscribe(context.Background(), app.TopicPaymentCreated, func(_ context.Context, _ ports.Message) error {
		mu.Lock()
		events++
		mu.Unlock()
		return nil
	})

	p1, res1, err := svc.RegisterBoleto(context.Background(), in)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	p2, res2, err := svc.RegisterBoleto(context.Background(), in)
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if p1.ID() != p2.ID() || res1.BoletoID != res2.BoletoID {
		t.Fatalf("idempotent retry returned different boleto: %s vs %s", res1.BoletoID, res2.BoletoID)
	}
	if h.store.LedgerLen() != 1 {
		t.Fatalf("idempotent retry should not bill again, got %d", h.store.LedgerLen())
	}
	mu.Lock()
	if events != 1 {
		t.Fatalf("expected 1 event, got %d", events)
	}
	mu.Unlock()
}

func TestRegisterBoletoValidationErrors(t *testing.T) {
	t.Parallel()
	svc, _, tenantID := newBoletoHarness(t)

	mut := func(f func(*app.RegisterBoletoInput)) app.RegisterBoletoInput {
		in := baseBoletoInput(tenantID, "k1")
		f(&in)
		return in
	}
	cases := []struct {
		name string
		in   app.RegisterBoletoInput
	}{
		{"zero_amount", mut(func(in *app.RegisterBoletoInput) { in.AmountCents = 0 })},
		{"negative_amount", mut(func(in *app.RegisterBoletoInput) { in.AmountCents = -1 })},
		{"bad_currency", mut(func(in *app.RegisterBoletoInput) { in.Currency = "XX" })},
		{"zero_due_date", mut(func(in *app.RegisterBoletoInput) { in.DueDate = time.Time{} })},
		{"fine_over_cap", mut(func(in *app.RegisterBoletoInput) { in.FineBps = 201 })},
		{"interest_over_cap", mut(func(in *app.RegisterBoletoInput) { in.MonthlyInterestBps = 101 })},
		{"missing_idem", mut(func(in *app.RegisterBoletoInput) { in.IdempotencyKey = "" })},
		{"bad_payer_tax_id", mut(func(in *app.RegisterBoletoInput) { in.Payer.TaxID = "123" })},
		{"both_fine_forms", mut(func(in *app.RegisterBoletoInput) { in.FineBps = 200; in.FineFixedCents = 100 })},
		{"fixed_fine_over_cap", mut(func(in *app.RegisterBoletoInput) { in.FineBps = 0; in.FineFixedCents = 9999 })},
		{"discount_both_set", mut(func(in *app.RegisterBoletoInput) {
			in.Discounts = []app.DiscountTierInput{{DaysBeforeDue: 0, Bps: 100, FixedCents: 100}}
		})},
		{"discount_exceeds_principal", mut(func(in *app.RegisterBoletoInput) {
			in.Discounts = []app.DiscountTierInput{{DaysBeforeDue: 0, FixedCents: 100000}}
		})},
		{"discount_not_ordered", mut(func(in *app.RegisterBoletoInput) {
			in.Discounts = []app.DiscountTierInput{
				{DaysBeforeDue: 5, Bps: 200},
				{DaysBeforeDue: 10, Bps: 500},
			}
		})},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := svc.RegisterBoleto(context.Background(), tc.in)
			if err == nil {
				t.Fatalf("want validation error for %s, got nil", tc.name)
			}
			if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("%s: want validation error, got %v", tc.name, err)
			}
		})
	}
}

// An invalid request must not reserve a payment (fail before the money seam).
func TestRegisterBoletoInvalidDoesNotReserve(t *testing.T) {
	t.Parallel()
	svc, h, tenantID := newBoletoHarness(t)
	in := baseBoletoInput(tenantID, "k1")
	in.FineBps = 201 // over cap
	if _, _, err := svc.RegisterBoleto(context.Background(), in); err == nil {
		t.Fatalf("want validation error")
	}
	if _, err := h.store.FindPaymentByIdempotencyKey(context.Background(), tenantID, "k1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("an invalid request must not reserve a payment, got %v", err)
	}
	if h.store.LedgerLen() != 0 {
		t.Fatalf("invalid request must not bill, got %d", h.store.LedgerLen())
	}
}

func TestRegisterBoletoInactiveTenant(t *testing.T) {
	t.Parallel()
	svc, h, tenantID := newBoletoHarness(t)
	tn, err := h.store.FindTenantByID(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("find tenant: %v", err)
	}
	tn.Deactivate()
	if err := h.store.SaveTenant(context.Background(), tn); err != nil {
		t.Fatalf("save tenant: %v", err)
	}
	if _, _, err := svc.RegisterBoleto(context.Background(), baseBoletoInput(tenantID, "k1")); err == nil {
		t.Fatalf("want error for inactive tenant")
	}
}

func TestRegisterBoletoUnknownTenant(t *testing.T) {
	t.Parallel()
	svc, _, _ := newBoletoHarness(t)
	if _, _, err := svc.RegisterBoleto(context.Background(), baseBoletoInput("nope", "k1")); err == nil {
		t.Fatalf("want error for unknown tenant")
	}
}

// TestRegisterBoletoNoPriceIsFree pins the SIN-69512 charge-time contract: a
// tenant with NO configured boleto price is served for free (billed 0 cents), not
// rejected; a single 0-cent ledger entry is written.
//
// Rule-3 disclosure: this test previously required an error for the unpriced case —
// the exact behavior the CEO reframed in SIN-69508/SIN-69512. Its assertion is
// updated to the new mandated contract; CTO ratifies at the review gate.
func TestRegisterBoletoNoPriceIsFree(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.deps.Boleto = h.bank
	admin := app.NewAdminService(h.deps)
	tn, err := admin.CreateTenant(context.Background(), "NoPrice")
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	h.deps.Credentials.(*secret.Store).Set(tn.ID(), ports.BankCredential{ClientID: "cid", Secret: "shh"})
	svc := app.NewBoletoService(h.deps)
	p, _, err := svc.RegisterBoleto(context.Background(), baseBoletoInput(tn.ID(), "k1"))
	if err != nil {
		t.Fatalf("unpriced boleto should succeed (free), got %v", err)
	}
	if p == nil || p.TxID() == "" {
		t.Fatal("boleto not created for unpriced (free) endpoint")
	}
	// Payment reserved normally under the free contract.
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

// A provider failure (the stub rejects a tenant without a bank credential) must
// surface as an error and never bill.
func TestRegisterBoletoBankError(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.deps.Boleto = h.bank
	admin := app.NewAdminService(h.deps)
	tn, err := admin.CreateTenant(context.Background(), "NoCred")
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	if _, err := admin.SetEndpointPrice(context.Background(), tn.ID(), app.BoletoCreateEndpoint, 40); err != nil {
		t.Fatalf("price: %v", err)
	}
	svc := app.NewBoletoService(h.deps)
	if _, _, err := svc.RegisterBoleto(context.Background(), baseBoletoInput(tn.ID(), "k1")); err == nil {
		t.Fatalf("want error when the provider rejects the request")
	}
	if h.store.LedgerLen() != 0 {
		t.Fatalf("a failed provider call must not bill, got %d ledger entries", h.store.LedgerLen())
	}
}

func TestGetBoletoValidationAndNotFound(t *testing.T) {
	t.Parallel()
	svc, _, tenantID := newBoletoHarness(t)
	if _, err := svc.GetBoleto(context.Background(), tenantID, "  "); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("blank id: want validation, got %v", err)
	}
	if _, err := svc.GetBoleto(context.Background(), tenantID, "missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("unknown id: want not found, got %v", err)
	}
}

func baseUpdateInput(tenantID, idemKey string) app.UpdateBoletoInput {
	return app.UpdateBoletoInput{
		TenantID:           tenantID,
		AmountCents:        90000,
		Currency:           "BRL",
		DueDate:            boletoDueDate,
		FineBps:            150,
		MonthlyInterestBps: 50,
		IdempotencyKey:     idemKey,
	}
}

// registerOne registers a boleto and returns its id (helper for cancel/update tests).
func registerOne(t *testing.T, svc *app.BoletoService, tenantID, idemKey string) string {
	t.Helper()
	_, res, err := svc.RegisterBoleto(context.Background(), baseBoletoInput(tenantID, idemKey))
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	return res.BoletoID
}

// roteiro grupo 4: baixa a-vencer (4.a) e vencido (4.b) — ambos retornam sucesso.
func TestCancelBoleto(t *testing.T) {
	t.Parallel()
	svc, _, tenantID := newBoletoHarness(t)
	id := registerOne(t, svc, tenantID, "k-cancel")

	if err := svc.CancelBoleto(context.Background(), tenantID, id); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	got, err := svc.GetBoleto(context.Background(), tenantID, id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != "CANCELLED" {
		t.Fatalf("status after cancel = %q, want CANCELLED", got.Status)
	}
	// Idempotent second cancel.
	if err := svc.CancelBoleto(context.Background(), tenantID, id); err != nil {
		t.Fatalf("second cancel: %v", err)
	}
}

func TestCancelBoletoErrors(t *testing.T) {
	t.Parallel()
	svc, _, tenantID := newBoletoHarness(t)
	if err := svc.CancelBoleto(context.Background(), tenantID, "  "); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("blank id: want validation, got %v", err)
	}
	if err := svc.CancelBoleto(context.Background(), tenantID, "missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("unknown id: want not found, got %v", err)
	}
}

// roteiro grupo 5: alteração de vencimento (5.a), validade (5.b), valor/multa/juros (5.c).
func TestUpdateBoletoVariants(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		mut    func(*app.UpdateBoletoInput)
		verify func(*testing.T, ports.BoletoResult)
	}{
		{"5a_due_date", func(in *app.UpdateBoletoInput) { in.DueDate = boletoDueDate.Add(72 * time.Hour) },
			func(t *testing.T, r ports.BoletoResult) {
				if !r.DueDate.Equal(boletoDueDate.Add(72 * time.Hour)) {
					t.Fatalf("due not amended: %v", r.DueDate)
				}
			}},
		{"5b_validity", func(in *app.UpdateBoletoInput) { in.ValidUntil = boletoDueDate.Add(240 * time.Hour) },
			func(t *testing.T, r ports.BoletoResult) {
				if !r.ValidUntil.Equal(boletoDueDate.Add(240 * time.Hour)) {
					t.Fatalf("validity not amended: %v", r.ValidUntil)
				}
			}},
		{"5c_amount_fine_interest", func(in *app.UpdateBoletoInput) {
			in.AmountCents = 70000
			in.FineFixedCents = 1000
			in.FineBps = 0
			in.MonthlyInterestBps = 80
		}, func(t *testing.T, r ports.BoletoResult) {
			if r.AmountCents != 70000 || r.FineFixedCents != 1000 || r.MonthlyInterestBps != 80 {
				t.Fatalf("amount/fine/interest not amended: %+v", r)
			}
		}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			svc, h, tenantID := newBoletoHarness(t)
			id := registerOne(t, svc, tenantID, "k-"+tc.name)
			in := baseUpdateInput(tenantID, "u-"+tc.name)
			tc.mut(&in)
			res, err := svc.UpdateBoleto(context.Background(), tenantID, id, in)
			if err != nil {
				t.Fatalf("update: %v", err)
			}
			if res.BoletoID != id {
				t.Fatalf("identity changed: %s != %s", res.BoletoID, id)
			}
			tc.verify(t, res)
			// Amendment does not bill again (register billed once).
			if h.store.LedgerLen() != 1 {
				t.Fatalf("update must not bill again, ledger=%d", h.store.LedgerLen())
			}
		})
	}
}

func TestUpdateBoletoErrors(t *testing.T) {
	t.Parallel()
	svc, _, tenantID := newBoletoHarness(t)
	id := registerOne(t, svc, tenantID, "k-upderr")

	mut := func(f func(*app.UpdateBoletoInput)) app.UpdateBoletoInput {
		in := baseUpdateInput(tenantID, "u1")
		f(&in)
		return in
	}
	cases := []struct {
		name    string
		id      string
		in      app.UpdateBoletoInput
		wantErr error
	}{
		{"blank_id", "  ", baseUpdateInput(tenantID, "u1"), shared.ErrValidation},
		{"missing_idem", id, mut(func(in *app.UpdateBoletoInput) { in.IdempotencyKey = "" }), shared.ErrValidation},
		{"bad_currency", id, mut(func(in *app.UpdateBoletoInput) { in.Currency = "XX" }), shared.ErrValidation},
		{"fine_over_cap", id, mut(func(in *app.UpdateBoletoInput) { in.FineBps = 201 }), shared.ErrValidation},
		{"validity_before_due", id, mut(func(in *app.UpdateBoletoInput) { in.ValidUntil = boletoDueDate.Add(-48 * time.Hour) }), shared.ErrValidation},
		{"unknown_id", "missing", baseUpdateInput(tenantID, "u1"), shared.ErrNotFound},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := svc.UpdateBoleto(context.Background(), tenantID, tc.id, tc.in)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("%s: want %v, got %v", tc.name, tc.wantErr, err)
			}
		})
	}
}

// Concurrent registers with the same idempotency key must register/bill exactly once.
func TestRegisterBoletoConcurrentSameKey(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.deps.Boleto = h.bank
	h.deps.UoW = h.store // real transactional boundary so the unique index serialises racers
	admin := app.NewAdminService(h.deps)
	tn, err := admin.CreateTenant(context.Background(), "Acme")
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	h.deps.Credentials.(*secret.Store).Set(tn.ID(), ports.BankCredential{ClientID: "cid", Secret: "shh"})
	if _, err := admin.SetEndpointPrice(context.Background(), tn.ID(), app.BoletoCreateEndpoint, 40); err != nil {
		t.Fatalf("price: %v", err)
	}
	svc := app.NewBoletoService(h.deps)
	in := baseBoletoInput(tn.ID(), "kc")

	const n = 8
	var wg sync.WaitGroup
	ids := make([]string, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p, _, err := svc.RegisterBoleto(context.Background(), in)
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
		t.Fatalf("concurrent same-key registers must bill once: ledger len = %d, want 1", got)
	}
}

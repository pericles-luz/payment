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

// newPixHarness builds a harness wired with the stub as the PIX provider and a
// seeded, priced, credentialed tenant. It returns the service and the tenant id.
func newPixHarness(t *testing.T) (*app.PixService, *harness, string) {
	t.Helper()
	h := newHarness(t)
	h.deps.Pix = h.bank
	admin := app.NewAdminService(h.deps)
	tn, err := admin.CreateTenant(context.Background(), "Acme")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	h.deps.Credentials.(*secret.Store).Set(tn.ID(), ports.BankCredential{ClientID: "cid", Secret: "shh"})
	if _, err := admin.SetEndpointPrice(context.Background(), tn.ID(), app.PixCreateEndpoint, 50); err != nil {
		t.Fatalf("price: %v", err)
	}
	return app.NewPixService(h.deps), h, tn.ID()
}

func TestPixCreateImmediateChargeSuccess(t *testing.T) {
	t.Parallel()
	svc, h, tenantID := newPixHarness(t)

	var events int
	var mu sync.Mutex
	_ = h.bus.Subscribe(context.Background(), app.TopicPaymentCreated, func(_ context.Context, _ ports.Message) error {
		mu.Lock()
		events++
		mu.Unlock()
		return nil
	})

	p, qr, err := svc.CreateImmediateCharge(context.Background(), app.CreateImmediateChargeInput{
		TenantID: tenantID, AmountCents: 1050, Currency: "BRL", IdempotencyKey: "k1", ExpiresInSeconds: 1800,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if p.Status() != payment.StatusPending || p.TxID() == "" {
		t.Fatalf("payment not created: %+v", p)
	}
	if qr.TxID != p.TxID() || qr.Status != "ATIVA" || qr.QRCodePayload == "" {
		t.Fatalf("unexpected qr: %+v", qr)
	}
	if h.store.LedgerLen() != 1 {
		t.Fatalf("expected 1 ledger entry, got %d", h.store.LedgerLen())
	}
	mu.Lock()
	if events != 1 {
		t.Fatalf("expected 1 event, got %d", events)
	}
	mu.Unlock()
}

func TestPixCreateWithDevedor(t *testing.T) {
	t.Parallel()
	svc, _, tenantID := newPixHarness(t)

	for _, taxID := range []string{"12345678901", "12345678000199"} {
		_, _, err := svc.CreateImmediateCharge(context.Background(), app.CreateImmediateChargeInput{
			TenantID: tenantID, AmountCents: 100, Currency: "BRL", IdempotencyKey: "k-" + taxID,
			DebtorTaxID: taxID, DebtorName: "Maria",
		})
		if err != nil {
			t.Fatalf("create with devedor %s: %v", taxID, err)
		}
	}
}

func TestPixCreateIdempotentRetry(t *testing.T) {
	t.Parallel()
	svc, h, tenantID := newPixHarness(t)
	in := app.CreateImmediateChargeInput{TenantID: tenantID, AmountCents: 500, Currency: "BRL", IdempotencyKey: "k1"}

	p1, qr1, err := svc.CreateImmediateCharge(context.Background(), in)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	p2, qr2, err := svc.CreateImmediateCharge(context.Background(), in)
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if p1.ID() != p2.ID() {
		t.Fatalf("idempotency violated: %q vs %q", p1.ID(), p2.ID())
	}
	if qr1.TxID != qr2.TxID {
		t.Fatalf("retry returned different txid: %q vs %q", qr1.TxID, qr2.TxID)
	}
	if h.store.LedgerLen() != 1 {
		t.Fatalf("idempotent retry should not bill again, got %d", h.store.LedgerLen())
	}
}

func TestPixCreateValidationErrors(t *testing.T) {
	t.Parallel()
	svc, _, tenantID := newPixHarness(t)
	ctx := context.Background()

	cases := []struct {
		name string
		in   app.CreateImmediateChargeInput
	}{
		{"missing idem", app.CreateImmediateChargeInput{TenantID: tenantID, AmountCents: 100, Currency: "BRL"}},
		{"negative expiry", app.CreateImmediateChargeInput{TenantID: tenantID, AmountCents: 100, Currency: "BRL", IdempotencyKey: "k", ExpiresInSeconds: -1}},
		{"zero amount", app.CreateImmediateChargeInput{TenantID: tenantID, AmountCents: 0, Currency: "BRL", IdempotencyKey: "k"}},
		{"bad devedor taxid", app.CreateImmediateChargeInput{TenantID: tenantID, AmountCents: 100, Currency: "BRL", IdempotencyKey: "k", DebtorTaxID: "123", DebtorName: "X"}},
		{"name without taxid", app.CreateImmediateChargeInput{TenantID: tenantID, AmountCents: 100, Currency: "BRL", IdempotencyKey: "k", DebtorName: "X"}},
		{"non-digit taxid", app.CreateImmediateChargeInput{TenantID: tenantID, AmountCents: 100, Currency: "BRL", IdempotencyKey: "k", DebtorTaxID: "1234567890a"}},
	}
	for _, tc := range cases {
		if _, _, err := svc.CreateImmediateCharge(ctx, tc.in); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("%s: want ErrValidation, got %v", tc.name, err)
		}
	}
}

func TestPixCreateUnknownTenant(t *testing.T) {
	t.Parallel()
	svc, _, _ := newPixHarness(t)
	if _, _, err := svc.CreateImmediateCharge(context.Background(), app.CreateImmediateChargeInput{
		TenantID: "nope", AmountCents: 100, Currency: "BRL", IdempotencyKey: "k",
	}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestPixCreateInactiveTenant(t *testing.T) {
	t.Parallel()
	svc, h, tenantID := newPixHarness(t)
	tn, err := h.store.FindTenantByID(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("find tenant: %v", err)
	}
	tn.Deactivate()
	if err := h.store.SaveTenant(context.Background(), tn); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, _, err := svc.CreateImmediateCharge(context.Background(), app.CreateImmediateChargeInput{
		TenantID: tenantID, AmountCents: 100, Currency: "BRL", IdempotencyKey: "k",
	}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation for inactive tenant, got %v", err)
	}
}

func TestPixCreateUnpricedEndpoint(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.deps.Pix = h.bank
	admin := app.NewAdminService(h.deps)
	tn, _ := admin.CreateTenant(context.Background(), "Acme")
	h.deps.Credentials.(*secret.Store).Set(tn.ID(), ports.BankCredential{ClientID: "cid", Secret: "shh"})
	// No price set for pix.create.
	svc := app.NewPixService(h.deps)
	if _, _, err := svc.CreateImmediateCharge(context.Background(), app.CreateImmediateChargeInput{
		TenantID: tn.ID(), AmountCents: 100, Currency: "BRL", IdempotencyKey: "k",
	}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want ErrNotFound for unpriced endpoint, got %v", err)
	}
}

func TestPixGetImmediateCharge(t *testing.T) {
	t.Parallel()
	svc, _, tenantID := newPixHarness(t)
	ctx := context.Background()

	_, qr, err := svc.CreateImmediateCharge(ctx, app.CreateImmediateChargeInput{
		TenantID: tenantID, AmountCents: 200, Currency: "BRL", IdempotencyKey: "k1",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := svc.GetImmediateCharge(ctx, tenantID, qr.TxID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.TxID != qr.TxID {
		t.Fatalf("get txid mismatch: %q vs %q", got.TxID, qr.TxID)
	}

	// Empty txid → validation.
	if _, err := svc.GetImmediateCharge(ctx, tenantID, "  "); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation for empty txid, got %v", err)
	}
	// Unknown txid → not found.
	if _, err := svc.GetImmediateCharge(ctx, tenantID, "missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestPixListImmediateCharges(t *testing.T) {
	t.Parallel()
	svc, h, tenantID := newPixHarness(t)
	ctx := context.Background()
	base := time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)
	h.bank.SetClock(func() time.Time { return base })

	for _, k := range []string{"k1", "k2"} {
		if _, _, err := svc.CreateImmediateCharge(ctx, app.CreateImmediateChargeInput{
			TenantID: tenantID, AmountCents: 100, Currency: "BRL", IdempotencyKey: k,
		}); err != nil {
			t.Fatalf("create %s: %v", k, err)
		}
	}

	list, err := svc.ListImmediateCharges(ctx, app.ListImmediateChargesInput{
		TenantID: tenantID, Start: base.Add(-time.Hour), End: base.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if list.TotalItems != 2 {
		t.Fatalf("want 2 charges, got %d", list.TotalItems)
	}
}

func TestPixListValidation(t *testing.T) {
	t.Parallel()
	svc, _, tenantID := newPixHarness(t)
	ctx := context.Background()
	now := time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name string
		in   app.ListImmediateChargesInput
	}{
		{"missing window", app.ListImmediateChargesInput{TenantID: tenantID, End: now}},
		{"end before start", app.ListImmediateChargesInput{TenantID: tenantID, Start: now, End: now.Add(-time.Hour)}},
		{"range too large", app.ListImmediateChargesInput{TenantID: tenantID, Start: now, End: now.Add(400 * 24 * time.Hour)}},
		{"negative page", app.ListImmediateChargesInput{TenantID: tenantID, Start: now, End: now.Add(time.Hour), Page: -1}},
		{"negative page size", app.ListImmediateChargesInput{TenantID: tenantID, Start: now, End: now.Add(time.Hour), PageSize: -1}},
	}
	for _, tc := range cases {
		if _, err := svc.ListImmediateCharges(ctx, tc.in); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("%s: want ErrValidation, got %v", tc.name, err)
		}
	}
}

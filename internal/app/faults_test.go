package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/billing"
	"github.com/ia-dev-sindireceita/payment/internal/domain/payment"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

var errInjected = errors.New("injected failure")

// faultRepo implements every repository port and lets a test inject a failure on
// any individual method, or override a return value. It is used only to exercise
// the application services' error-propagation branches — not to fake successful
// storage behaviour (the real SQLite / in-memory adapters cover that).
type faultRepo struct {
	saveTenant   error
	findTenant   error
	savePayment  error
	findByID     error
	findByIdem   error
	findByTx     error
	getPrice     error
	upsertPrice  error
	appendLedger error
	markProc     error

	// overrides
	tenant      *tenant.Tenant
	paymentByTx *payment.Payment
	paymentByID *payment.Payment
	markProcVal bool
	markProcSet bool
	priceVal    billing.EndpointPricing
	priceValSet bool
	idemPayment *payment.Payment // returned by FindPaymentByIdempotencyKey when set
}

func (f *faultRepo) SaveTenant(context.Context, *tenant.Tenant) error { return f.saveTenant }

func (f *faultRepo) FindTenantByID(context.Context, string) (*tenant.Tenant, error) {
	if f.findTenant != nil {
		return nil, f.findTenant
	}
	if f.tenant != nil {
		return f.tenant, nil
	}
	return tenant.Rehydrate("t1", "Acme", true, time.Unix(0, 0).UTC()), nil
}

func (f *faultRepo) SavePayment(context.Context, *payment.Payment) error { return f.savePayment }

func (f *faultRepo) FindPaymentByID(context.Context, string, string) (*payment.Payment, error) {
	if f.findByID != nil {
		return nil, f.findByID
	}
	return f.paymentByID, nil
}

func (f *faultRepo) FindPaymentByIdempotencyKey(context.Context, string, string) (*payment.Payment, error) {
	if f.findByIdem != nil {
		return nil, f.findByIdem
	}
	if f.idemPayment != nil {
		return f.idemPayment, nil
	}
	return nil, shared.ErrNotFound
}

func (f *faultRepo) FindPaymentByTxID(context.Context, string, string) (*payment.Payment, error) {
	if f.findByTx != nil {
		return nil, f.findByTx
	}
	return f.paymentByTx, nil
}

func (f *faultRepo) GetEndpointPrice(context.Context, string, string) (billing.EndpointPricing, error) {
	if f.getPrice != nil {
		return billing.EndpointPricing{}, f.getPrice
	}
	if f.priceValSet {
		return f.priceVal, nil
	}
	p, _ := billing.NewEndpointPricing("t1", "pix.create", 10)
	return p, nil
}

func (f *faultRepo) UpsertEndpointPrice(context.Context, billing.EndpointPricing) error {
	return f.upsertPrice
}

func (f *faultRepo) AppendLedgerEntry(context.Context, billing.LedgerEntry) error {
	return f.appendLedger
}

func (f *faultRepo) MarkProcessed(context.Context, string, string) (bool, error) {
	if f.markProc != nil {
		return false, f.markProc
	}
	if f.markProcSet {
		return f.markProcVal, nil
	}
	return true, nil
}

// depsWith builds app.Deps wiring the faultRepo for every storage port, with a
// real stub bank and in-memory bus.
func depsWith(f *faultRepo) app.Deps {
	h := newHarnessFor()
	return app.Deps{
		Payments:    f,
		Tenants:     f,
		Pricing:     f,
		Ledger:      f,
		Processed:   f,
		Bus:         h.bus,
		Bank:        h.bank,
		Credentials: h.deps.Credentials,
		Clock:       fixedClock{t: time.Unix(1000, 0).UTC()},
		IDs:         &seqIDs{},
	}
}

func TestCreateChargeErrorPropagation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("tenant lookup error", func(t *testing.T) {
		t.Parallel()
		svc := app.NewChargeService(depsWith(&faultRepo{findTenant: errInjected}))
		if _, err := svc.CreateCharge(ctx, validInput()); !errors.Is(err, errInjected) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("inactive tenant", func(t *testing.T) {
		t.Parallel()
		inactive := tenant.Rehydrate("t1", "Acme", false, time.Unix(0, 0).UTC())
		svc := app.NewChargeService(depsWith(&faultRepo{tenant: inactive}))
		if _, err := svc.CreateCharge(ctx, validInput()); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("idempotency lookup hard error", func(t *testing.T) {
		t.Parallel()
		svc := app.NewChargeService(depsWith(&faultRepo{findByIdem: errInjected}))
		if _, err := svc.CreateCharge(ctx, validInput()); !errors.Is(err, errInjected) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("price lookup error", func(t *testing.T) {
		t.Parallel()
		svc := app.NewChargeService(depsWith(&faultRepo{getPrice: errInjected}))
		if _, err := svc.CreateCharge(ctx, validInput()); !errors.Is(err, errInjected) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("save payment error", func(t *testing.T) {
		t.Parallel()
		svc := app.NewChargeService(depsWith(&faultRepo{savePayment: errInjected}))
		if _, err := svc.CreateCharge(ctx, validInput()); !errors.Is(err, errInjected) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("append ledger error", func(t *testing.T) {
		t.Parallel()
		svc := app.NewChargeService(depsWith(&faultRepo{appendLedger: errInjected}))
		if _, err := svc.CreateCharge(ctx, validInput()); !errors.Is(err, errInjected) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestGetPaymentErrorAndScope(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Find returns a hard error → propagated.
	svc := app.NewChargeService(depsWith(&faultRepo{findByID: errInjected}))
	if _, err := svc.GetPayment(ctx, "t1", "p1"); !errors.Is(err, errInjected) {
		t.Fatalf("got %v", err)
	}

	// Defensive tenant-mismatch branch: repo returns a payment owned by another
	// tenant → service surfaces not-found.
	money, _ := shared.NewMoney(10, "BRL")
	foreign := payment.Rehydrate("p1", "other", "pix.create", "k", "tx", money, payment.StatusPending, time.Unix(0, 0).UTC(), time.Unix(0, 0).UTC())
	svc = app.NewChargeService(depsWith(&faultRepo{paymentByID: foreign}))
	if _, err := svc.GetPayment(ctx, "t1", "p1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want not found for cross-tenant, got %v", err)
	}
}

func TestWebhookErrorPropagation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ev := app.PaymentEvent{TenantID: "t1", TxID: "tx1", EventKey: "e1"}

	t.Run("mark processed error", func(t *testing.T) {
		t.Parallel()
		svc := app.NewWebhookService(depsWith(&faultRepo{markProc: errInjected}))
		if err := svc.HandlePaymentEvent(ctx, ev); !errors.Is(err, errInjected) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("duplicate is no-op", func(t *testing.T) {
		t.Parallel()
		svc := app.NewWebhookService(depsWith(&faultRepo{markProcSet: true, markProcVal: false}))
		if err := svc.HandlePaymentEvent(ctx, ev); err != nil {
			t.Fatalf("duplicate should be nil, got %v", err)
		}
	})

	t.Run("reconcile error", func(t *testing.T) {
		t.Parallel()
		// Bank has no such charge → GetCharge returns not found.
		svc := app.NewWebhookService(depsWith(&faultRepo{}))
		if err := svc.HandlePaymentEvent(ctx, ev); err == nil {
			t.Fatal("expected reconcile error for unknown tx")
		}
	})

	t.Run("find payment error after settle", func(t *testing.T) {
		t.Parallel()
		h := newHarnessFor()
		// Seed a settled charge in the stub bank for tenant t1.
		_, _ = h.bank.CreateCharge(ctx, "t1", ports.ChargeRequest{TenantID: "t1", PaymentID: "p1"})
		h.bank.MarkSettled("t1", "tx_p1")
		f := &faultRepo{findByTx: errInjected}
		deps := app.Deps{
			Payments: f, Tenants: f, Pricing: f, Ledger: f, Processed: f,
			Bus: h.bus, Bank: h.bank, Credentials: h.deps.Credentials,
			Clock: fixedClock{t: time.Unix(1000, 0).UTC()}, IDs: &seqIDs{},
		}
		svc := app.NewWebhookService(deps)
		if err := svc.HandlePaymentEvent(ctx, app.PaymentEvent{TenantID: "t1", TxID: "tx_p1", EventKey: "e1"}); !errors.Is(err, errInjected) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestAdminErrorPropagation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("save tenant error", func(t *testing.T) {
		t.Parallel()
		svc := app.NewAdminService(depsWith(&faultRepo{saveTenant: errInjected}))
		if _, err := svc.CreateTenant(ctx, "Acme"); !errors.Is(err, errInjected) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("find tenant error", func(t *testing.T) {
		t.Parallel()
		svc := app.NewAdminService(depsWith(&faultRepo{findTenant: errInjected}))
		if _, err := svc.SetEndpointPrice(ctx, "t1", "pix.create", 10); !errors.Is(err, errInjected) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("upsert price error", func(t *testing.T) {
		t.Parallel()
		svc := app.NewAdminService(depsWith(&faultRepo{upsertPrice: errInjected}))
		if _, err := svc.SetEndpointPrice(ctx, "t1", "pix.create", 10); !errors.Is(err, errInjected) {
			t.Fatalf("got %v", err)
		}
	})
}

func validInput() app.CreateChargeInput {
	return app.CreateChargeInput{TenantID: "t1", Endpoint: "pix.create", AmountCents: 100, Currency: "BRL", IdempotencyKey: "k1"}
}

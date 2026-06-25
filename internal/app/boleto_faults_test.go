package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// boletoFaultDeps reuses the storage-fault harness (depsWith) and wires the stub bank
// as the boleto provider so the BoletoService error-propagation branches can be
// exercised in isolation.
func boletoFaultDeps(f *faultRepo) app.Deps {
	d := depsWith(f)
	d.Boleto = d.Bank.(ports.BoletoProvider)
	return d
}

func validBoletoFaultInput() app.RegisterBoletoInput {
	return app.RegisterBoletoInput{
		TenantID:           "t1",
		AmountCents:        100000,
		Currency:           "BRL",
		DueDate:            boletoDueDate,
		FineBps:            200,
		MonthlyInterestBps: 100,
		IdempotencyKey:     "k1",
	}
}

func TestRegisterBoletoErrorPropagation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("tenant lookup error", func(t *testing.T) {
		t.Parallel()
		svc := app.NewBoletoService(boletoFaultDeps(&faultRepo{findTenant: errInjected}))
		if _, _, err := svc.RegisterBoleto(ctx, validBoletoFaultInput()); !errors.Is(err, errInjected) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("inactive tenant", func(t *testing.T) {
		t.Parallel()
		inactive := tenant.Rehydrate("t1", "Acme", false, boletoDueDate)
		svc := app.NewBoletoService(boletoFaultDeps(&faultRepo{tenant: inactive}))
		if _, _, err := svc.RegisterBoleto(ctx, validBoletoFaultInput()); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("idempotency lookup hard error", func(t *testing.T) {
		t.Parallel()
		svc := app.NewBoletoService(boletoFaultDeps(&faultRepo{findByIdem: errInjected}))
		if _, _, err := svc.RegisterBoleto(ctx, validBoletoFaultInput()); !errors.Is(err, errInjected) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("price lookup error", func(t *testing.T) {
		t.Parallel()
		svc := app.NewBoletoService(boletoFaultDeps(&faultRepo{getPrice: errInjected}))
		if _, _, err := svc.RegisterBoleto(ctx, validBoletoFaultInput()); !errors.Is(err, errInjected) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("save payment error", func(t *testing.T) {
		t.Parallel()
		svc := app.NewBoletoService(boletoFaultDeps(&faultRepo{savePayment: errInjected}))
		if _, _, err := svc.RegisterBoleto(ctx, validBoletoFaultInput()); !errors.Is(err, errInjected) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("append ledger error", func(t *testing.T) {
		t.Parallel()
		svc := app.NewBoletoService(boletoFaultDeps(&faultRepo{appendLedger: errInjected}))
		if _, _, err := svc.RegisterBoleto(ctx, validBoletoFaultInput()); !errors.Is(err, errInjected) {
			t.Fatalf("got %v", err)
		}
	})
}

// A valid payer document (CPF) is accepted (roteiro optional payer block).
func TestRegisterBoletoWithValidPayer(t *testing.T) {
	t.Parallel()
	svc, h, tenantID := newBoletoHarness(t)
	in := baseBoletoInput(tenantID, "k-payer")
	in.Payer.TaxID = "12345678901"
	if _, _, err := svc.RegisterBoleto(context.Background(), in); err != nil {
		t.Fatalf("register with payer: %v", err)
	}
	if h.store.LedgerLen() != 1 {
		t.Fatalf("expected 1 ledger entry, got %d", h.store.LedgerLen())
	}
}

// An oversized discount schedule is rejected before reserving a payment.
func TestRegisterBoletoTooManyTiers(t *testing.T) {
	t.Parallel()
	svc, _, tenantID := newBoletoHarness(t)
	in := baseBoletoInput(tenantID, "k-many")
	tiers := make([]app.DiscountTierInput, 13)
	for i := range tiers {
		tiers[i] = app.DiscountTierInput{DaysBeforeDue: 13 - i, Bps: int64(13 - i)}
	}
	in.Discounts = tiers
	if _, _, err := svc.RegisterBoleto(context.Background(), in); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want validation error for too many tiers, got %v", err)
	}
}

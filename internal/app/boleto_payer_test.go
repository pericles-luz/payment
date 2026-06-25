package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

// The boundary structurally validates any payer field that is present (the C6 adapter
// is the one that requires the full payer — ADR-0005). A bad UF or CEP is rejected,
// while a complete, well-formed payer is accepted.
func TestRegisterBoletoPayerStructuralValidation(t *testing.T) {
	t.Parallel()

	validAddr := func() app.BoletoAddressInput {
		return app.BoletoAddressInput{Street: "Rua das Flores", Number: 123, City: "Brasília", State: "DF", ZipCode: "70000000"}
	}

	t.Run("bad_uf", func(t *testing.T) {
		t.Parallel()
		svc, _, tenantID := newBoletoHarness(t)
		in := baseBoletoInput(tenantID, "k-uf")
		in.Payer = app.BoletoPayerInput{TaxID: "12345678901", Address: validAddr()}
		in.Payer.Address.State = "DFX" // not a 2-letter UF
		if _, _, err := svc.RegisterBoleto(context.Background(), in); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("bad UF: want ErrValidation, got %v", err)
		}
	})

	t.Run("non_alpha_uf", func(t *testing.T) {
		t.Parallel()
		svc, _, tenantID := newBoletoHarness(t)
		in := baseBoletoInput(tenantID, "k-uf2")
		in.Payer = app.BoletoPayerInput{TaxID: "12345678901", Address: validAddr()}
		in.Payer.Address.State = "1F"
		if _, _, err := svc.RegisterBoleto(context.Background(), in); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("non-alpha UF: want ErrValidation, got %v", err)
		}
	})

	t.Run("bad_cep_length", func(t *testing.T) {
		t.Parallel()
		svc, _, tenantID := newBoletoHarness(t)
		in := baseBoletoInput(tenantID, "k-cep")
		in.Payer = app.BoletoPayerInput{TaxID: "12345678901", Address: validAddr()}
		in.Payer.Address.ZipCode = "7000000" // 7 digits
		if _, _, err := svc.RegisterBoleto(context.Background(), in); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("bad CEP length: want ErrValidation, got %v", err)
		}
	})

	t.Run("non_digit_cep", func(t *testing.T) {
		t.Parallel()
		svc, _, tenantID := newBoletoHarness(t)
		in := baseBoletoInput(tenantID, "k-cep2")
		in.Payer = app.BoletoPayerInput{TaxID: "12345678901", Address: validAddr()}
		in.Payer.Address.ZipCode = "7000000a"
		if _, _, err := svc.RegisterBoleto(context.Background(), in); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("non-digit CEP: want ErrValidation, got %v", err)
		}
	})

	t.Run("full_valid_payer_accepted", func(t *testing.T) {
		t.Parallel()
		svc, h, tenantID := newBoletoHarness(t)
		in := baseBoletoInput(tenantID, "k-ok")
		in.Payer = app.BoletoPayerInput{Name: "Fulano de Tal", TaxID: "12345678901", Address: validAddr()}
		if _, _, err := svc.RegisterBoleto(context.Background(), in); err != nil {
			t.Fatalf("full valid payer: %v", err)
		}
		if h.store.LedgerLen() != 1 {
			t.Fatalf("expected 1 ledger entry, got %d", h.store.LedgerLen())
		}
	})
}

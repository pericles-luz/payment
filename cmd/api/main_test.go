package main

import (
	"context"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/bank"
	"github.com/ia-dev-sindireceita/payment/internal/platform/config"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

type noopCreds struct{}

func (noopCreds) GetBankCredential(context.Context, string) (ports.BankCredential, error) {
	return ports.BankCredential{}, nil
}

// TestNewBankProviderSelectsStubWhenUnset asserts the in-memory stub backs the
// wiring when PAYMENT_C6_BASE_URL is unset (the launch-default; C6 must not be
// settlement-live until the routing decision lands — SIN-64780).
func TestNewBankProviderSelectsStubWhenUnset(t *testing.T) {
	b, pix, err := newBankProvider(config.Config{}, noopCreds{})
	if err != nil {
		t.Fatalf("newBankProvider: %v", err)
	}
	if _, ok := b.(*bank.StubProvider); !ok {
		t.Fatalf("want *bank.StubProvider when C6 base URL is unset, got %T", b)
	}
	if _, ok := pix.(*bank.StubProvider); !ok {
		t.Fatalf("want *bank.StubProvider as the PIX provider when unset, got %T", pix)
	}
}

// TestNewBankProviderWrapsC6InPixSettlement asserts that when C6 is configured the
// provider is wrapped in PixSettlementProvider, so the settlement reconcile read
// routes through the BACEN-verified PIX path rather than the generic /charges read
// (SIN-64780 routing decision).
func TestNewBankProviderWrapsC6InPixSettlement(t *testing.T) {
	cfg := config.Config{}
	cfg.C6.BaseURL = "https://api.c6bank.example"
	cfg.C6.TokenURL = "https://api.c6bank.example/oauth/token"

	b, pix, err := newBankProvider(cfg, noopCreds{})
	if err != nil {
		t.Fatalf("newBankProvider: %v", err)
	}
	if _, ok := b.(*bank.PixSettlementProvider); !ok {
		t.Fatalf("want *bank.PixSettlementProvider for a configured C6, got %T", b)
	}
	// The raw PIX provider is the C6 provider itself (NOT the settlement wrapper):
	// PixService speaks the BACEN PIX shape directly. The settlement wrapper does not
	// even satisfy ports.PixProvider, so a non-nil PIX provider here is necessarily
	// the underlying C6 provider.
	if pix == nil {
		t.Fatal("want a non-nil PIX provider for a configured C6")
	}
}

// TestNewBankProviderRejectsInsecureC6 asserts a non-HTTPS C6 base URL is rejected
// at construction (the c6 adapter is TLS-only) rather than silently degrading.
func TestNewBankProviderRejectsInsecureC6(t *testing.T) {
	cfg := config.Config{}
	cfg.C6.BaseURL = "http://api.c6bank.example"
	cfg.C6.TokenURL = "https://api.c6bank.example/oauth/token"

	if _, _, err := newBankProvider(cfg, noopCreds{}); err == nil {
		t.Fatal("expected an error for a non-HTTPS C6 base URL")
	}
}

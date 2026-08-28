package main

import (
	"context"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/bank"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/platform/config"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// newCertProvider is the real in-memory certificate vault used as the C6 mTLS
// transport's cert source in these wiring tests (SIN-69368). It is empty, so the
// transport carries no client cert (no §8 path here either) — exactly the launch
// default — while still satisfying the non-nil provider the wiring requires.
func newCertProvider() *secret.CertStore { return secret.NewCertStore() }

type noopCreds struct{}

func (noopCreds) GetBankCredential(context.Context, string, string) (ports.BankCredential, error) {
	return ports.BankCredential{}, nil
}

// TestNewBankRegistrySelectsStubWhenUnset asserts the in-memory stub backs the C6
// slot in the wired registry when PAYMENT_C6_BASE_URL is unset (the launch-default;
// C6 must not be settlement-live until the routing decision lands — SIN-64780).
// Migrated from the pre-multi-bank newBankProvider test (SIN-66022): the wiring now
// returns a Registry, so the same invariant is asserted on the C6 ProviderSet.
func TestNewBankRegistrySelectsStubWhenUnset(t *testing.T) {
	reg, err := newBankRegistry(config.Config{}, noopCreds{}, newCertProvider())
	if err != nil {
		t.Fatalf("newBankRegistry: %v", err)
	}
	set, ok := reg.Get(ports.BankIDC6)
	if !ok {
		t.Fatalf("want a wired %q bank in the registry", ports.BankIDC6)
	}
	if _, ok := set.Bank.(*bank.StubProvider); !ok {
		t.Fatalf("want *bank.StubProvider when C6 base URL is unset, got %T", set.Bank)
	}
	if _, ok := set.Pix.(*bank.StubProvider); !ok {
		t.Fatalf("want *bank.StubProvider as the PIX provider when unset, got %T", set.Pix)
	}
	// The stub caches no credential state, so its set carries no invalidator — the
	// admin services then fall back to a no-op evictor (ADR-0003).
	if set.CredInvalidator != nil {
		t.Fatalf("want nil CredInvalidator for the stub, got %T", set.CredInvalidator)
	}
	if banks := reg.Banks(); len(banks) != 1 {
		t.Fatalf("want exactly one wired bank, got %v", banks)
	}
}

// TestNewBankRegistryWrapsC6InPixSettlement asserts that when C6 is configured the
// registry's C6 ProviderSet's generic Bank port is wrapped in PixSettlementProvider,
// so the settlement reconcile read routes through the BACEN-verified PIX path rather
// than the generic /charges read (SIN-64780 routing decision). Migrated from the
// newBankProvider test (SIN-66022).
func TestNewBankRegistryWrapsC6InPixSettlement(t *testing.T) {
	cfg := config.Config{}
	cfg.C6.BaseURL = "https://api.c6bank.example"
	cfg.C6.TokenURL = "https://api.c6bank.example/oauth/token"

	reg, err := newBankRegistry(cfg, noopCreds{}, newCertProvider())
	if err != nil {
		t.Fatalf("newBankRegistry: %v", err)
	}
	set, ok := reg.Get(ports.BankIDC6)
	if !ok {
		t.Fatalf("want a wired %q bank in the registry", ports.BankIDC6)
	}
	if _, ok := set.Bank.(*bank.PixSettlementProvider); !ok {
		t.Fatalf("want *bank.PixSettlementProvider for a configured C6, got %T", set.Bank)
	}
	// The raw PIX provider is the C6 provider itself (NOT the settlement wrapper):
	// PixService speaks the BACEN PIX shape directly. The settlement wrapper does not
	// even satisfy ports.PixProvider, so a non-nil PIX provider here is necessarily
	// the underlying C6 provider.
	if set.Pix == nil {
		t.Fatal("want a non-nil PIX provider for a configured C6")
	}
	// The C6 settlement wrapper forwards InvalidateToken, so the set carries a real
	// credential-cache invalidator (closing the token-revocation lag, ADR-0003).
	if set.CredInvalidator == nil {
		t.Fatal("want a non-nil CredInvalidator for a configured C6")
	}
}

// TestNewBankRegistryRejectsInsecureC6 asserts a non-HTTPS C6 base URL is rejected at
// construction (the c6 adapter is TLS-only) rather than silently degrading. Migrated
// from the newBankProvider test (SIN-66022).
func TestNewBankRegistryRejectsInsecureC6(t *testing.T) {
	cfg := config.Config{}
	cfg.C6.BaseURL = "http://api.c6bank.example"
	cfg.C6.TokenURL = "https://api.c6bank.example/oauth/token"

	if _, err := newBankRegistry(cfg, noopCreds{}, newCertProvider()); err == nil {
		t.Fatal("expected an error for a non-HTTPS C6 base URL")
	}
}

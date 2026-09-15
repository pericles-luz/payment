package c6

import (
	"context"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// boletoCapabilitiesFor builds a provider with the given granted scope, configured
// bank-slip scope name and credential, and returns the two boleto capabilities.
func boletoCapabilitiesFor(t *testing.T, grantedScope, configuredScope string, creds *fakeCreds) (ports.Capability, ports.Capability) {
	t.Helper()
	srv := tokenServerWithScope(t, grantedScope)
	p, err := New(Config{
		BaseURL:            srv.URL,
		TokenURL:           srv.URL + "/oauth/token",
		HTTPClient:         srv.Client(),
		BankSlipWriteScope: configuredScope,
	}, creds)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	caps, err := p.BankCapabilities(context.Background(), "t1")
	if err != nil {
		t.Fatalf("BankCapabilities: %v", err)
	}
	return caps.Boleto, caps.Bolepix
}

// The anti-guess test. With no configured scope name there is nothing to test the granted
// scopes AGAINST, so the honest answer is "unknown" — not "no". Reporting false here would
// tell an empresa its account cannot issue boletos on the strength of a name nobody has
// ever verified against a real token.
func TestBoletoCapabilityUnknownWhenScopeNameUnconfigured(t *testing.T) {
	t.Parallel()
	boleto, _ := boletoCapabilitiesFor(t, "pix.write cob.write bank_slip.write", "", tenantWithPixKey("t1"))
	if boleto != ports.CapabilityUnknown {
		t.Fatalf("want Unknown with no configured scope name, got %v", boleto)
	}
	if boleto.Allowed() {
		t.Fatal("an unknown capability must never read as permission")
	}
	if boleto.Known() {
		t.Fatal("an unknown capability must not read as determined")
	}
}

// Once the name is known, the translation is the same conservative rule the other
// modalities use: the WRITE scope must be granted.
func TestBoletoCapabilityGrantedAndDenied(t *testing.T) {
	t.Parallel()
	granted, _ := boletoCapabilitiesFor(t, "pix.write bank_slip.write", "bank_slip.write", tenantWithPixKey("t1"))
	if granted != ports.CapabilityGranted {
		t.Fatalf("want Granted when the configured scope is present, got %v", granted)
	}
	denied, _ := boletoCapabilitiesFor(t, "pix.write cob.write", "bank_slip.write", tenantWithPixKey("t1"))
	if denied != ports.CapabilityDenied {
		t.Fatalf("want Denied when the configured scope is absent, got %v", denied)
	}
}

// BolePix needs a registered EVP key on top of the scope. Without one the bank creates the
// charge anyway, with no QR and no error — so this is the only place the console can learn
// that a BolePix would come out broken.
func TestBolepixCapabilityDeniedWithoutCreditorKey(t *testing.T) {
	t.Parallel()
	boleto, bolepix := boletoCapabilitiesFor(t, "bank_slip.write", "bank_slip.write", oneTenant("t1", "c", "s"))
	if boleto != ports.CapabilityGranted {
		t.Fatalf("the missing key must not affect plain boleto, got %v", boleto)
	}
	if bolepix != ports.CapabilityDenied {
		t.Fatalf("bolepix without an EVP key must be Denied, got %v", bolepix)
	}
}

// With both the scope and a key, BolePix tracks boleto exactly.
func TestBolepixCapabilityFollowsBoletoWhenKeyPresent(t *testing.T) {
	t.Parallel()
	boleto, bolepix := boletoCapabilitiesFor(t, "bank_slip.write", "bank_slip.write", tenantWithPixKey("t1"))
	if boleto != ports.CapabilityGranted || bolepix != ports.CapabilityGranted {
		t.Fatalf("both should be Granted, got boleto=%v bolepix=%v", boleto, bolepix)
	}
	// And an unknown boleto keeps bolepix unknown rather than inventing a decision.
	ub, ubp := boletoCapabilitiesFor(t, "bank_slip.write", "", tenantWithPixKey("t1"))
	if ub != ports.CapabilityUnknown || ubp != ports.CapabilityUnknown {
		t.Fatalf("unknown must propagate, got boleto=%v bolepix=%v", ub, ubp)
	}
}

// A denied boleto dominates: bolepix can never be stronger than the capability it builds on.
func TestBolepixNeverStrongerThanBoleto(t *testing.T) {
	t.Parallel()
	boleto, bolepix := boletoCapabilitiesFor(t, "pix.write", "bank_slip.write", tenantWithPixKey("t1"))
	if boleto != ports.CapabilityDenied || bolepix != ports.CapabilityDenied {
		t.Fatalf("a denied boleto must deny bolepix, got boleto=%v bolepix=%v", boleto, bolepix)
	}
}

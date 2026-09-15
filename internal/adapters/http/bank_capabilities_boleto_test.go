package http_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// null and false are DIFFERENT answers and the wire must keep them apart. null says "ainda
// não verificamos"; false says "a conta não pode". A screen that receives false will tell
// the empresa its account cannot issue boletos — a claim we have no basis for while the C6
// bank-slip scope name is still unconfirmed.
func TestBankCapabilitiesRendersUnknownBoletoAsNull(t *testing.T) {
	t.Parallel()
	f := newCapsFixture(t, &stubCapabilities{byTenant: map[string]ports.BankCapabilities{}})
	f.caps.byTenant[f.tenantA] = ports.BankCapabilities{
		PIX: true, Card: true,
		Boleto:  ports.CapabilityUnknown,
		Bolepix: ports.CapabilityUnknown,
	}

	rec := do(t, f.handler, http.MethodGet, capabilitiesPath, "tok-a", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	// Assert on the RAW body: a decoded nil and a decoded false are easy to confuse in Go,
	// but the bytes on the wire are what the console actually reads.
	raw := rec.Body.String()
	if !strings.Contains(raw, `"boleto":null`) || !strings.Contains(raw, `"bolepix":null`) {
		t.Fatalf("unknown capabilities must serialize as null, got %s", raw)
	}

	got := decodeCaps(t, rec.Body.Bytes())
	if v, present := got["boleto"]; !present || v != nil {
		t.Fatalf("boleto must be present and null, got %#v", v)
	}
}

// A determined capability serializes as a plain boolean, so a console can branch on it
// exactly like pix and card.
func TestBankCapabilitiesRendersKnownBoletoAsBool(t *testing.T) {
	t.Parallel()
	f := newCapsFixture(t, &stubCapabilities{byTenant: map[string]ports.BankCapabilities{}})
	f.caps.byTenant[f.tenantA] = ports.BankCapabilities{
		PIX: true, Card: true,
		Boleto:  ports.CapabilityGranted,
		Bolepix: ports.CapabilityDenied,
	}

	rec := do(t, f.handler, http.MethodGet, capabilitiesPath, "tok-a", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	got := decodeCaps(t, rec.Body.Bytes())
	if got["boleto"] != true {
		t.Fatalf("granted boleto must be true, got %#v", got["boleto"])
	}
	// The interesting pair: the account may issue a boleto but NOT a bolepix, because it
	// has no registered EVP key. Collapsing the two into one flag would hide that.
	if got["bolepix"] != false {
		t.Fatalf("denied bolepix must be false, got %#v", got["bolepix"])
	}
}

// A tenant with no credential at all keeps answering 200 configured=false, and the boleto
// capabilities stay null: "não configurado" is not a denial either.
func TestBankCapabilitiesUnconfiguredTenantKeepsBoletoNull(t *testing.T) {
	t.Parallel()
	f := newCapsFixture(t, &stubCapabilities{byTenant: map[string]ports.BankCapabilities{}})

	rec := do(t, f.handler, http.MethodGet, capabilitiesPath, "tok-a", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	got := decodeCaps(t, rec.Body.Bytes())
	if got["configured"] != false {
		t.Fatalf("configured must be false: %v", got)
	}
	if v, present := got["boleto"]; !present || v != nil {
		t.Fatalf("an unconfigured tenant must report boleto as null, got %#v", v)
	}
}

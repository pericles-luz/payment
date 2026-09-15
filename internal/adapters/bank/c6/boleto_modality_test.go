package c6

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// tenantWithPixKey is a credential carrying a registered random (EVP) key, which is the
// precondition for issuing a BolePix.
func tenantWithPixKey(tenantID string) *fakeCreds {
	return &fakeCreds{creds: map[string]ports.BankCredential{
		tenantID: {
			TenantID:    tenantID,
			ClientID:    "c",
			Secret:      "s",
			CreditorKey: "123e4567-e89b-12d3-a456-426614174000",
		},
	}}
}

// sentPaymentMethod decodes just the payment_method object from the last request body.
func sentPaymentMethod(t *testing.T, raw []byte) bankSlipPaymentMethodBody {
	t.Helper()
	var sent struct {
		PaymentMethod bankSlipPaymentMethodBody `json:"payment_method"`
	}
	if err := json.Unmarshal(raw, &sent); err != nil {
		t.Fatalf("decode body: %v (%s)", err, raw)
	}
	return sent.PaymentMethod
}

// A plain boleto never carries the pix sub-object — not even for a tenant that HAS a
// registered key. Before the modality existed, the key alone decided, so this case could
// not be expressed at all.
func TestCreateBoletoOmitsPixForPlainBoleto(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	p := ps.provider(t, tenantWithPixKey("t1"))

	req := baseLimitRequest()
	req.Modality = ports.ModalityBoleto
	res, err := p.CreateBoleto(context.Background(), "t1", req)
	if err != nil {
		t.Fatalf("CreateBoleto: %v", err)
	}
	if pm := sentPaymentMethod(t, ps.body()); pm.Pix != nil {
		t.Fatalf("a plain boleto must not send payment_method.pix, got %+v", pm.Pix)
	}
	if pm := sentPaymentMethod(t, ps.body()); pm.BankSlip.BillingScheme == "" {
		t.Fatal("bank_slip.billing_scheme is required even for a plain boleto")
	}
	_ = res
}

// An unset modality behaves as a plain boleto: the default must never promise a QR that
// the caller did not ask for and may not get.
func TestCreateBoletoDefaultsToPlainBoleto(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	p := ps.provider(t, tenantWithPixKey("t1"))

	req := baseLimitRequest() // Modality left at its zero value
	if _, err := p.CreateBoleto(context.Background(), "t1", req); err != nil {
		t.Fatalf("CreateBoleto: %v", err)
	}
	if pm := sentPaymentMethod(t, ps.body()); pm.Pix != nil {
		t.Fatalf("the default modality must not send payment_method.pix, got %+v", pm.Pix)
	}
}

// BolePix sends the key as an EVP type, which is the only type the contract accepts.
func TestCreateBolepixSendsEVPKey(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	p := ps.provider(t, tenantWithPixKey("t1"))

	req := baseLimitRequest()
	req.Modality = ports.ModalityBolepix
	if _, err := p.CreateBoleto(context.Background(), "t1", req); err != nil {
		t.Fatalf("CreateBoleto: %v", err)
	}
	pm := sentPaymentMethod(t, ps.body())
	if pm.Pix == nil {
		t.Fatalf("bolepix must send payment_method.pix, body=%s", ps.body())
	}
	if pm.Pix.Type != pixKeyTypeEVP {
		t.Fatalf("pix.type = %q, want %q", pm.Pix.Type, pixKeyTypeEVP)
	}
	if pm.Pix.Key != "123e4567-e89b-12d3-a456-426614174000" {
		t.Fatalf("pix.key must be the tenant's registered creditor key, got %q", pm.Pix.Key)
	}
}

// BolePix without a registered EVP key is refused BEFORE anything is sent.
//
// This is the case the bank will never report: the contract states that an absent or
// invalid key still creates the charge, just with payment_method.pix = null. So a silent
// degradation here surfaces only at payment time, to the payer, as a slip promising a QR
// that does not exist.
func TestCreateBolepixWithoutKeyFailsClosed(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	p := ps.provider(t, oneTenant("t1", "c", "s")) // no CreditorKey

	req := baseLimitRequest()
	req.Modality = ports.ModalityBolepix

	_, err := p.CreateBoleto(context.Background(), "t1", req)
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation, got %v", err)
	}
	if len(ps.body()) != 0 {
		t.Fatalf("nothing must reach the bank when the precondition fails, sent %s", ps.body())
	}
}

// The same tenant, with no key, can still issue a plain boleto: the precondition belongs
// to BolePix alone and must not block the modality that does not need it.
func TestCreateBoletoWithoutKeySucceeds(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	p := ps.provider(t, oneTenant("t1", "c", "s"))

	req := baseLimitRequest()
	req.Modality = ports.ModalityBoleto
	if _, err := p.CreateBoleto(context.Background(), "t1", req); err != nil {
		t.Fatalf("a plain boleto needs no pix key, got %v", err)
	}
}

// The result reports the rails the charge actually has, read off the bank's answer, so a
// caller never has to infer the modality from whether QRCode came back populated.
func TestBoletoResultEchoesModality(t *testing.T) {
	t.Parallel()
	withQR := toBankSlipResult("bol_1", func() bankSlipResponseBody {
		var out bankSlipResponseBody
		out.PaymentMethod.Pix.QRCode = "00020126_EMV"
		return out
	}())
	if withQR.Modality != ports.ModalityBolepix {
		t.Fatalf("a charge with a QR is a bolepix, got %q", withQR.Modality)
	}
	noQR := toBankSlipResult("bol_1", bankSlipResponseBody{})
	if noQR.Modality != ports.ModalityBoleto {
		t.Fatalf("a charge with no QR is a plain boleto, got %q", noQR.Modality)
	}
}

package bank

import (
	"context"
	"errors"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// stubCreds is a minimal CredentialStore for the stub product tests: it knows one
// tenant and returns ErrNotFound for any other.
type stubCreds struct{ known string }

func (s stubCreds) GetBankCredential(_ context.Context, tenantID string, _ string) (ports.BankCredential, error) {
	if tenantID != s.known {
		return ports.BankCredential{}, shared.ErrNotFound
	}
	return ports.BankCredential{TenantID: tenantID, ClientID: "c", Secret: "s"}, nil
}

func newStub(t *testing.T) *StubProvider {
	t.Helper()
	return NewStubProvider(stubCreds{known: "t1"})
}

func TestStubBoleto(t *testing.T) {
	t.Parallel()
	s := newStub(t)
	ctx := context.Background()

	res, err := s.CreateBoleto(ctx, "t1", ports.BoletoRequest{
		TenantID: "t1", BoletoID: "bol_1", AmountCents: 2500, Currency: "BRL",
		Modality: ports.ModalityBolepix,
	})
	if err != nil {
		t.Fatalf("CreateBoleto: %v", err)
	}
	if res.TxID != "tx_bol_1" || res.Status != "REGISTERED" || res.AmountCents != 2500 {
		t.Fatalf("unexpected: %+v", res)
	}
	// A BolePix carries BOTH rails: the barcode and the PIX QR.
	if res.QRCode == "" || res.Barcode == "" {
		t.Fatalf("expected scannable artifacts: %+v", res)
	}

	// A plain boleto carries the slip only. The stub must distinguish the two, or nothing
	// above this layer could test the difference.
	plain, err := s.CreateBoleto(ctx, "t1", ports.BoletoRequest{
		TenantID: "t1", BoletoID: "bol_plain", AmountCents: 2500, Currency: "BRL",
		Modality: ports.ModalityBoleto,
	})
	if err != nil {
		t.Fatalf("CreateBoleto plain: %v", err)
	}
	if plain.QRCode != "" {
		t.Fatalf("a plain boleto must carry no QR: %+v", plain)
	}
	if plain.Barcode == "" {
		t.Fatalf("a plain boleto must still carry a barcode: %+v", plain)
	}

	if _, err := s.CreateBoleto(ctx, "other", ports.BoletoRequest{TenantID: "other", BoletoID: "b"}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("unknown tenant: want ErrNotFound, got %v", err)
	}
}

func TestStubCheckout(t *testing.T) {
	t.Parallel()
	s := newStub(t)
	ctx := context.Background()

	res, err := s.CreateCheckoutSession(ctx, "t1", ports.CheckoutRequest{
		TenantID: "t1", SessionID: "sess_1", Currency: "BRL",
		Items: []ports.CheckoutItem{{Description: "a", AmountCents: 1000}, {Description: "b", AmountCents: 500}},
	})
	if err != nil {
		t.Fatalf("CreateCheckoutSession: %v", err)
	}
	if res.SessionID != "sess_1" || res.Status != "OPEN" || res.AmountCents != 1500 {
		t.Fatalf("unexpected: %+v", res)
	}
	if res.RedirectURL == "" {
		t.Fatalf("expected redirect url: %+v", res)
	}

	if _, err := s.CreateCheckoutSession(ctx, "other", ports.CheckoutRequest{TenantID: "other", SessionID: "s"}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("unknown tenant: want ErrNotFound, got %v", err)
	}
}

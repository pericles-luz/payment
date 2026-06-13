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

func (s stubCreds) GetBankCredential(_ context.Context, tenantID string) (ports.BankCredential, error) {
	if tenantID != s.known {
		return ports.BankCredential{}, shared.ErrNotFound
	}
	return ports.BankCredential{TenantID: tenantID, ClientID: "c", Secret: "s"}, nil
}

func newStub(t *testing.T) *StubProvider {
	t.Helper()
	return NewStubProvider(stubCreds{known: "t1"})
}

func TestStubConsentLifecycle(t *testing.T) {
	t.Parallel()
	s := newStub(t)
	ctx := context.Background()
	req := ports.ConsentRequest{TenantID: "t1", ConsentID: "con_1", DebtorTaxID: "12345678901", MaxAmountCents: 1000, Currency: "BRL", Frequency: "MONTHLY"}

	res, err := s.CreateConsent(ctx, "t1", req)
	if err != nil {
		t.Fatalf("CreateConsent: %v", err)
	}
	if res.ConsentID != "con_1" || res.Status != "PENDING" {
		t.Fatalf("unexpected: %+v", res)
	}

	// Idempotent: a repeat create returns the existing consent unchanged.
	again, err := s.CreateConsent(ctx, "t1", req)
	if err != nil || again != res {
		t.Fatalf("repeat create not idempotent: %+v / %v", again, err)
	}

	got, err := s.GetConsent(ctx, "t1", "con_1")
	if err != nil || got.Status != "PENDING" {
		t.Fatalf("GetConsent: %+v / %v", got, err)
	}

	cancelled, err := s.CancelConsent(ctx, "t1", "con_1")
	if err != nil || cancelled.Status != "CANCELLED" {
		t.Fatalf("CancelConsent: %+v / %v", cancelled, err)
	}
	// Cancel is idempotent.
	if again, err := s.CancelConsent(ctx, "t1", "con_1"); err != nil || again.Status != "CANCELLED" {
		t.Fatalf("repeat cancel: %+v / %v", again, err)
	}
	// The cancellation is now reflected by a reconcile.
	if got, err := s.GetConsent(ctx, "t1", "con_1"); err != nil || got.Status != "CANCELLED" {
		t.Fatalf("GetConsent after cancel: %+v / %v", got, err)
	}
}

func TestStubConsentNotFoundAndIsolation(t *testing.T) {
	t.Parallel()
	s := newStub(t)
	ctx := context.Background()

	if _, err := s.GetConsent(ctx, "t1", "missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("GetConsent missing: want ErrNotFound, got %v", err)
	}
	if _, err := s.CancelConsent(ctx, "t1", "missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("CancelConsent missing: want ErrNotFound, got %v", err)
	}

	// Unknown tenant: credential isolation rejects before any state is touched.
	req := ports.ConsentRequest{TenantID: "other", ConsentID: "c", DebtorTaxID: "12345678901", MaxAmountCents: 1, Currency: "BRL", Frequency: "MONTHLY"}
	if _, err := s.CreateConsent(ctx, "other", req); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("CreateConsent unknown tenant: want ErrNotFound, got %v", err)
	}
	if _, err := s.GetConsent(ctx, "other", "c"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("GetConsent unknown tenant: want ErrNotFound, got %v", err)
	}
	if _, err := s.CancelConsent(ctx, "other", "c"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("CancelConsent unknown tenant: want ErrNotFound, got %v", err)
	}
}

func TestStubBoleto(t *testing.T) {
	t.Parallel()
	s := newStub(t)
	ctx := context.Background()

	res, err := s.CreateBoleto(ctx, "t1", ports.BoletoRequest{TenantID: "t1", BoletoID: "bol_1", AmountCents: 2500, Currency: "BRL"})
	if err != nil {
		t.Fatalf("CreateBoleto: %v", err)
	}
	if res.TxID != "tx_bol_1" || res.Status != "REGISTERED" || res.AmountCents != 2500 {
		t.Fatalf("unexpected: %+v", res)
	}
	if res.QRCode == "" || res.Barcode == "" {
		t.Fatalf("expected scannable artifacts: %+v", res)
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

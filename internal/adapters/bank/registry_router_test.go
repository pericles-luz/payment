package bank_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/bank"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/platform/bankctx"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// recProvider is a recording test double that satisfies every bank output port. It
// stamps its label onto each result's TxID/SessionID so a test can assert WHICH
// bank's instance a router dispatched to.
type recProvider struct {
	label  string
	hits   int
	tenant string
}

func (r *recProvider) CreateCharge(_ context.Context, tenantID string, _ ports.ChargeRequest) (ports.ChargeResult, error) {
	r.hits++
	r.tenant = tenantID
	return ports.ChargeResult{TxID: r.label}, nil
}
func (r *recProvider) GetCharge(_ context.Context, _ string, _ string) (ports.ChargeResult, error) {
	r.hits++
	return ports.ChargeResult{TxID: r.label}, nil
}
func (r *recProvider) CreateImmediateCharge(_ context.Context, tenantID string, _ ports.ChargeRequest, _ time.Duration) (ports.PixChargeResult, error) {
	r.hits++
	r.tenant = tenantID
	return ports.PixChargeResult{TxID: r.label}, nil
}
func (r *recProvider) GetImmediateCharge(_ context.Context, _ string, _ string) (ports.PixChargeResult, error) {
	r.hits++
	return ports.PixChargeResult{TxID: r.label}, nil
}
func (r *recProvider) ListImmediateCharges(_ context.Context, _ string, _ ports.PixListFilter) (ports.PixChargeList, error) {
	r.hits++
	return ports.PixChargeList{}, nil
}
func (r *recProvider) CreateDueCharge(_ context.Context, _ string, _ ports.PixDueChargeRequest) (ports.PixDueChargeResult, error) {
	r.hits++
	return ports.PixDueChargeResult{TxID: r.label}, nil
}
func (r *recProvider) GetDueCharge(_ context.Context, _ string, _ string) (ports.PixDueChargeResult, error) {
	r.hits++
	return ports.PixDueChargeResult{TxID: r.label}, nil
}
func (r *recProvider) UpdateDueCharge(_ context.Context, _ string, _ string, _ ports.PixDueChargeRequest) (ports.PixDueChargeResult, error) {
	r.hits++
	return ports.PixDueChargeResult{TxID: r.label}, nil
}
func (r *recProvider) CreateCheckoutSession(_ context.Context, _ string, _ ports.CheckoutRequest) (ports.CheckoutResult, error) {
	r.hits++
	return ports.CheckoutResult{SessionID: r.label}, nil
}
func (r *recProvider) GetCheckoutSession(_ context.Context, _ string, _ string) (ports.CheckoutResult, error) {
	r.hits++
	return ports.CheckoutResult{SessionID: r.label}, nil
}
func (r *recProvider) CancelCheckoutSession(_ context.Context, _ string, _ string) (ports.CheckoutResult, error) {
	r.hits++
	return ports.CheckoutResult{SessionID: r.label}, nil
}
func (r *recProvider) CreateBoleto(_ context.Context, _ string, _ ports.BoletoRequest) (ports.BoletoResult, error) {
	r.hits++
	return ports.BoletoResult{TxID: r.label}, nil
}
func (r *recProvider) GetBoleto(_ context.Context, _ string, _ string) (ports.BoletoResult, error) {
	r.hits++
	return ports.BoletoResult{TxID: r.label}, nil
}
func (r *recProvider) CancelBoleto(_ context.Context, _ string, _ string) (ports.BoletoResult, error) {
	r.hits++
	return ports.BoletoResult{TxID: r.label}, nil
}
func (r *recProvider) UpdateBoleto(_ context.Context, _ string, _ string, _ ports.BoletoRequest) (ports.BoletoResult, error) {
	r.hits++
	return ports.BoletoResult{TxID: r.label}, nil
}
func (r *recProvider) ListOpenBoletos(_ context.Context, _ string) ([]ports.DDABoleto, error) {
	r.hits++
	return nil, nil
}
func (r *recProvider) CreatePaymentGroup(_ context.Context, _ string, _ ports.DDAGroupRequest) (ports.DDAGroup, error) {
	r.hits++
	return ports.DDAGroup{ID: r.label}, nil
}
func (r *recProvider) GetPaymentGroup(_ context.Context, _ string, _ string) (ports.DDAGroup, error) {
	r.hits++
	return ports.DDAGroup{ID: r.label}, nil
}
func (r *recProvider) RemovePaymentGroupItems(_ context.Context, _ string, _ string, _ []string) error {
	r.hits++
	return nil
}
func (r *recProvider) RemovePaymentGroupItem(_ context.Context, _ string, _ string, _ string) error {
	r.hits++
	return nil
}
func (r *recProvider) SubmitPaymentGroup(_ context.Context, _ string, _ string, _ string) error {
	r.hits++
	return nil
}
func (r *recProvider) GetStatement(_ context.Context, _ string, _ ports.StatementFilter) (ports.Statement, error) {
	r.hits++
	return ports.Statement{}, nil
}

// fullSet wires a recProvider into every port of a ProviderSet.
func fullSet(p *recProvider) bank.ProviderSet {
	return bank.ProviderSet{
		Bank:         p,
		Pix:          p,
		PixDueCharge: p,
		Checkout:     p,
		Boleto:       p,
		DDA:          p,
		Statement:    p,
	}
}

func TestRegistryRegisterGetHasBanks(t *testing.T) {
	reg := bank.NewRegistry()
	reg.Register("c6", fullSet(&recProvider{label: "c6"}))
	reg.Register("itau", fullSet(&recProvider{label: "itau"}))

	if !reg.Has("c6") || !reg.Has("itau") {
		t.Fatal("registered banks must be present")
	}
	if reg.Has("bb") {
		t.Fatal("unregistered bank must not be present")
	}
	if _, ok := reg.Get("c6"); !ok {
		t.Fatal("Get(c6) must resolve")
	}
	if _, ok := reg.Get("bb"); ok {
		t.Fatal("Get(bb) must not resolve")
	}
	if got := len(reg.Banks()); got != 2 {
		t.Fatalf("want 2 wired banks, got %d", got)
	}
}

// TestRouterDispatchesToContextBank asserts every router dispatches to the bank
// stamped on the context, not to any other wired bank.
func TestRouterDispatchesToContextBank(t *testing.T) {
	c6 := &recProvider{label: "c6"}
	itau := &recProvider{label: "itau"}
	reg := bank.NewRegistry()
	reg.Register("c6", fullSet(c6))
	reg.Register("itau", fullSet(itau))
	rt := bank.NewRouters(reg)

	ctx := bankctx.WithBankID(context.Background(), "itau")
	res, err := rt.Pix.CreateImmediateCharge(ctx, "tenant-1", ports.ChargeRequest{}, 0)
	if err != nil {
		t.Fatalf("CreateImmediateCharge: %v", err)
	}
	if res.TxID != "itau" {
		t.Fatalf("want dispatch to itau, got %q", res.TxID)
	}
	if itau.hits != 1 || c6.hits != 0 {
		t.Fatalf("want only itau hit; itau=%d c6=%d", itau.hits, c6.hits)
	}
	if itau.tenant != "tenant-1" {
		t.Fatalf("tenant must be forwarded verbatim, got %q", itau.tenant)
	}
}

// TestRouterDefaultsToC6WhenContextEmpty asserts an unstamped context resolves to
// the retro-compatible default bank (ports.BankIDC6).
func TestRouterDefaultsToC6WhenContextEmpty(t *testing.T) {
	c6 := &recProvider{label: "c6"}
	reg := bank.NewRegistry()
	reg.Register(ports.BankIDC6, fullSet(c6))
	rt := bank.NewRouters(reg)

	if _, err := rt.Bank.CreateCharge(context.Background(), "t", ports.ChargeRequest{}); err != nil {
		t.Fatalf("CreateCharge: %v", err)
	}
	if c6.hits != 1 {
		t.Fatalf("want default dispatch to c6, hits=%d", c6.hits)
	}
}

// TestRouterFailsClosedForUnknownBank asserts a context naming a bank with no wired
// adapter fails closed with ErrUnavailable — never a fallback to another bank.
func TestRouterFailsClosedForUnknownBank(t *testing.T) {
	reg := bank.NewRegistry()
	reg.Register(ports.BankIDC6, fullSet(&recProvider{label: "c6"}))
	rt := bank.NewRouters(reg)

	ctx := bankctx.WithBankID(context.Background(), "ghost")
	if _, err := rt.Pix.GetImmediateCharge(ctx, "t", "x"); !errors.Is(err, shared.ErrUnavailable) {
		t.Fatalf("want ErrUnavailable for an unwired bank, got %v", err)
	}
}

// TestRouterFailsClosedForNilPort asserts a wired bank that does not implement a
// given port yields ErrUnavailable on that port (but not on the ports it does
// implement).
func TestRouterFailsClosedForNilPort(t *testing.T) {
	p := &recProvider{label: "c6"}
	reg := bank.NewRegistry()
	// Only the Bank port is wired; the others are nil.
	reg.Register(ports.BankIDC6, bank.ProviderSet{Bank: p})
	rt := bank.NewRouters(reg)

	if _, err := rt.Statement.GetStatement(context.Background(), "t", ports.StatementFilter{}); !errors.Is(err, shared.ErrUnavailable) {
		t.Fatalf("want ErrUnavailable for a nil Statement port, got %v", err)
	}
	if _, err := rt.Bank.CreateCharge(context.Background(), "t", ports.ChargeRequest{}); err != nil {
		t.Fatalf("wired Bank port must still work, got %v", err)
	}
}

// TestAllRouterMethodsDispatchAndFailClosed drives every method of every router on
// both paths: the happy path (a wired bank stamped on the context dispatches and
// returns nil error) and the fail-closed path (an unwired bank yields
// shared.ErrUnavailable). This pins the (ctx, tenantID, …) signature and the
// uniform fail-closed behaviour across the whole routing surface.
func TestAllRouterMethodsDispatchAndFailClosed(t *testing.T) {
	p := &recProvider{label: "c6"}
	reg := bank.NewRegistry()
	reg.Register(ports.BankIDC6, fullSet(p))
	rt := bank.NewRouters(reg)

	okCtx := bankctx.WithBankID(context.Background(), ports.BankIDC6)
	badCtx := bankctx.WithBankID(context.Background(), "ghost")

	// Each invoker calls one router method and returns its error (nil on success).
	calls := map[string]func(ctx context.Context) error{
		"bank.CreateCharge": func(c context.Context) error { _, e := rt.Bank.CreateCharge(c, "t", ports.ChargeRequest{}); return e },
		"bank.GetCharge":    func(c context.Context) error { _, e := rt.Bank.GetCharge(c, "t", "x"); return e },
		"pix.CreateImmediate": func(c context.Context) error {
			_, e := rt.Pix.CreateImmediateCharge(c, "t", ports.ChargeRequest{}, 0)
			return e
		},
		"pix.GetImmediate": func(c context.Context) error { _, e := rt.Pix.GetImmediateCharge(c, "t", "x"); return e },
		"pix.ListImmediate": func(c context.Context) error {
			_, e := rt.Pix.ListImmediateCharges(c, "t", ports.PixListFilter{})
			return e
		},
		"cobv.CreateDue": func(c context.Context) error {
			_, e := rt.PixDueCharge.CreateDueCharge(c, "t", ports.PixDueChargeRequest{})
			return e
		},
		"cobv.GetDue": func(c context.Context) error { _, e := rt.PixDueCharge.GetDueCharge(c, "t", "x"); return e },
		"cobv.UpdateDue": func(c context.Context) error {
			_, e := rt.PixDueCharge.UpdateDueCharge(c, "t", "x", ports.PixDueChargeRequest{})
			return e
		},
		"checkout.Create": func(c context.Context) error {
			_, e := rt.Checkout.CreateCheckoutSession(c, "t", ports.CheckoutRequest{})
			return e
		},
		"checkout.Get":    func(c context.Context) error { _, e := rt.Checkout.GetCheckoutSession(c, "t", "x"); return e },
		"checkout.Cancel": func(c context.Context) error { _, e := rt.Checkout.CancelCheckoutSession(c, "t", "x"); return e },
		"boleto.Create":   func(c context.Context) error { _, e := rt.Boleto.CreateBoleto(c, "t", ports.BoletoRequest{}); return e },
		"boleto.Get":      func(c context.Context) error { _, e := rt.Boleto.GetBoleto(c, "t", "x"); return e },
		"boleto.Cancel":   func(c context.Context) error { _, e := rt.Boleto.CancelBoleto(c, "t", "x"); return e },
		"boleto.Update": func(c context.Context) error {
			_, e := rt.Boleto.UpdateBoleto(c, "t", "x", ports.BoletoRequest{})
			return e
		},
		"dda.ListOpen": func(c context.Context) error { _, e := rt.DDA.ListOpenBoletos(c, "t"); return e },
		"dda.CreateGroup": func(c context.Context) error {
			_, e := rt.DDA.CreatePaymentGroup(c, "t", ports.DDAGroupRequest{})
			return e
		},
		"dda.GetGroup":    func(c context.Context) error { _, e := rt.DDA.GetPaymentGroup(c, "t", "g"); return e },
		"dda.RemoveItems": func(c context.Context) error { return rt.DDA.RemovePaymentGroupItems(c, "t", "g", nil) },
		"dda.RemoveItem":  func(c context.Context) error { return rt.DDA.RemovePaymentGroupItem(c, "t", "g", "i") },
		"dda.SubmitGroup": func(c context.Context) error { return rt.DDA.SubmitPaymentGroup(c, "t", "g", "k") },
		"statement.Get": func(c context.Context) error {
			_, e := rt.Statement.GetStatement(c, "t", ports.StatementFilter{})
			return e
		},
	}

	for name, call := range calls {
		if err := call(okCtx); err != nil {
			t.Errorf("%s: happy path returned %v", name, err)
		}
		if err := call(badCtx); !errors.Is(err, shared.ErrUnavailable) {
			t.Errorf("%s: unwired bank returned %v, want ErrUnavailable", name, err)
		}
	}
}

// recInvalidator records token-cache evictions per tenant.
type recInvalidator struct{ calls []string }

func (r *recInvalidator) InvalidateToken(tenantID string) { r.calls = append(r.calls, tenantID) }

// TestRegistryCompositeInvalidatorFansOut asserts the composite invalidator evicts a
// tenant across every wired bank that caches credential state, and returns nil when
// no bank caches anything.
func TestRegistryCompositeInvalidatorFansOut(t *testing.T) {
	a := &recInvalidator{}
	b := &recInvalidator{}
	reg := bank.NewRegistry()
	reg.Register("c6", bank.ProviderSet{CredInvalidator: a})
	reg.Register("itau", bank.ProviderSet{CredInvalidator: b})

	inv := reg.CredentialInvalidator()
	if inv == nil {
		t.Fatal("want a composite invalidator when banks cache state")
	}
	inv.InvalidateToken("tenant-9")
	if len(a.calls) != 1 || a.calls[0] != "tenant-9" || len(b.calls) != 1 || b.calls[0] != "tenant-9" {
		t.Fatalf("eviction must fan out to all banks: a=%v b=%v", a.calls, b.calls)
	}

	empty := bank.NewRegistry()
	empty.Register("c6", bank.ProviderSet{})
	if empty.CredentialInvalidator() != nil {
		t.Fatal("want nil invalidator when no bank caches state")
	}
}

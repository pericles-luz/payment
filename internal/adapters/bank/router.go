package bank

import (
	"context"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/platform/bankctx"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// The routers below are output-port adapters that DISPATCH each call to the bank
// the request was routed to. The resolved bank id travels on the context
// (bankctx); the routers read it, look the bank up in the Registry and delegate to
// that bank's bound provider instance. The port signatures are unchanged
// (ctx, tenantID, …) — routing is a context concern, not a request field
// (SIN-66022 §4).
//
// Fail-closed is the rule everywhere: an absent bank id resolves to the
// retro-compatible default (ports.BankIDC6); a bank with no wired adapter, or a
// wired bank that does not implement the requested surface, yields
// shared.ErrUnavailable — NEVER a silent fallback to a different bank (no
// confused-deputy, ADR-0007). The HTTP selector has already validated that an
// explicitly-requested bank is both wired and configured for the tenant, so in
// practice the router only ever resolves a vetted bank; the guards here are
// defense-in-depth for internal/legacy call paths.

// resolve returns the ProviderSet for the bank stamped on ctx, applying the
// default bank when none is present.
func (r *Registry) resolve(ctx context.Context) (ProviderSet, bool) {
	id := bankctx.FromContext(ctx)
	if id == "" {
		id = ports.BankIDC6
	}
	return r.Get(id)
}

// Routers bundles one router per bank output port, all sharing the Registry. The
// wiring in cmd uses these as the providers behind the application services.
type Routers struct {
	Bank         ports.BankProvider
	Pix          ports.PixProvider
	PixDueCharge ports.PixDueChargeProvider
	Checkout     ports.CheckoutProvider
	Boleto       ports.BoletoProvider
	DDA          ports.DDAProvider
	Statement    ports.StatementProvider
}

// NewRouters builds the per-port routers over reg.
func NewRouters(reg *Registry) Routers {
	return Routers{
		Bank:         bankRouter{reg},
		Pix:          pixRouter{reg},
		PixDueCharge: pixDueChargeRouter{reg},
		Checkout:     checkoutRouter{reg},
		Boleto:       boletoRouter{reg},
		DDA:          ddaRouter{reg},
		Statement:    statementRouter{reg},
	}
}

// --- BankProvider ---

type bankRouter struct{ reg *Registry }

var _ ports.BankProvider = bankRouter{}

func (r bankRouter) CreateCharge(ctx context.Context, tenantID string, req ports.ChargeRequest) (ports.ChargeResult, error) {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.Bank == nil {
		return ports.ChargeResult{}, shared.ErrUnavailable
	}
	return set.Bank.CreateCharge(ctx, tenantID, req)
}

func (r bankRouter) GetCharge(ctx context.Context, tenantID, txID string) (ports.ChargeResult, error) {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.Bank == nil {
		return ports.ChargeResult{}, shared.ErrUnavailable
	}
	return set.Bank.GetCharge(ctx, tenantID, txID)
}

// --- PixProvider ---

type pixRouter struct{ reg *Registry }

var _ ports.PixProvider = pixRouter{}

func (r pixRouter) CreateImmediateCharge(ctx context.Context, tenantID string, req ports.ChargeRequest, expiresIn time.Duration) (ports.PixChargeResult, error) {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.Pix == nil {
		return ports.PixChargeResult{}, shared.ErrUnavailable
	}
	return set.Pix.CreateImmediateCharge(ctx, tenantID, req, expiresIn)
}

func (r pixRouter) GetImmediateCharge(ctx context.Context, tenantID, txID string) (ports.PixChargeResult, error) {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.Pix == nil {
		return ports.PixChargeResult{}, shared.ErrUnavailable
	}
	return set.Pix.GetImmediateCharge(ctx, tenantID, txID)
}

func (r pixRouter) ListImmediateCharges(ctx context.Context, tenantID string, filter ports.PixListFilter) (ports.PixChargeList, error) {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.Pix == nil {
		return ports.PixChargeList{}, shared.ErrUnavailable
	}
	return set.Pix.ListImmediateCharges(ctx, tenantID, filter)
}

// --- PixDueChargeProvider ---

type pixDueChargeRouter struct{ reg *Registry }

var _ ports.PixDueChargeProvider = pixDueChargeRouter{}

func (r pixDueChargeRouter) CreateDueCharge(ctx context.Context, tenantID string, req ports.PixDueChargeRequest) (ports.PixDueChargeResult, error) {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.PixDueCharge == nil {
		return ports.PixDueChargeResult{}, shared.ErrUnavailable
	}
	return set.PixDueCharge.CreateDueCharge(ctx, tenantID, req)
}

func (r pixDueChargeRouter) GetDueCharge(ctx context.Context, tenantID, txID string) (ports.PixDueChargeResult, error) {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.PixDueCharge == nil {
		return ports.PixDueChargeResult{}, shared.ErrUnavailable
	}
	return set.PixDueCharge.GetDueCharge(ctx, tenantID, txID)
}

func (r pixDueChargeRouter) UpdateDueCharge(ctx context.Context, tenantID, txID string, req ports.PixDueChargeRequest) (ports.PixDueChargeResult, error) {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.PixDueCharge == nil {
		return ports.PixDueChargeResult{}, shared.ErrUnavailable
	}
	return set.PixDueCharge.UpdateDueCharge(ctx, tenantID, txID, req)
}

// --- CheckoutProvider ---

type checkoutRouter struct{ reg *Registry }

var _ ports.CheckoutProvider = checkoutRouter{}

func (r checkoutRouter) CreateCheckoutSession(ctx context.Context, tenantID string, req ports.CheckoutRequest) (ports.CheckoutResult, error) {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.Checkout == nil {
		return ports.CheckoutResult{}, shared.ErrUnavailable
	}
	return set.Checkout.CreateCheckoutSession(ctx, tenantID, req)
}

func (r checkoutRouter) GetCheckoutSession(ctx context.Context, tenantID, sessionID string) (ports.CheckoutResult, error) {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.Checkout == nil {
		return ports.CheckoutResult{}, shared.ErrUnavailable
	}
	return set.Checkout.GetCheckoutSession(ctx, tenantID, sessionID)
}

func (r checkoutRouter) CancelCheckoutSession(ctx context.Context, tenantID, sessionID string) (ports.CheckoutResult, error) {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.Checkout == nil {
		return ports.CheckoutResult{}, shared.ErrUnavailable
	}
	return set.Checkout.CancelCheckoutSession(ctx, tenantID, sessionID)
}

// --- BoletoProvider ---

type boletoRouter struct{ reg *Registry }

var _ ports.BoletoProvider = boletoRouter{}

func (r boletoRouter) CreateBoleto(ctx context.Context, tenantID string, req ports.BoletoRequest) (ports.BoletoResult, error) {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.Boleto == nil {
		return ports.BoletoResult{}, shared.ErrUnavailable
	}
	return set.Boleto.CreateBoleto(ctx, tenantID, req)
}

func (r boletoRouter) GetBoleto(ctx context.Context, tenantID, boletoID string) (ports.BoletoResult, error) {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.Boleto == nil {
		return ports.BoletoResult{}, shared.ErrUnavailable
	}
	return set.Boleto.GetBoleto(ctx, tenantID, boletoID)
}

func (r boletoRouter) CancelBoleto(ctx context.Context, tenantID, boletoID string) (ports.BoletoResult, error) {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.Boleto == nil {
		return ports.BoletoResult{}, shared.ErrUnavailable
	}
	return set.Boleto.CancelBoleto(ctx, tenantID, boletoID)
}

func (r boletoRouter) UpdateBoleto(ctx context.Context, tenantID, boletoID string, req ports.BoletoRequest) (ports.BoletoResult, error) {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.Boleto == nil {
		return ports.BoletoResult{}, shared.ErrUnavailable
	}
	return set.Boleto.UpdateBoleto(ctx, tenantID, boletoID, req)
}

// --- DDAProvider ---

type ddaRouter struct{ reg *Registry }

var _ ports.DDAProvider = ddaRouter{}

func (r ddaRouter) ListOpenBoletos(ctx context.Context, tenantID string) ([]ports.DDABoleto, error) {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.DDA == nil {
		return nil, shared.ErrUnavailable
	}
	return set.DDA.ListOpenBoletos(ctx, tenantID)
}

func (r ddaRouter) CreatePaymentGroup(ctx context.Context, tenantID string, req ports.DDAGroupRequest) (ports.DDAGroup, error) {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.DDA == nil {
		return ports.DDAGroup{}, shared.ErrUnavailable
	}
	return set.DDA.CreatePaymentGroup(ctx, tenantID, req)
}

func (r ddaRouter) GetPaymentGroup(ctx context.Context, tenantID, groupID string) (ports.DDAGroup, error) {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.DDA == nil {
		return ports.DDAGroup{}, shared.ErrUnavailable
	}
	return set.DDA.GetPaymentGroup(ctx, tenantID, groupID)
}

func (r ddaRouter) RemovePaymentGroupItems(ctx context.Context, tenantID, groupID string, itemIDs []string) error {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.DDA == nil {
		return shared.ErrUnavailable
	}
	return set.DDA.RemovePaymentGroupItems(ctx, tenantID, groupID, itemIDs)
}

func (r ddaRouter) RemovePaymentGroupItem(ctx context.Context, tenantID, groupID, itemID string) error {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.DDA == nil {
		return shared.ErrUnavailable
	}
	return set.DDA.RemovePaymentGroupItem(ctx, tenantID, groupID, itemID)
}

func (r ddaRouter) SubmitPaymentGroup(ctx context.Context, tenantID, groupID, idemKey string) error {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.DDA == nil {
		return shared.ErrUnavailable
	}
	return set.DDA.SubmitPaymentGroup(ctx, tenantID, groupID, idemKey)
}

// --- StatementProvider ---

type statementRouter struct{ reg *Registry }

var _ ports.StatementProvider = statementRouter{}

func (r statementRouter) GetStatement(ctx context.Context, tenantID string, filter ports.StatementFilter) (ports.Statement, error) {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.Statement == nil {
		return ports.Statement{}, shared.ErrUnavailable
	}
	return set.Statement.GetStatement(ctx, tenantID, filter)
}

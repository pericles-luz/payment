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

	// Superfícies do roteiro v3.0.
	PixChargeReviser    ports.PixChargeReviser
	PixDueChargeReviser ports.PixDueChargeReviser
	PixDueChargeLister  ports.PixDueChargeLister
	PixLocation         ports.PixLocationProvider
	PixReceived         ports.PixReceivedProvider
	PixDueChargeBatch   ports.PixDueChargeBatchProvider
	AcquirerStatement   ports.AcquirerStatementProvider
	PlainBoleto         ports.PlainBoletoProvider
	BoletoLister        ports.BoletoLister
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

		PixChargeReviser:    pixChargeReviserRouter{reg},
		PixDueChargeReviser: pixDueChargeReviserRouter{reg},
		PixDueChargeLister:  pixDueChargeListerRouter{reg},
		PixLocation:         pixLocationRouter{reg},
		PixReceived:         pixReceivedRouter{reg},
		PixDueChargeBatch:   pixDueChargeBatchRouter{reg},
		AcquirerStatement:   acquirerStatementRouter{reg},
		PlainBoleto:         plainBoletoRouter{reg},
		BoletoLister:        boletoListerRouter{reg},
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

func (r boletoRouter) GetBoletoByBankRef(ctx context.Context, tenantID, bankRef string) (ports.BoletoResult, error) {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.Boleto == nil {
		return ports.BoletoResult{}, shared.ErrUnavailable
	}
	return set.Boleto.GetBoletoByBankRef(ctx, tenantID, bankRef)
}

func (r boletoRouter) GetBoletoPDF(ctx context.Context, tenantID, boletoID string) (ports.BoletoDocument, error) {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.Boleto == nil {
		return ports.BoletoDocument{}, shared.ErrUnavailable
	}
	return set.Boleto.GetBoletoPDF(ctx, tenantID, boletoID)
}

func (r boletoRouter) UpdateBoleto(ctx context.Context, tenantID, boletoID string, patch ports.BoletoPatch) (ports.BoletoResult, error) {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.Boleto == nil {
		return ports.BoletoResult{}, shared.ErrUnavailable
	}
	return set.Boleto.UpdateBoleto(ctx, tenantID, boletoID, patch)
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

func (r ddaRouter) SubmitPaymentGroup(ctx context.Context, tenantID, groupID, uploaderName, idemKey string) error {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.DDA == nil {
		return shared.ErrUnavailable
	}
	return set.DDA.SubmitPaymentGroup(ctx, tenantID, groupID, uploaderName, idemKey)
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

// --- Superfícies acrescentadas com o roteiro v3.0 --------------------------------
//
// Mesmo contrato dos routers acima: resolvem o banco do contexto e falham FECHADO
// (shared.ErrUnavailable) quando o banco resolvido não fala aquela superfície. Nunca
// caem para outro banco — rotear a cobrança de uma empresa para o banco errado seria
// pior do que não atender.

// --- PixChargeReviser ---

type pixChargeReviserRouter struct{ reg *Registry }

var _ ports.PixChargeReviser = pixChargeReviserRouter{}

func (r pixChargeReviserRouter) CreateImmediateChargeAutoTxID(ctx context.Context, tenantID string, req ports.ChargeRequest, expiresIn time.Duration) (ports.PixChargeResult, error) {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.PixChargeReviser == nil {
		return ports.PixChargeResult{}, shared.ErrUnavailable
	}
	return set.PixChargeReviser.CreateImmediateChargeAutoTxID(ctx, tenantID, req, expiresIn)
}

func (r pixChargeReviserRouter) ReviseImmediateCharge(ctx context.Context, tenantID, txID string, req ports.ChargeRequest, expiresIn time.Duration) (ports.PixChargeResult, error) {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.PixChargeReviser == nil {
		return ports.PixChargeResult{}, shared.ErrUnavailable
	}
	return set.PixChargeReviser.ReviseImmediateCharge(ctx, tenantID, txID, req, expiresIn)
}

// --- PixDueChargeReviser / PixDueChargeLister ---

type pixDueChargeReviserRouter struct{ reg *Registry }

var _ ports.PixDueChargeReviser = pixDueChargeReviserRouter{}

func (r pixDueChargeReviserRouter) ReviseDueCharge(ctx context.Context, tenantID, txID string, req ports.PixDueChargeRequest) (ports.PixDueChargeResult, error) {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.PixDueChargeReviser == nil {
		return ports.PixDueChargeResult{}, shared.ErrUnavailable
	}
	return set.PixDueChargeReviser.ReviseDueCharge(ctx, tenantID, txID, req)
}

type pixDueChargeListerRouter struct{ reg *Registry }

var _ ports.PixDueChargeLister = pixDueChargeListerRouter{}

func (r pixDueChargeListerRouter) ListDueCharges(ctx context.Context, tenantID string, filter ports.PixListFilter) (ports.PixDueChargeList, error) {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.PixDueChargeLister == nil {
		return ports.PixDueChargeList{}, shared.ErrUnavailable
	}
	return set.PixDueChargeLister.ListDueCharges(ctx, tenantID, filter)
}

// --- PixLocationProvider ---

type pixLocationRouter struct{ reg *Registry }

var _ ports.PixLocationProvider = pixLocationRouter{}

func (r pixLocationRouter) CreateLocation(ctx context.Context, tenantID, tipoCob string) (ports.PixLocation, error) {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.PixLocation == nil {
		return ports.PixLocation{}, shared.ErrUnavailable
	}
	return set.PixLocation.CreateLocation(ctx, tenantID, tipoCob)
}

func (r pixLocationRouter) ListLocations(ctx context.Context, tenantID string, filter ports.PixLocationFilter) (ports.PixLocationList, error) {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.PixLocation == nil {
		return ports.PixLocationList{}, shared.ErrUnavailable
	}
	return set.PixLocation.ListLocations(ctx, tenantID, filter)
}

func (r pixLocationRouter) GetLocation(ctx context.Context, tenantID string, id int64) (ports.PixLocation, error) {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.PixLocation == nil {
		return ports.PixLocation{}, shared.ErrUnavailable
	}
	return set.PixLocation.GetLocation(ctx, tenantID, id)
}

func (r pixLocationRouter) UnlinkLocationTxID(ctx context.Context, tenantID string, id int64) (ports.PixLocation, error) {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.PixLocation == nil {
		return ports.PixLocation{}, shared.ErrUnavailable
	}
	return set.PixLocation.UnlinkLocationTxID(ctx, tenantID, id)
}

// --- PixReceivedProvider ---

type pixReceivedRouter struct{ reg *Registry }

var _ ports.PixReceivedProvider = pixReceivedRouter{}

func (r pixReceivedRouter) GetReceivedPix(ctx context.Context, tenantID, endToEndID string) (ports.ReceivedPix, error) {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.PixReceived == nil {
		return ports.ReceivedPix{}, shared.ErrUnavailable
	}
	return set.PixReceived.GetReceivedPix(ctx, tenantID, endToEndID)
}

func (r pixReceivedRouter) ListReceivedPix(ctx context.Context, tenantID string, filter ports.ReceivedPixFilter) (ports.ReceivedPixList, error) {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.PixReceived == nil {
		return ports.ReceivedPixList{}, shared.ErrUnavailable
	}
	return set.PixReceived.ListReceivedPix(ctx, tenantID, filter)
}

func (r pixReceivedRouter) RequestRefund(ctx context.Context, tenantID, endToEndID, refundID string, req ports.PixRefundRequest) (ports.PixRefund, error) {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.PixReceived == nil {
		return ports.PixRefund{}, shared.ErrUnavailable
	}
	return set.PixReceived.RequestRefund(ctx, tenantID, endToEndID, refundID, req)
}

func (r pixReceivedRouter) GetRefund(ctx context.Context, tenantID, endToEndID, refundID string) (ports.PixRefund, error) {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.PixReceived == nil {
		return ports.PixRefund{}, shared.ErrUnavailable
	}
	return set.PixReceived.GetRefund(ctx, tenantID, endToEndID, refundID)
}

// --- PixDueChargeBatchProvider ---

type pixDueChargeBatchRouter struct{ reg *Registry }

var _ ports.PixDueChargeBatchProvider = pixDueChargeBatchRouter{}

func (r pixDueChargeBatchRouter) CreateBatch(ctx context.Context, tenantID, batchID, description string, charges []ports.PixDueChargeRequest) error {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.PixDueChargeBatch == nil {
		return shared.ErrUnavailable
	}
	return set.PixDueChargeBatch.CreateBatch(ctx, tenantID, batchID, description, charges)
}

func (r pixDueChargeBatchRouter) ReviseBatch(ctx context.Context, tenantID, batchID, description string, charges []ports.PixDueChargeRequest) error {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.PixDueChargeBatch == nil {
		return shared.ErrUnavailable
	}
	return set.PixDueChargeBatch.ReviseBatch(ctx, tenantID, batchID, description, charges)
}

func (r pixDueChargeBatchRouter) GetBatch(ctx context.Context, tenantID, batchID string) (ports.PixDueChargeBatch, error) {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.PixDueChargeBatch == nil {
		return ports.PixDueChargeBatch{}, shared.ErrUnavailable
	}
	return set.PixDueChargeBatch.GetBatch(ctx, tenantID, batchID)
}

func (r pixDueChargeBatchRouter) ListBatches(ctx context.Context, tenantID string, filter ports.PixDueChargeBatchFilter) (ports.PixDueChargeBatchList, error) {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.PixDueChargeBatch == nil {
		return ports.PixDueChargeBatchList{}, shared.ErrUnavailable
	}
	return set.PixDueChargeBatch.ListBatches(ctx, tenantID, filter)
}

// --- AcquirerStatementProvider ---

type acquirerStatementRouter struct{ reg *Registry }

var _ ports.AcquirerStatementProvider = acquirerStatementRouter{}

func (r acquirerStatementRouter) ListReceivables(ctx context.Context, tenantID string, filter ports.AcquirerStatementFilter) (ports.ReceivableList, error) {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.AcquirerStatement == nil {
		return ports.ReceivableList{}, shared.ErrUnavailable
	}
	return set.AcquirerStatement.ListReceivables(ctx, tenantID, filter)
}

func (r acquirerStatementRouter) ListCardTransactions(ctx context.Context, tenantID string, filter ports.AcquirerStatementFilter) (ports.CardTransactionList, error) {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.AcquirerStatement == nil {
		return ports.CardTransactionList{}, shared.ErrUnavailable
	}
	return set.AcquirerStatement.ListCardTransactions(ctx, tenantID, filter)
}

// --- PlainBoletoProvider ---

type plainBoletoRouter struct{ reg *Registry }

var _ ports.PlainBoletoProvider = plainBoletoRouter{}

func (r plainBoletoRouter) CreatePlainBoleto(ctx context.Context, tenantID string, req ports.BoletoRequest) (ports.BoletoResult, error) {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.PlainBoleto == nil {
		return ports.BoletoResult{}, shared.ErrUnavailable
	}
	return set.PlainBoleto.CreatePlainBoleto(ctx, tenantID, req)
}

func (r plainBoletoRouter) GetPlainBoleto(ctx context.Context, tenantID, slipID string) (ports.BoletoResult, error) {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.PlainBoleto == nil {
		return ports.BoletoResult{}, shared.ErrUnavailable
	}
	return set.PlainBoleto.GetPlainBoleto(ctx, tenantID, slipID)
}

func (r plainBoletoRouter) UpdatePlainBoleto(ctx context.Context, tenantID, slipID string, patch ports.BoletoPatch) (ports.BoletoResult, error) {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.PlainBoleto == nil {
		return ports.BoletoResult{}, shared.ErrUnavailable
	}
	return set.PlainBoleto.UpdatePlainBoleto(ctx, tenantID, slipID, patch)
}

func (r plainBoletoRouter) CancelPlainBoleto(ctx context.Context, tenantID, slipID string) error {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.PlainBoleto == nil {
		return shared.ErrUnavailable
	}
	return set.PlainBoleto.CancelPlainBoleto(ctx, tenantID, slipID)
}

func (r plainBoletoRouter) GetPlainBoletoPDF(ctx context.Context, tenantID, slipID string) (ports.BoletoDocument, error) {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.PlainBoleto == nil {
		return ports.BoletoDocument{}, shared.ErrUnavailable
	}
	return set.PlainBoleto.GetPlainBoletoPDF(ctx, tenantID, slipID)
}

// --- BoletoLister ---

type boletoListerRouter struct{ reg *Registry }

var _ ports.BoletoLister = boletoListerRouter{}

func (r boletoListerRouter) ListBoletos(ctx context.Context, tenantID string, filter ports.BoletoListFilter) (ports.BoletoList, error) {
	set, ok := r.reg.resolve(ctx)
	if !ok || set.BoletoLister == nil {
		return ports.BoletoList{}, shared.ErrUnavailable
	}
	return set.BoletoLister.ListBoletos(ctx, tenantID, filter)
}

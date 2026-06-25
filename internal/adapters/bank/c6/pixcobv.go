package c6

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// PIX cobrança-com-vencimento (cobv) support for the C6 adapter (roteiro 7.5–7.7).
//
// The lifecycle mirrors the immediate charge: CreateDueCharge PUTs an idempotent
// charge keyed by a txid derived from the idempotency anchor and gets back the QR
// material; GetDueCharge reconciles the authoritative status so settlement never
// trusts a raw webhook (reconcile-before-settle, threat W3); UpdateDueCharge amends
// the registered parameters. All cobv endpoints live here so the use-cases never
// speak HTTP/JSON or know the PSP wire shape (Hexagonal).
//
// The wire shape is the real BACEN cobrança-com-vencimento contract the C6 sandbox
// exposes at /v2/pix/cobv/{txid} (SIN-65856 live-discovery, SIN-65860): the schedule
// is calendario.dataDeVencimento (yyyy-MM-dd) + validadeAposVencimento (days); the
// money is valor.original with optional valor.multa/juros/desconto rate blocks; the
// recebedor key is chave; the payer is the devedor block (shared with the immediate
// charge). The fine/interest/discount RATES are transported as BACEN percent strings
// (or a fixed amount for a value-form discount); the amount owed at any instant is
// computed by the pixcobv domain, never here.

const (
	// pixCobvPath is the BACEN PIX v2 cobrança-com-vencimento collection path the C6
	// sandbox exposes (SIN-65856 live-discovery): PUT/GET /v2/pix/cobv/{txid}. It
	// replaced the placeholder /v1/pix/cobv that 404'd against the real PSP.
	pixCobvPath = "/v2/pix/cobv"

	// cobvDateLayout is the BACEN due-date format (calendario.dataDeVencimento): a
	// plain calendar date with no time/zone component.
	cobvDateLayout = "2006-01-02"

	// BACEN valor sub-component "modalidade" codes. multa and juros are transmitted
	// as percentual rates; a discount is percentual (DiscountBps) or a fixed value
	// (DiscountFixedCents), both "por antecipação" (no fixed-date schedule, which the
	// port does not model).
	cobvMultaPercentual         = 2 // multa: percentual sobre o valor
	cobvJurosPercentualAoMes    = 3 // juros: percentual ao mês, dias corridos
	cobvDescontoPercentualAntec = 5 // desconto: percentual por antecipação, dia corrido
	cobvDescontoValorAntec      = 3 // desconto: valor fixo por antecipação, dia corrido
)

// compile-time assertion that Provider satisfies the cobv port.
var _ ports.PixDueChargeProvider = (*Provider)(nil)

// cobvCalendario is the BACEN cobv schedule: the due date (dataDeVencimento,
// yyyy-MM-dd) and the number of days after it the charge may still be paid
// (validadeAposVencimento). Criacao is the PSP-assigned creation instant echoed on
// reads; it is consumed only as an opaque echo.
type cobvCalendario struct {
	Criacao                string `json:"criacao,omitempty"`
	DataDeVencimento       string `json:"dataDeVencimento"`
	ValidadeAposVencimento int    `json:"validadeAposVencimento"`
}

// cobvRate is one BACEN valor sub-component (multa, juros or desconto). Modalidade
// selects the calculation form; exactly one of ValorPerc (a percent string for the
// percentual modalidades) or Valor (a BACEN decimal amount for the fixed-value
// modalidades) carries the magnitude.
type cobvRate struct {
	Modalidade int    `json:"modalidade"`
	ValorPerc  string `json:"valorPerc,omitempty"`
	Valor      string `json:"valor,omitempty"`
}

// cobvValor is the BACEN cobv amount block: the original principal (a decimal
// string) plus the optional fine (multa), interest (juros) and early-payment
// discount (desconto) rate blocks. A block is omitted from the wire when the
// corresponding rate is zero.
type cobvValor struct {
	Original string    `json:"original"`
	Multa    *cobvRate `json:"multa,omitempty"`
	Juros    *cobvRate `json:"juros,omitempty"`
	Desconto *cobvRate `json:"desconto,omitempty"`
}

// cobvRequestBody is the BACEN cobrança-com-vencimento payload C6 expects on the
// PUT /v2/pix/cobv/{txid} create/amend. The txid is carried in the path, never the
// body. Devedor is omitted when no payer is supplied.
type cobvRequestBody struct {
	Calendario cobvCalendario `json:"calendario"`
	Devedor    *pixDevedor    `json:"devedor,omitempty"`
	Valor      cobvValor      `json:"valor"`
	Chave      string         `json:"chave,omitempty"`
}

// cobvResponseBody is the subset of C6's cobv representation we consume: the status,
// the scannable QR artifacts (pixCopiaECola + location), the registered schedule and
// rates echoed back for reconciliation (roteiro 7.6) and the received-payment list
// needed to reconcile a settlement. Like the immediate charge, the real C6 returns a
// top-level "location"; loc.location is read only as a fallback.
type cobvResponseBody struct {
	TxID          string         `json:"txid"`
	Status        string         `json:"status"`
	Calendario    cobvCalendario `json:"calendario"`
	Valor         cobvValor      `json:"valor"`
	Loc           pixLoc         `json:"loc"`
	Location      string         `json:"location"`
	PixCopiaECola string         `json:"pixCopiaECola"`
	// Pix is the list of received transactions, present once the charge is paid
	// (CONCLUIDA). Reconciliation sums each receipt's valor to learn how much was
	// actually received versus valor.original.
	Pix []pixReceipt `json:"pix"`
}

// cobvAnchor returns the request's idempotency anchor: the IdempotencyKey when
// present, else the TxID. Empty only when both are empty.
func cobvAnchor(req ports.PixDueChargeRequest) string {
	if req.IdempotencyKey != "" {
		return req.IdempotencyKey
	}
	return req.TxID
}

// cobvTxID derives a BACEN-valid (32 hex chars, inside the 26..35 [a-zA-Z0-9]
// range) txid from the request's idempotency anchor. Being deterministic, it makes
// the create PUT idempotent end-to-end: the same anchor always addresses the same
// charge.
func cobvTxID(anchor string) string {
	sum := sha256.Sum256([]byte(anchor))
	return hex.EncodeToString(sum[:])[:pixTxIDLen]
}

// percentFromBps renders a rate in basis points as the BACEN percent string used by
// valor.multa/juros/desconto.valorPerc: 100 bps == 1% so 250 -> "2.50". The 2-decimal
// scaling is identical to formatAmount's cents->decimal rendering, so it delegates.
func percentFromBps(bps int64) string {
	return formatAmount(bps)
}

// bpsFromPercent parses a BACEN percent string ("2.50") back into basis points
// (250). It is the inverse of percentFromBps. A malformed or empty rate yields zero:
// the rates are a registration echo, never the settlement money, so a reconcile read
// must not fail on a cosmetic field (the money is parsed strictly in toCobvResult).
func bpsFromPercent(s string) int64 {
	bps, err := parseAmountCents(s)
	if err != nil {
		return 0
	}
	return bps
}

// toCobvRequestBody maps the port request to the BACEN cobv transport JSON (shared
// by register and amend). The resolved creditor key (chave do recebedor) is supplied
// explicitly so the caller injects the tenant's configured key when the request
// omits one (ADR-0004 / SIN-65862). The fine and interest are transmitted as
// percentual modalidades; the discount is percentual (DiscountBps) or a fixed value
// (DiscountFixedCents) "por antecipação". The txid lives in the path, not the body.
func toCobvRequestBody(chave string, req ports.PixDueChargeRequest) cobvRequestBody {
	body := cobvRequestBody{
		Calendario: cobvCalendario{
			DataDeVencimento:       req.DueDate.UTC().Format(cobvDateLayout),
			ValidadeAposVencimento: req.ValidityDays,
		},
		Devedor: buildDevedorFields(req.DebtorTaxID, req.DebtorName),
		Valor:   cobvValor{Original: formatAmount(req.AmountCents)},
		Chave:   chave,
	}
	if req.FineBps > 0 {
		body.Valor.Multa = &cobvRate{Modalidade: cobvMultaPercentual, ValorPerc: percentFromBps(req.FineBps)}
	}
	if req.MonthlyInterestBps > 0 {
		body.Valor.Juros = &cobvRate{Modalidade: cobvJurosPercentualAoMes, ValorPerc: percentFromBps(req.MonthlyInterestBps)}
	}
	switch {
	case req.DiscountBps > 0:
		body.Valor.Desconto = &cobvRate{Modalidade: cobvDescontoPercentualAntec, ValorPerc: percentFromBps(req.DiscountBps)}
	case req.DiscountFixedCents > 0:
		body.Valor.Desconto = &cobvRate{Modalidade: cobvDescontoValorAntec, Valor: formatAmount(req.DiscountFixedCents)}
	}
	return body
}

// cobvLocation prefers the top-level "location" the real C6 returns, falling back to
// the BACEN loc.location object (mirrors the immediate charge's pixLocation).
func cobvLocation(b cobvResponseBody) string {
	if b.Location != "" {
		return b.Location
	}
	return b.Loc.Location
}

// parseCobvDate parses a BACEN due date (yyyy-MM-dd) into a time. An absent or
// malformed date yields the zero time (the due date is reconciliation context, not
// settlement money, so a cosmetic parse failure must not fail the read).
func parseCobvDate(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(cobvDateLayout, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// rateBps reads a percentual rate block (multa/juros) back into basis points; a nil
// block yields zero.
func rateBps(r *cobvRate) int64 {
	if r == nil {
		return 0
	}
	return bpsFromPercent(r.ValorPerc)
}

// descontoFixedCents reads a fixed-value discount block back into cents; a nil or
// percentual block yields zero (the percentual form is read via rateBps instead).
func descontoFixedCents(r *cobvRate) int64 {
	if r == nil || r.Valor == "" {
		return 0
	}
	cents, err := parseAmountCents(r.Valor)
	if err != nil {
		return 0
	}
	return cents
}

// toCobvResult maps a parsed C6 cobv representation to the port result. The money is
// reconciled fail-secure (like the immediate charge): valor.original is the expected
// amount and the sum of the pix[] receipts is what was received; a present-but-
// malformed money field maps to ErrUnavailable rather than reconciling to zero, while
// the registered rates/schedule are best-effort echoes that never fail the read.
func toCobvResult(b cobvResponseBody, op string) (ports.PixDueChargeResult, error) {
	expected, err := parseAmountCents(b.Valor.Original)
	if err != nil {
		return ports.PixDueChargeResult{}, &Error{Op: op, sentinel: shared.ErrUnavailable}
	}
	var received int64
	for _, r := range b.Pix {
		amount, err := parseAmountCents(r.Valor)
		if err != nil {
			return ports.PixDueChargeResult{}, &Error{Op: op, sentinel: shared.ErrUnavailable}
		}
		received += amount
	}
	return ports.PixDueChargeResult{
		TxID:                b.TxID,
		Status:              b.Status,
		QRCodePayload:       b.PixCopiaECola,
		QRCodeLocation:      cobvLocation(b),
		DueDate:             parseCobvDate(b.Calendario.DataDeVencimento),
		ValidityDays:        b.Calendario.ValidadeAposVencimento,
		FineBps:             rateBps(b.Valor.Multa),
		MonthlyInterestBps:  rateBps(b.Valor.Juros),
		DiscountBps:         rateBps(b.Valor.Desconto),
		DiscountFixedCents:  descontoFixedCents(b.Valor.Desconto),
		ExpectedAmountCents: expected,
		ReceivedAmountCents: received,
	}, nil
}

// CreateDueCharge registers a cobv charge at C6 via an idempotent PUT on
// /v2/pix/cobv/{txid}. The txid is derived deterministically from the idempotency
// anchor so a re-submit targets the same resource and the PSP returns the existing
// charge rather than creating a duplicate. The anchor is additionally forwarded as
// the Idempotency-Key header (defense-in-depth). The bearer token is attached per
// tenant. The chave do recebedor is resolved per tenant (configured key injected
// when the request omits one — ADR-0004). Complete mediation at the money seam: an
// empty anchor or a non-positive amount is refused at the boundary (no domain guard
// upstream guarantees it).
func (p *Provider) CreateDueCharge(ctx context.Context, tenantID string, req ports.PixDueChargeRequest) (ports.PixDueChargeResult, error) {
	anchor := cobvAnchor(req)
	if anchor == "" || req.AmountCents <= 0 {
		return ports.PixDueChargeResult{}, &Error{Op: "create_cobv", sentinel: shared.ErrValidation}
	}
	txid := cobvTxID(anchor)

	chave, err := p.resolveCreditorKey(ctx, tenantID, req.CreditorKey)
	if err != nil {
		return ports.PixDueChargeResult{}, err
	}

	payload, err := json.Marshal(toCobvRequestBody(chave, req))
	if err != nil {
		return ports.PixDueChargeResult{}, &Error{Op: "create_cobv", sentinel: shared.ErrValidation}
	}

	endpoint := p.baseURL + pixCobvPath + "/" + url.PathEscape(txid)
	httpReq, err := p.authedJSONRequest(ctx, tenantID, "create_cobv", http.MethodPut, endpoint, payload, anchor)
	if err != nil {
		return ports.PixDueChargeResult{}, err
	}

	var out cobvResponseBody
	if err := p.do(httpReq, "create_cobv", &out); err != nil {
		return ports.PixDueChargeResult{}, err
	}
	return toCobvResult(out, "create_cobv")
}

// GetDueCharge reconciles the authoritative state of a cobv charge from C6. This is
// the source of truth for settlement: a webhook may announce a payment, but the
// charge status is always read back here, never trusted from the raw event
// (reconcile-before-settle, threat W3). A 404 surfaces as shared.ErrNotFound; the
// read is tenant-scoped through the per-tenant OAuth2 bearer token.
func (p *Provider) GetDueCharge(ctx context.Context, tenantID, txID string) (ports.PixDueChargeResult, error) {
	endpoint := p.baseURL + pixCobvPath + "/" + url.PathEscape(txID)
	httpReq, err := p.authedJSONRequest(ctx, tenantID, "get_cobv", http.MethodGet, endpoint, nil, "")
	if err != nil {
		return ports.PixDueChargeResult{}, err
	}

	var out cobvResponseBody
	if err := p.do(httpReq, "get_cobv", &out); err != nil {
		return ports.PixDueChargeResult{}, err
	}
	return toCobvResult(out, "get_cobv")
}

// UpdateDueCharge amends a registered cobv's parameters at C6 (roteiro 7.7) via PUT
// on /v2/pix/cobv/{txid}. The caller's IdempotencyKey (falling back to the txid) is
// forwarded so a retried amendment is collapsed. The chave do recebedor is resolved
// per tenant (configured key injected when the request omits one — ADR-0004). A 404
// surfaces as shared.ErrNotFound; the operation is tenant-scoped through the
// per-tenant bearer.
func (p *Provider) UpdateDueCharge(ctx context.Context, tenantID, txID string, req ports.PixDueChargeRequest) (ports.PixDueChargeResult, error) {
	if req.AmountCents <= 0 {
		return ports.PixDueChargeResult{}, &Error{Op: "update_cobv", sentinel: shared.ErrValidation}
	}

	chave, err := p.resolveCreditorKey(ctx, tenantID, req.CreditorKey)
	if err != nil {
		return ports.PixDueChargeResult{}, err
	}

	payload, err := json.Marshal(toCobvRequestBody(chave, req))
	if err != nil {
		return ports.PixDueChargeResult{}, &Error{Op: "update_cobv", sentinel: shared.ErrValidation}
	}

	idem := req.IdempotencyKey
	if idem == "" {
		idem = txID
	}
	endpoint := p.baseURL + pixCobvPath + "/" + url.PathEscape(txID)
	httpReq, err := p.authedJSONRequest(ctx, tenantID, "update_cobv", http.MethodPut, endpoint, payload, idem)
	if err != nil {
		return ports.PixDueChargeResult{}, err
	}

	var out cobvResponseBody
	if err := p.do(httpReq, "update_cobv", &out); err != nil {
		return ports.PixDueChargeResult{}, err
	}
	return toCobvResult(out, "update_cobv")
}

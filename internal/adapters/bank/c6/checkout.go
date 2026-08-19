package c6

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// compile-time assertion that Provider satisfies the checkout port.
var _ ports.CheckoutProvider = (*Provider)(nil)

// checkoutPath is the real C6 checkout collection (OpenAPI "API de Checkout" v1.1.4,
// POST /v1/checkouts/). The trailing slash is appended at call sites to match the
// spec path "/". GET /{id} reconciles and PUT /{id}/cancel cancels. The legacy
// placeholder /checkout/sessions never existed on the real sandbox (it 404'd —
// SIN-65804/SIN-65883).
const checkoutPath = "/v1/checkouts"

// cardBody is the C6 payment.card object (schema: card). For the hosted checkout
// flow the payer types the card on C6's page, so card_info (card_hash/token) is
// never sent at creation — only the routing fields are.
//
// installments carries the ceiling the caller asked for (it was hardcoded to 1 until
// SIN-65726, which meant no buyer could ever split a payment), and interest_type says
// who pays for splitting it.
type cardBody struct {
	Type         string `json:"type"`                   // DEBIT | CREDIT
	Installments int    `json:"installments"`           // 1..12 — validado por NÓS, não pelo C6
	Authenticate string `json:"authenticate,omitempty"` // REQUIRED | OPTIONAL | NOT_REQUIRED
	// InterestType decide QUEM paga os juros do parcelamento: BY_ISSUER (o
	// comprador, via administradora) ou BY_SELLER (a loja absorve).
	//
	// Enviar isto não é opcional na prática. Omitir o campo faz o C6 assumir
	// BY_SELLER — observado numa captura real de produção —, ou seja, NÃO mandar é
	// escolher que o lojista pague, por omissão. É a pior forma de tomar uma decisão
	// de dinheiro. BY_ISSUER foi verificado no fio em 2026-08-19: a criação
	// respondeu 201.
	InterestType string `json:"interest_type,omitempty"`
}

// paymentBody is the C6 payment envelope (schema: payment). For a card checkout it
// carries the card object (a pix-only checkout would carry pix instead).
type paymentBody struct {
	Card *cardBody `json:"card,omitempty"`
}

// checkoutRequestBody is the JSON sent to C6 to open a hosted checkout (schema:
// checkout). The real contract is a single decimal amount in REAIS (brlDecimal,
// never cents) plus the payment method — there is no items[] array; our domain
// line items are summed into amount. external_reference_id/payer are optional (C6
// collects the payer on its page when omitted).
type checkoutRequestBody struct {
	Amount             brlDecimal  `json:"amount"`
	Payment            paymentBody `json:"payment"`
	ExpirationDateTime string      `json:"expiration_date_time,omitempty"`
}

// checkoutResponseBody is the subset of C6's checkout representation we consume. The
// create (201) response is {id, url}; the reconcile (GET 200) response is the full
// `checkout` schema — id, status, amount (decimal reais) and url. captured_amount is
// documented "EM BREVE" (not yet returned), so the adapter cannot reconcile by
// captured amount — see toCheckoutResult.
type checkoutResponseBody struct {
	ID     string     `json:"id"`
	Status string     `json:"status"`
	URL    string     `json:"url"`
	Amount brlDecimal `json:"amount"`
	// Payment carries the card settlement detail present on a reconcile (GET) read of a
	// paid session. Live-verified against the real C6 (SIN-69580): a PAID checkout
	// answers with payment.card.{installments,message,return_code,authorization_code}.
	// `amount` there is decimal REAIS on the wire; brlDecimal parses it to integer
	// cents by string, never through a float, so 5.01 is exactly 501.
	Payment struct {
		Card struct {
			Installments int    `json:"installments"`
			Message      string `json:"message"`
			ReturnCode   string `json:"return_code"`
		} `json:"card"`
	} `json:"payment"`
}

// CreateCheckoutSession opens a hosted checkout at C6 (POST /v1/checkouts/) and
// returns the hosted URL the caller sends the payer to. The domain session's line
// items are summed into the single `amount` C6 expects (decimal reais via
// brlDecimal); the permitted card method maps to payment.card.type and the step-up
// flag to payment.card.authenticate. The caller's IdempotencyKey (falling back to
// the SessionID) collapses retried openings; the per-tenant OAuth2 bearer is attached
// by authedJSONRequest.
func (p *Provider) CreateCheckoutSession(ctx context.Context, tenantID string, req ports.CheckoutRequest) (ports.CheckoutResult, error) {
	cardType := strings.ToUpper(strings.TrimSpace(req.CardType))
	if cardType != "CREDIT" && cardType != "DEBIT" {
		return ports.CheckoutResult{}, &Error{Op: "create_checkout", sentinel: shared.ErrValidation}
	}

	amounts := make([]int64, len(req.Items))
	for i, it := range req.Items {
		amounts[i] = it.AmountCents
	}
	sum, err := shared.SumCents(amounts...) // checked add — overflow fails closed (SIN-65706)
	if err != nil || sum <= 0 {
		return ports.CheckoutResult{}, &Error{Op: "create_checkout", sentinel: shared.ErrValidation}
	}

	authenticate := "NOT_REQUIRED"
	if req.RequireAuthentication {
		authenticate = "REQUIRED"
	}

	// A faixa e a regra do débito são NOSSAS. Sondado contra o C6 real em
	// 2026-08-19: uma criação com installments: 13 respondeu 201, e um cartão de
	// DÉBITO com 3 parcelas também. O PSP não valida nenhuma das duas, então um
	// valor fora da faixa passaria pela criação e só se manifestaria quando um
	// comprador de verdade fosse pagar — o pior lugar possível para descobrir.
	// Falha fechada aqui, mesmo o app já tendo validado: defesa em profundidade.
	installments := req.MaxInstallments
	if installments <= 0 {
		installments = 1
	}
	if installments > maxCardInstallments || (cardType == "DEBIT" && installments > 1) {
		return ports.CheckoutResult{}, &Error{Op: "create_checkout", sentinel: shared.ErrValidation}
	}

	body := checkoutRequestBody{
		Amount: brlDecimal(sum),
		Payment: paymentBody{Card: &cardBody{
			Type:         cardType,
			Installments: installments,
			Authenticate: authenticate,
			InterestType: cardInterestByIssuer,
		}},
	}
	if !req.ExpiresAt.IsZero() {
		body.ExpirationDateTime = req.ExpiresAt.UTC().Format(time.RFC3339)
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return ports.CheckoutResult{}, &Error{Op: "create_checkout", sentinel: shared.ErrValidation}
	}

	idem := req.IdempotencyKey
	if idem == "" {
		idem = req.SessionID
	}
	httpReq, err := p.authedJSONRequest(ctx, tenantID, "create_checkout", http.MethodPost, p.baseURL+checkoutPath+"/", payload, idem)
	if err != nil {
		return ports.CheckoutResult{}, err
	}

	var out checkoutResponseBody
	if err := p.do(httpReq, "create_checkout", &out); err != nil {
		return ports.CheckoutResult{}, err
	}
	// Defense-in-depth (open-redirect): the caller redirects the payer to this URL.
	// A tampered/compromised PSP could return a well-formed non-https / relative /
	// opaque target; refuse anything that is not an absolute https URL rather than
	// forward it. The raw value never leaks through the error.
	if err := validateRedirectURL(out.URL); err != nil {
		return ports.CheckoutResult{}, err
	}
	status := out.Status
	if status == "" {
		status = "CREATED" // create returns {id,url}; a fresh checkout is CREATED (spec)
	}
	return ports.CheckoutResult{
		SessionID:       out.ID,
		Status:          status,
		RedirectURL:     out.URL,
		MaxInstallments: installments,
		// AmountCents is the authorized total we sent (C6's create response does not
		// echo it); reflecting it keeps the result self-describing for the caller.
		AmountCents: sum,
		// Echo the permitted method back so the caller's response is self-describing
		// (C6's create response does not return them).
		CardType:              req.CardType,
		RequireAuthentication: req.RequireAuthentication,
	}, nil
}

// GetCheckoutSession reconciles the authoritative state of a checkout from C6 via
// GET /v1/checkouts/{id}. It is the source of truth for settlement — never trust a
// raw webhook (threat W3). A 404 surfaces as shared.ErrNotFound; the read is
// tenant-scoped through the per-tenant bearer. A redirect URL, when present, is
// validated (open-redirect defense).
func (p *Provider) GetCheckoutSession(ctx context.Context, tenantID, sessionID string) (ports.CheckoutResult, error) {
	endpoint := p.baseURL + checkoutPath + "/" + url.PathEscape(sessionID)
	httpReq, err := p.authedJSONRequest(ctx, tenantID, "get_checkout", http.MethodGet, endpoint, nil, "")
	if err != nil {
		return ports.CheckoutResult{}, err
	}
	var out checkoutResponseBody
	if err := p.do(httpReq, "get_checkout", &out); err != nil {
		return ports.CheckoutResult{}, err
	}
	return toCheckoutResult(out, "get_checkout")
}

// CancelCheckoutSession cancels a checkout at C6 via PUT /v1/checkouts/{id}/cancel.
// C6 answers 204 No Content (no body), so the cancelled state is synthesized. Cancel
// is idempotent at C6 (an unpaid checkout is aborted, a paid one is refunded when the
// method allows). A 404 surfaces as shared.ErrNotFound (no cross-tenant oracle).
func (p *Provider) CancelCheckoutSession(ctx context.Context, tenantID, sessionID string) (ports.CheckoutResult, error) {
	endpoint := p.baseURL + checkoutPath + "/" + url.PathEscape(sessionID) + "/cancel"
	httpReq, err := p.authedJSONRequest(ctx, tenantID, "cancel_checkout", http.MethodPut, endpoint, nil, "")
	if err != nil {
		return ports.CheckoutResult{}, err
	}
	if err := p.doNoContent(httpReq, "cancel_checkout"); err != nil {
		return ports.CheckoutResult{}, err
	}
	return ports.CheckoutResult{SessionID: sessionID, Status: "CANCELLED"}, nil
}

// toCheckoutResult maps a reconcile (GET) response into the port result. The redirect
// URL is validated only when present (a cancelled/paid checkout need not carry one);
// an untrusted non-https/relative target fails closed rather than being forwarded.
//
// SETTLEMENT ON status == PAID (SIN-65726, decided SIN-69580).
//
// C6 does not return a captured amount. That was verified against the live gateway, not
// inferred: a GET on a paid session answers with id/status/amount/payment_date_time and
// a payment.card block, and no captured_amount anywhere — the field documented as
// "EM BREVE" has no representation in this contract, and neither does a partial capture,
// so there is no field a lesser captured value could even arrive in.
//
// Holding ReceivedAmountCents at zero therefore did not implement the W3 amount gate for
// checkouts; it implemented "no checkout ever settles", indefinitely, waiting on a field
// that may never come in this shape. A PAID session with a successful capture is treated
// as captured for its authorized total: ReceivedAmountCents mirrors AmountCents so
// AmountReconciled() holds and the shared settlement core liquidates.
//
// The gate is deliberately narrow — status PAID alone is not enough. The capture must
// also be affirmed by the card block (return_code "00", the PSP's success code, e.g.
// alongside "Transacao capturada com sucesso"). Anything else leaves ReceivedAmountCents
// at zero and the charge unsettled, which keeps the divergence path as the fail-safe.
// Should C6 ever publish a real captured amount, this is the one place to read it.
func toCheckoutResult(out checkoutResponseBody, op string) (ports.CheckoutResult, error) {
	if out.URL != "" {
		if err := validateRedirectURL(out.URL); err != nil {
			return ports.CheckoutResult{}, &Error{Op: op, detail: "untrusted redirect url", sentinel: shared.ErrUnavailable}
		}
	}
	authorized := int64(out.Amount)
	var received int64
	if checkoutCaptured(out) {
		received = authorized
	}
	return ports.CheckoutResult{
		SessionID:           out.ID,
		Status:              out.Status,
		RedirectURL:         out.URL,
		AmountCents:         authorized,
		ReceivedAmountCents: received,
		Installments:        out.Payment.Card.Installments,
		Message:             out.Payment.Card.Message,
	}, nil
}

// validateRedirectURL rejects a checkout redirect target that is not an absolute
// https URL (empty/relative/opaque/non-https). It returns an *Error wrapping
// shared.ErrUnavailable — the upstream returned a 2xx the adapter cannot safely
// use — and never embeds the raw value, so a malicious URL cannot leak through an
// error or log.
func validateRedirectURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return &Error{Op: "create_checkout", detail: "untrusted redirect url", sentinel: shared.ErrUnavailable}
	}
	return nil
}

// checkoutStatusPaid is the C6 terminal status for a settled checkout session.
const checkoutStatusPaid = "PAID"

// checkoutReturnCodeApproved is the card network's success code on payment.card.
// Anything else (a decline, a pending capture) is not a settlement.
const checkoutReturnCodeApproved = "00"

// checkoutCaptured reports whether a reconcile read shows a session whose full amount
// was actually captured. Both signals must agree: the session status is PAID and the
// card authorisation returned the success code. Requiring the card block too means a
// status flipped without a matching capture does not liquidate money.
func checkoutCaptured(out checkoutResponseBody) bool {
	if !strings.EqualFold(strings.TrimSpace(out.Status), checkoutStatusPaid) {
		return false
	}
	return strings.TrimSpace(out.Payment.Card.ReturnCode) == checkoutReturnCodeApproved
}

// maxCardInstallments é o teto documentado do C6 para payment.card.installments.
// Repetido aqui, e não só no domínio, porque o PSP aceita valores acima dele.
const maxCardInstallments = 12

// cardInterestByIssuer põe os juros do parcelamento na conta do comprador, via
// administradora do cartão, em vez de a loja absorvê-los.
//
// É decisão de produto, tomada explicitamente: o default do C6 quando o campo é
// omitido é BY_SELLER, então deixar de mandar seria escolher pelo lojista sem ele
// saber. Se algum dia a política mudar, é aqui que ela muda.
const cardInterestByIssuer = "BY_ISSUER"

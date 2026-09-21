package c6

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// Received PIX and refunds (BACEN PIX v2 `/pix` and `/devolucao`, roteiro P_05) for
// the C6 adapter.
//
// # O que NÃO é modelado, e por quê
//
// O objeto `pagador` de um PIX recebido traz CPF/CNPJ e nome de quem pagou. Ele é
// deliberadamente ignorado aqui, como já era no `pixReceipt` da cobrança: é dado
// pessoal que nenhum fluxo daqui precisa, e o jeito de não vazá-lo em log, em erro ou
// numa resposta é não o carregar (ADR-0008). O que sobe é o `infoPagador` — a mensagem
// livre que o pagador digitou —, que é informação que ELE escolheu mandar.
//
// # Devolução é movimento de dinheiro
//
// `RequestRefund` é a única operação deste arquivo que move valor, e o id da devolução
// é do CHAMADOR, não do PSP. Isso é o que a torna idempotente: o par (e2eid, refundID)
// endereça sempre a mesma devolução, então um reenvio não devolve duas vezes. Um id
// aleatório por tentativa desfaz exatamente essa garantia.

const (
	// pixReceivedPath is the BACEN received-PIX collection under the PIX base.
	pixReceivedPath = "/v2/pix/pix"
	// pixRefundSegment is the refund sub-resource of a received PIX.
	pixRefundSegment = "/devolucao/"
)

// compile-time assertion that Provider satisfies the received-PIX port.
var _ ports.PixReceivedProvider = (*Provider)(nil)

// pixRefundRequestBody is the PUT body of a refund request. `valor` is required;
// natureza defaults to ORIGINAL at the PSP when omitted.
type pixRefundRequestBody struct {
	Valor     string `json:"valor"`
	Natureza  string `json:"natureza,omitempty"`
	Descricao string `json:"descricao,omitempty"`
}

// pixRefundResponseBody is a refund's representation.
type pixRefundResponseBody struct {
	ID        string `json:"id"`
	RtrID     string `json:"rtrId"`
	Valor     string `json:"valor"`
	Natureza  string `json:"natureza"`
	Descricao string `json:"descricao"`
	Status    string `json:"status"`
	Motivo    string `json:"motivo"`
	Horario   struct {
		Solicitacao string `json:"solicitacao"`
		Liquidacao  string `json:"liquidacao"`
	} `json:"horario"`
}

// pixReceivedResponseBody is a received PIX. `pagador` is absent on purpose — see the
// file comment.
type pixReceivedResponseBody struct {
	EndToEndID  string                  `json:"endToEndId"`
	TxID        string                  `json:"txid"`
	Valor       string                  `json:"valor"`
	Chave       string                  `json:"chave"`
	Horario     string                  `json:"horario"`
	InfoPagador string                  `json:"infoPagador"`
	Devolucoes  []pixRefundResponseBody `json:"devolucoes"`
}

// pixReceivedListResponseBody is the list envelope: pagination plus the `pix` array.
type pixReceivedListResponseBody struct {
	Parametros pixParametros             `json:"parametros"`
	Pix        []pixReceivedResponseBody `json:"pix"`
}

// parsePixInstant parses an optional RFC3339 instant, yielding the zero time when it
// is absent or malformed.
func parsePixInstant(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// toPixRefund maps a refund onto the port type. A malformed amount is an ERROR rather
// than zero: this is money leaving the account, and reading a corrupt value as zero
// would report a refund smaller than the one that happened.
func toPixRefund(b pixRefundResponseBody, op string) (ports.PixRefund, error) {
	amount, err := parseAmountCents(b.Valor)
	if err != nil {
		return ports.PixRefund{}, &Error{Op: op, sentinel: shared.ErrUnavailable}
	}
	return ports.PixRefund{
		ID:          b.ID,
		ReturnID:    b.RtrID,
		AmountCents: amount,
		Nature:      ports.PixRefundNature(b.Natureza),
		Description: b.Descricao,
		Status:      b.Status,
		Reason:      b.Motivo,
		RequestedAt: parsePixInstant(b.Horario.Solicitacao),
		SettledAt:   parsePixInstant(b.Horario.Liquidacao),
	}, nil
}

// toReceivedPix maps a received PIX onto the port type, with the same fail-secure
// money discipline as the charge mapping: a malformed amount is ErrUnavailable, never
// silently zero.
func toReceivedPix(b pixReceivedResponseBody, op string) (ports.ReceivedPix, error) {
	amount, err := parseAmountCents(b.Valor)
	if err != nil {
		return ports.ReceivedPix{}, &Error{Op: op, sentinel: shared.ErrUnavailable}
	}
	refunds := make([]ports.PixRefund, 0, len(b.Devolucoes))
	for _, d := range b.Devolucoes {
		r, err := toPixRefund(d, op)
		if err != nil {
			return ports.ReceivedPix{}, err
		}
		refunds = append(refunds, r)
	}
	return ports.ReceivedPix{
		EndToEndID:  b.EndToEndID,
		TxID:        b.TxID,
		AmountCents: amount,
		CreditorKey: b.Chave,
		ReceivedAt:  parsePixInstant(b.Horario),
		PayerInfo:   b.InfoPagador,
		Refunds:     refunds,
	}, nil
}

// GetReceivedPix reads one received PIX by its end-to-end id (roteiro P_05_01).
func (p *Provider) GetReceivedPix(ctx context.Context, tenantID, endToEndID string) (ports.ReceivedPix, error) {
	const op = "get_received_pix"
	endToEndID = strings.TrimSpace(endToEndID)
	if endToEndID == "" {
		return ports.ReceivedPix{}, &Error{Op: op, sentinel: shared.ErrValidation}
	}
	endpoint := p.baseURL + pixReceivedPath + "/" + url.PathEscape(endToEndID)
	httpReq, err := p.authedJSONRequest(ctx, tenantID, op, http.MethodGet, endpoint, nil, "")
	if err != nil {
		return ports.ReceivedPix{}, err
	}
	var out pixReceivedResponseBody
	if err := p.do(httpReq, op, &out); err != nil {
		return ports.ReceivedPix{}, err
	}
	return toReceivedPix(out, op)
}

// ListReceivedPix returns the PIX credited within the filter's window (roteiro
// P_05_02). The window bounds are mandatory.
//
// PayerTaxID is placed in `cpf` or `cnpj` BY LENGTH. The contract forbids sending both
// at once, so the caller never gets to pick the wrong one.
func (p *Provider) ListReceivedPix(ctx context.Context, tenantID string, filter ports.ReceivedPixFilter) (ports.ReceivedPixList, error) {
	const op = "list_received_pix"
	if filter.Start.IsZero() || filter.End.IsZero() {
		return ports.ReceivedPixList{}, &Error{Op: op, sentinel: shared.ErrValidation}
	}
	q := pixWindowQuery(filter.Start, filter.End, filter.Page, filter.PageSize)
	if txid := strings.TrimSpace(filter.TxID); txid != "" {
		q.Set("txid", txid)
	}
	if filter.TxIDPresent != nil {
		q.Set("txIdPresente", strconv.FormatBool(*filter.TxIDPresent))
	}
	if filter.RefundPresent != nil {
		q.Set("devolucaoPresente", strconv.FormatBool(*filter.RefundPresent))
	}
	if taxID := strings.TrimSpace(filter.PayerTaxID); taxID != "" {
		switch len(taxID) {
		case 11:
			q.Set("cpf", taxID)
		case 14:
			q.Set("cnpj", taxID)
		default:
			return ports.ReceivedPixList{}, &Error{Op: op, sentinel: shared.ErrValidation}
		}
	}

	httpReq, err := p.authedJSONRequest(ctx, tenantID, op, http.MethodGet, p.baseURL+pixReceivedPath+"?"+q.Encode(), nil, "")
	if err != nil {
		return ports.ReceivedPixList{}, err
	}
	var out pixReceivedListResponseBody
	if err := p.do(httpReq, op, &out); err != nil {
		return ports.ReceivedPixList{}, err
	}
	received := make([]ports.ReceivedPix, 0, len(out.Pix))
	for _, r := range out.Pix {
		mapped, err := toReceivedPix(r, op)
		if err != nil {
			return ports.ReceivedPixList{}, err
		}
		received = append(received, mapped)
	}
	return ports.ReceivedPixList{Received: received, PixPage: out.Parametros.toPixPage()}, nil
}

// RequestRefund asks for a refund of a received PIX (roteiro P_05_03). refundID is the
// caller's identifier and is what makes the operation idempotent — see the file
// comment. A non-positive amount is refused at the boundary: there is no such thing as
// a zero refund, and a negative one would be a payment.
func (p *Provider) RequestRefund(ctx context.Context, tenantID, endToEndID, refundID string, req ports.PixRefundRequest) (ports.PixRefund, error) {
	const op = "request_pix_refund"
	endToEndID = strings.TrimSpace(endToEndID)
	refundID = strings.TrimSpace(refundID)
	if endToEndID == "" || refundID == "" || req.AmountCents <= 0 {
		return ports.PixRefund{}, &Error{Op: op, sentinel: shared.ErrValidation}
	}
	payload, err := json.Marshal(pixRefundRequestBody{
		Valor:     formatAmount(req.AmountCents),
		Natureza:  string(req.Nature),
		Descricao: req.Description,
	})
	if err != nil {
		return ports.PixRefund{}, &Error{Op: op, sentinel: shared.ErrValidation}
	}
	endpoint := p.baseURL + pixReceivedPath + "/" + url.PathEscape(endToEndID) + pixRefundSegment + url.PathEscape(refundID)
	// The refund id already collapses retries at the PSP; forwarding it as the
	// Idempotency-Key too is defense in depth, not the primary guard.
	httpReq, err := p.authedJSONRequest(ctx, tenantID, op, http.MethodPut, endpoint, payload, refundID)
	if err != nil {
		return ports.PixRefund{}, err
	}
	var out pixRefundResponseBody
	if err := p.do(httpReq, op, &out); err != nil {
		return ports.PixRefund{}, err
	}
	return toPixRefund(out, op)
}

// GetRefund reconciles a refund's authoritative state (roteiro P_05_04). This is the
// source of truth for whether money actually left: a 201 from RequestRefund means the
// PSP accepted the request, and the status may still be EM_PROCESSAMENTO.
func (p *Provider) GetRefund(ctx context.Context, tenantID, endToEndID, refundID string) (ports.PixRefund, error) {
	const op = "get_pix_refund"
	endToEndID = strings.TrimSpace(endToEndID)
	refundID = strings.TrimSpace(refundID)
	if endToEndID == "" || refundID == "" {
		return ports.PixRefund{}, &Error{Op: op, sentinel: shared.ErrValidation}
	}
	endpoint := p.baseURL + pixReceivedPath + "/" + url.PathEscape(endToEndID) + pixRefundSegment + url.PathEscape(refundID)
	httpReq, err := p.authedJSONRequest(ctx, tenantID, op, http.MethodGet, endpoint, nil, "")
	if err != nil {
		return ports.PixRefund{}, err
	}
	var out pixRefundResponseBody
	if err := p.do(httpReq, op, &out); err != nil {
		return ports.PixRefund{}, err
	}
	return toPixRefund(out, op)
}

package c6

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// C6 Pay acquirer extract (`/v1/c6pay/statement`, roteiro grupo TR) for the C6
// adapter: the card transactions authorised and the receivables they settle into.
//
// # A chave do array não é a que a spec declara
//
// A OpenAPI publicada diz que a lista vem em `receivables` (e em `transactions`). O
// fio, medido em 02/09/2026 (docs/compliance/c6pay-recebiveis-notas.md), manda
// `content`:
//
//	{"content":[],"page":1,"last_page":0,"items":0}
//
// Quem implementar pela spec recebe lista vazia PARA SEMPRE, sem erro nenhum — é
// exatamente a forma do defeito da SIN-65856. Por isso as duas chaves são decodificadas
// e `content` ganha, com teste para as duas.
//
// # Escopo é outro produto
//
// Em produção esta superfície responde 403 `acess_denied` mesmo com um token que traz
// `statement.read`: o C6 Pay é produto separado, com habilitação própria. O 403 passa
// adiante como veio — é resposta de contratação, não defeito nosso.

const (
	// c6PayStatementPath is the C6 Pay extract collection.
	c6PayStatementPath = "/v1/c6pay/statement"
	// c6PayDateLayout is the extract's query date format.
	c6PayDateLayout = "2006-01-02"
	// c6PayMaxWindowDays is the widest window the acquirer accepts per request.
	c6PayMaxWindowDays = 60
)

// compile-time assertion that Provider satisfies the acquirer-statement port.
var _ ports.AcquirerStatementProvider = (*Provider)(nil)

// c6PayReceivable is one receivable on the wire. Money fields are JSON decimals in
// reais and land in cents through brlDecimal — the same no-float discipline as the
// boleto amounts.
type c6PayReceivable struct {
	LocalReference      string     `json:"local_reference"`
	AuthorizationCode   string     `json:"authorization_code"`
	AuthorizerReference string     `json:"authorizer_reference"`
	BrandName           string     `json:"brand_name"`
	ExpectedDate        string     `json:"expected_date"`
	ReceivableID        string     `json:"receivable_id"`
	InstallmentNumber   int        `json:"installment_number"`
	Installments        int        `json:"installments"`
	InterestType        string     `json:"interest_type"`
	GrossAmount         brlDecimal `json:"gross_amount"`
	Fee                 brlDecimal `json:"fee"`
	MDR                 brlDecimal `json:"mdr"`
	Discount            brlDecimal `json:"discount"`
	NetAmount           brlDecimal `json:"net_amount"`
	PaymentDate         string     `json:"payment_date"`
	PaymentType         string     `json:"payment_type"`
	TransactionDateTime string     `json:"transaction_date_time"`
	TransactionID       string     `json:"transaction_id"`
	Type                string     `json:"type"`
	Status              string     `json:"status"`
	Origin              string     `json:"origin"`
}

// c6PayTransaction is one authorisation on the wire. `card_number` and
// `card_holder_name` are present in the response and deliberately absent here — see
// the port comment.
type c6PayTransaction struct {
	Amount                      brlDecimal `json:"amount"`
	AuthorizationCode           string     `json:"authorization_code"`
	AuthorizerReference         string     `json:"authorizer_reference"`
	BrandName                   string     `json:"brand_name"`
	CardEntryMode               string     `json:"card_entry_mode"`
	CurrencyCode                string     `json:"currency_code"`
	DateTime                    string     `json:"date_time"`
	FraudAnalysisRecommendation string     `json:"fraud_analysis_recommendation"`
	ID                          string     `json:"id"`
	Installments                int        `json:"installments"`
	InterestType                string     `json:"interest_type"`
	LocalReference              string     `json:"local_reference"`
	Origin                      string     `json:"origin"`
	PaymentType                 string     `json:"payment_type"`
	Status                      string     `json:"status"`
	TerminalID                  string     `json:"terminal_id"`
}

// c6PayEnvelope is the paging envelope both extracts share. Content is what the wire
// really sends; Receivables and Transactions are the names the published spec uses and
// are read as a fallback so a future correction on their side does not break us.
type c6PayEnvelope struct {
	Page         int             `json:"page"`
	LastPage     int             `json:"last_page"`
	LastPageDash int             `json:"last-page"`
	Items        int             `json:"items"`
	Content      json.RawMessage `json:"content"`
	Receivables  json.RawMessage `json:"receivables"`
	Transactions json.RawMessage `json:"transactions"`
}

// rows picks the array the response actually carries. `content` wins; the spec's names
// are the fallback. A response with neither yields nil, which decodes to an empty list.
func (e c6PayEnvelope) rows(specKey json.RawMessage) json.RawMessage {
	if len(e.Content) > 0 && string(e.Content) != "null" {
		return e.Content
	}
	if len(specKey) > 0 && string(specKey) != "null" {
		return specKey
	}
	return nil
}

// page maps the envelope's paging onto the port type. Note `last-page` (hyphen): the
// transactions response spells it that way while receivables uses `last_page`, so both
// are read.
func (e c6PayEnvelope) page() ports.AcquirerPage {
	last := e.LastPage
	if last == 0 {
		last = e.LastPageDash
	}
	return ports.AcquirerPage{Page: e.Page, LastPage: last, Items: e.Items}
}

// parseC6PayDate parses a plain date, yielding the zero time when absent or malformed.
func parseC6PayDate(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(c6PayDateLayout, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// parseC6PayInstant parses a timestamp, tolerating both RFC3339 and a plain date —
// the contract leaves `date_time` untyped and the two forms have both been seen.
func parseC6PayInstant(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	return parseC6PayDate(s)
}

// c6PayQuery renders the extract query. start_date is required; end_date is omitted
// when absent, which makes the acquirer use start_date for both ends. page is required
// by the contract, so it defaults to 1 rather than being left out.
func c6PayQuery(filter ports.AcquirerStatementFilter) url.Values {
	q := url.Values{}
	q.Set("start_date", filter.Start.Format(c6PayDateLayout))
	if !filter.End.IsZero() {
		q.Set("end_date", filter.End.Format(c6PayDateLayout))
	}
	page := filter.Page
	if page <= 0 {
		page = 1
	}
	q.Set("page", strconv.Itoa(page))
	if filter.PageSize > 0 {
		q.Set("size", strconv.Itoa(filter.PageSize))
	}
	return q
}

// validateC6PayWindow refuses a window the acquirer would reject anyway, so the caller
// gets a typed validation error instead of an opaque 400.
func validateC6PayWindow(op string, filter ports.AcquirerStatementFilter) error {
	if filter.Start.IsZero() {
		return &Error{Op: op, sentinel: shared.ErrValidation}
	}
	if filter.End.IsZero() {
		return nil
	}
	if filter.End.Before(filter.Start) {
		return &Error{Op: op, sentinel: shared.ErrValidation}
	}
	if filter.End.Sub(filter.Start) > c6PayMaxWindowDays*24*time.Hour {
		return &Error{Op: op, sentinel: shared.ErrValidation}
	}
	return nil
}

// c6PayGet runs one extract read and decodes the shared envelope.
func (p *Provider) c6PayGet(ctx context.Context, tenantID, op, resource string, filter ports.AcquirerStatementFilter) (c6PayEnvelope, error) {
	if err := validateC6PayWindow(op, filter); err != nil {
		return c6PayEnvelope{}, err
	}
	endpoint := p.baseURL + c6PayStatementPath + resource + "?" + c6PayQuery(filter).Encode()
	httpReq, err := p.authedJSONRequest(ctx, tenantID, op, http.MethodGet, endpoint, nil, "")
	if err != nil {
		return c6PayEnvelope{}, err
	}
	setPartnerSoftware(httpReq)
	var out c6PayEnvelope
	if err := p.do(httpReq, op, &out); err != nil {
		return c6PayEnvelope{}, err
	}
	return out, nil
}

// ListReceivables returns the receivables scheduled or settled within the window
// (roteiro TR_01).
func (p *Provider) ListReceivables(ctx context.Context, tenantID string, filter ports.AcquirerStatementFilter) (ports.ReceivableList, error) {
	const op = "list_c6pay_receivables"
	env, err := p.c6PayGet(ctx, tenantID, op, "/receivables", filter)
	if err != nil {
		return ports.ReceivableList{}, err
	}
	var wire []c6PayReceivable
	if rows := env.rows(env.Receivables); rows != nil {
		if err := json.Unmarshal(rows, &wire); err != nil {
			return ports.ReceivableList{}, &Error{Op: op, sentinel: shared.ErrUnavailable}
		}
	}
	out := make([]ports.Receivable, len(wire))
	for i, r := range wire {
		out[i] = ports.Receivable{
			ReceivableID:     r.ReceivableID,
			TransactionID:    r.TransactionID,
			LocalRef:         r.LocalReference,
			BrandName:        r.BrandName,
			PaymentType:      r.PaymentType,
			Type:             r.Type,
			Status:           r.Status,
			Origin:           r.Origin,
			Installment:      r.InstallmentNumber,
			Installments:     r.Installments,
			InterestType:     r.InterestType,
			GrossAmountCents: int64(r.GrossAmount),
			FeeCents:         int64(r.Fee),
			DiscountCents:    int64(r.Discount),
			NetAmountCents:   int64(r.NetAmount),
			MDR:              int64(r.MDR),
			ExpectedDate:     parseC6PayDate(r.ExpectedDate),
			PaymentDate:      parseC6PayDate(r.PaymentDate),
			TransactionTime:  parseC6PayInstant(r.TransactionDateTime),
		}
	}
	return ports.ReceivableList{Receivables: out, AcquirerPage: env.page()}, nil
}

// ListCardTransactions returns the authorisations and cancellations within the window
// (roteiro TR_02).
func (p *Provider) ListCardTransactions(ctx context.Context, tenantID string, filter ports.AcquirerStatementFilter) (ports.CardTransactionList, error) {
	const op = "list_c6pay_transactions"
	env, err := p.c6PayGet(ctx, tenantID, op, "/transactions", filter)
	if err != nil {
		return ports.CardTransactionList{}, err
	}
	var wire []c6PayTransaction
	if rows := env.rows(env.Transactions); rows != nil {
		if err := json.Unmarshal(rows, &wire); err != nil {
			return ports.CardTransactionList{}, &Error{Op: op, sentinel: shared.ErrUnavailable}
		}
	}
	out := make([]ports.CardTransaction, len(wire))
	for i, tx := range wire {
		out[i] = ports.CardTransaction{
			ID:            tx.ID,
			LocalRef:      tx.LocalReference,
			AuthCode:      tx.AuthorizationCode,
			AuthorizerRef: tx.AuthorizerReference,
			BrandName:     tx.BrandName,
			PaymentType:   tx.PaymentType,
			Status:        tx.Status,
			Origin:        tx.Origin,
			EntryMode:     tx.CardEntryMode,
			Installments:  tx.Installments,
			InterestType:  tx.InterestType,
			CurrencyCode:  tx.CurrencyCode,
			TerminalID:    tx.TerminalID,
			FraudAnalysis: tx.FraudAnalysisRecommendation,
			AmountCents:   int64(tx.Amount),
			OccurredAt:    parseC6PayInstant(tx.DateTime),
		}
	}
	return ports.CardTransactionList{Transactions: out, AcquirerPage: env.page()}, nil
}

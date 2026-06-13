package c6

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// compile-time assertion that Provider satisfies the boleto port.
var _ ports.BoletoProvider = (*Provider)(nil)

// boletoRequestBody is the JSON sent to C6 to register a BolePix boleto. The fine
// and interest RATES are transmitted so C6 registers them; the amount owed at any
// instant is computed by the boleto domain, never here (Hexagonal).
type boletoRequestBody struct {
	BoletoID           string    `json:"boleto_id"`
	AmountCents        int64     `json:"amount_cents"`
	Currency           string    `json:"currency"`
	DueDate            time.Time `json:"due_date"`
	FineBps            int64     `json:"fine_bps"`
	MonthlyInterestBps int64     `json:"monthly_interest_bps"`
	PayerTaxID         string    `json:"payer_tax_id"`
}

// boletoResponseBody is the subset of C6's boleto representation we consume: the
// status plus the scannable artifacts (PIX EMV payload and boleto barcode).
type boletoResponseBody struct {
	BoletoID    string `json:"boleto_id"`
	TxID        string `json:"txid"`
	Status      string `json:"status"`
	QRCode      string `json:"qr_code"`
	Barcode     string `json:"barcode"`
	AmountCents int64  `json:"amount_cents"`
}

// CreateBoleto registers a BolePix boleto at C6 and returns the scannable
// artifacts (PIX copia-e-cola payload and barcode). The caller's IdempotencyKey
// (falling back to the BoletoID) is forwarded so the PSP collapses retried
// registrations into one boleto. The OAuth2 bearer token is attached per tenant.
func (p *Provider) CreateBoleto(ctx context.Context, tenantID string, req ports.BoletoRequest) (ports.BoletoResult, error) {
	payload, err := json.Marshal(boletoRequestBody{
		BoletoID:           req.BoletoID,
		AmountCents:        req.AmountCents,
		Currency:           req.Currency,
		DueDate:            req.DueDate,
		FineBps:            req.FineBps,
		MonthlyInterestBps: req.MonthlyInterestBps,
		PayerTaxID:         req.PayerTaxID,
	})
	if err != nil {
		return ports.BoletoResult{}, &Error{Op: "create_boleto", sentinel: shared.ErrValidation}
	}

	idem := req.IdempotencyKey
	if idem == "" {
		idem = req.BoletoID
	}
	httpReq, err := p.authedJSONRequest(ctx, tenantID, "create_boleto", http.MethodPost, p.baseURL+"/boletos", payload, idem)
	if err != nil {
		return ports.BoletoResult{}, err
	}

	var out boletoResponseBody
	if err := p.do(httpReq, "create_boleto", &out); err != nil {
		return ports.BoletoResult{}, err
	}
	return ports.BoletoResult{
		BoletoID:    out.BoletoID,
		TxID:        out.TxID,
		Status:      out.Status,
		QRCode:      out.QRCode,
		Barcode:     out.Barcode,
		AmountCents: out.AmountCents,
	}, nil
}

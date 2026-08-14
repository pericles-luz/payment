package c6

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// compile-time assertion that Provider satisfies the boleto port.
var _ ports.BoletoProvider = (*Provider)(nil)

// bankSlipsPath is the real C6 endpoint for registering a boleto (roteiro grupos
// 1–3; ADR-0005). The id-addressed read/cancel/amend operations still use the
// legacy /boletos/{id} path: their real contracts are not yet captured, so they
// are deliberately out of this remap's scope (see GetBoleto/CancelBoleto/UpdateBoleto).
const bankSlipsPath = "/v1/bank_slips"

// dueDateLayout is the date format the C6 bank_slips contract requires for
// due_date / valid_until — a plain calendar date (yyyy-MM-dd), NOT RFC3339. The
// port carries time.Time; this formatting is a transport concern owned by the
// adapter (ADR-0005).
const dueDateLayout = "2006-01-02"

// boletoDiscountBody is the transport JSON for one early-payment discount tier
// (roteiro grupo 3). Exactly one of Bps/FixedCents is non-zero.
type boletoDiscountBody struct {
	DaysBeforeDue int   `json:"days_before_due"`
	Bps           int64 `json:"bps,omitempty"`
	FixedCents    int64 `json:"fixed_cents,omitempty"`
}

// boletoAddressBody is the payer address in the C6 bank_slips contract. number is an
// integer per the contract (ADR-0005 "Riscos conhecidos": "S/N"/alphanumeric numbers
// are an open homologation question).
type boletoAddressBody struct {
	Street  string `json:"street"`
	Number  int    `json:"number"`
	City    string `json:"city"`
	State   string `json:"state"`
	ZipCode string `json:"zip_code"`
}

// boletoPayerBody is the `payer` object the C6 bank_slips contract requires.
type boletoPayerBody struct {
	Name    string            `json:"name"`
	TaxID   string            `json:"tax_id"`
	Address boletoAddressBody `json:"address"`
}

// boletoRequestBody is the LEGACY /boletos/{id} amend body (UpdateBoleto only). Its real
// contract is uncaptured, so it keeps the prior invented shape (amount in cents,
// fine_bps/etc) and is deliberately out of SIN-65953's scope. Registration uses the real
// bankSlipRequestBody below; do not route new work through this struct.
type boletoRequestBody struct {
	Amount              int64           `json:"amount"`
	DueDate             string          `json:"due_date"`
	ExternalReferenceID string          `json:"external_reference_id"`
	ValidUntil          string          `json:"valid_until,omitempty"`
	Payer               boletoPayerBody `json:"payer"`
	// --- rate parameters (roteiro grupos 1–3); wire names unconfirmed by a real 201 ---
	FineBps            int64                `json:"fine_bps"`
	FineFixedCents     int64                `json:"fine_fixed_cents,omitempty"`
	MonthlyInterestBps int64                `json:"monthly_interest_bps"`
	Discounts          []boletoDiscountBody `json:"discounts,omitempty"`
}

// externalReferenceID derives the C6 external_reference_id (^[a-zA-Z0-9]{1,10}$) from
// the boleto id. The boleto id is a UUID (>10 chars, contains hyphens), so it cannot
// be sent verbatim. The derivation is a pure function of the id — deterministic and
// idempotent — so a retried registration of the same boleto yields the same reference
// and C6 collapses the retry. Mechanism: base36 of the first 64 bits of SHA-256(id),
// truncated to 10 chars (~3.6e15 space, collision-resistant within a tenant's boletos,
// stable across processes). Lives in the adapter because it is a transport mapping,
// not a domain concept (ADR-0005 §"Hexagonal — o que NÃO entra no port").
func externalReferenceID(boletoID string) string {
	sum := sha256.Sum256([]byte(boletoID))
	ref := strconv.FormatUint(binary.BigEndian.Uint64(sum[:8]), 36)
	if len(ref) > 10 {
		ref = ref[:10]
	}
	return ref
}

// boletoResponseBody is the subset of C6's boleto representation we consume: the
// status plus the scannable artifacts (PIX EMV payload and boleto barcode) and the
// registered parameters echoed back for reconciliation (roteiro 6.a).
type boletoResponseBody struct {
	BoletoID           string               `json:"boleto_id"`
	TxID               string               `json:"txid"`
	Status             string               `json:"status"`
	QRCode             string               `json:"qr_code"`
	Barcode            string               `json:"barcode"`
	AmountCents        int64                `json:"amount_cents"`
	DueDate            time.Time            `json:"due_date"`
	ValidUntil         *time.Time           `json:"valid_until"`
	FineBps            int64                `json:"fine_bps"`
	FineFixedCents     int64                `json:"fine_fixed_cents"`
	MonthlyInterestBps int64                `json:"monthly_interest_bps"`
	Discounts          []boletoDiscountBody `json:"discounts"`
}

// --- Real C6 /v1/bank_slips contract (201 captured, SIN-65888) -----------------
//
// The register path has its own request/response DTOs: the captured 201 is shape-
// incompatible with the legacy /boletos/{id} representation above (still used by the
// id-addressed read/cancel/amend ops, contract uncaptured). On the wire amount is REAIS
// DECIMAIS (e.g. 12.34), NOT cents; fees are {value,type} objects; the response is
// id/our_number/bar_code/digitable_line (none of the legacy keys exist).

// brlDecimal is a money quantity carried in the port as integer minor units (centavos)
// but serialized to / parsed from the C6 wire as a JSON decimal number with exactly two
// fractional digits. Conversion is integer arithmetic ONLY — never float64 — so a payment
// amount can never drift (1234 centavos ⇒ "12.34", never "12.340000001"; ADR-0005
// addendum / SIN-65953). It also carries fee values measured in hundredths (bps ⇒
// percent: 150 bps ⇒ "1.50").
type brlDecimal int64

// MarshalJSON renders the minor-unit value as a bare JSON decimal number "<int>.<2-frac>".
func (d brlDecimal) MarshalJSON() ([]byte, error) {
	v := int64(d)
	sign := ""
	if v < 0 {
		sign, v = "-", -v
	}
	return []byte(fmt.Sprintf("%s%d.%02d", sign, v/100, v%100)), nil
}

// UnmarshalJSON parses a JSON decimal number (or numeric string) back to integer minor
// units by splitting on '.', never via strconv.ParseFloat — the same no-float discipline
// as MarshalJSON. Fractions are normalized to two digits (shorter padded, longer
// truncated). An empty/null value parses as zero.
func (d *brlDecimal) UnmarshalJSON(b []byte) error {
	s := strings.Trim(strings.TrimSpace(string(b)), `"`)
	if s == "" || s == "null" {
		*d = 0
		return nil
	}
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	intPart, fracPart := s, ""
	if i := strings.IndexByte(s, '.'); i >= 0 {
		intPart, fracPart = s[:i], s[i+1:]
	}
	if intPart == "" {
		intPart = "0"
	}
	whole, err := strconv.ParseInt(intPart, 10, 64)
	if err != nil {
		return fmt.Errorf("brlDecimal: bad integer part %q: %w", intPart, err)
	}
	if len(fracPart) > 2 {
		fracPart = fracPart[:2]
	}
	for len(fracPart) < 2 {
		fracPart += "0"
	}
	frac, err := strconv.ParseInt(fracPart, 10, 64)
	if err != nil {
		return fmt.Errorf("brlDecimal: bad fraction %q: %w", fracPart, err)
	}
	cents := whole*100 + frac
	if neg {
		cents = -cents
	}
	*d = brlDecimal(cents)
	return nil
}

// bankSlipFee is the C6 fine/interest object {value:<decimal>, type:<string>}. value is a
// brlDecimal (percent for "PERCENTAGE" — bps/100 — or reais for "FIXED" — cents/100).
type bankSlipFee struct {
	Value brlDecimal `json:"value"`
	Type  string     `json:"type"`
}

// bankSlipRequestBody is the JSON POSTed to C6 /v1/bank_slips (real 201 contract,
// SIN-65888). amount is decimal reais; fine/interest are omitempty objects (the C6 schema
// is strict — a zero-fee key is a 400, so the nil pointer omits it). The discount object
// is portal-gated (inner schema undiscovered) and intentionally omitted until captured —
// tracked as a child follow-up of SIN-65953.
type bankSlipRequestBody struct {
	Amount              brlDecimal      `json:"amount"`
	DueDate             string          `json:"due_date"`
	ExternalReferenceID string          `json:"external_reference_id"`
	ValidUntil          string          `json:"valid_until,omitempty"`
	Payer               boletoPayerBody `json:"payer"`
	Fine                *bankSlipFee    `json:"fine,omitempty"`
	Interest            *bankSlipFee    `json:"interest,omitempty"`
}

// bankSlipResponseBody is the C6 201 we consume (SIN-65888). id is the bank's registration
// reference (mapped to BoletoResult.TxID — the billing-finalized marker); our_number /
// bar_code / digitable_line are reconciliation/scannable artifacts. No status/txid/qr_code
// exist on create (status is read-sourced later).
type bankSlipResponseBody struct {
	ID            string     `json:"id"`
	OurNumber     string     `json:"our_number"`
	OriginatorID  string     `json:"originator_id"`
	BarCode       string     `json:"bar_code"`
	DigitableLine string     `json:"digitable_line"`
	Amount        brlDecimal `json:"amount"`
	BillingScheme string     `json:"billing_scheme"`
	BillingType   string     `json:"billing_type"`
	DueDate       string     `json:"due_date"`
}

// toBankSlipFees maps the port fine/interest RATES to the C6 fee objects. FineBps and
// FineFixedCents are mutually exclusive (percentage vs fixed); a zero rate yields a nil
// pointer so the strict C6 schema never sees the key (the "every CreateBoleto 400" fix).
// The "PERCENTAGE"/"FIXED" type strings are best-effort until a fee is echoed by a real
// 201 — a 400 here is the signal to adjust (SIN-65953).
func toBankSlipFees(req ports.BoletoRequest) (fine, interest *bankSlipFee) {
	switch {
	case req.FineBps > 0:
		fine = &bankSlipFee{Value: brlDecimal(req.FineBps), Type: "PERCENTAGE"}
	case req.FineFixedCents > 0:
		fine = &bankSlipFee{Value: brlDecimal(req.FineFixedCents), Type: "FIXED"}
	}
	if req.MonthlyInterestBps > 0 {
		interest = &bankSlipFee{Value: brlDecimal(req.MonthlyInterestBps), Type: "PERCENTAGE"}
	}
	return fine, interest
}

// toBankSlipRequestBody maps the port request to the real C6 bank_slips JSON. The full
// payer is mandatory (validation lives here so the stub stays lenient — ADR-0005);
// due_date/valid_until are yyyy-MM-dd and external_reference_id is derived from the boleto
// id (both transport concerns owned by the adapter).
func toBankSlipRequestBody(op string, req ports.BoletoRequest) (bankSlipRequestBody, error) {
	if err := validatePayer(op, req.Payer); err != nil {
		return bankSlipRequestBody{}, err
	}
	fine, interest := toBankSlipFees(req)
	body := bankSlipRequestBody{
		Amount:              brlDecimal(req.AmountCents),
		DueDate:             req.DueDate.Format(dueDateLayout),
		ExternalReferenceID: externalReferenceID(req.BoletoID),
		Payer: boletoPayerBody{
			Name:  req.Payer.Name,
			TaxID: req.Payer.TaxID,
			Address: boletoAddressBody{
				Street:  req.Payer.Address.Street,
				Number:  req.Payer.Address.Number,
				City:    req.Payer.Address.City,
				State:   req.Payer.Address.State,
				ZipCode: req.Payer.Address.ZipCode,
			},
		},
		Fine:     fine,
		Interest: interest,
	}
	if !req.ValidUntil.IsZero() {
		body.ValidUntil = req.ValidUntil.Format(dueDateLayout)
	}
	return body, nil
}

// toBankSlipResult maps the C6 201 onto the port result. CRITICAL: id → TxID. id is the
// bank's registration reference and the app treats a non-empty TxID as the
// billing-finalized marker (app/boleto.go); leaving it empty would let a retry/concurrent
// registration re-bill (duplicate ledger entry). Status/QRCode stay zero — C6 does not
// return them on create; they are read-sourced via GetBoleto/extrato (SIN-65953, CTO).
func toBankSlipResult(out bankSlipResponseBody) ports.BoletoResult {
	res := ports.BoletoResult{
		BoletoID:      out.ID,
		TxID:          out.ID,
		OurNumber:     out.OurNumber,
		DigitableLine: out.DigitableLine,
		Barcode:       out.BarCode,
		AmountCents:   int64(out.Amount),
	}
	if out.DueDate != "" {
		if t, err := time.Parse(dueDateLayout, out.DueDate); err == nil {
			res.DueDate = t
		}
	}
	return res
}

// toDiscountBodies maps the port discount tiers to their transport JSON.
func toDiscountBodies(in []ports.BoletoDiscountTier) []boletoDiscountBody {
	if len(in) == 0 {
		return nil
	}
	out := make([]boletoDiscountBody, len(in))
	for i, d := range in {
		out[i] = boletoDiscountBody{DaysBeforeDue: d.DaysBeforeDue, Bps: d.Bps, FixedCents: d.FixedCents}
	}
	return out
}

// fromDiscountBodies maps the transport discount JSON back to the port tiers.
func fromDiscountBodies(in []boletoDiscountBody) []ports.BoletoDiscountTier {
	if len(in) == 0 {
		return nil
	}
	out := make([]ports.BoletoDiscountTier, len(in))
	for i, d := range in {
		out[i] = ports.BoletoDiscountTier{DaysBeforeDue: d.DaysBeforeDue, Bps: d.Bps, FixedCents: d.FixedCents}
	}
	return out
}

// toBoletoRequestBody maps the port request to the LEGACY /boletos/{id} amend JSON
// (UpdateBoleto only — the real amend contract is uncaptured, so this path is out of
// SIN-65953's scope and keeps its prior shape). The payer is optional here (amend does
// not carry it); due_date/valid_until are yyyy-MM-dd and external_reference_id is derived
// from the boleto id. Registration goes through toBankSlipRequestBody, not this.
func toBoletoRequestBody(req ports.BoletoRequest) boletoRequestBody {
	body := boletoRequestBody{
		Amount:              req.AmountCents,
		DueDate:             req.DueDate.Format(dueDateLayout),
		ExternalReferenceID: externalReferenceID(req.BoletoID),
		Payer: boletoPayerBody{
			Name:  req.Payer.Name,
			TaxID: req.Payer.TaxID,
			Address: boletoAddressBody{
				Street:  req.Payer.Address.Street,
				Number:  req.Payer.Address.Number,
				City:    req.Payer.Address.City,
				State:   req.Payer.Address.State,
				ZipCode: req.Payer.Address.ZipCode,
			},
		},
		FineBps:            req.FineBps,
		FineFixedCents:     req.FineFixedCents,
		MonthlyInterestBps: req.MonthlyInterestBps,
		Discounts:          toDiscountBodies(req.Discounts),
	}
	if !req.ValidUntil.IsZero() {
		body.ValidUntil = req.ValidUntil.Format(dueDateLayout)
	}
	return body
}

// validatePayer enforces the C6 bank_slips mandatory payer block. Number is allowed to
// be zero (the "S/N"/no-number homologation case is open — ADR-0005). Returns an
// adapter validation error wrapping shared.ErrValidation so callers branch with
// errors.Is without the app or stub having to know the C6 requirement.
func validatePayer(op string, p ports.BoletoPayer) error {
	missing := ""
	switch {
	case p.Name == "":
		missing = "payer.name"
	case p.TaxID == "":
		missing = "payer.tax_id"
	case p.Address.Street == "":
		missing = "payer.address.street"
	case p.Address.City == "":
		missing = "payer.address.city"
	case p.Address.State == "":
		missing = "payer.address.state"
	case p.Address.ZipCode == "":
		missing = "payer.address.zip_code"
	}
	if missing != "" {
		return &Error{Op: op, detail: "missing required " + missing, sentinel: shared.ErrValidation}
	}
	return nil
}

// toBoletoResult maps a parsed C6 boleto representation to the port result.
func toBoletoResult(out boletoResponseBody) ports.BoletoResult {
	res := ports.BoletoResult{
		BoletoID:           out.BoletoID,
		TxID:               out.TxID,
		Status:             out.Status,
		QRCode:             out.QRCode,
		Barcode:            out.Barcode,
		AmountCents:        out.AmountCents,
		DueDate:            out.DueDate,
		FineBps:            out.FineBps,
		FineFixedCents:     out.FineFixedCents,
		MonthlyInterestBps: out.MonthlyInterestBps,
		Discounts:          fromDiscountBodies(out.Discounts),
	}
	if out.ValidUntil != nil {
		res.ValidUntil = *out.ValidUntil
	}
	return res
}

// CreateBoleto registers a BolePix boleto at C6 and returns the scannable
// artifacts (PIX copia-e-cola payload and barcode). The caller's IdempotencyKey
// (falling back to the BoletoID) is forwarded so the PSP collapses retried
// registrations into one boleto. The OAuth2 bearer token is attached per tenant.
func (p *Provider) CreateBoleto(ctx context.Context, tenantID string, req ports.BoletoRequest) (ports.BoletoResult, error) {
	body, err := toBankSlipRequestBody("create_boleto", req)
	if err != nil {
		return ports.BoletoResult{}, err
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return ports.BoletoResult{}, &Error{Op: "create_boleto", sentinel: shared.ErrValidation}
	}

	idem := req.IdempotencyKey
	if idem == "" {
		idem = req.BoletoID
	}
	httpReq, err := p.authedJSONRequest(ctx, tenantID, "create_boleto", http.MethodPost, p.baseURL+bankSlipsPath, payload, idem)
	if err != nil {
		return ports.BoletoResult{}, err
	}

	var out bankSlipResponseBody
	if err := p.do(httpReq, "create_boleto", &out); err != nil {
		return ports.BoletoResult{}, err
	}
	return toBankSlipResult(out), nil
}

// GetBoleto reconciles the authoritative state of a registered boleto from C6
// (roteiro 6.a). A 404 surfaces as shared.ErrNotFound via the adapter's error
// mapping; the read is tenant-scoped through the per-tenant OAuth2 bearer token, so
// one tenant can never read another's boleto.
func (p *Provider) GetBoleto(ctx context.Context, tenantID, boletoID string) (ports.BoletoResult, error) {
	endpoint := p.baseURL + "/boletos/" + url.PathEscape(boletoID)
	httpReq, err := p.authedJSONRequest(ctx, tenantID, "get_boleto", http.MethodGet, endpoint, nil, "")
	if err != nil {
		return ports.BoletoResult{}, err
	}

	var out boletoResponseBody
	if err := p.do(httpReq, "get_boleto", &out); err != nil {
		return ports.BoletoResult{}, err
	}
	return toBoletoResult(out), nil
}

// CancelBoleto performs the baixa/cancelamento of a registered boleto at C6 (roteiro
// grupo 4) via DELETE. The boleto id doubles as the idempotency anchor so a retried
// cancel is collapsed. A 404 surfaces as shared.ErrNotFound; the operation is
// tenant-scoped through the per-tenant OAuth2 bearer token.
func (p *Provider) CancelBoleto(ctx context.Context, tenantID, boletoID string) (ports.BoletoResult, error) {
	endpoint := p.baseURL + "/boletos/" + url.PathEscape(boletoID)
	httpReq, err := p.authedJSONRequest(ctx, tenantID, "cancel_boleto", http.MethodDelete, endpoint, nil, boletoID)
	if err != nil {
		return ports.BoletoResult{}, err
	}

	var out boletoResponseBody
	if err := p.do(httpReq, "cancel_boleto", &out); err != nil {
		return ports.BoletoResult{}, err
	}
	return toBoletoResult(out), nil
}

// UpdateBoleto amends a registered boleto's parameters at C6 (roteiro grupo 5) via
// PUT. The caller's IdempotencyKey (falling back to the boleto id) is forwarded so a
// retried amendment is collapsed. A 404 surfaces as shared.ErrNotFound; the operation
// is tenant-scoped through the per-tenant OAuth2 bearer token.
func (p *Provider) UpdateBoleto(ctx context.Context, tenantID, boletoID string, req ports.BoletoRequest) (ports.BoletoResult, error) {
	// Amend does not require the payer: the real bank_slips amendment contract is not
	// yet captured, and the app's UpdateBoleto path carries no payer (the payer is not
	// amended). The legacy amend body stays lenient so the stub tests stay green
	// (ADR-0005 §"UpdateBoleto compartilha toBoletoRequestBody").
	body := toBoletoRequestBody(req)
	payload, err := json.Marshal(body)
	if err != nil {
		return ports.BoletoResult{}, &Error{Op: "update_boleto", sentinel: shared.ErrValidation}
	}

	idem := req.IdempotencyKey
	if idem == "" {
		idem = boletoID
	}
	endpoint := p.baseURL + "/boletos/" + url.PathEscape(boletoID)
	httpReq, err := p.authedJSONRequest(ctx, tenantID, "update_boleto", http.MethodPut, endpoint, payload, idem)
	if err != nil {
		return ports.BoletoResult{}, err
	}

	var out boletoResponseBody
	if err := p.do(httpReq, "update_boleto", &out); err != nil {
		return ports.BoletoResult{}, err
	}
	return toBoletoResult(out), nil
}

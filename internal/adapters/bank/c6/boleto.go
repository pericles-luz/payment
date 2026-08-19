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
const bankSlipsPath = "/v2/bank_slips"

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
// --- C6 BolePix wire contract (/v2/bank_slips) ---------------------------------
//
// Shapes below mirror the OFFICIAL C6 "Bolepix" OpenAPI (3.0.3, v1.0.1), obtained from
// the published spec rather than inferred. The previous implementation targeted
// /v1/bank_slips with a flat body and would have been rejected by the bank: it omitted
// two required fields (`description`, `payment_method`), modelled fees as two separate
// objects, and sent a `valid_until` the contract does not define.
//
// The `payment_method` object is what makes a BolePix a BolePix: `bank_slip` registers
// the boleto, and the optional `pix` sub-object adds a QR Code payable against the same
// charge. C6 documents that an absent or invalid PIX key still creates the charge —
// silently, without any PIX artifact — so the key is resolved from the tenant's
// credential and the sub-object is omitted entirely when there is none, rather than sent
// empty.

// bankSlipAddressBody is the payer address in the C6 contract. Note it is NOT the legacy
// shape: C6 expects `address` (logradouro, composed with the number) and requires
// `neighborhood`, neither of which the previous body carried.
type bankSlipAddressBody struct {
	Address      string `json:"address"`
	Neighborhood string `json:"neighborhood"`
	City         string `json:"city"`
	State        string `json:"state"`
	ZipCode      string `json:"zip_code"`
}

type bankSlipPayerBody struct {
	Name    string              `json:"name"`
	TaxID   string              `json:"tax_id"`
	Email   string              `json:"email,omitempty"`
	Address bankSlipAddressBody `json:"address"`
}

// bankSlipFees is C6's single flat fee object — one object for fine, interest AND
// discount, not the three separate ones a reader might expect. Every field is omitempty:
// the schema is strict, and a zero-valued key is rejected.
type bankSlipFees struct {
	FineValue    *brlDecimal `json:"fine_value,omitempty"`
	FineDeadline *int        `json:"fine_deadline,omitempty"`
	FineType     string      `json:"fine_type,omitempty"`

	InterestValue    *brlDecimal `json:"interest_value,omitempty"`
	InterestDeadline *int        `json:"interest_deadline,omitempty"`
	InterestType     string      `json:"interest_type,omitempty"`

	DiscountType          string      `json:"discount_type,omitempty"`
	FirstDiscountValue    *brlDecimal `json:"first_discount_value,omitempty"`
	FirstDiscountDeadline *int        `json:"first_discount_deadline,omitempty"`
}

// Fee type discriminators, exactly as the C6 enums spell them.
const (
	feeTypeFixedValue        = "FIXED_VALUE"
	feeTypePercentage        = "PERCENTAGE"
	feeTypeValuePerDay       = "VALUE_PER_DAY"
	feeTypeMonthlyPercentage = "MONTHLY_PERCENTAGE"
)

// pixKeyTypeEVP is the only PIX key type C6 accepts here: a random key (chave aleatória)
// already registered at the bank. A key of any other type yields a charge with no PIX.
const pixKeyTypeEVP = "EVP"

// defaultBillingScheme is C6's production carteira. Sandbox uses 21 — see
// Config.BillingScheme; this default only avoids an empty required field.
const defaultBillingScheme = "15"

type bankSlipMethodBody struct {
	BillingScheme string   `json:"billing_scheme"`
	OurNumber     string   `json:"our_number,omitempty"`
	YourNumber    string   `json:"your_number,omitempty"`
	Instructions  []string `json:"instructions,omitempty"`
}

type bankSlipPixMethodBody struct {
	Key  string `json:"key"`
	Type string `json:"type"`
}

type bankSlipPaymentMethodBody struct {
	BankSlip bankSlipMethodBody     `json:"bank_slip"`
	Pix      *bankSlipPixMethodBody `json:"pix,omitempty"`
}

// bankSlipRequestBody is the JSON POSTed to /v2/bank_slips.
type bankSlipRequestBody struct {
	ExternalReferenceID string                    `json:"external_reference_id,omitempty"`
	Amount              brlDecimal                `json:"amount"`
	DueDate             string                    `json:"due_date"`
	Description         string                    `json:"description"`
	DaysAfterDueDate    *int                      `json:"days_after_due_date,omitempty"`
	Payer               bankSlipPayerBody         `json:"payer"`
	Fees                *bankSlipFees             `json:"fees,omitempty"`
	PaymentMethod       bankSlipPaymentMethodBody `json:"payment_method"`
	Origin              string                    `json:"origin,omitempty"`
}

// bankSlipResponseBody is the C6 201/200. The scannable artifacts are NESTED under
// payment_method.bank_slip — reading them at the top level (as the previous version did)
// yields empty strings, i.e. a boleto with no barcode. The PIX QR Code arrives on
// creation too, under payment_method.pix.
type bankSlipResponseBody struct {
	ID                  string        `json:"id"`
	ExternalReferenceID string        `json:"external_reference_id"`
	Amount              brlDecimal    `json:"amount"`
	DueDate             string        `json:"due_date"`
	Status              string        `json:"status"`
	DaysAfterDueDate    int           `json:"days_after_due_date"`
	Fees                *bankSlipFees `json:"fees"`
	PaymentMethod       struct {
		BankSlip struct {
			OriginatorID  string `json:"originator_id"`
			BillingScheme string `json:"billing_scheme"`
			BillingType   string `json:"billing_type"`
			DigitableLine string `json:"digitable_line"`
			BarCode       string `json:"bar_code"`
			OurNumber     string `json:"our_number"`
			Number        string `json:"number"`
		} `json:"bank_slip"`
		Pix struct {
			QRCode       string `json:"qr_code"`
			ImageContent string `json:"image_content"`
			MimeType     string `json:"mime_type"`
			Reference    string `json:"reference"`
		} `json:"pix"`
	} `json:"payment_method"`
}

// toBankSlipFees maps the port's fine/interest/discount onto C6's single fees object.
// A nil result means "no fees key at all", which is what the strict schema wants.
//
// Rates: the port carries basis points and brlDecimal renders hundredths, so a bps value
// marshals as its percentage (2000 bps -> 20.00) — the unit C6 expects for a PERCENTAGE.
//
// Discount caveat: C6 exposes only ONE discount tier (first_discount_*), and its
// discount_type enum reuses the interest values (VALUE_PER_DAY / MONTHLY_PERCENTAGE)
// rather than a fixed/percentage pair — which reads like a spec-side copy of the interest
// field. The mapping below is the faithful reading, but discounts are money-affecting:
// confirm the bank's actual behaviour against a real registration before relying on them.
func toBankSlipFees(op string, req ports.BoletoRequest) (*bankSlipFees, error) {
	fees := &bankSlipFees{}
	any := false

	switch {
	case req.FineBps > 0:
		v := brlDecimal(req.FineBps)
		fees.FineValue, fees.FineType, any = &v, feeTypePercentage, true
	case req.FineFixedCents > 0:
		v := brlDecimal(req.FineFixedCents)
		fees.FineValue, fees.FineType, any = &v, feeTypeFixedValue, true
	}
	if req.MonthlyInterestBps > 0 {
		v := brlDecimal(req.MonthlyInterestBps)
		fees.InterestValue, fees.InterestType, any = &v, feeTypeMonthlyPercentage, true
	}

	switch {
	case len(req.Discounts) > 1:
		// Dropping a tier silently would change what the payer owes. Refuse instead.
		return nil, &Error{Op: op, sentinel: shared.ErrValidation, detail: "bank supports at most one discount tier"}
	case len(req.Discounts) == 1:
		d := req.Discounts[0]
		deadline := d.DaysBeforeDue
		switch {
		case d.Bps > 0:
			v := brlDecimal(d.Bps)
			fees.DiscountType, fees.FirstDiscountValue, fees.FirstDiscountDeadline = feeTypeMonthlyPercentage, &v, &deadline
			any = true
		case d.FixedCents > 0:
			v := brlDecimal(d.FixedCents)
			fees.DiscountType, fees.FirstDiscountValue, fees.FirstDiscountDeadline = feeTypeValuePerDay, &v, &deadline
			any = true
		}
	}

	if !any {
		return nil, nil
	}
	return fees, nil
}

// daysAfterDueDate converts the port's ValidUntil instant into C6's expiry expressed as
// whole days after the due date. A ValidUntil at or before the due date yields nil (no
// key), since a non-positive window is not expressible and would be rejected.
func daysAfterDueDate(dueDate, validUntil time.Time) *int {
	if validUntil.IsZero() || !validUntil.After(dueDate) {
		return nil
	}
	days := int(validUntil.Sub(dueDate).Hours() / 24)
	if days <= 0 {
		return nil
	}
	return &days
}

// payerStreet composes C6's single `address` line from the port's street + number.
func payerStreet(a ports.BoletoAddress) string {
	street := strings.TrimSpace(a.Street)
	if a.Number > 0 {
		return street + ", " + strconv.Itoa(a.Number)
	}
	return street
}

// toBankSlipRequestBody maps the port request onto the C6 contract. Validation lives here
// so the stub stays lenient (ADR-0005); pixKey is the tenant's registered random key and
// may be empty, in which case the charge is registered as a plain boleto.
func (p *Provider) toBankSlipRequestBody(op string, req ports.BoletoRequest, pixKey string) (bankSlipRequestBody, error) {
	if err := validatePayer(op, req.Payer); err != nil {
		return bankSlipRequestBody{}, err
	}
	if strings.TrimSpace(req.Payer.Address.Neighborhood) == "" {
		return bankSlipRequestBody{}, &Error{Op: op, sentinel: shared.ErrValidation, detail: "payer neighborhood is required"}
	}
	description := strings.TrimSpace(req.Description)
	switch {
	case description == "":
		return bankSlipRequestBody{}, &Error{Op: op, sentinel: shared.ErrValidation, detail: "description is required"}
	case len(description) > maxDescriptionLen:
		return bankSlipRequestBody{}, &Error{Op: op, sentinel: shared.ErrValidation, detail: "description is too long"}
	}
	fees, err := toBankSlipFees(op, req)
	if err != nil {
		return bankSlipRequestBody{}, err
	}

	body := bankSlipRequestBody{
		ExternalReferenceID: externalReferenceID(req.BoletoID),
		Amount:              brlDecimal(req.AmountCents),
		DueDate:             req.DueDate.Format(dueDateLayout),
		Description:         description,
		DaysAfterDueDate:    daysAfterDueDate(req.DueDate, req.ValidUntil),
		Payer: bankSlipPayerBody{
			Name:  req.Payer.Name,
			TaxID: req.Payer.TaxID,
			Address: bankSlipAddressBody{
				Address:      payerStreet(req.Payer.Address),
				Neighborhood: strings.TrimSpace(req.Payer.Address.Neighborhood),
				City:         req.Payer.Address.City,
				State:        req.Payer.Address.State,
				ZipCode:      req.Payer.Address.ZipCode,
			},
		},
		Fees:          fees,
		PaymentMethod: bankSlipPaymentMethodBody{BankSlip: bankSlipMethodBody{BillingScheme: p.billingScheme}},
	}
	if k := strings.TrimSpace(pixKey); k != "" {
		body.PaymentMethod.Pix = &bankSlipPixMethodBody{Key: k, Type: pixKeyTypeEVP}
	}
	return body, nil
}

// maxDescriptionLen is the C6 cap on the slip description.
const maxDescriptionLen = 100

// toBankSlipResult maps the C6 response onto the port result. CRITICAL: id -> TxID. id is
// the bank's registration reference and the app treats a non-empty TxID as the
// billing-finalized marker (app/boleto.go); leaving it empty would let a retry or a
// concurrent registration re-bill (duplicate ledger entry).
func toBankSlipResult(out bankSlipResponseBody) ports.BoletoResult {
	slip := out.PaymentMethod.BankSlip
	res := ports.BoletoResult{
		BoletoID:      out.ID,
		TxID:          out.ID,
		Status:        out.Status,
		OurNumber:     slip.OurNumber,
		DigitableLine: slip.DigitableLine,
		Barcode:       slip.BarCode,
		AmountCents:   int64(out.Amount),
		// The BolePix QR Code is returned at REGISTRATION, not only on a later read.
		QRCode: out.PaymentMethod.Pix.QRCode,
	}
	if out.DueDate != "" {
		if t, err := time.Parse(dueDateLayout, out.DueDate); err == nil {
			res.DueDate = t
			// The contract expresses expiry as whole days after the due date; the port
			// carries an instant, so it is rebuilt here rather than surfaced as a count.
			if out.DaysAfterDueDate > 0 {
				res.ValidUntil = t.AddDate(0, 0, out.DaysAfterDueDate)
			}
		}
	}
	applyBankSlipFees(&res, out.Fees)
	return res
}

// applyBankSlipFees reconciles the registered fee parameters the bank echoes on a read
// back onto the port result. brlDecimal already parses a decimal into hundredths, which is
// exactly the unit the port uses for BOTH basis points and cents — so a 2.00 PERCENTAGE
// lands as 200 bps and a 5.50 FIXED_VALUE as 550 cents, with no float arithmetic.
//
// interest_type VALUE_PER_DAY (a fixed daily amount) has no port representation: the port
// models monthly interest only. It is left unmapped rather than coerced into a monthly
// rate, which would silently misstate what the payer owes.
func applyBankSlipFees(res *ports.BoletoResult, fees *bankSlipFees) {
	if fees == nil {
		return
	}
	if fees.FineValue != nil {
		switch fees.FineType {
		case feeTypePercentage:
			res.FineBps = int64(*fees.FineValue)
		case feeTypeFixedValue:
			res.FineFixedCents = int64(*fees.FineValue)
		}
	}
	if fees.InterestValue != nil && fees.InterestType == feeTypeMonthlyPercentage {
		res.MonthlyInterestBps = int64(*fees.InterestValue)
	}
	if fees.FirstDiscountValue != nil {
		tier := ports.BoletoDiscountTier{}
		if fees.FirstDiscountDeadline != nil {
			tier.DaysBeforeDue = *fees.FirstDiscountDeadline
		}
		switch fees.DiscountType {
		case feeTypeMonthlyPercentage:
			tier.Bps = int64(*fees.FirstDiscountValue)
		case feeTypeValuePerDay:
			tier.FixedCents = int64(*fees.FirstDiscountValue)
		}
		res.Discounts = []ports.BoletoDiscountTier{tier}
	}
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
	// The BolePix QR Code is generated from the tenant's registered random PIX key, the
	// same key the cob surfaces use. Resolving it here (rather than requiring the caller
	// to pass it) keeps a boleto and a PIX charge routing to the same account.
	pixKey, err := p.resolveCreditorKey(ctx, tenantID, "")
	if err != nil {
		return ports.BoletoResult{}, err
	}
	body, err := p.toBankSlipRequestBody("create_boleto", req, pixKey)
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
	endpoint := p.baseURL + bankSlipsPath + "/" + url.PathEscape(externalReferenceID(boletoID))
	httpReq, err := p.authedJSONRequest(ctx, tenantID, "get_boleto", http.MethodGet, endpoint, nil, "")
	if err != nil {
		return ports.BoletoResult{}, err
	}

	var out bankSlipResponseBody
	if err := p.do(httpReq, "get_boleto", &out); err != nil {
		return ports.BoletoResult{}, err
	}
	return toBankSlipResult(out), nil
}

// CancelBoleto performs the baixa/cancelamento of a registered boleto at C6 (roteiro
// grupo 4) via DELETE. The boleto id doubles as the idempotency anchor so a retried
// cancel is collapsed. A 404 surfaces as shared.ErrNotFound; the operation is
// tenant-scoped through the per-tenant OAuth2 bearer token.
func (p *Provider) CancelBoleto(ctx context.Context, tenantID, boletoID string) (ports.BoletoResult, error) {
	// Baixa is a PUT on a /cancel sub-resource — the contract exposes no DELETE.
	endpoint := p.baseURL + bankSlipsPath + "/" + url.PathEscape(externalReferenceID(boletoID)) + "/cancel"
	httpReq, err := p.authedJSONRequest(ctx, tenantID, "cancel_boleto", http.MethodPut, endpoint, nil, boletoID)
	if err != nil {
		return ports.BoletoResult{}, err
	}

	var out bankSlipResponseBody
	if err := p.do(httpReq, "cancel_boleto", &out); err != nil {
		return ports.BoletoResult{}, err
	}
	return toBankSlipResult(out), nil
}

// UpdateBoleto amends a registered boleto's parameters at C6 (roteiro grupo 5) via
// PUT. The caller's IdempotencyKey (falling back to the boleto id) is forwarded so a
// retried amendment is collapsed. A 404 surfaces as shared.ErrNotFound; the operation
// is tenant-scoped through the per-tenant OAuth2 bearer token.
func (p *Provider) UpdateBoleto(context.Context, string, string, ports.BoletoRequest) (ports.BoletoResult, error) {
	// The published C6 BolePix contract exposes registration, read, PDF, listing and
	// cancellation — there is NO amendment endpoint. The previous implementation PUT to a
	// speculative /boletos/{id}, which the bank does not serve.
	//
	// Failing closed here is deliberate: the alternative is a call that looks like it
	// amended a registered charge and did not, leaving our state and the bank's silently
	// divergent on money. A caller that needs to change a registered boleto cancels it and
	// registers a new one.
	return ports.BoletoResult{}, &Error{
		Op:       "update_boleto",
		sentinel: shared.ErrValidation,
		detail:   "bank does not support amending a registered boleto; cancel and re-register",
	}
}

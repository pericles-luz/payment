package c6

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

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

// externalRefAlphabet is Crockford base32 — 32 symbols drawn entirely from [A-Z0-9],
// with the visually ambiguous I, L, O and U omitted. Every symbol therefore satisfies
// the C6 charset, and 26 symbols carry 130 bits, enough to hold a 128-bit id whole.
const externalRefAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// externalRefLen is the EXACT length the C6 bank_slips contract demands of
// external_reference_id: `^[A-Z0-9]{26}$`, minLength == maxLength == 26 (Bolepix OAS
// 1.1.0, docs/compliance/c6-bolepix-oas.yaml). It is not a maximum — a 25-char value is
// rejected just as a 27-char one is.
const externalRefLen = 26

// externalRefBytes is the id width the encoding round-trips: 16 bytes == 128 bits.
const externalRefBytes = 16

// externalReferenceID maps the local boleto id onto the C6 external_reference_id.
//
// The local id is 16 random bytes rendered as 32 hex chars (system.IDProvider.NewID), so
// it cannot be sent verbatim: the contract wants 26 chars of [A-Z0-9]. Encoding those
// same 128 bits in Crockford base32 yields exactly 26 symbols — which makes this a
// BIJECTION, not a digest. That matters for three separate reasons:
//
//   - Deterministic and idempotent across processes, so a retried registration derives
//     the same reference and C6 collapses it. The contract is explicit that a duplicate
//     external_reference_id "retornará os dados da cobrança já existente", which is
//     precisely the retry-collapse we want — but only if the derivation never varies.
//   - No collisions at all. A truncated hash would trade a birthday bound for nothing;
//     here distinct ids cannot share a reference, because the map is invertible.
//   - Invertible, so an inbound webhook carrying the reference can be resolved back to
//     the local boleto without a lookup table (see boletoIDFromExternalReference).
//
// An id that is not 16 bytes of hex (only a caller bug, or a future id scheme) falls back
// to a digest of the same width, so the function is total and still deterministic — it
// simply stops being invertible, which boletoIDFromExternalReference reports honestly.
//
// This lives in the adapter because it is a transport mapping, not a domain concept
// (ADR-0005 §"Hexagonal — o que NÃO entra no port").
func externalReferenceID(boletoID string) string {
	raw, err := hex.DecodeString(boletoID)
	if err != nil || len(raw) != externalRefBytes {
		sum := sha256.Sum256([]byte(boletoID))
		raw = sum[:externalRefBytes]
	}
	return encodeCrockford(raw)
}

// encodeCrockford renders 16 bytes as 26 Crockford base32 symbols, most-significant
// symbol first. The 130-bit output is 2 bits wider than the input, so the leading symbol
// only ever carries the top 3 bits of the id — the padding is on the high end, which is
// what keeps decoding exact.
func encodeCrockford(raw []byte) string {
	n := new(big.Int).SetBytes(raw)
	out := make([]byte, externalRefLen)
	base := big.NewInt(int64(len(externalRefAlphabet)))
	rem := new(big.Int)
	for i := externalRefLen - 1; i >= 0; i-- {
		n.QuoRem(n, base, rem)
		out[i] = externalRefAlphabet[rem.Int64()]
	}
	return string(out)
}

// boletoIDFromExternalReference is the inverse of externalReferenceID: it recovers the
// local boleto id from a C6 external_reference_id. ok is false when ref is not a
// well-formed 26-symbol Crockford value, or when it decodes to more than 16 bytes —
// which is what happens when the value handed in is NOT one of ours (C6's own charge
// `id` is also 26 chars of [A-Z0-9], so shape alone cannot tell the two apart; only the
// decode can, and even then only probabilistically).
//
// Callers MUST treat a successful decode as a candidate to be confirmed against the
// store, never as proof: a foreign 26-char id can decode cleanly to 16 bytes that simply
// match no boleto we ever issued.
func boletoIDFromExternalReference(ref string) (string, bool) {
	if len(ref) != externalRefLen {
		return "", false
	}
	n := new(big.Int)
	base := big.NewInt(int64(len(externalRefAlphabet)))
	for i := 0; i < len(ref); i++ {
		idx := strings.IndexByte(externalRefAlphabet, ref[i])
		if idx < 0 {
			return "", false
		}
		n.Mul(n, base).Add(n, big.NewInt(int64(idx)))
	}
	raw := n.Bytes()
	if len(raw) > externalRefBytes {
		return "", false
	}
	// Left-pad: Bytes() drops leading zero bytes, which a low-valued id legitimately has.
	padded := make([]byte, externalRefBytes)
	copy(padded[externalRefBytes-len(raw):], raw)
	return hex.EncodeToString(padded), true
}

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

// bankSlipStatusCanceled is the state a successful baixa leaves the charge in. The contract
// answers the cancel with 204 and no body, so this is synthesized rather than read back.
//
// Note the single L: the Bolepix contract spells it CANCELED, while the legacy v1 boleto API
// spells the same state CANCELLED. The full status vocabulary is INTERPRETED one layer up,
// in the settlement path (internal/app/webhook_boleto.go), which is what decides whether a
// status settles, waits or is terminal — the adapter only maps the wire.
const bankSlipStatusCanceled = "CANCELED"

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
	if description == "" {
		return bankSlipRequestBody{}, &Error{Op: op, sentinel: shared.ErrValidation, detail: "description is required"}
	}
	// The UF is normalized before validation so a lowercase "sp" is accepted and sent as
	// "SP" rather than refused by the bank's [A-Z]{2} pattern.
	req.Payer.Address.State = strings.ToUpper(strings.TrimSpace(req.Payer.Address.State))
	if err := validateBankSlipLimits(op, req, description); err != nil {
		return bankSlipRequestBody{}, err
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
	// The pix sub-object is what makes a BolePix a BolePix, so it rides on the CALLER's
	// choice, not on whether a key happens to exist. A plain boleto never carries it, even
	// for a tenant that has a key registered.
	if req.Modality.Normalized() == ports.ModalityBolepix {
		k := strings.TrimSpace(pixKey)
		if k == "" {
			// Fail closed. The bank does not refuse this: it creates the charge and returns
			// payment_method.pix = null, so the payer is handed a slip promising a QR that
			// does not exist and nobody finds out until payment time. Since no error path
			// exists downstream, this is the only place it can be caught.
			return bankSlipRequestBody{}, &Error{Op: op, sentinel: shared.ErrValidation,
				detail: "bolepix requires a registered random (EVP) pix key for the tenant"}
		}
		body.PaymentMethod.Pix = &bankSlipPixMethodBody{Key: k, Type: pixKeyTypeEVP}
	}
	return body, nil
}

// Field limits the C6 Bolepix contract enforces (docs/compliance/c6-bolepix-oas.yaml).
//
// They are checked HERE, in the adapter, for two reasons. First, they are the bank's
// limits, not ours — the stub must stay lenient (ADR-0005). Second, a violation caught
// here names the offending field, while the same violation caught by C6 comes back as an
// opaque 400 whose problem+json this adapter deliberately discards.
//
// Every one of these is a CHARACTER count in JSON Schema, so they are measured with
// utf8.RuneCountInString and never len(). Measuring bytes rejects perfectly legal
// Portuguese: "Mensalidade de Março/2026 — condomínio do Edifício Solar" is 57 characters
// but 63 bytes, and a description at the 100-character limit routinely exceeds 100 bytes.
const (
	maxDescriptionLen  = 100
	maxPayerNameLen    = 40
	maxAddressLineLen  = 40 // `address` = logradouro AND número, composed
	maxNeighborhoodLen = 40
	maxCityLen         = 40
	maxEmailLen        = 70

	// maxAmountCents mirrors the contract's `amount` maximum of R$ 5.000.000,00. The port
	// carries centavos, so the ceiling is expressed in centavos too.
	maxAmountCents = 5_000_000_00
)

// tooLong reports whether s exceeds n CHARACTERS (not bytes).
func tooLong(s string, n int) bool { return utf8.RuneCountInString(s) > n }

// validateBankSlipLimits enforces the contract's field constraints on an outgoing
// registration. It runs after validatePayer (which enforces presence) and checks size and
// shape, so a caller gets one named field back instead of an opaque bank rejection.
func validateBankSlipLimits(op string, req ports.BoletoRequest, description string) error {
	bad := func(detail string) error {
		return &Error{Op: op, sentinel: shared.ErrValidation, detail: detail}
	}
	switch {
	case req.AmountCents > maxAmountCents:
		return bad("amount exceeds the bank maximum of BRL 5,000,000.00")
	case tooLong(description, maxDescriptionLen):
		return bad("description is too long")
	case tooLong(req.Payer.Name, maxPayerNameLen):
		return bad("payer.name is too long")
	// The contract models logradouro and número as ONE 40-character field, so the limit
	// applies to the composed value — checking street alone would let a long number push
	// the composed line over.
	case tooLong(payerStreet(req.Payer.Address), maxAddressLineLen):
		return bad("payer.address street and number exceed the combined limit")
	case tooLong(req.Payer.Address.Neighborhood, maxNeighborhoodLen):
		return bad("payer.address.neighborhood is too long")
	case tooLong(req.Payer.Address.City, maxCityLen):
		return bad("payer.address.city is too long")
	case !validTaxIDDigits(req.Payer.TaxID):
		return bad("payer.tax_id must be a valid CPF (11 digits) or CNPJ (14 digits), unmasked")
	case !validUFCode(req.Payer.Address.State):
		return bad("payer.address.state must be a two-letter UF")
	case !validZipDigits(req.Payer.Address.ZipCode):
		return bad("payer.address.zip_code must be 8 digits")
	}
	return nil
}

// validTaxIDDigits accepts only an unmasked CPF (11 digits) or CNPJ (14). The contract
// says "somente números, sem máscara, respeitando zeros à esquerda"; a masked value is
// the common integration mistake and is worth naming rather than forwarding.
func validTaxIDDigits(s string) bool {
	if !allDigits(s) {
		return false
	}
	switch len(s) {
	case 11:
		return validCPFCheckDigits(s)
	case 14:
		return validCNPJCheckDigits(s)
	}
	return false
}

// validCPFCheckDigits verifies the two check digits of a CPF (módulo 11).
//
// Checking the digits — not merely the width — is what turns a wrong CPF into a NAMED field
// error instead of a round trip to the bank. Measured 15/09/2026: the syntactically fine but
// invalid 12345678901 came back from C6 as an opaque 422 whose reason our own API discards,
// and only the probe could show it said "cnpjCpf do grupo pagador não pertence ao Domínio".
// The arithmetic is free; the round trip and the blind diagnosis were not.
//
// Repeated digits (00000000000, 11111111111, …) satisfy the módulo-11 arithmetic but are not
// issuable CPFs, so they are rejected explicitly.
func validCPFCheckDigits(s string) bool {
	if allSameDigit(s) {
		return false
	}
	return mod11CheckDigit(s[:9]) == int(s[9]-'0') &&
		mod11CheckDigit(s[:10]) == int(s[10]-'0')
}

// mod11CheckDigit computes one CPF check digit over the given prefix: each digit is weighted
// by its distance from the end (len+1 down to 2), and a remainder of 0 or 1 yields 0.
func mod11CheckDigit(prefix string) int {
	sum := 0
	weight := len(prefix) + 1
	for i := 0; i < len(prefix); i++ {
		sum += int(prefix[i]-'0') * weight
		weight--
	}
	if r := 11 - sum%11; r < 10 {
		return r
	}
	return 0
}

// validCNPJCheckDigits verifies the two check digits of a CNPJ. The weights differ from the
// CPF's: they cycle 2..9 from the right rather than descending monotonically.
func validCNPJCheckDigits(s string) bool {
	if allSameDigit(s) {
		return false
	}
	return cnpjCheckDigit(s[:12]) == int(s[12]-'0') &&
		cnpjCheckDigit(s[:13]) == int(s[13]-'0')
}

func cnpjCheckDigit(prefix string) int {
	sum, weight := 0, 2
	for i := len(prefix) - 1; i >= 0; i-- {
		sum += int(prefix[i]-'0') * weight
		weight++
		if weight > 9 {
			weight = 2
		}
	}
	if r := 11 - sum%11; r < 10 {
		return r
	}
	return 0
}

// allSameDigit reports whether every character is the same digit.
func allSameDigit(s string) bool {
	for i := 1; i < len(s); i++ {
		if s[i] != s[0] {
			return false
		}
	}
	return len(s) > 0
}

// validZipDigits accepts an unmasked 8-digit CEP (contract pattern \d{8}).
func validZipDigits(s string) bool { return len(s) == 8 && allDigits(s) }

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// validUFCode accepts exactly two ASCII uppercase letters (contract pattern [A-Z]{2}).
// The value is uppercased before this runs, so a lowercase "sp" is normalized rather than
// rejected — it is unambiguous, and refusing it would be pedantry, not safety.
func validUFCode(s string) bool {
	if len(s) != 2 {
		return false
	}
	return s[0] >= 'A' && s[0] <= 'Z' && s[1] >= 'A' && s[1] <= 'Z'
}

// toBankSlipResult maps the C6 response onto the port result.
//
// Two identifiers, two destinations, and they must not be swapped:
//
//   - C6's `id` -> TxID. It is the bank's registration reference, and the app treats a
//     non-empty TxID as the billing-finalized marker (app/boleto.go); leaving it empty
//     would let a retry or a concurrent registration re-bill (duplicate ledger entry).
//   - boletoID (OURS) -> BoletoID. This is the one the caller addresses every later
//     operation by, and every later operation derives external_reference_id FROM it.
//     Returning C6's id here instead — as this did until now — meant the caller was handed
//     an id whose derived reference was never registered, so every subsequent read, PDF,
//     amendment and cancellation answered 404. It went unnoticed because the in-memory
//     stub echoes back the id it was given, so only the real bank ever showed it.
//
// external_reference_id is echoed onto the result too: it is the key the C6 read/cancel/
// patch paths address, and an inbound settlement notification may carry it.
func toBankSlipResult(boletoID string, out bankSlipResponseBody) ports.BoletoResult {
	slip := out.PaymentMethod.BankSlip
	res := ports.BoletoResult{
		BoletoID:            boletoID,
		TxID:                out.ID,
		ExternalReferenceID: out.ExternalReferenceID,
		Status:              out.Status,
		OurNumber:           slip.OurNumber,
		DigitableLine:       slip.DigitableLine,
		Barcode:             slip.BarCode,
		AmountCents:         int64(out.Amount),
		// The BolePix QR Code is returned at REGISTRATION, not only on a later read.
		QRCode: out.PaymentMethod.Pix.QRCode,
	}
	// Report what the charge actually is, read off the bank's own answer rather than off
	// what was asked for: a QR present means both rails are live.
	res.Modality = ports.ModalityBoleto
	if res.QRCode != "" {
		res.Modality = ports.ModalityBolepix
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
	return toBankSlipResult(req.BoletoID, out), nil
}

// GetBoleto reconciles the authoritative state of a registered boleto from C6
// (roteiro 6.a). A 404 surfaces as shared.ErrNotFound via the adapter's error
// mapping; the read is tenant-scoped through the per-tenant OAuth2 bearer token, so
// one tenant can never read another's boleto.
func (p *Provider) GetBoleto(ctx context.Context, tenantID, boletoID string) (ports.BoletoResult, error) {
	return p.getBankSlip(ctx, tenantID, externalReferenceID(boletoID), boletoID, "get_boleto")
}

// GetBoletoByBankRef reads a charge addressed by the bank's external_reference_id VERBATIM.
//
// The settlement path needs this because an inbound notification carries an identifier we
// cannot always map back to a local boleto id, and GetBoleto derives the reference FROM
// that id — so it is the wrong tool for a charge we only know the reference of.
//
// The reference is validated against the contract's shape BEFORE any call: a malformed one
// is a local error rather than a round trip that the bank would reject anyway.
//
// Note the result's BoletoID is left EMPTY on purpose. A reference that is not one of ours
// does not decode to a boleto id, and inventing one here would let a caller believe a local
// boleto exists when none does — the caller resolves that against the store.
func (p *Provider) GetBoletoByBankRef(ctx context.Context, tenantID, bankRef string) (ports.BoletoResult, error) {
	const op = "get_boleto_by_ref"
	ref := strings.TrimSpace(bankRef)
	if !validExternalReference(ref) {
		return ports.BoletoResult{}, &Error{Op: op, sentinel: shared.ErrValidation,
			detail: "external reference must be 26 uppercase alphanumerics"}
	}
	res, err := p.getBankSlip(ctx, tenantID, ref, "", op)
	if err != nil {
		return ports.BoletoResult{}, err
	}
	// If the reference IS one of ours, the bijection recovers the local id for free.
	if localID, ok := boletoIDFromExternalReference(ref); ok {
		res.BoletoID = localID
	}
	return res, nil
}

// validExternalReference reports whether ref matches the contract's ^[A-Z0-9]{26}$.
func validExternalReference(ref string) bool {
	if len(ref) != externalRefLen {
		return false
	}
	for i := 0; i < len(ref); i++ {
		c := ref[i]
		if (c < '0' || c > '9') && (c < 'A' || c > 'Z') {
			return false
		}
	}
	return true
}

// getBankSlip is the shared read: one endpoint, addressed by reference, mapped onto the
// port. boletoID is what the result should report as the LOCAL id, which the caller knows
// and this function does not.
func (p *Provider) getBankSlip(ctx context.Context, tenantID, ref, boletoID, op string) (ports.BoletoResult, error) {
	endpoint := p.baseURL + bankSlipsPath + "/" + url.PathEscape(ref)
	httpReq, err := p.authedJSONRequest(ctx, tenantID, op, http.MethodGet, endpoint, nil, "")
	if err != nil {
		return ports.BoletoResult{}, err
	}

	var out bankSlipResponseBody
	if err := p.do(httpReq, op, &out); err != nil {
		return ports.BoletoResult{}, err
	}
	return toBankSlipResult(boletoID, out), nil
}

// CancelBoleto performs the baixa/cancelamento of a registered boleto at C6 (roteiro
// grupo 4). The boleto id doubles as the idempotency anchor so a retried cancel is
// collapsed. A 404 surfaces as shared.ErrNotFound; the operation is tenant-scoped through
// the per-tenant OAuth2 bearer token.
//
// The contract answers 204 with NO body, so this uses doNoContent rather than do(): do()
// json.Unmarshals every 2xx body and would read the empty 204 as a malformed response,
// turning a successful baixa into shared.ErrUnavailable. The result is therefore
// synthesized from what the call proves — this boleto is now cancelled — instead of being
// mapped from a body the bank never sends.
func (p *Provider) CancelBoleto(ctx context.Context, tenantID, boletoID string) (ports.BoletoResult, error) {
	// Baixa is a PUT on a /cancel sub-resource — the contract exposes no DELETE.
	ref := externalReferenceID(boletoID)
	endpoint := p.baseURL + bankSlipsPath + "/" + url.PathEscape(ref) + "/cancel"
	httpReq, err := p.authedJSONRequest(ctx, tenantID, "cancel_boleto", http.MethodPut, endpoint, nil, boletoID)
	if err != nil {
		return ports.BoletoResult{}, err
	}
	if err := p.doNoContent(httpReq, "cancel_boleto"); err != nil {
		return ports.BoletoResult{}, err
	}
	return ports.BoletoResult{
		BoletoID:            boletoID,
		ExternalReferenceID: ref,
		Status:              bankSlipStatusCanceled,
	}, nil
}

// bankSlipPatchFees mirrors bankSlipFees for a PATCH: every field a pointer, so a fee the
// caller did not mention is OMITTED rather than sent as zero. The contract's schema is
// strict and a zero-valued key is rejected, which is why the create body already takes the
// same discipline.
type bankSlipPatchBody struct {
	Amount           *brlDecimal   `json:"amount,omitempty"`
	DueDate          *string       `json:"due_date,omitempty"`
	Description      *string       `json:"description,omitempty"`
	DaysAfterDueDate *int          `json:"days_after_due_date,omitempty"`
	Fees             *bankSlipFees `json:"fees,omitempty"`
}

// toBankSlipPatchBody maps a partial amendment onto the C6 PATCH contract.
//
// Partial means partial: a nil field is left out of the JSON entirely. That distinction is
// the whole point of the type — sending amount: 0 to mean "do not change the amount" would
// ask the bank to make the charge free.
func toBankSlipPatchBody(op string, patch ports.BoletoPatch) (bankSlipPatchBody, error) {
	body := bankSlipPatchBody{}
	if patch.AmountCents != nil {
		if *patch.AmountCents > maxAmountCents {
			return body, &Error{Op: op, sentinel: shared.ErrValidation,
				detail: "amount exceeds the bank maximum of BRL 5,000,000.00"}
		}
		v := brlDecimal(*patch.AmountCents)
		body.Amount = &v
	}
	if patch.DueDate != nil {
		d := patch.DueDate.Format(dueDateLayout)
		body.DueDate = &d
	}
	if patch.Description != nil {
		d := strings.TrimSpace(*patch.Description)
		if tooLong(d, maxDescriptionLen) {
			return body, &Error{Op: op, sentinel: shared.ErrValidation, detail: "description is too long"}
		}
		body.Description = &d
	}
	// ValidUntil is expressed to the bank as whole days after the due date, so amending it
	// requires knowing which due date it is counted from. Rather than read-modify-write the
	// registered one (a race on money), the caller supplies both.
	if patch.ValidUntil != nil {
		if patch.DueDate == nil {
			return body, &Error{Op: op, sentinel: shared.ErrValidation,
				detail: "valid_until requires due_date: the bank counts expiry in days after the due date"}
		}
		body.DaysAfterDueDate = daysAfterDueDate(*patch.DueDate, *patch.ValidUntil)
	}
	if patch.Fees != nil {
		fees, err := toBankSlipFees(op, ports.BoletoRequest{
			FineBps:            patch.Fees.FineBps,
			FineFixedCents:     patch.Fees.FineFixedCents,
			MonthlyInterestBps: patch.Fees.MonthlyInterestBps,
			Discounts:          patch.Fees.Discounts,
		})
		if err != nil {
			return body, err
		}
		body.Fees = fees
	}
	return body, nil
}

// empty reports whether the patch would send no changes at all.
func (b bankSlipPatchBody) empty() bool {
	return b.Amount == nil && b.DueDate == nil && b.Description == nil &&
		b.DaysAfterDueDate == nil && b.Fees == nil
}

// UpdateBoleto amends a registered boleto at C6 (roteiro grupo 5).
//
// This used to fail closed on the premise that the bank had no amendment endpoint. That
// premise was wrong: the published Bolepix contract (v1.1.0, docs/compliance/
// c6-bolepix-oas.yaml) exposes PATCH /v2/bank_slips/{external_reference_id}. What the
// earlier implementation actually got wrong was the verb and the path — it PUT to a
// speculative /boletos/{id} — not the existence of the operation.
//
// It is a PARTIAL update, so only the fields the caller set are sent. A patch that would
// change nothing is refused here rather than sent as an empty body.
func (p *Provider) UpdateBoleto(ctx context.Context, tenantID, boletoID string, patch ports.BoletoPatch) (ports.BoletoResult, error) {
	const op = "update_boleto"
	body, err := toBankSlipPatchBody(op, patch)
	if err != nil {
		return ports.BoletoResult{}, err
	}
	if body.empty() {
		return ports.BoletoResult{}, &Error{Op: op, sentinel: shared.ErrValidation,
			detail: "no amendable field was supplied"}
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return ports.BoletoResult{}, &Error{Op: op, sentinel: shared.ErrValidation}
	}

	ref := externalReferenceID(boletoID)
	endpoint := p.baseURL + bankSlipsPath + "/" + url.PathEscape(ref)
	idem := patch.IdempotencyKey
	if idem == "" {
		idem = boletoID
	}
	httpReq, err := p.authedJSONRequest(ctx, tenantID, op, http.MethodPatch, endpoint, payload, idem)
	if err != nil {
		return ports.BoletoResult{}, err
	}

	var out bankSlipResponseBody
	if err := p.do(httpReq, op, &out); err != nil {
		return ports.BoletoResult{}, err
	}
	return toBankSlipResult(boletoID, out), nil
}

// pdfMediaType is what a boleto document is served as.
const pdfMediaType = "application/pdf"

// pdfMagic is the signature every PDF starts with. It is checked before returning, so an
// error page or a JSON body that arrived with the wrong Content-Type is never handed back
// labelled as a PDF.
var pdfMagic = []byte("%PDF-")

// GetBoletoPDF downloads the registered boleto as a PDF from C6.
//
// The contract declares the 200 with no content type at all, and the legacy v1 API returned
// the document base64-encoded INSIDE a JSON body. Both shapes are therefore accepted: what
// identifies a PDF is its own signature, not a header the bank may or may not set.
func (p *Provider) GetBoletoPDF(ctx context.Context, tenantID, boletoID string) (ports.BoletoDocument, error) {
	const op = "get_boleto_pdf"
	ref := externalReferenceID(boletoID)
	endpoint := p.baseURL + bankSlipsPath + "/" + url.PathEscape(ref) + "/pdf"
	httpReq, err := p.authedJSONRequest(ctx, tenantID, op, http.MethodGet, endpoint, nil, "")
	if err != nil {
		return ports.BoletoDocument{}, err
	}

	body, contentType, err := p.doRaw(httpReq, op, maxDocumentBytes)
	if err != nil {
		return ports.BoletoDocument{}, err
	}

	content := body
	if !bytes.HasPrefix(content, pdfMagic) {
		// Not raw bytes — try the legacy JSON envelope before giving up.
		decoded, ok := decodeBase64PDFEnvelope(body)
		if !ok {
			return ports.BoletoDocument{}, &Error{Op: op, sentinel: shared.ErrUnavailable,
				detail: "response is not a PDF"}
		}
		content = decoded
	}
	_ = contentType // the signature decides; the header is advisory on this endpoint
	return ports.BoletoDocument{
		ContentType: pdfMediaType,
		Filename:    "boleto-" + boletoID + ".pdf",
		Content:     content,
	}, nil
}

// decodeBase64PDFEnvelope unwraps the legacy JSON shape {"base64_pdf_file": "..."} (or one
// of its aliases). It returns ok only when the decoded bytes are actually a PDF, so a
// base64 field carrying something else is rejected rather than forwarded.
func decodeBase64PDFEnvelope(body []byte) ([]byte, bool) {
	var env struct {
		Base64PDFFile string `json:"base64_pdf_file"`
		PDF           string `json:"pdf"`
		Content       string `json:"content"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, false
	}
	for _, encoded := range []string{env.Base64PDFFile, env.PDF, env.Content} {
		if encoded == "" {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err == nil && bytes.HasPrefix(decoded, pdfMagic) {
			return decoded, true
		}
	}
	return nil, false
}

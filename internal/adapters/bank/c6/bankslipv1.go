package c6

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// C6 "Boleto Bancário" v1 (`/v1/bank_slips`, roteiro grupo B) for the C6 adapter.
//
// This is NOT an older version of the BolePix surface in boleto.go — see the comment on
// ports.PlainBoletoProvider for why they are separate products. The shapes here come
// from docs/compliance/c6-bankslip-v1-oas.yaml (v1.7.2).
//
// # A faixa de desconto que o v2 não tem
//
// docs/homologacao/boleto-camadaA.md registra que o adapter RECUSA duas ou mais faixas
// de desconto, porque "o contrato Bolepix v2 expõe uma só". Verdade — sobre o v2. O v1
// expõe três (`first`/`second`/`third`, prazos estritamente decrescentes), e é aqui que
// uma regra de "10% até dez dias antes, 5% até cinco" cabe.
//
// As três faixas compartilham UM `discount_type`. Misturar percentual com valor fixo na
// mesma lista não é uma requisição que o banco recusa de forma clara — é uma em que ele
// aplica o tipo errado a alguma faixa —, então é recusada aqui.

const (
	// bankSlipV1Path is the C6 Boleto Bancário v1 collection.
	bankSlipV1Path = "/v1/bank_slips"
	// bankSlipV1MaxDiscounts is how many discount tiers the contract carries.
	bankSlipV1MaxDiscounts = 3
	// bankSlipV1RefMaxLen is the ceiling on external_reference_id in v1
	// (`^[a-zA-Z0-9]{1,10}$`) — a quarter of what the v2 reference uses, which is why
	// the v2 derivation cannot be reused here.
	bankSlipV1RefMaxLen = 10
)

// Fee/discount discriminators, exactly as the v1 enum spells them: "V" is a fixed
// amount in reais, "P" a percentage.
const (
	bankSlipV1TypeValue   = "V"
	bankSlipV1TypePercent = "P"
)

// compile-time assertion that Provider satisfies the plain bank-slip port.
var _ ports.PlainBoletoProvider = (*Provider)(nil)

// bankSlipV1Address is the payer address in the v1 contract. It differs from the v2
// one in two ways that matter: `number` is a NUMBER, and there is no `neighborhood`.
type bankSlipV1Address struct {
	Street     string `json:"street"`
	Number     int    `json:"number"`
	Complement string `json:"complement,omitempty"`
	City       string `json:"city"`
	State      string `json:"state"`
	ZipCode    string `json:"zip_code"`
}

// bankSlipV1Payer is the sacado.
type bankSlipV1Payer struct {
	Name    string            `json:"name"`
	TaxID   string            `json:"tax_id"`
	Email   string            `json:"email,omitempty"`
	Address bankSlipV1Address `json:"address"`
}

// bankSlipV1Fee is the v1 fine/interest block: a discriminated value plus the number of
// days after the due date it starts applying.
type bankSlipV1Fee struct {
	Type     string     `json:"type"`
	Value    brlDecimal `json:"value"`
	DeadLine int        `json:"dead_line"`
}

// bankSlipV1DiscountTier is one early-payment discount band: the value (or percentage)
// and how many days BEFORE the due date it still applies.
type bankSlipV1DiscountTier struct {
	Value    brlDecimal `json:"value"`
	DeadLine int        `json:"dead_line"`
}

// bankSlipV1Discount is the discount schedule: one type for the whole schedule plus up
// to three bands, whose deadlines must be strictly decreasing.
type bankSlipV1Discount struct {
	DiscountType string                  `json:"discount_type"`
	First        *bankSlipV1DiscountTier `json:"first,omitempty"`
	Second       *bankSlipV1DiscountTier `json:"second,omitempty"`
	Third        *bankSlipV1DiscountTier `json:"third,omitempty"`
}

// bankSlipV1Request is the create body.
type bankSlipV1Request struct {
	ExternalReferenceID string              `json:"external_reference_id"`
	Amount              brlDecimal          `json:"amount"`
	DueDate             string              `json:"due_date"`
	Discount            *bankSlipV1Discount `json:"discount,omitempty"`
	Interest            *bankSlipV1Fee      `json:"interest,omitempty"`
	Fine                *bankSlipV1Fee      `json:"fine,omitempty"`
	BillingScheme       string              `json:"billing_scheme,omitempty"`
	OurNumber           string              `json:"our_number,omitempty"`
	Payer               bankSlipV1Payer     `json:"payer"`
}

// bankSlipV1Patch is the amend body. Every field is a pointer: the contract requires at
// least one property and a zero-valued key would be a real change, not a no-op.
type bankSlipV1Patch struct {
	Amount   *brlDecimal         `json:"amount,omitempty"`
	DueDate  string              `json:"due_date,omitempty"`
	Discount *bankSlipV1Discount `json:"discount,omitempty"`
	Interest *bankSlipV1Fee      `json:"interest,omitempty"`
	Fine     *bankSlipV1Fee      `json:"fine,omitempty"`
}

// empty reports whether the patch would send nothing, which the contract rejects
// (minProperties: 1) and which is always a caller bug.
func (b bankSlipV1Patch) empty() bool {
	return b.Amount == nil && b.DueDate == "" && b.Discount == nil && b.Interest == nil && b.Fine == nil
}

// bankSlipV1Payment is one settlement line the bank fills in when the slip is paid.
type bankSlipV1Payment struct {
	Date   string     `json:"date"`
	Amount brlDecimal `json:"amount"`
}

// bankSlipV1Response covers both the create response and the read: the create carries
// the printable artifacts, the read adds status, payments and the registered fees.
type bankSlipV1Response struct {
	ID                  string              `json:"id"`
	OriginatorID        string              `json:"originator_id"`
	ExternalReferenceID string              `json:"external_reference_id"`
	Amount              brlDecimal          `json:"amount"`
	Status              string              `json:"status"`
	EmissionDate        string              `json:"emission_date"`
	DueDate             string              `json:"due_date"`
	Instructions        []string            `json:"instructions"`
	Payments            []bankSlipV1Payment `json:"payments"`
	InternalID          string              `json:"internal_id"`
	BillingScheme       string              `json:"billing_scheme"`
	BillingType         string              `json:"billing_type"`
	DigitableLine       string              `json:"digitable_line"`
	BarCode             string              `json:"bar_code"`
	OurNumber           string              `json:"our_number"`
	Discount            *bankSlipV1Discount `json:"discount"`
	Interest            *bankSlipV1Fee      `json:"interest"`
	Fine                *bankSlipV1Fee      `json:"fine"`
}

// externalReferenceV1 derives the v1 external reference from a local boleto id. The
// ceiling is 10 alphanumeric characters, so the 26-char Crockford derivation the v2
// surface uses does not fit — this takes the leading characters of that same encoding,
// which keeps it deterministic and addressable while staying inside the pattern.
//
// Ten Crockford characters carry 50 bits. That is not a collision-proof namespace the
// way the v2 reference is, and it is the contract's ceiling, not a choice: the bank
// says the reference "deve ser único para cada cliente" and does not validate it.
func externalReferenceV1(boletoID string) string {
	ref := externalReferenceID(boletoID)
	if len(ref) > bankSlipV1RefMaxLen {
		return ref[:bankSlipV1RefMaxLen]
	}
	return ref
}

// toBankSlipV1Fee maps a percentage-or-fixed pair into the v1 fee block, or nil when
// both are zero. bps and cents are mutually exclusive; a caller setting both is a
// caller error, because the bank carries ONE value with ONE type.
func toBankSlipV1Fee(op string, bps, cents int64, afterDays int) (*bankSlipV1Fee, error) {
	switch {
	case bps > 0 && cents > 0:
		return nil, &Error{Op: op, sentinel: shared.ErrValidation}
	case bps > 0:
		return &bankSlipV1Fee{Type: bankSlipV1TypePercent, Value: brlDecimal(bps), DeadLine: afterDays}, nil
	case cents > 0:
		return &bankSlipV1Fee{Type: bankSlipV1TypeValue, Value: brlDecimal(cents), DeadLine: afterDays}, nil
	default:
		return nil, nil
	}
}

// toBankSlipV1Discount maps the discount schedule. All tiers must use the same form
// (percentage or fixed) because the contract carries one discount_type for the whole
// schedule, and the deadlines must be strictly decreasing from first to third —
// the bank's own rule, checked here so a violation is a typed error rather than a 400.
func toBankSlipV1Discount(op string, tiers []ports.BoletoDiscountTier) (*bankSlipV1Discount, error) {
	if len(tiers) == 0 {
		return nil, nil
	}
	if len(tiers) > bankSlipV1MaxDiscounts {
		return nil, &Error{Op: op, sentinel: shared.ErrValidation}
	}

	var percent, fixed bool
	for _, t := range tiers {
		switch {
		case t.Bps > 0 && t.FixedCents > 0:
			return nil, &Error{Op: op, sentinel: shared.ErrValidation}
		case t.Bps > 0:
			percent = true
		case t.FixedCents > 0:
			fixed = true
		default:
			// A tier worth nothing is not a discount; it would occupy a band the
			// caller probably meant to fill.
			return nil, &Error{Op: op, sentinel: shared.ErrValidation}
		}
		if t.DaysBeforeDue < 0 {
			return nil, &Error{Op: op, sentinel: shared.ErrValidation}
		}
	}
	if percent && fixed {
		return nil, &Error{Op: op, sentinel: shared.ErrValidation}
	}

	out := &bankSlipV1Discount{DiscountType: bankSlipV1TypeValue}
	if percent {
		out.DiscountType = bankSlipV1TypePercent
	}
	bands := []**bankSlipV1DiscountTier{&out.First, &out.Second, &out.Third}
	prev := -1
	for i, t := range tiers {
		if prev >= 0 && t.DaysBeforeDue >= prev {
			// first > second > third, strictly. Equal deadlines are rejected by the
			// bank, and an ascending list means the caller ordered them backwards.
			return nil, &Error{Op: op, sentinel: shared.ErrValidation}
		}
		prev = t.DaysBeforeDue
		value := t.FixedCents
		if percent {
			value = t.Bps
		}
		*bands[i] = &bankSlipV1DiscountTier{Value: brlDecimal(value), DeadLine: t.DaysBeforeDue}
	}
	return out, nil
}

// validateBankSlipV1 checks what the v1 contract bounds and what it does NOT carry.
//
// ValidUntil is refused rather than dropped: the v1 create has no payment-validity
// field at all, and silently discarding one would register a slip payable for longer
// than the caller intended.
func validateBankSlipV1(op string, req ports.BoletoRequest) error {
	if req.AmountCents <= 0 || req.DueDate.IsZero() {
		return &Error{Op: op, sentinel: shared.ErrValidation}
	}
	if !req.ValidUntil.IsZero() {
		return &Error{Op: op, sentinel: shared.ErrValidation}
	}
	if req.Modality.Normalized() != ports.ModalityBoleto {
		// v1 issues no PIX QR. A caller asking for BolePix must go to the v2 surface,
		// not receive a slip with no QR and no explanation.
		return &Error{Op: op, sentinel: shared.ErrValidation}
	}
	return validatePayer(op, req.Payer)
}

// toBankSlipV1Payer maps the payer. The street and number are separate fields here,
// unlike the v2 surface which composes them into one string.
func toBankSlipV1Payer(p ports.BoletoPayer) bankSlipV1Payer {
	return bankSlipV1Payer{
		Name:  strings.TrimSpace(p.Name),
		TaxID: strings.TrimSpace(p.TaxID),
		Address: bankSlipV1Address{
			Street:  strings.TrimSpace(p.Address.Street),
			Number:  p.Address.Number,
			City:    strings.TrimSpace(p.Address.City),
			State:   strings.ToUpper(strings.TrimSpace(p.Address.State)),
			ZipCode: strings.TrimSpace(p.Address.ZipCode),
		},
	}
}

// toPlainBoletoResult maps a v1 representation onto the shared boleto result. The
// modality is always ModalityBoleto: this surface has no PIX leg, so QRCode stays
// empty rather than being left to look merely absent.
func toPlainBoletoResult(boletoID string, out bankSlipV1Response) ports.BoletoResult {
	res := ports.BoletoResult{
		BoletoID:            boletoID,
		TxID:                out.ID,
		Status:              out.Status,
		Modality:            ports.ModalityBoleto,
		ExternalReferenceID: out.ExternalReferenceID,
		OurNumber:           out.OurNumber,
		DigitableLine:       out.DigitableLine,
		Barcode:             out.BarCode,
		AmountCents:         int64(out.Amount),
		DueDate:             parseScheduleDate(out.DueDate),
	}
	if out.Fine != nil {
		if out.Fine.Type == bankSlipV1TypePercent {
			res.FineBps = int64(out.Fine.Value)
		} else {
			res.FineFixedCents = int64(out.Fine.Value)
		}
	}
	if out.Interest != nil && out.Interest.Type == bankSlipV1TypePercent {
		res.MonthlyInterestBps = int64(out.Interest.Value)
	}
	if d := out.Discount; d != nil {
		percent := d.DiscountType == bankSlipV1TypePercent
		for _, tier := range []*bankSlipV1DiscountTier{d.First, d.Second, d.Third} {
			if tier == nil {
				continue
			}
			t := ports.BoletoDiscountTier{DaysBeforeDue: tier.DeadLine}
			if percent {
				t.Bps = int64(tier.Value)
			} else {
				t.FixedCents = int64(tier.Value)
			}
			res.Discounts = append(res.Discounts, t)
		}
	}
	return res
}

// CreatePlainBoleto registers a plain bank slip (roteiro B_01–B_03).
func (p *Provider) CreatePlainBoleto(ctx context.Context, tenantID string, req ports.BoletoRequest) (ports.BoletoResult, error) {
	const op = "create_plain_boleto"
	if strings.TrimSpace(req.BoletoID) == "" {
		return ports.BoletoResult{}, &Error{Op: op, sentinel: shared.ErrValidation}
	}
	if err := validateBankSlipV1(op, req); err != nil {
		return ports.BoletoResult{}, err
	}
	fine, err := toBankSlipV1Fee(op, req.FineBps, req.FineFixedCents, 0)
	if err != nil {
		return ports.BoletoResult{}, err
	}
	interest, err := toBankSlipV1Fee(op, req.MonthlyInterestBps, 0, 0)
	if err != nil {
		return ports.BoletoResult{}, err
	}
	discount, err := toBankSlipV1Discount(op, req.Discounts)
	if err != nil {
		return ports.BoletoResult{}, err
	}

	body := bankSlipV1Request{
		ExternalReferenceID: externalReferenceV1(req.BoletoID),
		Amount:              brlDecimal(req.AmountCents),
		DueDate:             req.DueDate.UTC().Format(dueDateLayout),
		Discount:            discount,
		Interest:            interest,
		Fine:                fine,
		BillingScheme:       p.billingScheme,
		Payer:               toBankSlipV1Payer(req.Payer),
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return ports.BoletoResult{}, &Error{Op: op, sentinel: shared.ErrValidation}
	}

	idem := req.IdempotencyKey
	if idem == "" {
		idem = req.BoletoID
	}
	httpReq, err := p.authedJSONRequest(ctx, tenantID, op, http.MethodPost, p.baseURL+bankSlipV1Path+"/", payload, idem)
	if err != nil {
		return ports.BoletoResult{}, err
	}
	setPartnerSoftware(httpReq)
	var out bankSlipV1Response
	if err := p.do(httpReq, op, &out); err != nil {
		return ports.BoletoResult{}, err
	}
	if strings.TrimSpace(out.ID) == "" {
		// The app treats a non-empty TxID as the billing-finalized marker; an empty one
		// would let a retry re-bill. Same guard the v2 create carries.
		return ports.BoletoResult{}, &Error{Op: op, sentinel: shared.ErrUnavailable}
	}
	res := toPlainBoletoResult(req.BoletoID, out)
	if res.ExternalReferenceID == "" {
		res.ExternalReferenceID = body.ExternalReferenceID
	}
	return res, nil
}

// GetPlainBoleto reconciles a registered slip (roteiro B_05).
func (p *Provider) GetPlainBoleto(ctx context.Context, tenantID, slipID string) (ports.BoletoResult, error) {
	const op = "get_plain_boleto"
	slipID = strings.TrimSpace(slipID)
	if slipID == "" {
		return ports.BoletoResult{}, &Error{Op: op, sentinel: shared.ErrValidation}
	}
	endpoint := p.baseURL + bankSlipV1Path + "/" + url.PathEscape(slipID)
	httpReq, err := p.authedJSONRequest(ctx, tenantID, op, http.MethodGet, endpoint, nil, "")
	if err != nil {
		return ports.BoletoResult{}, err
	}
	setPartnerSoftware(httpReq)
	var out bankSlipV1Response
	if err := p.do(httpReq, op, &out); err != nil {
		return ports.BoletoResult{}, err
	}
	return toPlainBoletoResult("", out), nil
}

// UpdatePlainBoleto amends a registered slip (roteiro B_04). The v1 contract admits
// amount, due date and the fee blocks; a patch that only touches something else — the
// payer, the instructions — is refused rather than sent as an empty body.
func (p *Provider) UpdatePlainBoleto(ctx context.Context, tenantID, slipID string, patch ports.BoletoPatch) (ports.BoletoResult, error) {
	const op = "update_plain_boleto"
	slipID = strings.TrimSpace(slipID)
	if slipID == "" {
		return ports.BoletoResult{}, &Error{Op: op, sentinel: shared.ErrValidation}
	}

	var body bankSlipV1Patch
	if patch.AmountCents != nil {
		if *patch.AmountCents <= 0 {
			return ports.BoletoResult{}, &Error{Op: op, sentinel: shared.ErrValidation}
		}
		v := brlDecimal(*patch.AmountCents)
		body.Amount = &v
	}
	if patch.DueDate != nil {
		if patch.DueDate.IsZero() {
			return ports.BoletoResult{}, &Error{Op: op, sentinel: shared.ErrValidation}
		}
		body.DueDate = patch.DueDate.UTC().Format(dueDateLayout)
	}
	if patch.Fees != nil {
		fine, err := toBankSlipV1Fee(op, patch.Fees.FineBps, patch.Fees.FineFixedCents, 0)
		if err != nil {
			return ports.BoletoResult{}, err
		}
		interest, err := toBankSlipV1Fee(op, patch.Fees.MonthlyInterestBps, 0, 0)
		if err != nil {
			return ports.BoletoResult{}, err
		}
		discount, err := toBankSlipV1Discount(op, patch.Fees.Discounts)
		if err != nil {
			return ports.BoletoResult{}, err
		}
		body.Fine, body.Interest, body.Discount = fine, interest, discount
	}
	if body.empty() {
		return ports.BoletoResult{}, &Error{Op: op, sentinel: shared.ErrValidation}
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return ports.BoletoResult{}, &Error{Op: op, sentinel: shared.ErrValidation}
	}
	endpoint := p.baseURL + bankSlipV1Path + "/" + url.PathEscape(slipID)
	httpReq, err := p.authedJSONRequest(ctx, tenantID, op, http.MethodPut, endpoint, payload, slipID)
	if err != nil {
		return ports.BoletoResult{}, err
	}
	setPartnerSoftware(httpReq)
	var out bankSlipV1Response
	if err := p.do(httpReq, op, &out); err != nil {
		return ports.BoletoResult{}, err
	}
	return toPlainBoletoResult("", out), nil
}

// CancelPlainBoleto performs the baixa of a registered slip (roteiro B_08). The
// contract answers 204 with no body, so there is nothing to map back.
func (p *Provider) CancelPlainBoleto(ctx context.Context, tenantID, slipID string) error {
	const op = "cancel_plain_boleto"
	slipID = strings.TrimSpace(slipID)
	if slipID == "" {
		return &Error{Op: op, sentinel: shared.ErrValidation}
	}
	endpoint := p.baseURL + bankSlipV1Path + "/" + url.PathEscape(slipID) + "/cancel"
	httpReq, err := p.authedJSONRequest(ctx, tenantID, op, http.MethodPut, endpoint, nil, slipID)
	if err != nil {
		return err
	}
	setPartnerSoftware(httpReq)
	return p.doNoContent(httpReq, op)
}

// GetPlainBoletoPDF renders the slip for the payer (roteiro B_06).
//
// The v1 contract declares a `base64_pdf_file` schema but the path's 200 references no
// schema at all, so both shapes are accepted — raw bytes and the base64 envelope — and
// what identifies a PDF is its own signature, never a header the bank may not set.
func (p *Provider) GetPlainBoletoPDF(ctx context.Context, tenantID, slipID string) (ports.BoletoDocument, error) {
	const op = "get_plain_boleto_pdf"
	slipID = strings.TrimSpace(slipID)
	if slipID == "" {
		return ports.BoletoDocument{}, &Error{Op: op, sentinel: shared.ErrValidation}
	}
	endpoint := p.baseURL + bankSlipV1Path + "/" + url.PathEscape(slipID) + "/pdf"
	httpReq, err := p.authedJSONRequest(ctx, tenantID, op, http.MethodGet, endpoint, nil, "")
	if err != nil {
		return ports.BoletoDocument{}, err
	}
	setPartnerSoftware(httpReq)
	body, _, err := p.doRaw(httpReq, op, maxDocumentBytes)
	if err != nil {
		return ports.BoletoDocument{}, err
	}
	content := body
	if !bytes.HasPrefix(content, pdfMagic) {
		decoded, ok := decodeBase64PDFEnvelope(body)
		if !ok {
			return ports.BoletoDocument{}, &Error{Op: op, sentinel: shared.ErrUnavailable,
				detail: "response is not a PDF"}
		}
		content = decoded
	}
	return ports.BoletoDocument{
		ContentType: pdfMediaType,
		Filename:    "boleto-" + slipID + ".pdf",
		Content:     content,
	}, nil
}

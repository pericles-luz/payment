package c6

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// fullBoletoPayer returns a complete, valid payer for the C6 bank_slips contract
// (ADR-0005). Shared by the boleto adapter tests that need to clear the adapter's
// mandatory-payer validation.
func fullBoletoPayer() ports.BoletoPayer {
	return ports.BoletoPayer{
		Name:  "Fulano de Tal",
		TaxID: "12345678901",
		Address: ports.BoletoAddress{
			Street:       "Rua das Flores",
			Number:       123,
			Neighborhood: "Asa Sul",
			City:         "Brasília",
			State:        "DF",
			ZipCode:      "70000000",
		},
	}
}

// externalRefPattern is the exact format the C6 bank_slips contract requires for
// external_reference_id (ADR-0005).
var externalRefPattern = regexp.MustCompile(`^[a-zA-Z0-9]{1,10}$`)

// roteiro grupos 1–3 (ADR-0005): CreateBoleto must serialize the real C6 bank_slips
// contract — amount, due_date (yyyy-MM-dd), external_reference_id (^[a-zA-Z0-9]{1,10}$),
// and the nested payer{name,tax_id,address{...}} — to POST /v1/bank_slips, NOT the
// previous invented /boletos body.
func TestCreateBoletoBankSlipsBody(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	// A tenant WITH a registered random PIX key: that key is what turns a plain boleto
	// into a BolePix, so the QR sub-object only appears when the credential carries one.
	creds := oneTenant("t1", "client-1", "secret-1")
	c := creds.creds["t1"]
	c.CreditorKey = "123e4567-e89b-12d3-a456-426614174000"
	creds.creds["t1"] = c
	p := ps.provider(t, creds)

	due := time.Date(2026, 7, 1, 15, 4, 5, 0, time.UTC)
	if _, err := p.CreateBoleto(context.Background(), "t1", ports.BoletoRequest{
		TenantID: "t1", BoletoID: "11111111-2222-3333-4444-555555555555",
		AmountCents: 1234, Currency: "BRL", DueDate: due,
		FineBps: 200, MonthlyInterestBps: 100,
		Payer:       fullBoletoPayer(),
		Description: "Compra de produto X",
	}); err != nil {
		t.Fatalf("CreateBoleto: %v", err)
	}

	// amount is a decimal NUMBER on the wire (reais) — json.Number preserves the raw token
	// so the exact serialization is asserted without a float comparison.
	var sent struct {
		Amount              json.Number `json:"amount"`
		DueDate             string      `json:"due_date"`
		Description         string      `json:"description"`
		ExternalReferenceID string      `json:"external_reference_id"`
		Fees                *struct {
			FineValue     json.Number `json:"fine_value"`
			FineType      string      `json:"fine_type"`
			InterestValue json.Number `json:"interest_value"`
			InterestType  string      `json:"interest_type"`
		} `json:"fees"`
		Payer struct {
			Name    string `json:"name"`
			TaxID   string `json:"tax_id"`
			Address struct {
				Address      string `json:"address"`
				Neighborhood string `json:"neighborhood"`
				City         string `json:"city"`
				State        string `json:"state"`
				ZipCode      string `json:"zip_code"`
			} `json:"address"`
		} `json:"payer"`
		PaymentMethod struct {
			BankSlip struct {
				BillingScheme string `json:"billing_scheme"`
			} `json:"bank_slip"`
			Pix *struct {
				Key  string `json:"key"`
				Type string `json:"type"`
			} `json:"pix"`
		} `json:"payment_method"`
	}
	if err := json.Unmarshal(ps.body(), &sent); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	// 1234 centavos => the decimal "12.34" (not 1234, not 12.340000001).
	if sent.Amount.String() != "12.34" {
		t.Fatalf("amount: want decimal 12.34, got %q (body=%s)", sent.Amount.String(), ps.body())
	}
	if sent.DueDate != "2026-07-01" {
		t.Fatalf("due_date must be yyyy-MM-dd, got %q", sent.DueDate)
	}
	// description is REQUIRED by the bank; a body without it is refused at registration.
	if sent.Description != "Compra de produto X" {
		t.Fatalf("description not transported: %q", sent.Description)
	}
	if !externalRefPattern.MatchString(sent.ExternalReferenceID) {
		t.Fatalf("external_reference_id %q must match %s", sent.ExternalReferenceID, externalRefPattern)
	}
	// Fees ride in ONE flat object — not the two separate fine/interest objects the
	// pre-contract implementation sent. 200 bps => "2.00" PERCENTAGE.
	if sent.Fees == nil {
		t.Fatalf("fees object missing: %s", ps.body())
	}
	if sent.Fees.FineValue.String() != "2.00" || sent.Fees.FineType != "PERCENTAGE" {
		t.Fatalf("fine not mapped: %+v (body=%s)", sent.Fees, ps.body())
	}
	if sent.Fees.InterestValue.String() != "1.00" || sent.Fees.InterestType != "MONTHLY_PERCENTAGE" {
		t.Fatalf("interest not mapped: %+v (body=%s)", sent.Fees, ps.body())
	}
	if sent.Payer.Name != "Fulano de Tal" || sent.Payer.TaxID != "12345678901" {
		t.Fatalf("payer not mapped: %+v", sent.Payer)
	}
	// The contract has ONE address line (street composed with the number) plus a
	// mandatory neighborhood — not the street/number pair of the previous body.
	a := sent.Payer.Address
	if a.Address != "Rua das Flores, 123" || a.Neighborhood != "Asa Sul" || a.City != "Brasília" || a.State != "DF" || a.ZipCode != "70000000" {
		t.Fatalf("payer address not mapped: %+v", a)
	}
	// payment_method is what makes this a BolePix: the carteira registers the slip and the
	// tenant's random PIX key adds the QR Code to the same charge.
	if got := sent.PaymentMethod.BankSlip.BillingScheme; got != defaultBillingScheme {
		t.Fatalf("billing_scheme = %q, want %q", got, defaultBillingScheme)
	}
	if sent.PaymentMethod.Pix == nil || sent.PaymentMethod.Pix.Type != pixKeyTypeEVP {
		t.Fatalf("pix sub-object missing or wrong type: %+v (body=%s)", sent.PaymentMethod.Pix, ps.body())
	}

	// Fields the contract does not define must be gone: the strict schema rejects them,
	// and `valid_until` in particular was invented by the previous implementation.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(ps.body(), &raw); err != nil {
		t.Fatalf("decode raw: %v", err)
	}
	for _, gone := range []string{
		"payer_tax_id", "amount_cents", "boleto_id", "currency", "valid_until",
		"fine", "interest", "fine_bps", "fine_fixed_cents", "monthly_interest_bps", "discounts",
	} {
		if _, ok := raw[gone]; ok {
			t.Fatalf("field %q is not in the C6 contract: %s", gone, ps.body())
		}
	}
}

// The real C6 201 (SIN-65888) is mapped onto the port result. The response carries
// id/our_number/bar_code/digitable_line/amount — none of the legacy keys — and NO
// status/txid/qr_code (those are read-sourced later).
func TestCreateBoleto201Mapped(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	ps.boletoCreate = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		// Verbatim shape from the captured 201 (SIN-65888 contrato-real-bank-slips).
		// Official C6 201: artifacts nested under payment_method.bank_slip, QR under .pix.
		_, _ = w.Write([]byte(`{"amount":12.34,"due_date":"2026-07-25","id":"01KW0CY8QNAQK50SJ2ESDG5YFP","external_reference_id":"ref1","payment_method":{"bank_slip":{"originator_id":"000006572943","our_number":"10233820","billing_scheme":"21","billing_type":"3","bar_code":"33699151800000012340000065729430010233820213","digitable_line":"33690.00009 65729.430010 02338.202134 9 15180000001234"},"pix":{"qr_code":"00020126_EMV_PAYLOAD","reference":"ref-pix"}}}`))
	}
	p := ps.provider(t, oneTenant("t1", "c", "s"))

	res, err := p.CreateBoleto(context.Background(), "t1", ports.BoletoRequest{
		TenantID: "t1", BoletoID: "bol_9", AmountCents: 1234, Currency: "BRL",
		DueDate: time.Unix(1_800_000_000, 0), Payer: fullBoletoPayer(), Description: "Compra de produto X",
	})
	if err != nil {
		t.Fatalf("CreateBoleto: %v", err)
	}
	if res.BoletoID != "01KW0CY8QNAQK50SJ2ESDG5YFP" {
		t.Fatalf("BoletoID: want C6 id, got %q", res.BoletoID)
	}
	// CRITICAL (billing-finalized invariant): id must map to TxID, never empty — an empty
	// TxID lets a retry/concurrent registration re-bill (duplicate ledger entry).
	if res.TxID == "" {
		t.Fatalf("TxID must be non-empty (id), else double-bill: %+v", res)
	}
	if res.TxID != res.BoletoID {
		t.Fatalf("TxID must equal the C6 id (%q), got %q", res.BoletoID, res.TxID)
	}
	if res.OurNumber != "10233820" {
		t.Fatalf("OurNumber: want 10233820, got %q", res.OurNumber)
	}
	if res.DigitableLine != "33690.00009 65729.430010 02338.202134 9 15180000001234" {
		t.Fatalf("DigitableLine not mapped: %q", res.DigitableLine)
	}
	if res.Barcode != "33699151800000012340000065729430010233820213" {
		t.Fatalf("Barcode (bar_code) not mapped: %q", res.Barcode)
	}
	// amount 12.34 (decimal reais) parses back to 1234 centavos with no float drift.
	if res.AmountCents != 1234 {
		t.Fatalf("AmountCents: want 1234 (from 12.34), got %d", res.AmountCents)
	}
	// The BolePix QR Code IS returned at registration (payment_method.pix.qr_code) — the
	// pre-contract implementation assumed it was only available on a later read, so a
	// caller could never hand the payer a QR without an extra round-trip. Status stays
	// empty: C6 does not echo it on create.
	if res.QRCode != "00020126_EMV_PAYLOAD" {
		t.Fatalf("QR Code must be mapped from payment_method.pix: %+v", res)
	}
	if res.Status != "" {
		t.Fatalf("status is not echoed on create: %+v", res)
	}
}

// The adapter (not the app, not the stub) enforces the mandatory payer for the real
// C6 contract: each missing required field is shared.ErrValidation, surfaced BEFORE the
// request reaches C6 (the token endpoint is never hit). Number==0 is allowed (the
// "S/N" homologation case, ADR-0005).
func TestCreateBoletoRequiresFullPayer(t *testing.T) {
	t.Parallel()
	base := func() ports.BoletoRequest {
		return ports.BoletoRequest{
			TenantID: "t1", BoletoID: "bol_1", AmountCents: 100, Currency: "BRL",
			DueDate: time.Unix(1_800_000_000, 0), Payer: fullBoletoPayer(), Description: "Compra de produto X",
		}
	}
	cases := []struct {
		name string
		mut  func(*ports.BoletoRequest)
	}{
		{"no_name", func(r *ports.BoletoRequest) { r.Payer.Name = "" }},
		{"no_tax_id", func(r *ports.BoletoRequest) { r.Payer.TaxID = "" }},
		{"no_street", func(r *ports.BoletoRequest) { r.Payer.Address.Street = "" }},
		{"no_city", func(r *ports.BoletoRequest) { r.Payer.Address.City = "" }},
		{"no_state", func(r *ports.BoletoRequest) { r.Payer.Address.State = "" }},
		{"no_zip", func(r *ports.BoletoRequest) { r.Payer.Address.ZipCode = "" }},
		{"empty_payer", func(r *ports.BoletoRequest) { r.Payer = ports.BoletoPayer{} }},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ps := newProductServer(t)
			p := ps.provider(t, oneTenant("t1", "client-1", "secret-1"))
			req := base()
			tc.mut(&req)
			if _, err := p.CreateBoleto(context.Background(), "t1", req); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("%s: want ErrValidation, got %v", tc.name, err)
			}
			if ps.tokenCount() != 0 {
				t.Fatalf("%s: a malformed payer must fail before C6 is called, token hits=%d", tc.name, ps.tokenCount())
			}
		})
	}

	// Number==0 ("S/N") is accepted (not a missing-field error).
	t.Run("zero_number_allowed", func(t *testing.T) {
		t.Parallel()
		ps := newProductServer(t)
		p := ps.provider(t, oneTenant("t1", "client-1", "secret-1"))
		req := base()
		req.Payer.Address.Number = 0
		if _, err := p.CreateBoleto(context.Background(), "t1", req); err != nil {
			t.Fatalf("zero number must be allowed: %v", err)
		}
	})
}

// external_reference_id is a deterministic, idempotent function of the boleto id so a
// retried registration yields the same reference and C6 collapses the retry.
func TestExternalReferenceID(t *testing.T) {
	t.Parallel()
	const id = "11111111-2222-3333-4444-555555555555"
	a := externalReferenceID(id)
	b := externalReferenceID(id)
	if a != b {
		t.Fatalf("not deterministic: %q vs %q", a, b)
	}
	if !externalRefPattern.MatchString(a) {
		t.Fatalf("ref %q must match %s", a, externalRefPattern)
	}
	if other := externalReferenceID("99999999-8888-7777-6666-555555555555"); other == a {
		t.Fatalf("distinct ids should (almost surely) differ: both %q", a)
	}
}

// brlDecimal must serialize/parse money via integer arithmetic ONLY — never float64 — so a
// payment amount can never drift. Values are chosen to expose float drift (1234/100 in
// float64 is 12.340000000000001) and the 2-digit-fraction edge cases (sub-real, trailing
// zero). This invariant is the defect SIN-65953 exists to kill; it must stay test-locked.
func TestBrlDecimalNoFloatDrift(t *testing.T) {
	t.Parallel()
	cases := []struct {
		cents int64
		wire  string
	}{
		{1234, "12.34"},
		{1010, "10.10"},
		{100000, "1000.00"},
		{5, "0.05"},
		{99, "0.99"},
		{200, "2.00"}, // 200 bps ⇒ "2.00" (fee value path)
		{0, "0.00"},
		{-1234, "-12.34"},
	}
	for _, tc := range cases {
		b, err := json.Marshal(brlDecimal(tc.cents))
		if err != nil {
			t.Fatalf("marshal %d: %v", tc.cents, err)
		}
		if string(b) != tc.wire {
			t.Fatalf("marshal %d: want %q, got %q", tc.cents, tc.wire, string(b))
		}
		// Round-trip: the wire decimal parses back to the exact centavos.
		var back brlDecimal
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatalf("unmarshal %q: %v", string(b), err)
		}
		if int64(back) != tc.cents {
			t.Fatalf("round-trip %q: want %d centavos, got %d", string(b), tc.cents, int64(back))
		}
	}
}

// brlDecimal.UnmarshalJSON accepts the value as a JSON number OR a numeric string and
// normalizes the fraction to two digits, all via integer parsing (never ParseFloat).
func TestBrlDecimalUnmarshalForms(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in    string
		cents int64
	}{
		{`12.34`, 1234},
		{`"12.34"`, 1234}, // numeric string
		{`10.1`, 1010},    // short fraction padded
		{`7`, 700},        // no fraction
		{`0.05`, 5},
		{`100`, 10000},
		{`""`, 0},
		{`null`, 0},
	}
	for _, tc := range cases {
		var d brlDecimal
		if err := json.Unmarshal([]byte(tc.in), &d); err != nil {
			t.Fatalf("unmarshal %s: %v", tc.in, err)
		}
		if int64(d) != tc.cents {
			t.Fatalf("unmarshal %s: want %d, got %d", tc.in, tc.cents, int64(d))
		}
	}
}

// Zero-fee must OMIT the fine/interest keys entirely (the strict C6 schema 400s on a
// zero-valued fee key); a fixed fine maps to type FIXED with the value in reais. FineBps
// and FineFixedCents are mutually exclusive (percentage wins when both are set).
func TestBankSlipFeesShapeAndOmitEmpty(t *testing.T) {
	t.Parallel()

	decodeFee := func(t *testing.T, body []byte, key string) (present bool, value, typ string) {
		t.Helper()
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(body, &raw); err != nil {
			t.Fatalf("decode raw: %v", err)
		}
		msg, ok := raw["fees"]
		if !ok {
			return false, "", ""
		}
		var f struct {
			FineValue     json.Number `json:"fine_value"`
			FineType      string      `json:"fine_type"`
			InterestValue json.Number `json:"interest_value"`
			InterestType  string      `json:"interest_type"`
		}
		if err := json.Unmarshal(msg, &f); err != nil {
			t.Fatalf("decode fees: %v", err)
		}
		if key == "interest" {
			if f.InterestType == "" {
				return false, "", ""
			}
			return true, f.InterestValue.String(), f.InterestType
		}
		if f.FineType == "" {
			return false, "", ""
		}
		return true, f.FineValue.String(), f.FineType
	}

	t.Run("zero_fees_omit_keys", func(t *testing.T) {
		t.Parallel()
		ps := newProductServer(t)
		p := ps.provider(t, oneTenant("t1", "c", "s"))
		if _, err := p.CreateBoleto(context.Background(), "t1", ports.BoletoRequest{
			TenantID: "t1", BoletoID: "b", AmountCents: 100, Currency: "BRL",
			DueDate: time.Unix(1_800_000_000, 0), Payer: fullBoletoPayer(), Description: "Compra de produto X",
		}); err != nil {
			t.Fatalf("CreateBoleto: %v", err)
		}
		if present, _, _ := decodeFee(t, ps.body(), "fine"); present {
			t.Fatalf("zero fine must omit the key: %s", ps.body())
		}
		if present, _, _ := decodeFee(t, ps.body(), "interest"); present {
			t.Fatalf("zero interest must omit the key: %s", ps.body())
		}
	})

	t.Run("fixed_fine_is_FIXED_reais", func(t *testing.T) {
		t.Parallel()
		ps := newProductServer(t)
		p := ps.provider(t, oneTenant("t1", "c", "s"))
		if _, err := p.CreateBoleto(context.Background(), "t1", ports.BoletoRequest{
			TenantID: "t1", BoletoID: "b", AmountCents: 100, Currency: "BRL",
			DueDate: time.Unix(1_800_000_000, 0), FineFixedCents: 550, Payer: fullBoletoPayer(), Description: "Compra de produto X",
		}); err != nil {
			t.Fatalf("CreateBoleto: %v", err)
		}
		present, value, typ := decodeFee(t, ps.body(), "fine")
		if !present || value != "5.50" || typ != feeTypeFixedValue {
			t.Fatalf("fixed fine: want {5.50,FIXED_VALUE}, got present=%v value=%q type=%q (body=%s)", present, value, typ, ps.body())
		}
	})

	t.Run("percentage_wins_when_both_set", func(t *testing.T) {
		t.Parallel()
		ps := newProductServer(t)
		p := ps.provider(t, oneTenant("t1", "c", "s"))
		if _, err := p.CreateBoleto(context.Background(), "t1", ports.BoletoRequest{
			TenantID: "t1", BoletoID: "b", AmountCents: 100, Currency: "BRL",
			DueDate: time.Unix(1_800_000_000, 0), FineBps: 150, FineFixedCents: 999, Payer: fullBoletoPayer(), Description: "Compra de produto X",
		}); err != nil {
			t.Fatalf("CreateBoleto: %v", err)
		}
		present, value, typ := decodeFee(t, ps.body(), "fine")
		if !present || value != "1.50" || typ != "PERCENTAGE" {
			t.Fatalf("percentage must win: want {1.50,PERCENTAGE}, got present=%v value=%q type=%q", present, value, typ)
		}
	})
}

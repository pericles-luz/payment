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
			Street:  "Rua das Flores",
			Number:  123,
			City:    "Brasília",
			State:   "DF",
			ZipCode: "70000000",
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
	p := ps.provider(t, oneTenant("t1", "client-1", "secret-1"))

	due := time.Date(2026, 7, 1, 15, 4, 5, 0, time.UTC)
	if _, err := p.CreateBoleto(context.Background(), "t1", ports.BoletoRequest{
		TenantID: "t1", BoletoID: "11111111-2222-3333-4444-555555555555",
		AmountCents: 1234, Currency: "BRL", DueDate: due,
		FineBps: 200, MonthlyInterestBps: 100,
		Payer: fullBoletoPayer(),
	}); err != nil {
		t.Fatalf("CreateBoleto: %v", err)
	}

	var sent struct {
		Amount              int64  `json:"amount"`
		DueDate             string `json:"due_date"`
		ExternalReferenceID string `json:"external_reference_id"`
		Payer               struct {
			Name    string `json:"name"`
			TaxID   string `json:"tax_id"`
			Address struct {
				Street  string `json:"street"`
				Number  int    `json:"number"`
				City    string `json:"city"`
				State   string `json:"state"`
				ZipCode string `json:"zip_code"`
			} `json:"address"`
		} `json:"payer"`
	}
	if err := json.Unmarshal(ps.body(), &sent); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if sent.Amount != 1234 {
		t.Fatalf("amount: want 1234, got %d (body=%s)", sent.Amount, ps.body())
	}
	if sent.DueDate != "2026-07-01" {
		t.Fatalf("due_date must be yyyy-MM-dd, got %q", sent.DueDate)
	}
	if !externalRefPattern.MatchString(sent.ExternalReferenceID) {
		t.Fatalf("external_reference_id %q must match %s", sent.ExternalReferenceID, externalRefPattern)
	}
	if sent.Payer.Name != "Fulano de Tal" || sent.Payer.TaxID != "12345678901" {
		t.Fatalf("payer not mapped: %+v", sent.Payer)
	}
	a := sent.Payer.Address
	if a.Street != "Rua das Flores" || a.Number != 123 || a.City != "Brasília" || a.State != "DF" || a.ZipCode != "70000000" {
		t.Fatalf("payer address not mapped: %+v", a)
	}

	// The invented flat fields must be gone (mass-assignment / contract drift guard).
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(ps.body(), &raw); err != nil {
		t.Fatalf("decode raw: %v", err)
	}
	for _, gone := range []string{"payer_tax_id", "amount_cents", "boleto_id", "currency"} {
		if _, ok := raw[gone]; ok {
			t.Fatalf("legacy field %q must not be in the bank_slips body: %s", gone, ps.body())
		}
	}
}

// The C6 201 (with the scannable artifacts) is mapped onto the port result.
func TestCreateBoleto201Mapped(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	ps.boletoCreate = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"boleto_id":"bol_9","txid":"tx_9","status":"REGISTERED","qr_code":"emv-9","barcode":"bar-9","amount_cents":1234}`))
	}
	p := ps.provider(t, oneTenant("t1", "c", "s"))

	res, err := p.CreateBoleto(context.Background(), "t1", ports.BoletoRequest{
		TenantID: "t1", BoletoID: "bol_9", AmountCents: 1234, Currency: "BRL",
		DueDate: time.Unix(1_800_000_000, 0), Payer: fullBoletoPayer(),
	})
	if err != nil {
		t.Fatalf("CreateBoleto: %v", err)
	}
	if res.BoletoID != "bol_9" || res.TxID != "tx_9" || res.Status != "REGISTERED" || res.QRCode != "emv-9" || res.Barcode != "bar-9" {
		t.Fatalf("201 not mapped: %+v", res)
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
			DueDate: time.Unix(1_800_000_000, 0), Payer: fullBoletoPayer(),
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

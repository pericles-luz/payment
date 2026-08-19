package c6

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// --- Real BACEN cobv wire mapping (SIN-65860) ---

// A fixed-amount discount is transported as the BACEN "valor por antecipação"
// modalidade (3) carrying valor (not valorPerc), and read back into DiscountFixedCents.
func TestCobvFixedDiscountRoundTrip(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	ps.cobvGet = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"txid":"` + r.PathValue("txid") + `","status":"ATIVA","pixCopiaECola":"emv","location":"https://pix.c6/cobv","calendario":{"dataDeVencimento":"2030-03-17","validadeAposVencimento":3},"valor":{"original":"10.00","desconto":{"modalidade":3,"valor":"2.50"}}}`))
	}
	p := ps.provider(t, oneTenant("t1", "c", "s"))

	req := cobvReq("t1")
	req.DiscountBps = 0
	req.DiscountFixedCents = 250
	if _, err := p.CreateDueCharge(context.Background(), "t1", req); err != nil {
		t.Fatalf("CreateDueCharge: %v", err)
	}
	var sent struct {
		Valor struct {
			Desconto struct {
				Modalidade int    `json:"modalidade"`
				Valor      string `json:"valor"`
				ValorPerc  string `json:"valorPerc"`
			} `json:"desconto"`
		} `json:"valor"`
	}
	if err := json.Unmarshal(ps.body(), &sent); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if sent.Valor.Desconto.Modalidade != 3 || sent.Valor.Desconto.Valor != "2.50" || sent.Valor.Desconto.ValorPerc != "" {
		t.Fatalf("fixed discount must be modalidade 3 valor, got %s", ps.body())
	}

	res, err := p.GetDueCharge(context.Background(), "t1", "tx")
	if err != nil {
		t.Fatalf("GetDueCharge: %v", err)
	}
	if res.DiscountFixedCents != 250 || res.DiscountBps != 0 {
		t.Fatalf("fixed discount must read back into DiscountFixedCents, got %+v", res)
	}
	if !res.DueDate.Equal(time.Date(2030, 3, 17, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("due date not echoed: %v", res.DueDate)
	}
}

// When C6 omits the top-level "location", the adapter falls back to the BACEN
// loc.location object (mirrors the immediate-charge behaviour).
func TestCobvLocationFallback(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	ps.cobvGet = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"txid":"` + r.PathValue("txid") + `","status":"ATIVA","pixCopiaECola":"emv","loc":{"location":"https://pix.c6/loc-fallback"},"valor":{"original":"10.00"}}`))
	}
	p := ps.provider(t, oneTenant("t1", "c", "s"))

	res, err := p.GetDueCharge(context.Background(), "t1", "tx")
	if err != nil {
		t.Fatalf("GetDueCharge: %v", err)
	}
	if res.QRCodeLocation != "https://pix.c6/loc-fallback" {
		t.Fatalf("location must fall back to loc.location, got %q", res.QRCodeLocation)
	}
	// A malformed/absent dataDeVencimento must not fail the read; it maps to zero.
	if !res.DueDate.IsZero() {
		t.Fatalf("absent due date must be zero, got %v", res.DueDate)
	}
}

// The money is parsed fail-secure: a present-but-malformed valor.original (or a
// malformed receipt) maps to ErrUnavailable rather than reconciling to zero, while a
// malformed cosmetic rate is tolerated as zero.
func TestCobvMalformedMoneyFailsSecure(t *testing.T) {
	t.Parallel()
	t.Run("original", func(t *testing.T) {
		t.Parallel()
		ps := newProductServer(t)
		ps.cobvGet = func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"txid":"x","status":"ATIVA","valor":{"original":"abc"}}`))
		}
		p := ps.provider(t, oneTenant("t1", "c", "s"))
		if _, err := p.GetDueCharge(context.Background(), "t1", "tx"); !errors.Is(err, shared.ErrUnavailable) {
			t.Fatalf("malformed original must map to ErrUnavailable, got %v", err)
		}
	})
	t.Run("receipt", func(t *testing.T) {
		t.Parallel()
		ps := newProductServer(t)
		ps.cobvGet = func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"txid":"x","status":"CONCLUIDA","valor":{"original":"10.00"},"pix":[{"valor":"nope"}]}`))
		}
		p := ps.provider(t, oneTenant("t1", "c", "s"))
		if _, err := p.GetDueCharge(context.Background(), "t1", "tx"); !errors.Is(err, shared.ErrUnavailable) {
			t.Fatalf("malformed receipt must map to ErrUnavailable, got %v", err)
		}
	})
	t.Run("rate-tolerated", func(t *testing.T) {
		t.Parallel()
		ps := newProductServer(t)
		ps.cobvGet = func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"txid":"x","status":"ATIVA","valor":{"original":"10.00","multa":{"modalidade":2,"valorPerc":"oops"}}}`))
		}
		p := ps.provider(t, oneTenant("t1", "c", "s"))
		res, err := p.GetDueCharge(context.Background(), "t1", "tx")
		if err != nil {
			t.Fatalf("a cosmetic rate must not fail the read: %v", err)
		}
		if res.FineBps != 0 || res.ExpectedAmountCents != 1000 {
			t.Fatalf("malformed rate must read as zero, money intact: %+v", res)
		}
	})
}

// A charge with no devedor and no creditor key omits those blocks from the wire
// entirely (omitempty), proving the optional-field handling.
func TestCobvOmitsOptionalBlocks(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	p := ps.provider(t, oneTenant("t1", "c", "s"))

	req := ports.PixDueChargeRequest{
		TenantID: "t1", AmountCents: 1000, Currency: "BRL",
		DueDate: time.Date(2030, 3, 17, 0, 0, 0, 0, time.UTC), ValidityDays: 0,
		// `chave` is required by the contract, so it is always present — what this test
		// pins is that the OPTIONAL blocks stay omitted.
		CreditorKey:    "123e4567-e89b-12d3-a456-426614174000",
		IdempotencyKey: "no-extras",
	}
	if _, err := p.CreateDueCharge(context.Background(), "t1", req); err != nil {
		t.Fatalf("CreateDueCharge: %v", err)
	}
	var sent map[string]json.RawMessage
	if err := json.Unmarshal(ps.body(), &sent); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if _, ok := sent["devedor"]; ok {
		t.Fatalf("devedor must be omitted when no payer, body=%s", ps.body())
	}
	// `chave` is REQUIRED by the contract, so it must always ride — the field was
	// previously omitempty, which produced an opaque PSP 400.
	if _, ok := sent["chave"]; !ok {
		t.Fatalf("chave is required and must always be sent, body=%s", ps.body())
	}
	var valor struct {
		Multa    json.RawMessage `json:"multa"`
		Juros    json.RawMessage `json:"juros"`
		Desconto json.RawMessage `json:"desconto"`
	}
	_ = json.Unmarshal(sent["valor"], &valor)
	if valor.Multa != nil || valor.Juros != nil || valor.Desconto != nil {
		t.Fatalf("zero rates must omit their blocks, body=%s", ps.body())
	}
}

// A tenant with no registered PIX key cannot receive, so the charge is refused at our
// boundary with a named cause instead of an opaque 400 from the bank.
func TestCobvRequiresCreditorKey(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	p := ps.provider(t, oneTenant("t1", "c", "s"))

	_, err := p.CreateDueCharge(context.Background(), "t1", ports.PixDueChargeRequest{
		TenantID: "t1", AmountCents: 1000, Currency: "BRL",
		DueDate:        time.Date(2030, 3, 17, 0, 0, 0, 0, time.UTC),
		IdempotencyKey: "no-key",
	})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation, got %v", err)
	}
	if len(ps.body()) > 0 {
		t.Fatalf("nothing may reach the bank: %s", ps.body())
	}
}

// A due-date charge carries the debtor's FULL address — nome, cpf, logradouro, cidade,
// uf and cep are all required by the contract. The previous body sent only cpf/nome, so
// every cobv would have been refused by the bank. An immediate charge is deliberately
// unaffected: its devedor is optional and address-less.
func TestCobvDevedorCarriesFullAddress(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	p := ps.provider(t, oneTenant("t1", "c", "s"))

	if _, err := p.CreateDueCharge(context.Background(), "t1", ports.PixDueChargeRequest{
		TenantID: "t1", AmountCents: 1000, Currency: "BRL",
		DueDate:        time.Date(2030, 3, 17, 0, 0, 0, 0, time.UTC),
		DebtorTaxID:    "12345678901",
		DebtorName:     "Maria",
		DebtorStreet:   "Rua das Flores, 123",
		DebtorCity:     "Brasília",
		DebtorState:    "DF",
		DebtorZipCode:  "70000000",
		CreditorKey:    "123e4567-e89b-12d3-a456-426614174000",
		IdempotencyKey: "addr-1",
	}); err != nil {
		t.Fatalf("CreateDueCharge: %v", err)
	}

	var sent struct {
		Devedor struct {
			Nome       string `json:"nome"`
			CPF        string `json:"cpf"`
			Logradouro string `json:"logradouro"`
			Cidade     string `json:"cidade"`
			UF         string `json:"uf"`
			CEP        string `json:"cep"`
		} `json:"devedor"`
	}
	if err := json.Unmarshal(ps.body(), &sent); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	d := sent.Devedor
	if d.Nome != "Maria" || d.CPF != "12345678901" {
		t.Fatalf("devedor identity not mapped: %+v", d)
	}
	if d.Logradouro != "Rua das Flores, 123" || d.Cidade != "Brasília" || d.UF != "DF" || d.CEP != "70000000" {
		t.Fatalf("devedor address not mapped: %+v (body=%s)", d, ps.body())
	}
}

// The immediate charge keeps its address-less devedor: the contract does not ask for one
// there, and sending fields a schema does not define is how the boleto path broke. Asserted
// on the builders directly — the cobv builder is the only one that adds the address.
func TestCobDevedorStaysAddressLess(t *testing.T) {
	t.Parallel()
	cob := buildDevedorFields("12345678901", "Maria")
	if cob == nil {
		t.Fatal("devedor should be built")
	}
	if cob.Logradouro != "" || cob.Cidade != "" || cob.UF != "" || cob.CEP != "" {
		t.Fatalf("immediate charge must not carry an address: %+v", cob)
	}
	cobv := buildCobvDevedor(ports.PixDueChargeRequest{
		DebtorTaxID: "12345678901", DebtorName: "Maria",
		DebtorStreet: "Rua das Flores, 123", DebtorCity: "Brasília",
		DebtorState: "DF", DebtorZipCode: "70000000",
	})
	if cobv.Logradouro == "" || cobv.Cidade == "" || cobv.UF == "" || cobv.CEP == "" {
		t.Fatalf("due-date charge must carry the address: %+v", cobv)
	}
}

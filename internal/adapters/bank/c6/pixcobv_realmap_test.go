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
	if _, ok := sent["chave"]; ok {
		t.Fatalf("chave must be omitted when no creditor key, body=%s", ps.body())
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

package http_test

import (
	"net/http"
	"testing"
	"time"
)

// boletoBodyWithPayer is boletoBody plus the nested payer block (ADR-0005).
func boletoBodyWithPayer(payer map[string]any) map[string]any {
	return map[string]any{
		"amount_cents":         100000,
		"currency":             "BRL",
		"due_date":             time.Now().Add(240 * time.Hour).UTC().Format(time.RFC3339),
		"fine_bps":             200,
		"monthly_interest_bps": 100,
		"payer":                payer,
	}
}

func validPayerBody() map[string]any {
	return map[string]any{
		"name":   "Fulano de Tal",
		"tax_id": "12345678901",
		"address": map[string]any{
			"street":   "Rua das Flores",
			"number":   123,
			"city":     "Brasília",
			"state":    "DF",
			"zip_code": "70000000",
		},
	}
}

// The nested payer block decodes and maps through DTO → app (ADR-0005). A full,
// well-formed payer registers (201); a structurally invalid field is a 400; an unknown
// nested field is rejected by decodeJSON (anti mass-assignment).
func TestBoletoCreateWithPayerHTTP(t *testing.T) {
	t.Parallel()
	handler, _, _ := newBoletoFixture(t)

	t.Run("valid_full_payer_201", func(t *testing.T) {
		rec := do(t, handler, http.MethodPost, "/v1/boletos", tenantToken,
			map[string]string{"Idempotency-Key": "kp-ok"}, boletoBodyWithPayer(validPayerBody()))
		if rec.Code != http.StatusCreated {
			t.Fatalf("want 201, got %d body %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("bad_uf_400", func(t *testing.T) {
		payer := validPayerBody()
		payer["address"].(map[string]any)["state"] = "DFX"
		rec := do(t, handler, http.MethodPost, "/v1/boletos", tenantToken,
			map[string]string{"Idempotency-Key": "kp-uf"}, boletoBodyWithPayer(payer))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("bad UF: want 400, got %d body %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("bad_cep_400", func(t *testing.T) {
		payer := validPayerBody()
		payer["address"].(map[string]any)["zip_code"] = "700"
		rec := do(t, handler, http.MethodPost, "/v1/boletos", tenantToken,
			map[string]string{"Idempotency-Key": "kp-cep"}, boletoBodyWithPayer(payer))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("bad CEP: want 400, got %d body %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("unknown_nested_field_400", func(t *testing.T) {
		payer := validPayerBody()
		payer["evil"] = "x"
		rec := do(t, handler, http.MethodPost, "/v1/boletos", tenantToken,
			map[string]string{"Idempotency-Key": "kp-evil"}, boletoBodyWithPayer(payer))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("unknown nested field: want 400, got %d body %s", rec.Code, rec.Body.String())
		}
	})
}

package http_test

import (
	"net/http"
	"testing"
)

// The caller chooses the rails. "bolepix" yields a charge carrying a PIX QR alongside the
// slip; the response echoes the modality so nobody has to infer it from qr_code.
func TestBoletoPaymentMethodBolepix(t *testing.T) {
	t.Parallel()
	handler, _, _ := newBoletoFixture(t)

	body := boletoBody()
	body["payment_method"] = "bolepix"
	rec := do(t, handler, http.MethodPost, "/v1/boletos", tenantToken,
		map[string]string{"Idempotency-Key": "kbp1"}, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: status %d body %s", rec.Code, rec.Body.String())
	}
	got := decodePix(t, rec)
	if got["payment_method"] != "bolepix" {
		t.Fatalf("payment_method must be echoed: %v", got)
	}
	if qr, _ := got["qr_code"].(string); qr == "" {
		t.Fatalf("a bolepix must carry a qr_code: %v", got)
	}
}

// "boleto" yields a plain slip, and qr_code is omitted ENTIRELY rather than rendered as an
// empty string — a client that keys off presence must not see a QR field that promises
// nothing.
func TestBoletoPaymentMethodPlainOmitsQRCode(t *testing.T) {
	t.Parallel()
	handler, _, _ := newBoletoFixture(t)

	body := boletoBody()
	body["payment_method"] = "boleto"
	rec := do(t, handler, http.MethodPost, "/v1/boletos", tenantToken,
		map[string]string{"Idempotency-Key": "kbp2"}, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: status %d body %s", rec.Code, rec.Body.String())
	}
	got := decodePix(t, rec)
	if got["payment_method"] != "boleto" {
		t.Fatalf("payment_method must be echoed: %v", got)
	}
	if _, present := got["qr_code"]; present {
		t.Fatalf("a plain boleto must omit qr_code entirely: %v", got)
	}
}

// An absent payment_method means plain boleto. The default promises the least: it can
// never hand the payer a slip advertising a QR that was never issued.
func TestBoletoPaymentMethodDefaultsToPlain(t *testing.T) {
	t.Parallel()
	handler, _, _ := newBoletoFixture(t)

	rec := do(t, handler, http.MethodPost, "/v1/boletos", tenantToken,
		map[string]string{"Idempotency-Key": "kbp3"}, boletoBody())
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: status %d body %s", rec.Code, rec.Body.String())
	}
	got := decodePix(t, rec)
	if got["payment_method"] != "boleto" {
		t.Fatalf("default modality must be boleto, got %v", got["payment_method"])
	}
}

// An unrecognised modality is refused, not silently defaulted: sending "pix" or a typo is
// a caller error, and defaulting it would issue a product they did not ask for.
func TestBoletoPaymentMethodUnknownIsRejected(t *testing.T) {
	t.Parallel()
	handler, _, _ := newBoletoFixture(t)

	for _, v := range []string{"pix", "BOLEPIX_TYPO", "cartao"} {
		body := boletoBody()
		body["payment_method"] = v
		rec := do(t, handler, http.MethodPost, "/v1/boletos", tenantToken,
			map[string]string{"Idempotency-Key": "kbp-" + v}, body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("payment_method %q: status %d, want 400 (body %s)", v, rec.Code, rec.Body.String())
		}
	}
}

// Casing and surrounding space are normalized rather than rejected — they are unambiguous.
func TestBoletoPaymentMethodIsNormalized(t *testing.T) {
	t.Parallel()
	handler, _, _ := newBoletoFixture(t)

	body := boletoBody()
	body["payment_method"] = "  BolePix  "
	rec := do(t, handler, http.MethodPost, "/v1/boletos", tenantToken,
		map[string]string{"Idempotency-Key": "kbp4"}, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: status %d body %s", rec.Code, rec.Body.String())
	}
	if got := decodePix(t, rec); got["payment_method"] != "bolepix" {
		t.Fatalf("modality must be normalized, got %v", got["payment_method"])
	}
}

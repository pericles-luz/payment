package http_test

import (
	"net/http"
	"strings"
	"testing"
)

// registerBoletoForPDF registers a boleto and returns its id.
func registerBoletoForPDF(t *testing.T, handler http.Handler, idemKey string) string {
	t.Helper()
	rec := do(t, handler, http.MethodPost, "/v1/boletos", tenantToken,
		map[string]string{"Idempotency-Key": idemKey}, boletoBody())
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: status %d body %s", rec.Code, rec.Body.String())
	}
	id, _ := decodePix(t, rec)["boleto_id"].(string)
	if id == "" {
		t.Fatal("no boleto_id returned")
	}
	return id
}

// The PDF is served as BINARY, not base64 inside JSON: the integrator can hand the URL
// straight to a browser or an email pipeline.
func TestBoletoPDFIsServedAsBinary(t *testing.T) {
	t.Parallel()
	handler, _, _ := newBoletoFixture(t)
	id := registerBoletoForPDF(t, handler, "kpdf1")

	rec := do(t, handler, http.MethodGet, "/v1/boletos/"+id+"/pdf", tenantToken, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("pdf: status %d body %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/pdf" {
		t.Fatalf("Content-Type = %q, want application/pdf", ct)
	}
	if !strings.HasPrefix(rec.Body.String(), "%PDF-") {
		t.Fatalf("body is not a PDF: %q", rec.Body.String())
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, ".pdf") {
		t.Fatalf("Content-Disposition should suggest a .pdf filename, got %q", cd)
	}
	// The slip carries payer PII (name, CPF/CNPJ, address), so no intermediary may cache it.
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", cc)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("X-Content-Type-Options: nosniff is required on a binary response")
	}
}

// OWASP A01: another tenant's boleto PDF must 404 — the document carries the payer's name,
// tax id and address, so a cross-tenant read is a PII disclosure, not just an id leak.
func TestBoletoPDFCrossTenantIsolation(t *testing.T) {
	t.Parallel()
	handler, _, _ := newBoletoFixture(t)
	id := registerBoletoForPDF(t, handler, "kpdf2")

	rec := do(t, handler, http.MethodGet, "/v1/boletos/"+id+"/pdf", tenantTokenB, nil, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant pdf: status %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
}

// Deny by default: no token, no document.
func TestBoletoPDFRequiresAuth(t *testing.T) {
	t.Parallel()
	handler, _, _ := newBoletoFixture(t)
	id := registerBoletoForPDF(t, handler, "kpdf3")

	rec := do(t, handler, http.MethodGet, "/v1/boletos/"+id+"/pdf", "", nil, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated pdf: status %d, want 401", rec.Code)
	}
}

// An unknown id is a plain 404 in the JSON envelope — only the success path is binary.
func TestBoletoPDFUnknownIDIsJSONError(t *testing.T) {
	t.Parallel()
	handler, _, _ := newBoletoFixture(t)

	rec := do(t, handler, http.MethodGet, "/v1/boletos/does-not-exist/pdf", tenantToken, nil, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "json") {
		t.Fatalf("an error must keep the JSON envelope, got %q", ct)
	}
}

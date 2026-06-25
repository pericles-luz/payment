package c6

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// Tests for the SIN-65856 remap of the adapter onto the real C6 contract: the
// BACEN PIX v2 cob surface (/v2/pix/cob), the recebedor "chave", the top-level
// "location" field and the RFC7807 problem+json error contract.

// TestProblemTypeCode covers the RFC7807 "type" URN parsing both real C6 surfaces
// return: only the final path segment (a stable token) is surfaced, query/fragment
// trimmed.
func TestProblemTypeCode(t *testing.T) {
	t.Parallel()
	cases := []struct{ name, in, want string }{
		{"bacen pix urn", "https://pix.bcb.gov.br/api/v2/error/RequisicaoInvalida", "RequisicaoInvalida"},
		{"c6 urn", "https://developers.c6bank.com.br/v1/error/invalid_request", "invalid_request"},
		{"query trimmed", "https://x/error/Foo?bar=1", "Foo"},
		{"fragment trimmed", "https://x/error/Foo#frag", "Foo"},
		{"empty", "", ""},
		{"trailing slash", "https://x/error/", ""},
		{"bare token", "Foo", "Foo"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := problemTypeCode(tc.in); got != tc.want {
				t.Fatalf("problemTypeCode(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestParseErrorCodeRFC7807 asserts parseErrorCode precedence (code > error > type
// tail) and that a problem+json's human title/detail is never surfaced.
func TestParseErrorCodeRFC7807(t *testing.T) {
	t.Parallel()
	cases := []struct{ name, body, want string }{
		{"type tail bacen", `{"type":"https://pix.bcb.gov.br/api/v2/error/RequisicaoInvalida","title":"Requisição inválida.","detail":"leak-me"}`, "RequisicaoInvalida"},
		{"type tail c6", `{"type":"https://developers.c6bank.com.br/v1/error/invalid_request","detail":"Object has missing required properties"}`, "invalid_request"},
		{"code wins", `{"code":"X","error":"y","type":"https://x/error/Z"}`, "X"},
		{"error over type", `{"error":"invalid_client","type":"https://x/error/Z"}`, "invalid_client"},
		{"empty body", ``, ""},
		{"not json", `not-json`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := parseErrorCode([]byte(tc.body))
			if got != tc.want {
				t.Fatalf("parseErrorCode(%q) = %q, want %q", tc.body, got, tc.want)
			}
			if strings.Contains(got, "leak-me") || strings.Contains(got, "missing required") || strings.Contains(got, "Requisição") {
				t.Fatalf("error code leaked human detail/title: %q", got)
			}
		})
	}
}

// TestErrorMappingSurfacesProblemTypeCode asserts an end-to-end non-2xx C6
// problem+json maps its type-URN tail into Error.Code, maps the status to the right
// sentinel, and never leaks the human detail/title.
func TestErrorMappingSurfacesProblemTypeCode(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t)
	ts.createHandler = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"type":"https://developers.c6bank.com.br/v1/error/invalid_request","title":"Requisição inválida.","detail":"Object has missing required properties"}`))
	}
	p := ts.provider(t, oneTenant("t1", "c", "s"))
	_, err := p.CreateCharge(context.Background(), "t1", ports.ChargeRequest{TenantID: "t1", PaymentID: "p", AmountCents: 1, Currency: "BRL"})
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("want *Error, got %v", err)
	}
	if e.Code != "invalid_request" {
		t.Fatalf("want code invalid_request, got %q", e.Code)
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("400 should map to ErrValidation, got %v", err)
	}
	if strings.Contains(e.Error(), "missing required") || strings.Contains(e.Error(), "Requisição") {
		t.Fatalf("error leaked human detail/title: %q", e.Error())
	}
}

// TestCreateChargeRejectsInvalid covers complete mediation at the money seam: an
// empty idempotency anchor or a non-positive amount fails closed BEFORE any PSP
// call (no cob is ever PUT).
func TestCreateChargeRejectsInvalid(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t)
	p := ts.provider(t, oneTenant("t1", "c", "s"))

	if _, err := p.CreateCharge(context.Background(), "t1", ports.ChargeRequest{TenantID: "t1", AmountCents: 100}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty anchor: want ErrValidation, got %v", err)
	}
	if _, err := p.CreateCharge(context.Background(), "t1", ports.ChargeRequest{TenantID: "t1", PaymentID: "p", AmountCents: 0}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("zero amount: want ErrValidation, got %v", err)
	}
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.createHits != 0 {
		t.Fatalf("PSP must not be called on invalid input, got %d hits", ts.createHits)
	}
}

// TestCreateChargeForwardsChaveAndReconcilesCobMoney asserts the generic charge
// surface now PUTs a BACEN cob carrying the recebedor chave, and reconciles
// valor.original (expected) against the pix[] receipts (received).
func TestCreateChargeForwardsChaveAndReconcilesCobMoney(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t)
	var gotChave, gotMethod string
	ts.createHandler = func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		var body pixChargeRequestBody
		_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
		gotChave = body.Chave
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"txid":"tx-cob","status":"CONCLUIDA","valor":{"original":"15.00"},"pix":[{"valor":"10.00"},{"valor":"5.00"}]}`))
	}
	p := ts.provider(t, oneTenant("t1", "c", "s"))

	res, err := p.CreateCharge(context.Background(), "t1", ports.ChargeRequest{
		TenantID: "t1", PaymentID: "pay-9", AmountCents: 1500, Currency: "BRL", CreditorKey: "creditor@example.com",
	})
	if err != nil {
		t.Fatalf("CreateCharge: %v", err)
	}
	if gotMethod != http.MethodPut {
		t.Fatalf("cob create must be a PUT, got %s", gotMethod)
	}
	if gotChave != "creditor@example.com" {
		t.Fatalf("chave not forwarded: %q", gotChave)
	}
	if res.TxID != "tx-cob" || res.ExpectedAmountCents != 1500 || res.ReceivedAmountCents != 1500 {
		t.Fatalf("cob money not reconciled: %+v", res)
	}
}

// TestCreateImmediateChargeForwardsChave asserts the immediate cob create carries
// the recebedor chave from ChargeRequest.CreditorKey (trimmed).
func TestCreateImmediateChargeForwardsChave(t *testing.T) {
	t.Parallel()
	ts := newPixTestServer(t)
	p := ts.provider(t, oneTenant("t1", "c", "s"), nil)

	if _, err := p.CreateImmediateCharge(context.Background(), "t1", ports.ChargeRequest{
		TenantID: "t1", PaymentID: "pay-1", AmountCents: 1000, CreditorKey: "  key@example.com  ",
	}, time.Hour); err != nil {
		t.Fatalf("CreateImmediateCharge: %v", err)
	}
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.lastReqBody.Chave != "key@example.com" {
		t.Fatalf("chave not forwarded/trimmed: %q", ts.lastReqBody.Chave)
	}
}

// TestGetImmediateChargePrefersTopLevelLocation asserts the adapter reads the
// top-level "location" the real C6 sandbox returns, in preference to loc.location.
func TestGetImmediateChargePrefersTopLevelLocation(t *testing.T) {
	t.Parallel()
	ts := newPixTestServer(t)
	ts.getHandler = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"txid":"tx1","status":"ATIVA","valor":{"original":"10.00"},"location":"top-level-loc","loc":{"location":"nested-loc"},"pixCopiaECola":"qr"}`))
	}
	p := ts.provider(t, oneTenant("t1", "c", "s"), nil)

	res, err := p.GetImmediateCharge(context.Background(), "t1", "tx1")
	if err != nil {
		t.Fatalf("GetImmediateCharge: %v", err)
	}
	if res.QRCodeLocation != "top-level-loc" {
		t.Fatalf("want top-level location, got %q", res.QRCodeLocation)
	}
}

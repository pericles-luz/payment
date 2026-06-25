package c6

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// productServer is a configurable C6 double for the C6-C products (consent,
// boleto, checkout) plus the OAuth2 token endpoint, backed by httptest TLS. It
// uses Go's method+path routing so each product/operation has its own handler,
// defaulting to a happy path that can be overridden per test. It records the last
// Authorization / Idempotency-Key / request body so tests can assert plumbing
// without races.
type productServer struct {
	*httptest.Server

	mu             sync.Mutex
	tokenHits      int
	lastAuthHeader string
	lastIdemKey    string
	lastBody       []byte

	consentCreate http.HandlerFunc
	consentGet    http.HandlerFunc
	consentCancel http.HandlerFunc
	boletoCreate  http.HandlerFunc
	boletoGet     http.HandlerFunc
	boletoCancel  http.HandlerFunc
	boletoUpdate  http.HandlerFunc
	checkout      http.HandlerFunc
	// cobvPut backs both create and amend (both PUT /v2/pix/cobv/{txid}); cobvGet
	// backs the reconcile read (roteiro 7.5–7.7).
	cobvPut http.HandlerFunc
	cobvGet http.HandlerFunc
}

func newProductServer(t *testing.T) *productServer {
	t.Helper()
	ps := &productServer{}

	record := func(r *http.Request) {
		ps.mu.Lock()
		defer ps.mu.Unlock()
		ps.lastAuthHeader = r.Header.Get("Authorization")
		ps.lastIdemKey = r.Header.Get("Idempotency-Key")
		ps.lastBody, _ = io.ReadAll(io.LimitReader(r.Body, 1<<20))
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /oauth/token", func(w http.ResponseWriter, r *http.Request) {
		ps.mu.Lock()
		ps.tokenHits++
		ps.mu.Unlock()
		user, _, _ := r.BasicAuth()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok-` + user + `","token_type":"Bearer","expires_in":3600}`))
	})
	mux.HandleFunc("POST /consents", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		if ps.consentCreate != nil {
			ps.consentCreate(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"consent_id":"con_1","status":"PENDING"}`))
	})
	mux.HandleFunc("GET /consents/{id}", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		if ps.consentGet != nil {
			ps.consentGet(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"consent_id":"con_1","status":"ACTIVE"}`))
	})
	mux.HandleFunc("POST /consents/{id}/cancel", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		if ps.consentCancel != nil {
			ps.consentCancel(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"consent_id":"con_1","status":"CANCELLED"}`))
	})
	mux.HandleFunc("POST /v1/bank_slips", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		if ps.boletoCreate != nil {
			ps.boletoCreate(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"boleto_id":"bol_1","txid":"tx_1","status":"REGISTERED","qr_code":"pix-emv","barcode":"123","amount_cents":1000}`))
	})
	mux.HandleFunc("GET /boletos/{id}", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		if ps.boletoGet != nil {
			ps.boletoGet(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"boleto_id":"bol_1","txid":"tx_1","status":"REGISTERED","qr_code":"pix-emv","barcode":"123","amount_cents":1000,"fine_bps":200,"monthly_interest_bps":100,"discounts":[{"days_before_due":0,"bps":500}]}`))
	})
	mux.HandleFunc("DELETE /boletos/{id}", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		if ps.boletoCancel != nil {
			ps.boletoCancel(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"boleto_id":"bol_1","txid":"tx_1","status":"CANCELLED","qr_code":"pix-emv","barcode":"123","amount_cents":1000}`))
	})
	mux.HandleFunc("PUT /boletos/{id}", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		if ps.boletoUpdate != nil {
			ps.boletoUpdate(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"boleto_id":"bol_1","txid":"tx_1","status":"REGISTERED","qr_code":"pix-emv","barcode":"123","amount_cents":2000,"fine_bps":150,"monthly_interest_bps":80}`))
	})
	mux.HandleFunc("POST /checkout/sessions", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		if ps.checkout != nil {
			ps.checkout(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"session_id":"sess_1","status":"OPEN","redirect_url":"https://pay.c6/sess_1","amount_cents":1500}`))
	})

	// Real BACEN cobv wire (SIN-65860): calendario.dataDeVencimento/validadeApos-
	// Vencimento, valor.original + multa/juros/desconto rate blocks, pixCopiaECola +
	// top-level location, and a pix[] receipt list on the paid read.
	mux.HandleFunc("PUT /v2/pix/cobv/{txid}", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		if ps.cobvPut != nil {
			ps.cobvPut(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"txid":"` + r.PathValue("txid") + `","status":"ATIVA","pixCopiaECola":"pix-cobv-emv","location":"https://pix.c6/cobv","calendario":{"dataDeVencimento":"2030-03-17","validadeAposVencimento":5},"valor":{"original":"10.00","multa":{"modalidade":2,"valorPerc":"2.00"},"juros":{"modalidade":3,"valorPerc":"1.00"},"desconto":{"modalidade":5,"valorPerc":"5.00"}}}`))
	})
	mux.HandleFunc("GET /v2/pix/cobv/{txid}", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		if ps.cobvGet != nil {
			ps.cobvGet(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"txid":"` + r.PathValue("txid") + `","status":"CONCLUIDA","pixCopiaECola":"pix-cobv-emv","location":"https://pix.c6/cobv","calendario":{"dataDeVencimento":"2030-03-17","validadeAposVencimento":5},"valor":{"original":"10.00","multa":{"modalidade":2,"valorPerc":"2.00"},"juros":{"modalidade":3,"valorPerc":"1.00"}},"pix":[{"valor":"10.00"}]}`))
	})

	ps.Server = httptest.NewTLSServer(mux)
	t.Cleanup(ps.Close)
	return ps
}

func (ps *productServer) provider(t *testing.T, creds ports.CredentialStore) *Provider {
	t.Helper()
	p, err := New(Config{
		BaseURL:    ps.URL,
		TokenURL:   ps.URL + "/oauth/token",
		HTTPClient: ps.Client(),
	}, creds)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func (ps *productServer) idemKey() string {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	return ps.lastIdemKey
}

func (ps *productServer) body() []byte {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	return ps.lastBody
}

func (ps *productServer) tokenCount() int {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	return ps.tokenHits
}

// --- Consent ---

func TestCreateConsentSuccess(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	p := ps.provider(t, oneTenant("t1", "client-1", "secret-1"))

	res, err := p.CreateConsent(context.Background(), "t1", ports.ConsentRequest{
		TenantID: "t1", ConsentID: "con_1", DebtorTaxID: "12345678901",
		MaxAmountCents: 50000, Currency: "BRL", Frequency: "MONTHLY",
		StartAt: time.Unix(1_700_000_000, 0),
	})
	if err != nil {
		t.Fatalf("CreateConsent: %v", err)
	}
	if res.ConsentID != "con_1" || res.Status != "PENDING" {
		t.Fatalf("unexpected result: %+v", res)
	}
	if ps.lastAuthHeader != "Bearer tok-client-1" {
		t.Fatalf("bearer not attached: %q", ps.lastAuthHeader)
	}
	if ps.idemKey() != "con_1" {
		t.Fatalf("idempotency key should fall back to consent id, got %q", ps.idemKey())
	}
}

func TestCreateConsentForwardsIdempotencyKeyAndOmitsZeroEnd(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	p := ps.provider(t, oneTenant("t1", "c", "s"))

	_, err := p.CreateConsent(context.Background(), "t1", ports.ConsentRequest{
		TenantID: "t1", ConsentID: "con_1", DebtorTaxID: "12345678901",
		MaxAmountCents: 50000, Currency: "BRL", Frequency: "MONTHLY",
		StartAt: time.Unix(1_700_000_000, 0), IdempotencyKey: "idem-xyz",
	})
	if err != nil {
		t.Fatalf("CreateConsent: %v", err)
	}
	if ps.idemKey() != "idem-xyz" {
		t.Fatalf("explicit idempotency key should win, got %q", ps.idemKey())
	}
	// Open-ended consent: end_at must be omitted from the JSON body entirely.
	var got map[string]json.RawMessage
	if err := json.Unmarshal(ps.body(), &got); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if _, present := got["end_at"]; present {
		t.Fatalf("end_at must be omitted when zero, body=%s", ps.body())
	}
}

func TestCreateConsentSendsBoundedEnd(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	p := ps.provider(t, oneTenant("t1", "c", "s"))

	_, err := p.CreateConsent(context.Background(), "t1", ports.ConsentRequest{
		TenantID: "t1", ConsentID: "con_1", DebtorTaxID: "12345678901",
		MaxAmountCents: 50000, Currency: "BRL", Frequency: "MONTHLY",
		StartAt: time.Unix(1_700_000_000, 0), EndAt: time.Unix(1_800_000_000, 0),
	})
	if err != nil {
		t.Fatalf("CreateConsent: %v", err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(ps.body(), &got); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if _, present := got["end_at"]; !present {
		t.Fatalf("end_at must be present when bounded, body=%s", ps.body())
	}
}

func TestGetConsentSuccess(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	p := ps.provider(t, oneTenant("t1", "client-1", "secret-1"))

	res, err := p.GetConsent(context.Background(), "t1", "con_1")
	if err != nil {
		t.Fatalf("GetConsent: %v", err)
	}
	if res.Status != "ACTIVE" {
		t.Fatalf("unexpected result: %+v", res)
	}
	if ps.lastAuthHeader != "Bearer tok-client-1" {
		t.Fatalf("bearer not attached: %q", ps.lastAuthHeader)
	}
}

func TestGetConsentNotFound(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	ps.consentGet = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":"NOT_FOUND"}`))
	}
	p := ps.provider(t, oneTenant("t1", "c", "s"))
	if _, err := p.GetConsent(context.Background(), "t1", "missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestCancelConsentSuccess(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	p := ps.provider(t, oneTenant("t1", "c", "s"))

	res, err := p.CancelConsent(context.Background(), "t1", "con_1")
	if err != nil {
		t.Fatalf("CancelConsent: %v", err)
	}
	if res.Status != "CANCELLED" {
		t.Fatalf("unexpected result: %+v", res)
	}
	if ps.idemKey() != "con_1" {
		t.Fatalf("cancel should carry consent id as idempotency key, got %q", ps.idemKey())
	}
}

func TestCancelConsentError(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	ps.consentCancel = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"code":"X"}`))
	}
	p := ps.provider(t, oneTenant("t1", "c", "s"))
	if _, err := p.CancelConsent(context.Background(), "t1", "con_1"); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("want ErrConflict, got %v", err)
	}
}

func TestConsentMissingCredential(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	p := ps.provider(t, &fakeCreds{creds: map[string]ports.BankCredential{}})

	if _, err := p.CreateConsent(context.Background(), "unknown", ports.ConsentRequest{
		TenantID: "unknown", ConsentID: "c", DebtorTaxID: "12345678901",
		MaxAmountCents: 1, Currency: "BRL", Frequency: "MONTHLY", StartAt: time.Unix(1, 0),
	}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("missing credential should propagate ErrNotFound, got %v", err)
	}
	if ps.tokenCount() != 0 {
		t.Fatalf("token endpoint must not be hit without a credential, hits=%d", ps.tokenCount())
	}
}

// --- Boleto ---

func TestCreateBoletoSuccess(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	p := ps.provider(t, oneTenant("t1", "client-1", "secret-1"))

	res, err := p.CreateBoleto(context.Background(), "t1", ports.BoletoRequest{
		TenantID: "t1", BoletoID: "bol_1", AmountCents: 1000, Currency: "BRL",
		DueDate: time.Unix(1_800_000_000, 0), FineBps: 200, MonthlyInterestBps: 100,
		Payer: fullBoletoPayer(),
	})
	if err != nil {
		t.Fatalf("CreateBoleto: %v", err)
	}
	if res.TxID != "tx_1" || res.Status != "REGISTERED" || res.QRCode != "pix-emv" || res.Barcode != "123" {
		t.Fatalf("unexpected result: %+v", res)
	}
	if ps.lastAuthHeader != "Bearer tok-client-1" {
		t.Fatalf("bearer not attached: %q", ps.lastAuthHeader)
	}
	if ps.idemKey() != "bol_1" {
		t.Fatalf("idempotency key should fall back to boleto id, got %q", ps.idemKey())
	}
	// The adapter transports the fine/interest RATES (the domain computes amounts).
	var sent map[string]json.RawMessage
	if err := json.Unmarshal(ps.body(), &sent); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	for _, f := range []string{"fine_bps", "monthly_interest_bps", "due_date"} {
		if _, ok := sent[f]; !ok {
			t.Fatalf("boleto request must carry %q, body=%s", f, ps.body())
		}
	}
}

func TestCreateBoletoErrorMapping(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	ps.boletoCreate = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"code":"BAD"}`))
	}
	p := ps.provider(t, oneTenant("t1", "c", "s"))
	if _, err := p.CreateBoleto(context.Background(), "t1", ports.BoletoRequest{
		TenantID: "t1", BoletoID: "b", AmountCents: 1, Currency: "BRL", DueDate: time.Unix(1, 0),
		Payer: fullBoletoPayer(),
	}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("400 should map to ErrValidation, got %v", err)
	}
}

func TestBoletoMissingCredential(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	p := ps.provider(t, &fakeCreds{creds: map[string]ports.BankCredential{}})
	if _, err := p.CreateBoleto(context.Background(), "unknown", ports.BoletoRequest{
		TenantID: "unknown", BoletoID: "b", AmountCents: 1, Currency: "BRL", DueDate: time.Unix(1, 0),
		Payer: fullBoletoPayer(),
	}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("missing credential should propagate ErrNotFound, got %v", err)
	}
	if ps.tokenCount() != 0 {
		t.Fatalf("token must not be hit without a credential, hits=%d", ps.tokenCount())
	}
}

// --- Checkout ---

func TestCreateCheckoutSessionSuccess(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	p := ps.provider(t, oneTenant("t1", "client-1", "secret-1"))

	res, err := p.CreateCheckoutSession(context.Background(), "t1", ports.CheckoutRequest{
		TenantID: "t1", SessionID: "sess_1", Currency: "BRL",
		Items:     []ports.CheckoutItem{{Description: "a", AmountCents: 1000}, {Description: "b", AmountCents: 500}},
		ExpiresAt: time.Unix(1_800_000_000, 0),
	})
	if err != nil {
		t.Fatalf("CreateCheckoutSession: %v", err)
	}
	if res.SessionID != "sess_1" || res.Status != "OPEN" || res.RedirectURL != "https://pay.c6/sess_1" || res.AmountCents != 1500 {
		t.Fatalf("unexpected result: %+v", res)
	}
	if ps.idemKey() != "sess_1" {
		t.Fatalf("idempotency key should fall back to session id, got %q", ps.idemKey())
	}
	var sent struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(ps.body(), &sent); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if len(sent.Items) != 2 {
		t.Fatalf("checkout request should carry 2 items, got %d", len(sent.Items))
	}
}

func TestCreateCheckoutSessionErrorMapping(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	ps.checkout = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"code":"X"}`))
	}
	p := ps.provider(t, oneTenant("t1", "c", "s"))
	if _, err := p.CreateCheckoutSession(context.Background(), "t1", ports.CheckoutRequest{
		TenantID: "t1", SessionID: "s", Currency: "BRL",
		Items:     []ports.CheckoutItem{{Description: "a", AmountCents: 1}},
		ExpiresAt: time.Unix(1, 0),
	}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("422 should map to ErrValidation, got %v", err)
	}
}

func TestCheckoutMissingCredential(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	p := ps.provider(t, &fakeCreds{creds: map[string]ports.BankCredential{}})
	if _, err := p.CreateCheckoutSession(context.Background(), "unknown", ports.CheckoutRequest{
		TenantID: "unknown", SessionID: "s", Currency: "BRL",
		Items:     []ports.CheckoutItem{{Description: "a", AmountCents: 1}},
		ExpiresAt: time.Unix(1, 0),
	}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("missing credential should propagate ErrNotFound, got %v", err)
	}
}

// TestCreateCheckoutSessionRejectsUntrustedRedirectURL is the F2 regression: the
// adapter must refuse to forward the payer to a redirect_url that is not an
// absolute https URL, even on an otherwise-2xx response (tampered/compromised
// PSP). The result must be empty and the error must map to ErrUnavailable without
// leaking the malicious value.
func TestCreateCheckoutSessionRejectsUntrustedRedirectURL(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		redirect string
	}{
		{"empty", ""},
		{"http not https", "http://pay.c6/sess_1"},
		{"scheme relative", "//evil.example/sess_1"},
		{"path relative", "/sess_1"},
		{"javascript scheme", "javascript:alert(1)"},
		{"https without host", "https:///sess_1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ps := newProductServer(t)
			ps.checkout = func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				body, _ := json.Marshal(checkoutResponseBody{
					SessionID: "sess_1", Status: "OPEN", RedirectURL: tc.redirect, AmountCents: 1500,
				})
				_, _ = w.Write(body)
			}
			p := ps.provider(t, oneTenant("t1", "c", "s"))

			res, err := p.CreateCheckoutSession(context.Background(), "t1", ports.CheckoutRequest{
				TenantID: "t1", SessionID: "sess_1", Currency: "BRL",
				Items:     []ports.CheckoutItem{{Description: "a", AmountCents: 1500}},
				ExpiresAt: time.Unix(1_800_000_000, 0),
			})
			if !errors.Is(err, shared.ErrUnavailable) {
				t.Fatalf("untrusted redirect must map to ErrUnavailable, got %v", err)
			}
			if res != (ports.CheckoutResult{}) {
				t.Fatalf("result must be empty on untrusted redirect, got %+v", res)
			}
			if tc.redirect != "" && strings.Contains(err.Error(), tc.redirect) {
				t.Fatalf("error leaked the untrusted redirect url: %q", err.Error())
			}
			if !strings.Contains(err.Error(), "untrusted redirect url") {
				t.Fatalf("error should name the guard, got %q", err.Error())
			}
		})
	}
}

// TestProductSecretNeverLeaks asserts the client secret never reaches an error on
// a product call when the token endpoint rejects the credentials.
func TestProductSecretNeverLeaks(t *testing.T) {
	t.Parallel()
	const secret = "TOP-SECRET-PRODUCTS-7766"

	mux := http.NewServeMux()
	mux.HandleFunc("POST /oauth/token", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)

	p, err := New(Config{BaseURL: srv.URL, TokenURL: srv.URL + "/oauth/token", HTTPClient: srv.Client()}, oneTenant("t1", "client-1", secret))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = p.CreateBoleto(context.Background(), "t1", ports.BoletoRequest{
		TenantID: "t1", BoletoID: "b", AmountCents: 1, Currency: "BRL", DueDate: time.Unix(1, 0),
		Payer: fullBoletoPayer(),
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, shared.ErrUnauthorized) {
		t.Fatalf("want ErrUnauthorized, got %v", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaked the client secret: %q", err.Error())
	}
}

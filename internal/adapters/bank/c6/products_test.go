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

// productServer is a configurable C6 double for the C6-C products (boleto,
// checkout) plus the OAuth2 token endpoint, backed by httptest TLS. It uses
// Go's method+path routing so each product/operation has its own handler,
// defaulting to a happy path that can be overridden per test. It records the
// last Authorization / Idempotency-Key / request body so tests can assert
// plumbing without races.
type productServer struct {
	*httptest.Server

	mu             sync.Mutex
	tokenHits      int
	lastAuthHeader string
	lastIdemKey    string
	lastBody       []byte

	boletoCreate http.HandlerFunc
	boletoGet    http.HandlerFunc
	boletoCancel http.HandlerFunc
	boletoUpdate http.HandlerFunc
	checkout     http.HandlerFunc
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
	mux.HandleFunc("POST /v2/bank_slips", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		if ps.boletoCreate != nil {
			ps.boletoCreate(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// Official C6 BolePix 201: the scannable artifacts are NESTED under
		// payment_method.bank_slip, and the QR Code arrives under payment_method.pix.
		_, _ = w.Write([]byte(`{"id":"01HBANKSLIP0000000000000001","external_reference_id":"ref1","amount":10.00,"due_date":"2027-01-15","payment_method":{"bank_slip":{"originator_id":"000000000001","billing_scheme":"21","billing_type":"3","digitable_line":"dl-1","bar_code":"bc-1","our_number":"55501","number":"1"},"pix":{"qr_code":"pix-emv","mime_type":"image/png","reference":"ref-pix"}}}`))
	})
	mux.HandleFunc("GET /v2/bank_slips/{id}", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		if ps.boletoGet != nil {
			ps.boletoGet(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"bol_1","external_reference_id":"ref1","status":"REGISTERED","amount":10.00,"due_date":"2027-01-15","fees":{"fine_value":2.00,"fine_type":"PERCENTAGE","interest_value":1.00,"interest_type":"MONTHLY_PERCENTAGE","discount_type":"MONTHLY_PERCENTAGE","first_discount_value":5.00,"first_discount_deadline":0},"payment_method":{"bank_slip":{"digitable_line":"dl-1","bar_code":"123","our_number":"55501"},"pix":{"qr_code":"pix-emv"}}}`))
	})
	mux.HandleFunc("PUT /v2/bank_slips/{id}/cancel", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		if ps.boletoCancel != nil {
			ps.boletoCancel(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"bol_1","status":"CANCELLED","amount":10.00,"payment_method":{"bank_slip":{"bar_code":"123"},"pix":{"qr_code":"pix-emv"}}}`))
	})
	mux.HandleFunc("POST /v1/checkouts/", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		if ps.checkout != nil {
			ps.checkout(w, r)
			return
		}
		// Real C6 create (201) response is {id, url} — no status/amount echoed.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"chk_1","url":"https://checkout.c6bank.info/chk_1"}`))
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

// --- Boleto ---

func TestCreateBoletoSuccess(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	p := ps.provider(t, oneTenant("t1", "client-1", "secret-1"))

	res, err := p.CreateBoleto(context.Background(), "t1", ports.BoletoRequest{
		TenantID: "t1", BoletoID: "bol_1", AmountCents: 1000, Currency: "BRL",
		DueDate: time.Unix(1_800_000_000, 0), FineBps: 200, MonthlyInterestBps: 100,
		Payer:       fullBoletoPayer(),
		Description: "Compra de produto X",
	})
	if err != nil {
		t.Fatalf("CreateBoleto: %v", err)
	}
	// Real 201 maps id→TxID (non-empty: billing-finalized marker), our_number, bar_code,
	// digitable_line and amount(decimal 10.00)→1000 centavos. No status/qr_code on create.
	if res.TxID != "01HBANKSLIP0000000000000001" || res.BoletoID != "01HBANKSLIP0000000000000001" {
		t.Fatalf("id must map to BoletoID and TxID, got %+v", res)
	}
	if res.OurNumber != "55501" || res.Barcode != "bc-1" || res.DigitableLine != "dl-1" {
		t.Fatalf("our_number/bar_code/digitable_line not mapped: %+v", res)
	}
	if res.AmountCents != 1000 {
		t.Fatalf("amount 10.00 must parse to 1000 centavos, got %d", res.AmountCents)
	}
	if ps.lastAuthHeader != "Bearer tok-client-1" {
		t.Fatalf("bearer not attached: %q", ps.lastAuthHeader)
	}
	if ps.idemKey() != "bol_1" {
		t.Fatalf("idempotency key should fall back to boleto id, got %q", ps.idemKey())
	}
	// The adapter transports fine/interest RATES inside the single `fees` object and the
	// decimal amount (the domain still computes amounts owed). `description` and
	// `payment_method` are required by the bank, so their absence is a registration error.
	var sent map[string]json.RawMessage
	if err := json.Unmarshal(ps.body(), &sent); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	for _, f := range []string{"fees", "due_date", "amount", "description", "payment_method"} {
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
		Payer:       fullBoletoPayer(),
		Description: "Compra de produto X",
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
		Payer:       fullBoletoPayer(),
		Description: "Compra de produto X",
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
		TenantID: "t1", SessionID: "sess_1", Currency: "BRL", CardType: "credit",
		Items:     []ports.CheckoutItem{{Description: "a", AmountCents: 1000}, {Description: "b", AmountCents: 500}},
		ExpiresAt: time.Unix(1_800_000_000, 0),
	})
	if err != nil {
		t.Fatalf("CreateCheckoutSession: %v", err)
	}
	// Create maps the real {id,url} response: id->SessionID, url->RedirectURL, a fresh
	// checkout is CREATED, and AmountCents echoes the authorized total we sent.
	if res.SessionID != "chk_1" || res.Status != "CREATED" || res.RedirectURL != "https://checkout.c6bank.info/chk_1" || res.AmountCents != 1500 {
		t.Fatalf("unexpected result: %+v", res)
	}
	if ps.idemKey() != "sess_1" {
		t.Fatalf("idempotency key should fall back to session id, got %q", ps.idemKey())
	}
	// Real wire: a single decimal amount in reais (items summed, never cents) +
	// payment.card{type,installments}; there is no items[] array.
	var sent struct {
		Amount  json.RawMessage   `json:"amount"`
		Items   []json.RawMessage `json:"items"`
		Payment struct {
			Card struct {
				Type         string `json:"type"`
				Installments int    `json:"installments"`
				Authenticate string `json:"authenticate"`
			} `json:"card"`
		} `json:"payment"`
	}
	if err := json.Unmarshal(ps.body(), &sent); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if len(sent.Items) != 0 {
		t.Fatalf("real contract has no items[], got %d", len(sent.Items))
	}
	if string(sent.Amount) != "15.00" {
		t.Fatalf("amount must be decimal reais 15.00 (1500 cents summed), got %s", sent.Amount)
	}
	if sent.Payment.Card.Type != "CREDIT" || sent.Payment.Card.Installments != 1 || sent.Payment.Card.Authenticate != "NOT_REQUIRED" {
		t.Fatalf("unexpected payment.card: %+v", sent.Payment.Card)
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
		TenantID: "t1", SessionID: "s", Currency: "BRL", CardType: "credit",
		Items:     []ports.CheckoutItem{{Description: "a", AmountCents: 600}},
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
		TenantID: "unknown", SessionID: "s", Currency: "BRL", CardType: "credit",
		Items:     []ports.CheckoutItem{{Description: "a", AmountCents: 600}},
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
				w.WriteHeader(http.StatusCreated)
				body, _ := json.Marshal(checkoutResponseBody{
					ID: "chk_1", Status: "CREATED", URL: tc.redirect, Amount: 1500,
				})
				_, _ = w.Write(body)
			}
			p := ps.provider(t, oneTenant("t1", "c", "s"))

			res, err := p.CreateCheckoutSession(context.Background(), "t1", ports.CheckoutRequest{
				TenantID: "t1", SessionID: "sess_1", Currency: "BRL", CardType: "credit",
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
		Payer:       fullBoletoPayer(),
		Description: "Compra de produto X",
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

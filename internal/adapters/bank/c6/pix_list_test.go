package c6

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// TestCreateImmediateChargeWithDevedor asserts the optional devedor block (roteiro
// 7.2) is mapped into the request body, choosing cpf vs cnpj by length.
func TestCreateImmediateChargeWithDevedor(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		taxID    string
		wantCPF  string
		wantCNPJ string
	}{
		{"cpf", "12345678901", "12345678901", ""},
		{"cnpj", "12345678000199", "", "12345678000199"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ts := newPixTestServer(t)
			p := ts.provider(t, oneTenant("t1", "c", "s"), nil)

			_, err := p.CreateImmediateCharge(context.Background(), "t1", ports.ChargeRequest{
				TenantID: "t1", PaymentID: "pay-1", IdempotencyKey: "idem-1",
				AmountCents: 1000, Currency: "BRL",
				DebtorTaxID: tc.taxID, DebtorName: "Maria",
			}, time.Hour)
			if err != nil {
				t.Fatalf("CreateImmediateCharge: %v", err)
			}
			ts.mu.Lock()
			dev := ts.lastReqBody.Devedor
			ts.mu.Unlock()
			if dev == nil {
				t.Fatalf("devedor block not sent")
			}
			if dev.Nome != "Maria" {
				t.Fatalf("nome: want Maria, got %q", dev.Nome)
			}
			if dev.CPF != tc.wantCPF || dev.CNPJ != tc.wantCNPJ {
				t.Fatalf("cpf/cnpj: got cpf=%q cnpj=%q want cpf=%q cnpj=%q", dev.CPF, dev.CNPJ, tc.wantCPF, tc.wantCNPJ)
			}
		})
	}
}

// TestCreateImmediateChargeNoDevedor asserts a charge with no payer omits the
// devedor block entirely.
func TestCreateImmediateChargeNoDevedor(t *testing.T) {
	t.Parallel()
	ts := newPixTestServer(t)
	p := ts.provider(t, oneTenant("t1", "c", "s"), nil)

	if _, err := p.CreateImmediateCharge(context.Background(), "t1", ports.ChargeRequest{
		TenantID: "t1", PaymentID: "pay-1", AmountCents: 1000, Currency: "BRL",
	}, time.Hour); err != nil {
		t.Fatalf("CreateImmediateCharge: %v", err)
	}
	ts.mu.Lock()
	dev := ts.lastReqBody.Devedor
	ts.mu.Unlock()
	if dev != nil {
		t.Fatalf("devedor should be nil, got %+v", dev)
	}
}

// pixListTestServer is a C6 + OAuth2 double exposing the cob-list endpoint
// (GET /v1/pix with inicio/fim) so the list path can be exercised distinctly from
// the per-txid PUT/GET.
type pixListTestServer struct {
	*httptest.Server
	lastQuery  url.Values
	statusCode int
	body       string
}

func newPixListTestServer(t *testing.T) *pixListTestServer {
	t.Helper()
	ts := &pixListTestServer{statusCode: http.StatusOK}
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		user, _, _ := r.BasicAuth()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok-` + user + `","token_type":"Bearer","expires_in":3600}`))
	})
	mux.HandleFunc("/v1/pix", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		ts.lastQuery = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(ts.statusCode)
		_, _ = w.Write([]byte(ts.body))
	})
	ts.Server = httptest.NewTLSServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

func (ts *pixListTestServer) provider(t *testing.T, creds ports.CredentialStore) *Provider {
	t.Helper()
	p, err := New(Config{
		BaseURL:    ts.URL,
		TokenURL:   ts.URL + "/oauth/token",
		HTTPClient: ts.Client(),
	}, creds)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func TestListImmediateChargesSuccess(t *testing.T) {
	t.Parallel()
	ts := newPixListTestServer(t)
	ts.body = `{
		"parametros":{"paginacao":{"paginaAtual":0,"itensPorPagina":100,"quantidadeDePaginas":1,"quantidadeTotalDeItens":2}},
		"cobs":[
			{"txid":"tx1","status":"ATIVA","valor":{"original":"10.00"},"loc":{"location":"loc1"},"pixCopiaECola":"qr1"},
			{"txid":"tx2","status":"CONCLUIDA","valor":{"original":"20.00"},"pix":[{"valor":"20.00"}]}
		]
	}`
	p := ts.provider(t, oneTenant("t1", "client-1", "s"))

	start := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC)
	list, err := p.ListImmediateCharges(context.Background(), "t1", ports.PixListFilter{
		Start: start, End: end, Page: 0, PageSize: 100,
	})
	if err != nil {
		t.Fatalf("ListImmediateCharges: %v", err)
	}

	if ts.lastQuery.Get("inicio") != "2026-06-01T00:00:00Z" || ts.lastQuery.Get("fim") != "2026-06-30T00:00:00Z" {
		t.Fatalf("date window not forwarded: %v", ts.lastQuery)
	}
	if ts.lastQuery.Get("paginacao.itensPorPagina") != "100" {
		t.Fatalf("page size not forwarded: %v", ts.lastQuery)
	}
	if len(list.Charges) != 2 || list.TotalItems != 2 || list.TotalPages != 1 {
		t.Fatalf("unexpected list: %+v", list)
	}
	if list.Charges[0].TxID != "tx1" || list.Charges[0].ExpectedAmountCents != 1000 {
		t.Fatalf("charge 0: %+v", list.Charges[0])
	}
	if list.Charges[1].ReceivedAmountCents != 2000 {
		t.Fatalf("charge 1 received: %+v", list.Charges[1])
	}
}

func TestListImmediateChargesMissingWindow(t *testing.T) {
	t.Parallel()
	ts := newPixListTestServer(t)
	p := ts.provider(t, oneTenant("t1", "c", "s"))

	_, err := p.ListImmediateCharges(context.Background(), "t1", ports.PixListFilter{
		End: time.Now(),
	})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation for missing inicio, got %v", err)
	}
}

func TestListImmediateChargesUpstreamError(t *testing.T) {
	t.Parallel()
	ts := newPixListTestServer(t)
	ts.statusCode = http.StatusInternalServerError
	ts.body = `{}`
	p := ts.provider(t, oneTenant("t1", "c", "s"))

	_, err := p.ListImmediateCharges(context.Background(), "t1", ports.PixListFilter{
		Start: time.Now().Add(-time.Hour), End: time.Now(),
	})
	if !errors.Is(err, shared.ErrUnavailable) {
		t.Fatalf("want ErrUnavailable on 5xx, got %v", err)
	}
}

func TestListImmediateChargesMalformedAmount(t *testing.T) {
	t.Parallel()
	ts := newPixListTestServer(t)
	ts.body = `{"parametros":{"paginacao":{}},"cobs":[{"txid":"tx1","valor":{"original":"abc"}}]}`
	p := ts.provider(t, oneTenant("t1", "c", "s"))

	_, err := p.ListImmediateCharges(context.Background(), "t1", ports.PixListFilter{
		Start: time.Now().Add(-time.Hour), End: time.Now(),
	})
	if !errors.Is(err, shared.ErrUnavailable) {
		t.Fatalf("want ErrUnavailable on malformed amount, got %v", err)
	}
}

// TestListImmediateChargesPaginationOmitted asserts pagination params are omitted
// when zero, letting the PSP apply its default.
func TestListImmediateChargesPaginationOmitted(t *testing.T) {
	t.Parallel()
	ts := newPixListTestServer(t)
	ts.body = `{"parametros":{"paginacao":{}},"cobs":[]}`
	p := ts.provider(t, oneTenant("t1", "c", "s"))

	if _, err := p.ListImmediateCharges(context.Background(), "t1", ports.PixListFilter{
		Start: time.Now().Add(-time.Hour), End: time.Now(),
	}); err != nil {
		t.Fatalf("ListImmediateCharges: %v", err)
	}
	if _, ok := ts.lastQuery["paginacao.paginaAtual"]; ok {
		t.Fatalf("paginaAtual should be omitted when zero: %v", ts.lastQuery)
	}
	if _, ok := ts.lastQuery["paginacao.itensPorPagina"]; ok {
		t.Fatalf("itensPorPagina should be omitted when zero: %v", ts.lastQuery)
	}
}

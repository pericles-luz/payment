package c6

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// bacenServer is a configurable C6 double for the BACEN PIX v2 surfaces beyond
// cob/cobv: payload locations, received PIX and refunds, batches of due-date charges,
// plus the two cob verbs and the two cobv verbs added alongside them.
//
// Every route it serves is spelled out from docs/compliance/c6-pix-oas.yaml. A path
// the adapter gets wrong simply 404s here, which is the cheap version of finding out.
type bacenServer struct {
	*httptest.Server

	mu          sync.Mutex
	lastMethod  string
	lastPath    string
	lastQuery   url.Values
	lastBody    []byte
	lastIdemKey string

	handlers map[string]http.HandlerFunc
}

func newBacenServer(t *testing.T) *bacenServer {
	t.Helper()
	bs := &bacenServer{handlers: map[string]http.HandlerFunc{}}
	record := func(r *http.Request) {
		bs.mu.Lock()
		defer bs.mu.Unlock()
		bs.lastMethod = r.Method
		bs.lastPath = r.URL.Path
		bs.lastQuery = r.URL.Query()
		bs.lastIdemKey = r.Header.Get("Idempotency-Key")
		bs.lastBody, _ = io.ReadAll(io.LimitReader(r.Body, 1<<20))
	}
	mux := http.NewServeMux()
	handle := func(pattern string, fallback http.HandlerFunc) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			record(r)
			bs.mu.Lock()
			h := bs.handlers[pattern]
			bs.mu.Unlock()
			if h != nil {
				h(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			fallback(w, r)
		})
	}

	mux.HandleFunc("POST /oauth/token", func(w http.ResponseWriter, r *http.Request) {
		user, _, _ := r.BasicAuth()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok-` + user + `","token_type":"Bearer","expires_in":3600}`))
	})

	// --- /loc ---
	handle("POST /v2/pix/loc", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":7,"location":"pix.example.com/qr/v2/abc","tipoCob":"cob","criacao":"2026-09-21T10:00:00Z"}`))
	})
	handle("GET /v2/pix/loc", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"parametros":{"paginacao":{"paginaAtual":0,"itensPorPagina":100,"quantidadeDePaginas":1,"quantidadeTotalDeItens":1}},` +
			`"loc":[{"id":7,"txid":"tx1","location":"pix.example.com/qr/v2/abc","tipoCob":"cobv","criacao":"2026-09-21T10:00:00Z"}]}`))
	})
	handle("GET /v2/pix/loc/{id}", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":7,"txid":"tx1","location":"pix.example.com/qr/v2/abc","tipoCob":"cob","criacao":"2026-09-21T10:00:00Z"}`))
	})
	handle("DELETE /v2/pix/loc/{id}/txid", func(w http.ResponseWriter, _ *http.Request) {
		// The unlink answers 200 with the location whose txid it just cleared.
		_, _ = w.Write([]byte(`{"id":7,"location":"pix.example.com/qr/v2/abc","tipoCob":"cob","criacao":"2026-09-21T10:00:00Z"}`))
	})

	// --- /pix (recebidos) + /devolucao ---
	const refundJSON = `{"id":"dev1","rtrId":"D12345678202009091000abcde123456","valor":"1.50",` +
		`"natureza":"ORIGINAL","descricao":"troco","status":"EM_PROCESSAMENTO","motivo":"",` +
		`"horario":{"solicitacao":"2026-09-21T11:00:00Z"}}`
	const receivedJSON = `{"endToEndId":"E12345678202609211100abcdef1234","txid":"tx1","valor":"10.00",` +
		`"chave":"pericles@example.com","horario":"2026-09-21T11:00:00Z","infoPagador":"obrigado",` +
		`"pagador":{"cpf":"12345678909","nome":"Fulano"},"devolucoes":[` + refundJSON + `]}`
	handle("GET /v2/pix/pix", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"parametros":{"paginacao":{"paginaAtual":0,"itensPorPagina":100,"quantidadeDePaginas":1,"quantidadeTotalDeItens":1}},` +
			`"pix":[` + receivedJSON + `]}`))
	})
	handle("GET /v2/pix/pix/{e2eid}", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(receivedJSON))
	})
	handle("PUT /v2/pix/pix/{e2eid}/devolucao/{id}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(refundJSON))
	})
	handle("GET /v2/pix/pix/{e2eid}/devolucao/{id}", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(refundJSON))
	})

	// --- /lotecobv ---
	const batchJSON = `{"id":42,"descricao":"lote de setembro","criacao":"2026-09-21T09:00:00Z","cobsv":[` +
		`{"txid":"tx1","status":"CRIADA","criacao":"2026-09-21T09:00:01Z"},` +
		`{"txid":"tx2","status":"NEGADA","problema":{"title":"Not found","detail":"chave inexistente","status":404}}]}`
	handle("PUT /v2/pix/lotecobv/{id}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	})
	handle("PATCH /v2/pix/lotecobv/{id}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	})
	handle("GET /v2/pix/lotecobv/{id}", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(batchJSON))
	})
	handle("GET /v2/pix/lotecobv", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"parametros":{"paginacao":{"paginaAtual":0,"itensPorPagina":100,"quantidadeDePaginas":1,"quantidadeTotalDeItens":1}},` +
			`"lotes":[` + batchJSON + `]}`))
	})

	// --- cob sem txid / revisão de cob e cobv / lista de cobv ---
	handle("POST /v2/pix/cob", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"txid":"psp-assigned-txid","status":"ATIVA","calendario":{"expiracao":3600},` +
			`"valor":{"original":"10.00"},"location":"qr.example/1","pixCopiaECola":"0002..."}`))
	})
	handle("PATCH /v2/pix/cob/{txid}", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"txid":"` + r.PathValue("txid") + `","status":"ATIVA","revisao":1,` +
			`"calendario":{"expiracao":7200},"valor":{"original":"20.00"},"location":"qr.example/1"}`))
	})
	handle("PATCH /v2/pix/cobv/{txid}", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"txid":"` + r.PathValue("txid") + `","status":"ATIVA",` +
			`"calendario":{"dataDeVencimento":"2026-10-01","validadeAposVencimento":45},` +
			`"valor":{"original":"20.00"},"location":"qr.example/2"}`))
	})
	handle("GET /v2/pix/cobv", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"parametros":{"paginacao":{"paginaAtual":0,"itensPorPagina":100,"quantidadeDePaginas":1,"quantidadeTotalDeItens":2}},` +
			`"cobs":[{"txid":"tx1","status":"ATIVA","calendario":{"dataDeVencimento":"2026-10-01","validadeAposVencimento":30},` +
			`"valor":{"original":"10.00"},"location":"qr.example/3"}]}`))
	})

	bs.Server = httptest.NewTLSServer(mux)
	t.Cleanup(bs.Close)
	return bs
}

func (bs *bacenServer) provider(t *testing.T, creds ports.CredentialStore) *Provider {
	t.Helper()
	p, err := New(Config{BaseURL: bs.URL, TokenURL: bs.URL + "/oauth/token", HTTPClient: bs.Client()}, creds)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func (bs *bacenServer) override(pattern string, h http.HandlerFunc) {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	bs.handlers[pattern] = h
}

func (bs *bacenServer) snapshot() (method, path string, query url.Values, body []byte, idem string) {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	return bs.lastMethod, bs.lastPath, bs.lastQuery, bs.lastBody, bs.lastIdemKey
}

func bacenProvider(t *testing.T) (*Provider, *bacenServer) {
	t.Helper()
	bs := newBacenServer(t)
	return bs.provider(t, oneTenant("t1", "c", "s")), bs
}

func bacenWindow() (time.Time, time.Time) {
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	return start, start.AddDate(0, 0, 20)
}

// --- Payload locations (roteiro P_04) -------------------------------------------

func TestC6CreateLocation(t *testing.T) {
	t.Parallel()
	p, bs := bacenProvider(t)

	loc, err := p.CreateLocation(context.Background(), "t1", "cob")
	if err != nil {
		t.Fatalf("CreateLocation: %v", err)
	}
	if loc.ID != 7 || loc.TipoCob != "cob" || loc.Location == "" || loc.CreatedAt.IsZero() {
		t.Fatalf("unexpected location: %+v", loc)
	}
	method, path, _, body, _ := bs.snapshot()
	if method != http.MethodPost || path != "/v2/pix/loc" {
		t.Fatalf("unexpected request: %s %s", method, path)
	}
	if !strings.Contains(string(body), `"tipoCob":"cob"`) {
		t.Fatalf("unexpected body: %s", body)
	}
}

func TestC6CreateLocationRejectsUnknownKind(t *testing.T) {
	t.Parallel()
	p, _ := bacenProvider(t)
	for _, kind := range []string{"", "cobr", "COB", "boleto"} {
		if _, err := p.CreateLocation(context.Background(), "t1", kind); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("tipoCob %q: want validation, got %v", kind, err)
		}
	}
}

// A 201 with no id leaves the location unaddressable — nothing could bind a charge to
// it or read it back — so it is a failure, not a success with a zero id.
func TestC6CreateLocationRejectsMissingID(t *testing.T) {
	t.Parallel()
	p, bs := bacenProvider(t)
	bs.override("POST /v2/pix/loc", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"location":"pix.example.com/qr/v2/abc","tipoCob":"cob"}`))
	})
	if _, err := p.CreateLocation(context.Background(), "t1", "cob"); !errors.Is(err, shared.ErrUnavailable) {
		t.Fatalf("want ErrUnavailable, got %v", err)
	}
}

func TestC6ListLocations(t *testing.T) {
	t.Parallel()
	p, bs := bacenProvider(t)
	start, end := bacenWindow()
	yes := true

	got, err := p.ListLocations(context.Background(), "t1", ports.PixLocationFilter{
		Start: start, End: end, TipoCob: "cobv", TxIDPresent: &yes, Page: 2, PageSize: 50,
	})
	if err != nil {
		t.Fatalf("ListLocations: %v", err)
	}
	if len(got.Locations) != 1 || got.Locations[0].TxID != "tx1" || got.TotalItems != 1 {
		t.Fatalf("unexpected list: %+v", got)
	}
	_, path, query, _, _ := bs.snapshot()
	if path != "/v2/pix/loc" {
		t.Fatalf("unexpected path: %s", path)
	}
	if query.Get("tipoCob") != "cobv" || query.Get("txIdPresente") != "true" ||
		query.Get("paginacao.paginaAtual") != "2" || query.Get("paginacao.itensPorPagina") != "50" {
		t.Fatalf("unexpected query: %v", query)
	}
	if query.Get("inicio") != start.Format(time.RFC3339) || query.Get("fim") != end.Format(time.RFC3339) {
		t.Fatalf("window not forwarded: %v", query)
	}
}

func TestC6ListLocationsValidation(t *testing.T) {
	t.Parallel()
	p, _ := bacenProvider(t)
	start, end := bacenWindow()
	ctx := context.Background()

	if _, err := p.ListLocations(ctx, "t1", ports.PixLocationFilter{End: end}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing start: want validation, got %v", err)
	}
	if _, err := p.ListLocations(ctx, "t1", ports.PixLocationFilter{Start: start}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing end: want validation, got %v", err)
	}
	bad := ports.PixLocationFilter{Start: start, End: end, TipoCob: "cobr"}
	if _, err := p.ListLocations(ctx, "t1", bad); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("bad tipoCob: want validation, got %v", err)
	}
}

func TestC6GetAndUnlinkLocation(t *testing.T) {
	t.Parallel()
	p, bs := bacenProvider(t)
	ctx := context.Background()

	loc, err := p.GetLocation(ctx, "t1", 7)
	if err != nil {
		t.Fatalf("GetLocation: %v", err)
	}
	if loc.TxID != "tx1" {
		t.Fatalf("unexpected location: %+v", loc)
	}
	if _, path, _, _, _ := bs.snapshot(); path != "/v2/pix/loc/7" {
		t.Fatalf("unexpected path: %s", path)
	}

	unlinked, err := p.UnlinkLocationTxID(ctx, "t1", 7)
	if err != nil {
		t.Fatalf("UnlinkLocationTxID: %v", err)
	}
	// After the unlink the location carries no charge — that is the whole observable
	// effect, and the charge's own status is untouched.
	if unlinked.TxID != "" {
		t.Fatalf("unlinked location must carry no txid: %+v", unlinked)
	}
	method, path, _, _, _ := bs.snapshot()
	if method != http.MethodDelete || path != "/v2/pix/loc/7/txid" {
		t.Fatalf("unexpected request: %s %s", method, path)
	}

	for _, id := range []int64{0, -1} {
		if _, err := p.GetLocation(ctx, "t1", id); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("GetLocation(%d): want validation, got %v", id, err)
		}
		if _, err := p.UnlinkLocationTxID(ctx, "t1", id); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("UnlinkLocationTxID(%d): want validation, got %v", id, err)
		}
	}
}

func TestC6GetLocationNotFound(t *testing.T) {
	t.Parallel()
	p, bs := bacenProvider(t)
	bs.override("GET /v2/pix/loc/{id}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"title":"Not found","status":404}`))
	})
	if _, err := p.GetLocation(context.Background(), "t1", 9); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("404 should map to ErrNotFound, got %v", err)
	}
}

// --- PIX recebidos e devolução (roteiro P_05) ------------------------------------

func TestC6GetReceivedPix(t *testing.T) {
	t.Parallel()
	p, bs := bacenProvider(t)

	got, err := p.GetReceivedPix(context.Background(), "t1", "E12345678202609211100abcdef1234")
	if err != nil {
		t.Fatalf("GetReceivedPix: %v", err)
	}
	if got.AmountCents != 1000 || got.TxID != "tx1" || got.CreditorKey != "pericles@example.com" ||
		got.PayerInfo != "obrigado" || got.ReceivedAt.IsZero() {
		t.Fatalf("unexpected received pix: %+v", got)
	}
	if len(got.Refunds) != 1 || got.Refunds[0].AmountCents != 150 ||
		got.Refunds[0].Status != "EM_PROCESSAMENTO" || got.Refunds[0].SettledAt != (time.Time{}) {
		t.Fatalf("unexpected refunds: %+v", got.Refunds)
	}
	if _, path, _, _, _ := bs.snapshot(); path != "/v2/pix/pix/E12345678202609211100abcdef1234" {
		t.Fatalf("unexpected path: %s", path)
	}
}

// The payer's CPF and name are in the response and must NOT reach the port: not
// modelling them is how they never get logged, returned or stored (ADR-0008).
func TestC6ReceivedPixDoesNotCarryPayerIdentity(t *testing.T) {
	t.Parallel()
	p, _ := bacenProvider(t)
	got, err := p.GetReceivedPix(context.Background(), "t1", "E12345678202609211100abcdef1234")
	if err != nil {
		t.Fatalf("GetReceivedPix: %v", err)
	}
	rendered, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, leak := range []string{"12345678909", "Fulano"} {
		if strings.Contains(string(rendered), leak) {
			t.Fatalf("payer identity leaked into the port type: %s", rendered)
		}
	}
}

func TestC6GetReceivedPixRejectsMalformedAmount(t *testing.T) {
	t.Parallel()
	p, bs := bacenProvider(t)
	bs.override("GET /v2/pix/pix/{e2eid}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"endToEndId":"E1","valor":"dez reais","horario":"2026-09-21T11:00:00Z"}`))
	})
	if _, err := p.GetReceivedPix(context.Background(), "t1", "E1"); !errors.Is(err, shared.ErrUnavailable) {
		t.Fatalf("corrupt money must not read as zero: %v", err)
	}
}

func TestC6ListReceivedPixFilters(t *testing.T) {
	t.Parallel()
	p, bs := bacenProvider(t)
	start, end := bacenWindow()
	no := false

	got, err := p.ListReceivedPix(context.Background(), "t1", ports.ReceivedPixFilter{
		Start: start, End: end, TxID: "tx1", RefundPresent: &no, PayerTaxID: "12345678909",
	})
	if err != nil {
		t.Fatalf("ListReceivedPix: %v", err)
	}
	if len(got.Received) != 1 || got.Received[0].AmountCents != 1000 {
		t.Fatalf("unexpected list: %+v", got)
	}
	_, path, query, _, _ := bs.snapshot()
	if path != "/v2/pix/pix" {
		t.Fatalf("unexpected path: %s", path)
	}
	// An 11-digit document is a CPF; the contract forbids sending cpf and cnpj at once,
	// so the adapter places it by length instead of letting the caller pick wrong.
	if query.Get("cpf") != "12345678909" || query.Has("cnpj") {
		t.Fatalf("tax id must go to cpf alone: %v", query)
	}
	if query.Get("txid") != "tx1" || query.Get("devolucaoPresente") != "false" {
		t.Fatalf("unexpected query: %v", query)
	}

	if _, err := p.ListReceivedPix(context.Background(), "t1", ports.ReceivedPixFilter{
		Start: start, End: end, PayerTaxID: "05471416000101",
	}); err != nil {
		t.Fatalf("ListReceivedPix(cnpj): %v", err)
	}
	if _, _, query, _, _ := bs.snapshot(); query.Get("cnpj") != "05471416000101" || query.Has("cpf") {
		t.Fatalf("14-digit document must go to cnpj alone: %v", query)
	}
}

func TestC6ListReceivedPixValidation(t *testing.T) {
	t.Parallel()
	p, _ := bacenProvider(t)
	start, end := bacenWindow()
	ctx := context.Background()

	if _, err := p.ListReceivedPix(ctx, "t1", ports.ReceivedPixFilter{End: end}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing start: want validation, got %v", err)
	}
	bad := ports.ReceivedPixFilter{Start: start, End: end, PayerTaxID: "123"}
	if _, err := p.ListReceivedPix(ctx, "t1", bad); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("bad tax id: want validation, got %v", err)
	}
}

func TestC6RequestRefund(t *testing.T) {
	t.Parallel()
	p, bs := bacenProvider(t)

	got, err := p.RequestRefund(context.Background(), "t1", "E1", "dev1", ports.PixRefundRequest{
		AmountCents: 150, Nature: ports.RefundMEDFraud, Description: "troco",
	})
	if err != nil {
		t.Fatalf("RequestRefund: %v", err)
	}
	if got.ID != "dev1" || got.AmountCents != 150 || got.Status != "EM_PROCESSAMENTO" {
		t.Fatalf("unexpected refund: %+v", got)
	}
	method, path, _, body, idem := bs.snapshot()
	if method != http.MethodPut || path != "/v2/pix/pix/E1/devolucao/dev1" {
		t.Fatalf("unexpected request: %s %s", method, path)
	}
	// The refund id in the path IS the idempotency: the same pair can never pay twice.
	if idem != "dev1" {
		t.Fatalf("refund id must travel as the idempotency key too, got %q", idem)
	}
	var sent struct {
		Valor     string `json:"valor"`
		Natureza  string `json:"natureza"`
		Descricao string `json:"descricao"`
	}
	if err := json.Unmarshal(body, &sent); err != nil {
		t.Fatalf("decode body: %v (%s)", err, body)
	}
	if sent.Valor != "1.50" || sent.Natureza != "MED_FRAUDE" || sent.Descricao != "troco" {
		t.Fatalf("unexpected body: %s", body)
	}
}

// There is no such thing as a zero refund, and a negative one would be a payment.
func TestC6RequestRefundValidation(t *testing.T) {
	t.Parallel()
	p, _ := bacenProvider(t)
	ctx := context.Background()
	ok := ports.PixRefundRequest{AmountCents: 150}

	cases := []struct {
		name          string
		e2e, refundID string
		req           ports.PixRefundRequest
	}{
		{"no_e2eid", " ", "dev1", ok},
		{"no_refund_id", "E1", " ", ok},
		{"zero_amount", "E1", "dev1", ports.PixRefundRequest{}},
		{"negative_amount", "E1", "dev1", ports.PixRefundRequest{AmountCents: -1}},
	}
	for _, tc := range cases {
		if _, err := p.RequestRefund(ctx, "t1", tc.e2e, tc.refundID, tc.req); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("%s: want validation, got %v", tc.name, err)
		}
		if _, err := p.GetRefund(ctx, "t1", tc.e2e, tc.refundID); tc.name == "no_e2eid" || tc.name == "no_refund_id" {
			if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("GetRefund %s: want validation, got %v", tc.name, err)
			}
		}
	}
}

func TestC6GetRefund(t *testing.T) {
	t.Parallel()
	p, bs := bacenProvider(t)
	got, err := p.GetRefund(context.Background(), "t1", "E1", "dev1")
	if err != nil {
		t.Fatalf("GetRefund: %v", err)
	}
	if got.ReturnID == "" || got.AmountCents != 150 {
		t.Fatalf("unexpected refund: %+v", got)
	}
	method, path, _, _, _ := bs.snapshot()
	if method != http.MethodGet || path != "/v2/pix/pix/E1/devolucao/dev1" {
		t.Fatalf("unexpected request: %s %s", method, path)
	}
}

// --- Lote de cobranças com vencimento (roteiro P_03) -----------------------------

func loteCharges() []ports.PixDueChargeRequest {
	due := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	return []ports.PixDueChargeRequest{
		{TxID: "tx1", AmountCents: 1000, DueDate: due, ValidityDays: 30, CreditorKey: "k@example.com"},
		{TxID: "tx2", AmountCents: 2000, DueDate: due, CreditorKey: "k@example.com"},
	}
}

func TestC6CreateBatch(t *testing.T) {
	t.Parallel()
	p, bs := bacenProvider(t)

	if err := p.CreateBatch(context.Background(), "t1", "lote-1", "lote de setembro", loteCharges()); err != nil {
		t.Fatalf("CreateBatch: %v", err)
	}
	method, path, _, body, idem := bs.snapshot()
	if method != http.MethodPut || path != "/v2/pix/lotecobv/lote-1" {
		t.Fatalf("unexpected request: %s %s", method, path)
	}
	if idem != "lote-1" {
		t.Fatalf("batch id must anchor idempotency, got %q", idem)
	}
	var sent struct {
		Descricao string `json:"descricao"`
		CobsV     []struct {
			TxID  string `json:"txid"`
			Valor struct {
				Original string `json:"original"`
			} `json:"valor"`
		} `json:"cobsv"`
	}
	if err := json.Unmarshal(body, &sent); err != nil {
		t.Fatalf("decode body: %v (%s)", err, body)
	}
	if sent.Descricao != "lote de setembro" || len(sent.CobsV) != 2 ||
		sent.CobsV[0].TxID != "tx1" || sent.CobsV[0].Valor.Original != "10.00" {
		t.Fatalf("unexpected body: %s", body)
	}
}

func TestC6BatchWriteValidation(t *testing.T) {
	t.Parallel()
	p, _ := bacenProvider(t)
	ctx := context.Background()
	due := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

	cases := map[string]struct {
		batchID, description string
		charges              []ports.PixDueChargeRequest
	}{
		"no_batch_id":    {" ", "d", loteCharges()},
		"no_description": {"lote-1", " ", loteCharges()},
		"no_charges":     {"lote-1", "d", nil},
		"charge_without_txid": {"lote-1", "d", []ports.PixDueChargeRequest{
			{AmountCents: 100, DueDate: due},
		}},
		"charge_without_amount": {"lote-1", "d", []ports.PixDueChargeRequest{
			{TxID: "tx1", DueDate: due},
		}},
		"charge_without_due_date": {"lote-1", "d", []ports.PixDueChargeRequest{
			{TxID: "tx1", AmountCents: 100},
		}},
	}
	for name, tc := range cases {
		if err := p.CreateBatch(ctx, "t1", tc.batchID, tc.description, tc.charges); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("CreateBatch %s: want validation, got %v", name, err)
		}
		if err := p.ReviseBatch(ctx, "t1", tc.batchID, tc.description, tc.charges); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("ReviseBatch %s: want validation, got %v", name, err)
		}
	}
}

func TestC6ReviseBatch(t *testing.T) {
	t.Parallel()
	p, bs := bacenProvider(t)
	if err := p.ReviseBatch(context.Background(), "t1", "lote-1", "lote revisado", loteCharges()); err != nil {
		t.Fatalf("ReviseBatch: %v", err)
	}
	if method, path, _, _, _ := bs.snapshot(); method != http.MethodPatch || path != "/v2/pix/lotecobv/lote-1" {
		t.Fatalf("unexpected request: %s %s", method, path)
	}
}

// The batch read is the ONLY place the outcome of a batched registration appears —
// the write answered 202, which says the PSP took it, not that the charges exist.
func TestC6GetBatch(t *testing.T) {
	t.Parallel()
	p, bs := bacenProvider(t)

	got, err := p.GetBatch(context.Background(), "t1", "lote-1")
	if err != nil {
		t.Fatalf("GetBatch: %v", err)
	}
	// The read declares `id` as an integer while the path takes a string; both parse.
	if got.ID != "42" || got.Description != "lote de setembro" || got.CreatedAt.IsZero() {
		t.Fatalf("unexpected batch: %+v", got)
	}
	if len(got.Items) != 2 {
		t.Fatalf("want 2 items, got %d", len(got.Items))
	}
	if got.Items[0].Status != string(ports.BatchChargeCreated) || got.Items[0].Problem != "" {
		t.Fatalf("item 0: %+v", got.Items[0])
	}
	// A NEGADA charge's reason is the only record of WHY that one line was refused.
	if got.Items[1].Status != string(ports.BatchChargeDenied) ||
		got.Items[1].Problem != "Not found: chave inexistente" {
		t.Fatalf("item 1: %+v", got.Items[1])
	}
	if _, path, _, _, _ := bs.snapshot(); path != "/v2/pix/lotecobv/lote-1" {
		t.Fatalf("unexpected path: %s", path)
	}
}

func TestC6GetBatchValidationAndNotFound(t *testing.T) {
	t.Parallel()
	p, bs := bacenProvider(t)
	if _, err := p.GetBatch(context.Background(), "t1", "  "); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty id: want validation, got %v", err)
	}
	bs.override("GET /v2/pix/lotecobv/{id}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"title":"Not found","status":404}`))
	})
	if _, err := p.GetBatch(context.Background(), "t1", "nope"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("404 should map to ErrNotFound, got %v", err)
	}
}

func TestC6ListBatches(t *testing.T) {
	t.Parallel()
	p, bs := bacenProvider(t)
	start, end := bacenWindow()

	got, err := p.ListBatches(context.Background(), "t1", ports.PixDueChargeBatchFilter{Start: start, End: end})
	if err != nil {
		t.Fatalf("ListBatches: %v", err)
	}
	if len(got.Batches) != 1 || got.Batches[0].ID != "42" || got.TotalItems != 1 {
		t.Fatalf("unexpected list: %+v", got)
	}
	if _, path, _, _, _ := bs.snapshot(); path != "/v2/pix/lotecobv" {
		t.Fatalf("unexpected path: %s", path)
	}
	if _, err := p.ListBatches(context.Background(), "t1", ports.PixDueChargeBatchFilter{Start: start}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing end: want validation, got %v", err)
	}
}

// --- Cobrança imediata sem txid e revisões (roteiro P_01_02/P_01_03/P_02_02) -----

func TestC6CreateImmediateChargeAutoTxID(t *testing.T) {
	t.Parallel()
	p, bs := bacenProvider(t)

	got, err := p.CreateImmediateChargeAutoTxID(context.Background(), "t1",
		ports.ChargeRequest{PaymentID: "pay-1", AmountCents: 1000, CreditorKey: "k@example.com"}, time.Hour)
	if err != nil {
		t.Fatalf("CreateImmediateChargeAutoTxID: %v", err)
	}
	if got.TxID != "psp-assigned-txid" {
		t.Fatalf("the PSP assigns the txid here: %+v", got)
	}
	method, path, _, _, idem := bs.snapshot()
	if method != http.MethodPost || path != "/v2/pix/cob" {
		t.Fatalf("unexpected request: %s %s", method, path)
	}
	// There is no txid to collapse a retry onto, so the header is the only guard.
	if idem != "pay-1" {
		t.Fatalf("idempotency key must be forwarded, got %q", idem)
	}
}

func TestC6CreateImmediateChargeAutoTxIDValidation(t *testing.T) {
	t.Parallel()
	p, bs := bacenProvider(t)
	ctx := context.Background()

	if _, err := p.CreateImmediateChargeAutoTxID(ctx, "t1", ports.ChargeRequest{AmountCents: 100}, 0); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("no anchor: want validation, got %v", err)
	}
	if _, err := p.CreateImmediateChargeAutoTxID(ctx, "t1", ports.ChargeRequest{PaymentID: "p"}, 0); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("zero amount: want validation, got %v", err)
	}
	bs.override("POST /v2/pix/cob", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"status":"ATIVA","valor":{"original":"10.00"}}`))
	})
	req := ports.ChargeRequest{PaymentID: "p", AmountCents: 100}
	if _, err := p.CreateImmediateChargeAutoTxID(ctx, "t1", req, 0); !errors.Is(err, shared.ErrUnavailable) {
		t.Fatalf("a 201 without a txid is unaddressable: %v", err)
	}
}

func TestC6ReviseImmediateCharge(t *testing.T) {
	t.Parallel()
	p, bs := bacenProvider(t)

	got, err := p.ReviseImmediateCharge(context.Background(), "t1", "tx-9",
		ports.ChargeRequest{PaymentID: "pay-1", AmountCents: 2000}, 2*time.Hour)
	if err != nil {
		t.Fatalf("ReviseImmediateCharge: %v", err)
	}
	if got.TxID != "tx-9" || got.ExpectedAmountCents != 2000 {
		t.Fatalf("unexpected result: %+v", got)
	}
	method, path, _, body, _ := bs.snapshot()
	if method != http.MethodPatch || path != "/v2/pix/cob/tx-9" {
		t.Fatalf("unexpected request: %s %s", method, path)
	}
	// PATCH amends: a field the caller did not set must be ABSENT, not zero.
	var sent map[string]any
	if err := json.Unmarshal(body, &sent); err != nil {
		t.Fatalf("decode body: %v (%s)", err, body)
	}
	if _, ok := sent["devedor"]; ok {
		t.Fatalf("absent devedor must be omitted: %s", body)
	}
	if _, ok := sent["valor"]; !ok {
		t.Fatalf("amount was set and must be sent: %s", body)
	}
}

// An empty PATCH is a lost field, not a no-op: answering "ok" to it would report a
// change that never happened.
func TestC6ReviseImmediateChargeRejectsEmptyPatch(t *testing.T) {
	t.Parallel()
	p, _ := bacenProvider(t)
	ctx := context.Background()

	if _, err := p.ReviseImmediateCharge(ctx, "t1", "tx-9", ports.ChargeRequest{}, 0); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty patch: want validation, got %v", err)
	}
	if _, err := p.ReviseImmediateCharge(ctx, "t1", "  ", ports.ChargeRequest{AmountCents: 1}, 0); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty txid: want validation, got %v", err)
	}
	neg := ports.ChargeRequest{AmountCents: -1}
	if _, err := p.ReviseImmediateCharge(ctx, "t1", "tx-9", neg, 0); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("negative amount: want validation, got %v", err)
	}
}

func TestC6ReviseDueCharge(t *testing.T) {
	t.Parallel()
	p, bs := bacenProvider(t)

	got, err := p.ReviseDueCharge(context.Background(), "t1", "tx-9", ports.PixDueChargeRequest{
		AmountCents: 2000, ValidityDays: 45,
		DueDate: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("ReviseDueCharge: %v", err)
	}
	if got.TxID != "tx-9" || got.ExpectedAmountCents != 2000 || got.ValidityDays != 45 {
		t.Fatalf("unexpected result: %+v", got)
	}
	if method, path, _, _, _ := bs.snapshot(); method != http.MethodPatch || path != "/v2/pix/cobv/tx-9" {
		t.Fatalf("unexpected request: %s %s", method, path)
	}
}

func TestC6ReviseDueChargeRejectsEmptyPatch(t *testing.T) {
	t.Parallel()
	p, _ := bacenProvider(t)
	ctx := context.Background()
	if _, err := p.ReviseDueCharge(ctx, "t1", "tx-9", ports.PixDueChargeRequest{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty patch: want validation, got %v", err)
	}
	if _, err := p.ReviseDueCharge(ctx, "t1", "  ", ports.PixDueChargeRequest{AmountCents: 1}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty txid: want validation, got %v", err)
	}
}

func TestC6ListDueCharges(t *testing.T) {
	t.Parallel()
	p, bs := bacenProvider(t)
	start, end := bacenWindow()

	got, err := p.ListDueCharges(context.Background(), "t1", ports.PixListFilter{Start: start, End: end})
	if err != nil {
		t.Fatalf("ListDueCharges: %v", err)
	}
	if len(got.Charges) != 1 || got.Charges[0].ExpectedAmountCents != 1000 || got.TotalItems != 2 {
		t.Fatalf("unexpected list: %+v", got)
	}
	if _, path, _, _, _ := bs.snapshot(); path != "/v2/pix/cobv" {
		t.Fatalf("unexpected path: %s", path)
	}
	if _, err := p.ListDueCharges(context.Background(), "t1", ports.PixListFilter{Start: start}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing end: want validation, got %v", err)
	}
}

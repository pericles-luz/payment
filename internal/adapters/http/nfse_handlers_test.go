package http_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	httpadapter "github.com/ia-dev-sindireceita/payment/internal/adapters/http"
	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/system"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/nfse"
	"github.com/ia-dev-sindireceita/payment/internal/nfse/a1import"
	"github.com/ia-dev-sindireceita/payment/internal/nfse/custody"
)

const (
	nfseEmitter = "67188163000110"
	nfseTaker   = "57151944000187"
	nfseChave   = "35261167188163000110000000000000001123456789012345"
)

type httpFakeADN struct {
	mu      sync.Mutex
	receipt nfse.Receipt
	err     error
	pdf     []byte
	pdfErr  error
}

func (f *httpFakeADN) Transmit(context.Context, string, []byte) (nfse.Receipt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.receipt, f.err
}

func (f *httpFakeADN) GetDANFSe(context.Context, string, string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pdf, f.pdfErr
}

type httpFakeImporter struct {
	err  error
	meta custody.A1Meta
	got  string
}

func (f *httpFakeImporter) Import(_ context.Context, tenantID string, pfx []byte, password, cnpj string) (a1import.Result, error) {
	f.got = tenantID + "|" + string(pfx) + "|" + password + "|" + cnpj
	if f.err != nil {
		return a1import.Result{}, f.err
	}
	return a1import.Result{CNPJ: strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, cnpj), Meta: f.meta, RetiredSerial: "old"}, nil
}

func (f *httpFakeImporter) Certificate(context.Context, string, string) (custody.A1Meta, error) {
	if f.err != nil {
		return custody.A1Meta{}, f.err
	}
	return f.meta, nil
}

type nfseFixture struct {
	handler  http.Handler
	tenantID string
	adn      *httpFakeADN
	imp      *httpFakeImporter
}

func newNFSeFixture(t *testing.T, enabled bool) *nfseFixture {
	t.Helper()
	store := persistence.NewStore()
	deps := app.Deps{
		Tenants: store, Pricing: store, Ledger: store, Payments: store, Processed: store,
		UoW: store, Audit: store, Clock: system.Clock{}, IDs: system.IDProvider{},
	}
	admin := app.NewAdminService(deps)
	tn, err := admin.CreateTenant(context.Background(), "LHMOST")
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	signer := custody.NewLocalTestSigner()
	companyID := custody.CompanyIDFor(tn.ID(), nfseEmitter)
	chain, meta, err := signer.Provision(companyID, nfseEmitter, 365*24*time.Hour)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if err := store.NFSeCerts().PutA1(context.Background(), companyID, chain, meta); err != nil {
		t.Fatalf("put a1: %v", err)
	}
	fa := &httpFakeADN{receipt: nfse.Receipt{ChaveAcesso: nfseChave, NFSeNumber: "17", XML: []byte("<NFSe>ok</NFSe>")}, pdf: []byte("%PDF-1.7")}
	imp := &httpFakeImporter{meta: custody.A1Meta{Serial: "abc", Subject: "LHMOST", NotAfter: time.Now().Add(48 * time.Hour)}}
	auth := httpadapter.NewStaticTokenAuth(map[string]string{tenantToken: tn.ID()}, []string{adminToken}, nil)
	cfg := httpadapter.Config{Admin: admin, TenantAuth: auth, AdminAuth: auth, WebhookAuth: auth}
	if enabled {
		cfg.NFSe = app.NewNFSeService(deps, app.NFSeDeps{
			Store: store, Certs: store.NFSeCerts(), Signer: signer, ADN: fa, Importer: imp,
		})
	}
	return &nfseFixture{handler: httpadapter.NewServer(cfg).Router(), tenantID: tn.ID(), adn: fa, imp: imp}
}

func nfseBody() map[string]any {
	return map[string]any{
		"cnpj":                        "67.188.163/0001-10",
		"competencia":                 "2026-10",
		"municipio_prestacao":         "3550308",
		"codigo_servico":              "010501",
		"codigo_tributacao_municipal": "001",
		"codigo_nbs":                  "1.1106.20.00",
		"descricao":                   "Licenciamento — outubro/2026",
		"valor_cents":                 269000,
		"simples_nacional":            "me_epp",
		"aliquota_simples_bps":        600,
		"tomador":                     map[string]any{"documento": nfseTaker, "nome": "SYNDEOTECH"},
	}
}

func decodeMap(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return m
}

func TestNFSeRoutesUnavailableWhenDisabled(t *testing.T) {
	t.Parallel()
	f := newNFSeFixture(t, false)
	for _, rt := range []struct{ method, path string }{
		{http.MethodPost, "/v1/nfse"},
		{http.MethodGet, "/v1/nfse/x"},
		{http.MethodGet, "/v1/nfse/x/xml"},
		{http.MethodGet, "/v1/nfse/x/pdf"},
		{http.MethodPut, "/v1/nfse-certificates"},
		{http.MethodGet, "/v1/nfse-certificates/" + nfseEmitter},
	} {
		rec := do(t, f.handler, rt.method, rt.path, tenantToken, idem("k"), nfseBody())
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s %s = %d, want 503", rt.method, rt.path, rec.Code)
		}
	}
	rec := do(t, f.handler, http.MethodPut, "/admin/tenants/"+f.tenantID+"/nfse-certificate", adminToken, nil, map[string]any{})
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("admin put = %d, want 503", rec.Code)
	}
}

func TestNFSeEmitAndReadOverHTTP(t *testing.T) {
	t.Parallel()
	f := newNFSeFixture(t, true)
	if rec := do(t, f.handler, http.MethodPost, "/v1/nfse", "", idem("k"), nfseBody()); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated = %d", rec.Code)
	}
	rec := do(t, f.handler, http.MethodPost, "/v1/nfse", tenantToken, idem("invoice:2026-0010"), nfseBody())
	if rec.Code != http.StatusCreated {
		t.Fatalf("emit = %d %s", rec.Code, rec.Body.String())
	}
	got := decodeMap(t, rec)
	id, _ := got["id"].(string)
	if got["status"] != "authorized" || got["chave_acesso"] != nfseChave || got["numero_dps"] != "1" ||
		got["serie"] != "1" || got["competencia"] != "2026-10" || got["tomador_documento"] != nfseTaker || id == "" {
		t.Fatalf("emit body = %v", got)
	}
	// Replay returns the same emission.
	rec = do(t, f.handler, http.MethodPost, "/v1/nfse", tenantToken, idem("invoice:2026-0010"), nfseBody())
	if rec.Code != http.StatusCreated || decodeMap(t, rec)["id"] != id {
		t.Fatalf("replay = %d %s", rec.Code, rec.Body.String())
	}

	rec = do(t, f.handler, http.MethodGet, "/v1/nfse/"+id, tenantToken, nil, nil)
	if rec.Code != http.StatusOK || decodeMap(t, rec)["numero_nfse"] != "17" {
		t.Fatalf("get = %d %s", rec.Code, rec.Body.String())
	}
	rec = do(t, f.handler, http.MethodGet, "/v1/nfse/"+id+"/xml", tenantToken, nil, nil)
	if rec.Code != http.StatusOK || rec.Body.String() != "<NFSe>ok</NFSe>" || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/xml") {
		t.Fatalf("xml = %d %q %s", rec.Code, rec.Body.String(), rec.Header().Get("Content-Type"))
	}
	rec = do(t, f.handler, http.MethodGet, "/v1/nfse/"+id+"/pdf", tenantToken, nil, nil)
	if rec.Code != http.StatusOK || rec.Body.String() != "%PDF-1.7" || rec.Header().Get("Content-Type") != "application/pdf" {
		t.Fatalf("pdf = %d %q", rec.Code, rec.Body.String())
	}
	if rec := do(t, f.handler, http.MethodGet, "/v1/nfse/nfse_unknown", tenantToken, nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown = %d", rec.Code)
	}
}

func TestNFSeEmitValidation(t *testing.T) {
	t.Parallel()
	f := newNFSeFixture(t, true)
	cases := []struct {
		name   string
		mut    func(map[string]any)
		noKey  bool
		status int
		code   string
	}{
		{name: "no idempotency key", noKey: true, status: 400},
		{name: "bad cnpj", mut: func(b map[string]any) { b["cnpj"] = "123" }, status: 400, code: "nfse_invalid_cnpj"},
		{name: "zero day", mut: func(b map[string]any) { b["competencia"] = "2026-10-00" }, status: 400, code: "nfse_invalid_competencia"},
		{name: "bad competencia", mut: func(b map[string]any) { b["competencia"] = "10/2026" }, status: 400, code: "nfse_invalid_competencia"},
		{name: "bad regime", mut: func(b map[string]any) { b["simples_nacional"] = "lucro_real" }, status: 400, code: "nfse_invalid_regime"},
		{name: "bad tomador", mut: func(b map[string]any) { b["tomador"] = map[string]any{"documento": "1", "nome": "x"} }, status: 400, code: "nfse_invalid_tomador"},
		{name: "bad nbs", mut: func(b map[string]any) { b["codigo_nbs"] = "12" }, status: 400, code: "nfse_invalid_codigo_nbs"},
		{name: "bad value", mut: func(b map[string]any) { b["valor_cents"] = 0 }, status: 400, code: "nfse_invalid_valor"},
		{name: "mei with rate", mut: func(b map[string]any) { b["simples_nacional"] = "mei" }, status: 400, code: "nfse_invalid_aliquota_simples"},
		{name: "unknown field", mut: func(b map[string]any) { b["numero"] = "9" }, status: 400},
		{name: "no certificate", mut: func(b map[string]any) { b["cnpj"] = nfseTaker }, status: 422, code: "nfse_no_certificate"},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := nfseBody()
			if tc.mut != nil {
				tc.mut(b)
			}
			h := idem("k" + string(rune('a'+i)))
			if tc.noKey {
				h = nil
			}
			rec := do(t, f.handler, http.MethodPost, "/v1/nfse", tenantToken, h, b)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d (%s)", rec.Code, tc.status, rec.Body.String())
			}
			if tc.code != "" && decodeMap(t, rec)["code"] != tc.code {
				t.Fatalf("code = %v, want %s", decodeMap(t, rec)["code"], tc.code)
			}
		})
	}
}

func TestNFSeEmitADNFailures(t *testing.T) {
	t.Parallel()
	f := newNFSeFixture(t, true)
	f.adn.err = &nfse.BusinessError{HTTPStatus: 400, Items: []nfse.BusinessErrorItem{{Code: "E0712", Message: "x"}}}
	rec := do(t, f.handler, http.MethodPost, "/v1/nfse", tenantToken, idem("rej"), nfseBody())
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("rejected = %d %s", rec.Code, rec.Body.String())
	}
	body := decodeMap(t, rec)
	em, _ := body["emission"].(map[string]any)
	if body["code"] != "nfse_rejected" || em["status"] != "rejected" || em["rejeicao_codigo"] != "E0712" {
		t.Fatalf("rejected body = %v", body)
	}
	id, _ := em["id"].(string)
	if rec := do(t, f.handler, http.MethodGet, "/v1/nfse/"+id+"/pdf", tenantToken, nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("pdf of rejected = %d", rec.Code)
	}
	if rec := do(t, f.handler, http.MethodGet, "/v1/nfse/"+id+"/xml", tenantToken, nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("xml of rejected = %d", rec.Code)
	}

	f.adn.err = &nfse.TransportError{Op: "do", Err: errors.New("timeout")}
	if rec := do(t, f.handler, http.MethodPost, "/v1/nfse", tenantToken, idem("down"), nfseBody()); rec.Code != http.StatusBadGateway {
		t.Fatalf("transport = %d", rec.Code)
	}

	f.adn.err = nil
	f.adn.pdfErr = &nfse.TransportError{Op: "do", Err: errors.New("timeout")}
	rec = do(t, f.handler, http.MethodPost, "/v1/nfse", tenantToken, idem("ok"), nfseBody())
	id, _ = decodeMap(t, rec)["id"].(string)
	if rec := do(t, f.handler, http.MethodGet, "/v1/nfse/"+id+"/pdf", tenantToken, nil, nil); rec.Code != http.StatusBadGateway {
		t.Fatalf("pdf transport = %d", rec.Code)
	}
	if rec := do(t, f.handler, http.MethodGet, "/v1/nfse/nope/pdf", tenantToken, nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("pdf unknown = %d", rec.Code)
	}
}

func TestNFSeCertificateRoutes(t *testing.T) {
	t.Parallel()
	f := newNFSeFixture(t, true)
	body := map[string]any{"cnpj": "67.188.163/0001-10", "pfx_base64": base64.StdEncoding.EncodeToString([]byte("PFX")), "password": "pw"}

	rec := do(t, f.handler, http.MethodPut, "/v1/nfse-certificates", tenantToken, nil, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("put = %d %s", rec.Code, rec.Body.String())
	}
	got := decodeMap(t, rec)
	if got["serial"] != "abc" || got["cnpj"] != nfseEmitter || got["replaced_serial"] != "old" {
		t.Fatalf("put body = %v", got)
	}
	if f.imp.got != f.tenantID+"|PFX|pw|67.188.163/0001-10" {
		t.Fatalf("importer got %q", f.imp.got)
	}
	if strings.Contains(rec.Body.String(), "pw") {
		t.Fatal("password echoed")
	}

	rec = do(t, f.handler, http.MethodPut, "/admin/tenants/"+f.tenantID+"/nfse-certificate", adminToken, nil, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin put = %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(t, f.handler, http.MethodPut, "/admin/tenants/"+f.tenantID+"/nfse-certificate", tenantToken, nil, body); rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
		t.Fatalf("admin put with tenant token = %d", rec.Code)
	}

	rec = do(t, f.handler, http.MethodGet, "/v1/nfse-certificates/67188163000110", tenantToken, nil, nil)
	if rec.Code != http.StatusOK || decodeMap(t, rec)["subject"] != "LHMOST" {
		t.Fatalf("get = %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(t, f.handler, http.MethodGet, "/v1/nfse-certificates/123", tenantToken, nil, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("get bad cnpj = %d", rec.Code)
	}

	bad := map[string]any{"cnpj": "123", "pfx_base64": "UEZY", "password": "pw"}
	if rec := do(t, f.handler, http.MethodPut, "/v1/nfse-certificates", tenantToken, nil, bad); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad cnpj = %d", rec.Code)
	}
	bad = map[string]any{"cnpj": nfseEmitter, "pfx_base64": "%%%", "password": "pw"}
	if rec := do(t, f.handler, http.MethodPut, "/v1/nfse-certificates", tenantToken, nil, bad); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("bad base64 = %d", rec.Code)
	}
	if rec := do(t, f.handler, http.MethodPut, "/v1/nfse-certificates", tenantToken, nil, map[string]any{"x": 1}); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown field = %d", rec.Code)
	}

	huge := bytes.Repeat([]byte("A"), a1import.MaxPFXSize*2)
	req := httptest.NewRequest(http.MethodPut, "/v1/nfse-certificates",
		strings.NewReader(`{"cnpj":"`+nfseEmitter+`","password":"x","pfx_base64":"`+string(huge)+`"}`))
	req.Header.Set("Authorization", "Bearer "+tenantToken)
	big := httptest.NewRecorder()
	f.handler.ServeHTTP(big, req)
	if big.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("too large = %d", big.Code)
	}

	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{
		{a1import.ErrWrongPassword, 422, "nfse_cert_wrong_password"},
		{a1import.ErrOlderCertificate, 409, "nfse_cert_older"},
		{custody.ErrVaultTransport, 503, "nfse_custody_unavailable"},
	} {
		f.imp.err = tc.err
		rec := do(t, f.handler, http.MethodPut, "/v1/nfse-certificates", tenantToken, nil, body)
		if rec.Code != tc.status || decodeMap(t, rec)["code"] != tc.code {
			t.Fatalf("%v: %d %s", tc.err, rec.Code, rec.Body.String())
		}
	}
	f.imp.err = custody.ErrCertNotFound
	if rec := do(t, f.handler, http.MethodGet, "/v1/nfse-certificates/"+nfseEmitter, tenantToken, nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("get missing = %d", rec.Code)
	}
}

func TestNFSeCompetenciaFormats(t *testing.T) {
	t.Parallel()
	f := newNFSeFixture(t, true)
	today := time.Now().In(time.FixedZone("BRT", -3*3600)).Format("2006-01-02")
	for _, tc := range []struct{ in, want string }{
		{"", today},
		{today, today},
		{"2026-10", "2026-10"},
	} {
		b := nfseBody()
		b["competencia"] = tc.in
		rec := do(t, f.handler, http.MethodPost, "/v1/nfse", tenantToken, idem("comp-"+tc.in), b)
		if rec.Code != http.StatusCreated {
			t.Fatalf("%q: %d %s", tc.in, rec.Code, rec.Body.String())
		}
		if got := decodeMap(t, rec)["competencia"]; got != tc.want {
			t.Errorf("%q: competencia = %v, want %s", tc.in, got, tc.want)
		}
	}
}

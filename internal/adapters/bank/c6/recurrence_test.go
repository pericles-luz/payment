package c6

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// recServer is a configurable C6 double for the PIX Automático (Recorrência)
// surface plus the OAuth2 token endpoint, backed by httptest TLS. Each route has a
// happy-path default that a test can override. It records the last Authorization /
// Idempotency-Key / Accept / body so tests can assert plumbing without races.
type recServer struct {
	*httptest.Server

	lastAuth   string
	lastIdem   string
	lastAccept string
	lastMethod string
	lastBody   []byte

	recCreate http.HandlerFunc
	recGet    http.HandlerFunc
	recCancel http.HandlerFunc
	solicPost http.HandlerFunc
	solicGet  http.HandlerFunc
	cobrPost  http.HandlerFunc
	cobrGet   http.HandlerFunc
	cobrPut   http.HandlerFunc
	cobrRetry http.HandlerFunc
}

const (
	recRespJSON   = `{"data":{"idRec":"RR318724952026062600000000abc","status":"CRIADA","vinculo":{"contrato":"CT-1","devedor":{"cpf":"12345678909","nome":"Fulano"}},"calendario":{"dataInicial":"2026-08-01","periodicidade":"MENSAL"},"recebedor":{"ispbParticipante":"31872495","cnpj":"32159366000102","nome":"Acme"},"politicaRetentativa":"PERMITE_3R_7D","ativacao":{"tipoJornada":"AGUARDANDO_DEFINICAO"}}}`
	recCancelJSON = `{"data":{"idRec":"RR318724952026062600000000abc","status":"CANCELADA","vinculo":{"contrato":"CT-1","devedor":{"cpf":"12345678909","nome":"Fulano"}},"calendario":{"dataInicial":"2026-08-01","periodicidade":"MENSAL"},"recebedor":{"cnpj":"32159366000102","nome":"Acme"},"politicaRetentativa":"PERMITE_3R_7D","ativacao":{"tipoJornada":"AGUARDANDO_DEFINICAO"}}}`
	solicRespJSON = `{"data":{"idSolicRec":"SC318724952026062600000000xyz","idRec":"RR318724952026062600000000abc","status":"CRIADA","calendario":{"dataExpiracaoSolicitacao":"2026-07-10T23:59:59Z"},"destinatario":{"cpf":"12345678909","agencia":"0001","conta":"12345","ispbParticipante":"00000000"}}}`
	cobrRespJSON  = `{"data":{"txid":"tx-cobr-1","idRec":"RR318724952026062600000000abc","status":"CRIADA","valor":{"original":"10.50"}}}`
)

func newRecServer(t *testing.T) *recServer {
	t.Helper()
	rs := &recServer{}

	record := func(r *http.Request) {
		rs.lastAuth = r.Header.Get("Authorization")
		rs.lastIdem = r.Header.Get("Idempotency-Key")
		rs.lastAccept = r.Header.Get("Accept")
		rs.lastMethod = r.Method
		rs.lastBody, _ = io.ReadAll(io.LimitReader(r.Body, 1<<20))
	}
	json201 := func(w http.ResponseWriter, body string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(body))
	}
	// A signed read returns an opaque JWS compact serialization; the body content
	// is irrelevant because the (fake) verifier supplies the decoded payload.
	jose := func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/jose")
		_, _ = w.Write([]byte("eyJ.signed.jws"))
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /oauth/token", func(w http.ResponseWriter, r *http.Request) {
		user, _, _ := r.BasicAuth()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok-` + user + `","token_type":"Bearer","expires_in":3600}`))
	})
	mux.HandleFunc("POST /v2/pix/rec", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		if rs.recCreate != nil {
			rs.recCreate(w, r)
			return
		}
		json201(w, recRespJSON)
	})
	mux.HandleFunc("GET /v2/pix/rec/{idRec}", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		if rs.recGet != nil {
			rs.recGet(w, r)
			return
		}
		jose(w)
	})
	mux.HandleFunc("PATCH /v2/pix/rec/{idRec}", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		if rs.recCancel != nil {
			rs.recCancel(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(recCancelJSON))
	})
	mux.HandleFunc("POST /v2/pix/solicrec", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		if rs.solicPost != nil {
			rs.solicPost(w, r)
			return
		}
		json201(w, solicRespJSON)
	})
	mux.HandleFunc("GET /v2/pix/solicrec/{id}", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		if rs.solicGet != nil {
			rs.solicGet(w, r)
			return
		}
		jose(w)
	})
	mux.HandleFunc("POST /v2/pix/cobr", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		if rs.cobrPost != nil {
			rs.cobrPost(w, r)
			return
		}
		json201(w, cobrRespJSON)
	})
	mux.HandleFunc("GET /v2/pix/cobr/{txid}", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		if rs.cobrGet != nil {
			rs.cobrGet(w, r)
			return
		}
		jose(w)
	})
	mux.HandleFunc("PUT /v2/pix/cobr/{txid}", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		if rs.cobrPut != nil {
			rs.cobrPut(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(cobrRespJSON))
	})
	mux.HandleFunc("POST /v2/pix/cobr/{txid}/retentativa/{data}", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		if rs.cobrRetry != nil {
			rs.cobrRetry(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(cobrRespJSON))
	})

	rs.Server = httptest.NewTLSServer(mux)
	t.Cleanup(rs.Close)
	return rs
}

func (rs *recServer) provider(t *testing.T, creds ports.CredentialStore, v RecurrenceVerifier) *Provider {
	t.Helper()
	p, err := New(Config{
		BaseURL:            rs.URL,
		TokenURL:           rs.URL + "/oauth/token",
		HTTPClient:         rs.Client(),
		RecurrenceVerifier: v,
	}, creds)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

// fakeVerifier is a test double for RecurrenceVerifier: it returns a fixed decoded
// payload (or error) and records the compact bytes it was handed.
type fakeVerifier struct {
	payload    []byte
	err        error
	gotCompact []byte
}

func (f *fakeVerifier) VerifyJWS(_ context.Context, compact []byte) ([]byte, error) {
	f.gotCompact = compact
	if f.err != nil {
		return nil, f.err
	}
	return f.payload, nil
}

func recReq() ports.CreateRecRequest {
	return ports.CreateRecRequest{
		Vinculo: ports.RecVinculo{
			Contrato: "CT-1",
			Devedor:  ports.RecDevedor{CPF: "12345678909", Nome: "Fulano"},
			Objeto:   "Assinatura",
		},
		Calendario:          ports.RecCalendario{DataInicial: "2026-08-01", Periodicidade: ports.RecMensal},
		PoliticaRetentativa: ports.Retry3R7D,
		IdempotencyKey:      "rec-key-1",
	}
}

func cobrReq() ports.CreateCobRRequest {
	return ports.CreateCobRRequest{
		IDRec:          "RR318724952026062600000000abc",
		TxID:           "tx-cobr-1",
		DataVencimento: "2026-09-01",
		AjusteDiaUtil:  true,
		ValorCents:     1050,
		Recebedor:      ports.CobRRecebedor{Conta: "12345", TipoConta: ports.ContaCorrente},
		IdempotencyKey: "cobr-key-1",
	}
}

// --- rec ---

func TestCreateRecSuccess(t *testing.T) {
	t.Parallel()
	rs := newRecServer(t)
	p := rs.provider(t, oneTenant("t1", "client-1", "secret-1"), nil)

	res, err := p.CreateRec(context.Background(), "t1", recReq())
	if err != nil {
		t.Fatalf("CreateRec: %v", err)
	}
	if res.IDRec != "RR318724952026062600000000abc" || res.Status != ports.RecCriada {
		t.Fatalf("unexpected result: %+v", res)
	}
	if res.TipoJornada != "AGUARDANDO_DEFINICAO" || res.Recebedor.CNPJ != "32159366000102" {
		t.Fatalf("recebedor/jornada not reconciled: %+v", res)
	}
	if res.PoliticaRetentativa != ports.Retry3R7D {
		t.Fatalf("politica not reconciled: %+v", res)
	}
	if rs.lastAuth != "Bearer tok-client-1" {
		t.Fatalf("bearer not attached: %q", rs.lastAuth)
	}
	if rs.lastIdem != "rec-key-1" {
		t.Fatalf("idempotency key not forwarded: %q", rs.lastIdem)
	}
	// Wire shape is the real BACEN rec contract: vinculo + calendario + politica,
	// and the recebedor is NOT sent (auto-filled by the bank).
	var sent map[string]json.RawMessage
	if err := json.Unmarshal(rs.lastBody, &sent); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if _, ok := sent["recebedor"]; ok {
		t.Fatalf("recebedor must not be sent on create: %s", rs.lastBody)
	}
	var wire struct {
		Vinculo struct {
			Contrato string `json:"contrato"`
			Devedor  struct {
				CPF  string `json:"cpf"`
				Nome string `json:"nome"`
			} `json:"devedor"`
			Objeto string `json:"objeto"`
		} `json:"vinculo"`
		Calendario struct {
			DataInicial   string `json:"dataInicial"`
			Periodicidade string `json:"periodicidade"`
		} `json:"calendario"`
		PoliticaRetentativa string `json:"politicaRetentativa"`
	}
	if err := json.Unmarshal(rs.lastBody, &wire); err != nil {
		t.Fatalf("decode wire: %v", err)
	}
	if wire.Vinculo.Contrato != "CT-1" || wire.Vinculo.Devedor.CPF != "12345678909" ||
		wire.Vinculo.Objeto != "Assinatura" || wire.Calendario.DataInicial != "2026-08-01" ||
		wire.Calendario.Periodicidade != "MENSAL" || wire.PoliticaRetentativa != "PERMITE_3R_7D" {
		t.Fatalf("wire shape wrong: %+v", wire)
	}
}

func TestCreateRecValidation(t *testing.T) {
	t.Parallel()
	rs := newRecServer(t)
	p := rs.provider(t, oneTenant("t1", "client-1", "secret-1"), nil)

	cases := map[string]func(r *ports.CreateRecRequest){
		"empty contrato":      func(r *ports.CreateRecRequest) { r.Vinculo.Contrato = "" },
		"empty dataInicial":   func(r *ports.CreateRecRequest) { r.Calendario.DataInicial = "" },
		"empty periodicidade": func(r *ports.CreateRecRequest) { r.Calendario.Periodicidade = "" },
		"empty politica":      func(r *ports.CreateRecRequest) { r.PoliticaRetentativa = "" },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			req := recReq()
			mut(&req)
			_, err := p.CreateRec(context.Background(), "t1", req)
			if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want ErrValidation, got %v", err)
			}
		})
	}
}

func TestCreateRecObjetoValidation(t *testing.T) {
	t.Parallel()
	rs := newRecServer(t)
	p := rs.provider(t, oneTenant("t1", "client-1", "secret-1"), nil)

	// C6 rejects an objeto with whitespace; the adapter must fail fast at the
	// boundary (SIN-66072) without ever hitting the upstream.
	for name, objeto := range map[string]string{
		"space":          "Mensalidade homologacao",
		"leading space":  " Mensalidade",
		"trailing space": "Mensalidade ",
		"tab":            "Mensalidade\tX",
	} {
		t.Run(name, func(t *testing.T) {
			req := recReq()
			req.Vinculo.Objeto = objeto
			_, err := p.CreateRec(context.Background(), "t1", req)
			if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want ErrValidation for %q, got %v", objeto, err)
			}
			if rs.lastBody != nil {
				t.Fatalf("invalid objeto must not reach upstream, body=%s", rs.lastBody)
			}
		})
	}
}

func TestCreateRecObjetoAccepted(t *testing.T) {
	t.Parallel()
	rs := newRecServer(t)
	p := rs.provider(t, oneTenant("t1", "client-1", "secret-1"), nil)

	// A single-token objeto (and an empty one) are accepted and forwarded verbatim.
	for name, objeto := range map[string]string{"single token": "Mensalidade", "empty": ""} {
		t.Run(name, func(t *testing.T) {
			req := recReq()
			req.Vinculo.Objeto = objeto
			if _, err := p.CreateRec(context.Background(), "t1", req); err != nil {
				t.Fatalf("CreateRec(%q): %v", objeto, err)
			}
			var wire struct {
				Vinculo struct {
					Objeto string `json:"objeto"`
				} `json:"vinculo"`
			}
			if err := json.Unmarshal(rs.lastBody, &wire); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			if wire.Vinculo.Objeto != objeto {
				t.Fatalf("objeto not forwarded verbatim: want %q got %q", objeto, wire.Vinculo.Objeto)
			}
		})
	}
}

func TestCreateCobRPutsTxidInPath(t *testing.T) {
	t.Parallel()
	rs := newRecServer(t)
	var gotTxid string
	rs.cobrPut = func(w http.ResponseWriter, r *http.Request) {
		gotTxid = r.PathValue("txid")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(cobrRespJSON))
	}
	p := rs.provider(t, oneTenant("t1", "client-1", "secret-1"), nil)

	if _, err := p.CreateCobR(context.Background(), "t1", cobrReq()); err != nil {
		t.Fatalf("CreateCobR: %v", err)
	}
	if gotTxid != "tx-cobr-1" {
		t.Fatalf("txid must be the path resource key, got %q", gotTxid)
	}
	if rs.lastMethod != http.MethodPut {
		t.Fatalf("CobR create must PUT, got %q", rs.lastMethod)
	}
}

func TestCreateRecUpstreamError(t *testing.T) {
	t.Parallel()
	rs := newRecServer(t)
	rs.recCreate = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"type":"https://x/api/v2/error/RequisicaoInvalida"}`))
	}
	p := rs.provider(t, oneTenant("t1", "client-1", "secret-1"), nil)

	_, err := p.CreateRec(context.Background(), "t1", recReq())
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation, got %v", err)
	}
	var ce *Error
	if !errors.As(err, &ce) || ce.Code != "RequisicaoInvalida" {
		t.Fatalf("want parsed code, got %v", err)
	}
}

func TestGetRecSignedSuccess(t *testing.T) {
	t.Parallel()
	rs := newRecServer(t)
	v := &fakeVerifier{payload: []byte(recRespJSON)}
	p := rs.provider(t, oneTenant("t1", "client-1", "secret-1"), v)

	res, err := p.GetRec(context.Background(), "t1", "RR318724952026062600000000abc")
	if err != nil {
		t.Fatalf("GetRec: %v", err)
	}
	if res.IDRec != "RR318724952026062600000000abc" || res.Status != ports.RecCriada {
		t.Fatalf("unexpected result: %+v", res)
	}
	if rs.lastAccept != "application/jose" {
		t.Fatalf("read must request JOSE, got Accept %q", rs.lastAccept)
	}
	if string(v.gotCompact) != "eyJ.signed.jws" {
		t.Fatalf("verifier not handed the signed body: %q", v.gotCompact)
	}
}

func TestGetRecBarePayload(t *testing.T) {
	t.Parallel()
	rs := newRecServer(t)
	// A verified payload delivered WITHOUT the {"data":...} envelope is still parsed.
	v := &fakeVerifier{payload: []byte(`{"idRec":"RRbare","status":"APROVADA","calendario":{"periodicidade":"ANUAL"}}`)}
	p := rs.provider(t, oneTenant("t1", "client-1", "secret-1"), v)

	res, err := p.GetRec(context.Background(), "t1", "RRbare")
	if err != nil {
		t.Fatalf("GetRec: %v", err)
	}
	if res.IDRec != "RRbare" || res.Status != ports.RecAprovada || res.Calendario.Periodicidade != ports.RecAnual {
		t.Fatalf("bare payload not parsed: %+v", res)
	}
}

func TestGetRecValidation(t *testing.T) {
	t.Parallel()
	rs := newRecServer(t)
	p := rs.provider(t, oneTenant("t1", "client-1", "secret-1"), &fakeVerifier{payload: []byte(recRespJSON)})
	if _, err := p.GetRec(context.Background(), "t1", "  "); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation, got %v", err)
	}
}

func TestGetRecNoVerifierFailsSecure(t *testing.T) {
	t.Parallel()
	rs := newRecServer(t)
	p := rs.provider(t, oneTenant("t1", "client-1", "secret-1"), nil) // no verifier

	_, err := p.GetRec(context.Background(), "t1", "RR1")
	if !errors.Is(err, shared.ErrUnavailable) {
		t.Fatalf("want ErrUnavailable (fail secure), got %v", err)
	}
}

func TestGetRecVerifierError(t *testing.T) {
	t.Parallel()
	rs := newRecServer(t)
	v := &fakeVerifier{err: errors.New("bad signature")}
	p := rs.provider(t, oneTenant("t1", "client-1", "secret-1"), v)

	_, err := p.GetRec(context.Background(), "t1", "RR1")
	if !errors.Is(err, shared.ErrUnavailable) {
		t.Fatalf("want ErrUnavailable on verify failure, got %v", err)
	}
}

func TestGetRecNotFound(t *testing.T) {
	t.Parallel()
	rs := newRecServer(t)
	rs.recGet = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"type":"https://x/api/v2/error/NaoEncontrado"}`))
	}
	p := rs.provider(t, oneTenant("t1", "client-1", "secret-1"), &fakeVerifier{payload: []byte(recRespJSON)})

	_, err := p.GetRec(context.Background(), "t1", "RRmissing")
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestGetRecMalformedSignedBody(t *testing.T) {
	t.Parallel()
	rs := newRecServer(t)
	v := &fakeVerifier{payload: []byte(`}not json{`)}
	p := rs.provider(t, oneTenant("t1", "client-1", "secret-1"), v)

	_, err := p.GetRec(context.Background(), "t1", "RR1")
	if !errors.Is(err, shared.ErrUnavailable) {
		t.Fatalf("want ErrUnavailable on malformed body, got %v", err)
	}
}

func TestCancelRecSuccess(t *testing.T) {
	t.Parallel()
	rs := newRecServer(t)
	p := rs.provider(t, oneTenant("t1", "client-1", "secret-1"), nil)

	res, err := p.CancelRec(context.Background(), "t1", "RR318724952026062600000000abc")
	if err != nil {
		t.Fatalf("CancelRec: %v", err)
	}
	if res.Status != ports.RecCancelada {
		t.Fatalf("want CANCELADA, got %+v", res)
	}
	if rs.lastMethod != http.MethodPatch {
		t.Fatalf("cancel must PATCH, got %q", rs.lastMethod)
	}
	if rs.lastIdem != "RR318724952026062600000000abc" {
		t.Fatalf("idRec must be forwarded as idempotency key: %q", rs.lastIdem)
	}
	var wire struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(rs.lastBody, &wire); err != nil || wire.Status != "CANCELADA" {
		t.Fatalf("cancel body wrong: %s (%v)", rs.lastBody, err)
	}
}

func TestCancelRecValidation(t *testing.T) {
	t.Parallel()
	rs := newRecServer(t)
	p := rs.provider(t, oneTenant("t1", "client-1", "secret-1"), nil)
	if _, err := p.CancelRec(context.Background(), "t1", ""); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation, got %v", err)
	}
}

// --- solicrec ---

func TestCreateSolicRecSuccess(t *testing.T) {
	t.Parallel()
	rs := newRecServer(t)
	p := rs.provider(t, oneTenant("t1", "client-1", "secret-1"), nil)

	exp := time.Date(2026, 7, 10, 23, 59, 59, 0, time.UTC)
	res, err := p.CreateSolicRec(context.Background(), "t1", ports.CreateSolicRecRequest{
		IDRec:        "RR318724952026062600000000abc",
		Destinatario: ports.SolicRecDestinatario{CPF: "12345678909", Agencia: "0001", Conta: "12345", ISPBParticipante: "00000000"},
		ExpiraEm:     exp,
	})
	if err != nil {
		t.Fatalf("CreateSolicRec: %v", err)
	}
	if res.IDSolicRec != "SC318724952026062600000000xyz" || res.IDRec != "RR318724952026062600000000abc" {
		t.Fatalf("unexpected result: %+v", res)
	}
	if !res.ExpiraEm.Equal(exp) {
		t.Fatalf("expiry not reconciled: %v want %v", res.ExpiraEm, exp)
	}
	// No explicit idempotency key supplied → idRec used as the anchor.
	if rs.lastIdem != "RR318724952026062600000000abc" {
		t.Fatalf("idRec fallback idempotency key not forwarded: %q", rs.lastIdem)
	}
	var wire struct {
		IDRec      string `json:"idRec"`
		Calendario struct {
			DataExpiracaoSolicitacao string `json:"dataExpiracaoSolicitacao"`
		} `json:"calendario"`
		Destinatario struct {
			CPF              string `json:"cpf"`
			ISPBParticipante string `json:"ispbParticipante"`
		} `json:"destinatario"`
	}
	if err := json.Unmarshal(rs.lastBody, &wire); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if wire.IDRec == "" || wire.Calendario.DataExpiracaoSolicitacao != "2026-07-10T23:59:59Z" ||
		wire.Destinatario.CPF != "12345678909" || wire.Destinatario.ISPBParticipante != "00000000" {
		t.Fatalf("wire shape wrong: %+v", wire)
	}
}

func TestCreateSolicRecValidation(t *testing.T) {
	t.Parallel()
	rs := newRecServer(t)
	p := rs.provider(t, oneTenant("t1", "client-1", "secret-1"), nil)

	cases := map[string]ports.CreateSolicRecRequest{
		"empty idRec": {ExpiraEm: time.Now().Add(time.Hour)},
		"zero expiry": {IDRec: "RR1"},
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := p.CreateSolicRec(context.Background(), "t1", req); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want ErrValidation, got %v", err)
			}
		})
	}
}

func TestGetSolicRecSignedSuccess(t *testing.T) {
	t.Parallel()
	rs := newRecServer(t)
	v := &fakeVerifier{payload: []byte(solicRespJSON)}
	p := rs.provider(t, oneTenant("t1", "client-1", "secret-1"), v)

	res, err := p.GetSolicRec(context.Background(), "t1", "SC318724952026062600000000xyz")
	if err != nil {
		t.Fatalf("GetSolicRec: %v", err)
	}
	if res.IDSolicRec != "SC318724952026062600000000xyz" || res.Status != "CRIADA" {
		t.Fatalf("unexpected result: %+v", res)
	}
	if rs.lastAccept != "application/jose" {
		t.Fatalf("read must request JOSE, got %q", rs.lastAccept)
	}
}

func TestGetSolicRecValidation(t *testing.T) {
	t.Parallel()
	rs := newRecServer(t)
	p := rs.provider(t, oneTenant("t1", "client-1", "secret-1"), &fakeVerifier{payload: []byte(solicRespJSON)})
	if _, err := p.GetSolicRec(context.Background(), "t1", ""); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation, got %v", err)
	}
}

// --- cobr ---

func TestCreateCobRSuccess(t *testing.T) {
	t.Parallel()
	rs := newRecServer(t)
	p := rs.provider(t, oneTenant("t1", "client-1", "secret-1"), nil)

	res, err := p.CreateCobR(context.Background(), "t1", cobrReq())
	if err != nil {
		t.Fatalf("CreateCobR: %v", err)
	}
	if res.TxID != "tx-cobr-1" || res.Status != "CRIADA" || res.ValorCents != 1050 {
		t.Fatalf("unexpected result: %+v", res)
	}
	if rs.lastIdem != "cobr-key-1" {
		t.Fatalf("idempotency key not forwarded: %q", rs.lastIdem)
	}
	// Wire money is centavos rendered as the BACEN decimal string; devedor is {}.
	var wire struct {
		AjusteDiaUtil bool `json:"ajusteDiaUtil"`
		Calendario    struct {
			DataDeVencimento string `json:"dataDeVencimento"`
		} `json:"calendario"`
		Valor struct {
			Original string `json:"original"`
		} `json:"valor"`
		Recebedor struct {
			Conta     string `json:"conta"`
			TipoConta string `json:"tipoConta"`
		} `json:"recebedor"`
		Devedor map[string]any `json:"devedor"`
		IDRec   string         `json:"idRec"`
		TxID    string         `json:"txid"`
	}
	if err := json.Unmarshal(rs.lastBody, &wire); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if wire.Valor.Original != "10.50" {
		t.Fatalf("money not rendered as decimal string: %q", wire.Valor.Original)
	}
	if len(wire.Devedor) != 0 {
		t.Fatalf("devedor must be empty object: %v", wire.Devedor)
	}
	// txid MUST NOT be in the body — C6 rejects it (SIN-66072). It is the resource
	// key in the path, proven by routing to the PUT /v2/pix/cobr/{txid} handler.
	if !wire.AjusteDiaUtil || wire.Calendario.DataDeVencimento != "2026-09-01" ||
		wire.Recebedor.Conta != "12345" || wire.Recebedor.TipoConta != "CORRENTE" ||
		wire.IDRec == "" || wire.TxID != "" {
		t.Fatalf("wire shape wrong: %+v", wire)
	}
	if rs.lastMethod != http.MethodPut {
		t.Fatalf("CobR create must PUT /v2/pix/cobr/{txid}, got %q", rs.lastMethod)
	}
}

func TestCreateCobRValidation(t *testing.T) {
	t.Parallel()
	rs := newRecServer(t)
	p := rs.provider(t, oneTenant("t1", "client-1", "secret-1"), nil)

	cases := map[string]func(r *ports.CreateCobRRequest){
		"empty txid":      func(r *ports.CreateCobRRequest) { r.TxID = "" },
		"empty idRec":     func(r *ports.CreateCobRRequest) { r.IDRec = "" },
		"zero amount":     func(r *ports.CreateCobRRequest) { r.ValorCents = 0 },
		"negative amount": func(r *ports.CreateCobRRequest) { r.ValorCents = -1 },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			req := cobrReq()
			mut(&req)
			if _, err := p.CreateCobR(context.Background(), "t1", req); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want ErrValidation, got %v", err)
			}
		})
	}
}

func TestCreateCobRIdempotencyFallback(t *testing.T) {
	t.Parallel()
	rs := newRecServer(t)
	p := rs.provider(t, oneTenant("t1", "client-1", "secret-1"), nil)

	req := cobrReq()
	req.IdempotencyKey = "" // fall back to txid as the anti-double-bill anchor
	if _, err := p.CreateCobR(context.Background(), "t1", req); err != nil {
		t.Fatalf("CreateCobR: %v", err)
	}
	if rs.lastIdem != "tx-cobr-1" {
		t.Fatalf("txid fallback idempotency key not forwarded: %q", rs.lastIdem)
	}
}

func TestReviseCobRSuccess(t *testing.T) {
	t.Parallel()
	rs := newRecServer(t)
	p := rs.provider(t, oneTenant("t1", "client-1", "secret-1"), nil)

	res, err := p.ReviseCobR(context.Background(), "t1", cobrReq())
	if err != nil {
		t.Fatalf("ReviseCobR: %v", err)
	}
	if res.TxID != "tx-cobr-1" {
		t.Fatalf("unexpected result: %+v", res)
	}
	if rs.lastMethod != http.MethodPut {
		t.Fatalf("revise must PUT, got %q", rs.lastMethod)
	}
}

func TestReviseCobRValidation(t *testing.T) {
	t.Parallel()
	rs := newRecServer(t)
	p := rs.provider(t, oneTenant("t1", "client-1", "secret-1"), nil)
	req := cobrReq()
	req.TxID = ""
	if _, err := p.ReviseCobR(context.Background(), "t1", req); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation, got %v", err)
	}
}

func TestRetryCobRSuccess(t *testing.T) {
	t.Parallel()
	rs := newRecServer(t)
	p := rs.provider(t, oneTenant("t1", "client-1", "secret-1"), nil)

	res, err := p.RetryCobR(context.Background(), "t1", "tx-cobr-1", "2026-09-08")
	if err != nil {
		t.Fatalf("RetryCobR: %v", err)
	}
	if res.TxID != "tx-cobr-1" {
		t.Fatalf("unexpected result: %+v", res)
	}
	if rs.lastMethod != http.MethodPost {
		t.Fatalf("retry must POST, got %q", rs.lastMethod)
	}
}

func TestRetryCobRValidation(t *testing.T) {
	t.Parallel()
	rs := newRecServer(t)
	p := rs.provider(t, oneTenant("t1", "client-1", "secret-1"), nil)
	if _, err := p.RetryCobR(context.Background(), "t1", "tx-1", ""); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation on empty date, got %v", err)
	}
	if _, err := p.RetryCobR(context.Background(), "t1", "", "2026-09-08"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation on empty txid, got %v", err)
	}
}

func TestGetCobRSignedSuccess(t *testing.T) {
	t.Parallel()
	rs := newRecServer(t)
	v := &fakeVerifier{payload: []byte(cobrRespJSON)}
	p := rs.provider(t, oneTenant("t1", "client-1", "secret-1"), v)

	res, err := p.GetCobR(context.Background(), "t1", "tx-cobr-1")
	if err != nil {
		t.Fatalf("GetCobR: %v", err)
	}
	if res.TxID != "tx-cobr-1" || res.ValorCents != 1050 {
		t.Fatalf("unexpected result: %+v", res)
	}
	if rs.lastAccept != "application/jose" {
		t.Fatalf("read must request JOSE, got %q", rs.lastAccept)
	}
}

func TestGetCobRValidation(t *testing.T) {
	t.Parallel()
	rs := newRecServer(t)
	p := rs.provider(t, oneTenant("t1", "client-1", "secret-1"), &fakeVerifier{payload: []byte(cobrRespJSON)})
	if _, err := p.GetCobR(context.Background(), "t1", ""); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation, got %v", err)
	}
}

// Credential resolution failure (unknown tenant) propagates from the token fetch.
func TestRecUnknownTenant(t *testing.T) {
	t.Parallel()
	rs := newRecServer(t)
	p := rs.provider(t, oneTenant("t1", "client-1", "secret-1"), nil)
	if _, err := p.CreateRec(context.Background(), "other", recReq()); err == nil {
		t.Fatalf("want error for unknown tenant")
	}
}

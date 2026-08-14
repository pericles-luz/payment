package c6

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// PIX Automático (Recorrência) against the real C6 contract captured live in
// SIN-66034 (F0). C6 follows the BACEN surface under the same /v2/pix prefix as
// cob/cobv: rec (mandato), solicrec (solicitação de confirmação) and cobr
// (cobrança recorrente). Writes are application/json with a {"data":{...}} envelope
// (201); reads are JWS-signed (Accept: application/jose) and go through
// signedRead/RecurrenceVerifier. This file replaces the chutado consent scaffold.
const (
	recPath      = "/v2/pix/rec"
	solicRecPath = "/v2/pix/solicrec"
	cobrPath     = "/v2/pix/cobr"
)

// compile-time assertions that Provider satisfies the Recorrência ports.
var (
	_ ports.RecProvider      = (*Provider)(nil)
	_ ports.SolicRecProvider = (*Provider)(nil)
	_ ports.CobRProvider     = (*Provider)(nil)
)

// RecurrenceVerifier verifies a JWS-signed Recorrência read document and returns
// its decoded JSON payload. C6 returns rec/solicrec/cobr reads as a JWS (Accept:
// application/jose) so the BACEN mandate is non-reputable; the adapter MUST verify
// the signature against C6's published JWKS before trusting the body. F1 defines
// this seam so the read path is hexagonal and table-testable; the concrete
// implementation is *JWSVerifier (go-jose v4, explicit asymmetric allowlist + JWKS
// by kid with rotation), wired in cmd/api/main.go when PAYMENT_C6_REC_JWKS_URL is
// set (SIN-66061). When no verifier is injected the reads fail secure.
type RecurrenceVerifier interface {
	VerifyJWS(ctx context.Context, compact []byte) (payload []byte, err error)
}

// ---- rec (mandato) ----

type recDevedorBody struct {
	CPF  string `json:"cpf,omitempty"`
	CNPJ string `json:"cnpj,omitempty"`
	Nome string `json:"nome,omitempty"`
}

type recVinculoBody struct {
	Contrato string         `json:"contrato"`
	Devedor  recDevedorBody `json:"devedor"`
	Objeto   string         `json:"objeto,omitempty"`
}

type recCalendarioBody struct {
	DataInicial   string `json:"dataInicial"`
	Periodicidade string `json:"periodicidade"`
}

type recebedorBody struct {
	ISPBParticipante string `json:"ispbParticipante,omitempty"`
	CNPJ             string `json:"cnpj,omitempty"`
	CPF              string `json:"cpf,omitempty"`
	Nome             string `json:"nome,omitempty"`
}

type recRequestBody struct {
	Vinculo             recVinculoBody    `json:"vinculo"`
	Calendario          recCalendarioBody `json:"calendario"`
	PoliticaRetentativa string            `json:"politicaRetentativa"`
}

type recResponseBody struct {
	IDRec               string            `json:"idRec"`
	Status              string            `json:"status"`
	Vinculo             recVinculoBody    `json:"vinculo"`
	Calendario          recCalendarioBody `json:"calendario"`
	Recebedor           recebedorBody     `json:"recebedor"`
	PoliticaRetentativa string            `json:"politicaRetentativa"`
	Ativacao            struct {
		TipoJornada string `json:"tipoJornada"`
	} `json:"ativacao"`
}

func (b recResponseBody) toResult() ports.RecResult {
	return ports.RecResult{
		IDRec:  b.IDRec,
		Status: ports.RecStatus(b.Status),
		Vinculo: ports.RecVinculo{
			Contrato: b.Vinculo.Contrato,
			Devedor: ports.RecDevedor{
				CPF:  b.Vinculo.Devedor.CPF,
				CNPJ: b.Vinculo.Devedor.CNPJ,
				Nome: b.Vinculo.Devedor.Nome,
			},
			Objeto: b.Vinculo.Objeto,
		},
		Calendario: ports.RecCalendario{
			DataInicial:   b.Calendario.DataInicial,
			Periodicidade: ports.RecPeriodicidade(b.Calendario.Periodicidade),
		},
		Recebedor: ports.Recebedor{
			ISPB: b.Recebedor.ISPBParticipante,
			CNPJ: b.Recebedor.CNPJ,
			CPF:  b.Recebedor.CPF,
			Nome: b.Recebedor.Nome,
		},
		PoliticaRetentativa: ports.RetryPolicy(b.PoliticaRetentativa),
		TipoJornada:         b.Ativacao.TipoJornada,
	}
}

// validateObjeto enforces C6's charset restriction on vinculo.objeto. C6's rec
// schema rejects any objeto containing whitespace (confirmed live in SIN-66072:
// objeto "Mensalidade homologacao PIX Automatico" → 400, "Mensalidade" → 201),
// and the upstream RFC7807 detail is otherwise discarded — the caller would only
// see an opaque 400. Validating at the boundary turns that into a precise
// ErrValidation. objeto is optional (omitempty), so an empty value is allowed.
func validateObjeto(objeto string) error {
	if objeto == "" {
		return nil
	}
	if strings.ContainsFunc(objeto, unicode.IsSpace) {
		return &Error{Op: "create_rec", sentinel: shared.ErrValidation, detail: "objeto must not contain whitespace"}
	}
	return nil
}

// CreateRec registers a recurring-debit mandate (POST /v2/pix/rec). The recebedor
// is auto-filled by C6 from the authenticated tenant's account and is therefore
// never sent (confused-deputy defense, ADR-0004). Required fields are validated at
// the boundary so a malformed mandate fails fast as ErrValidation.
func (p *Provider) CreateRec(ctx context.Context, tenantID string, req ports.CreateRecRequest) (ports.RecResult, error) {
	if strings.TrimSpace(req.Vinculo.Contrato) == "" ||
		strings.TrimSpace(req.Calendario.DataInicial) == "" ||
		req.Calendario.Periodicidade == "" ||
		req.PoliticaRetentativa == "" {
		return ports.RecResult{}, &Error{Op: "create_rec", sentinel: shared.ErrValidation}
	}
	if err := validateObjeto(req.Vinculo.Objeto); err != nil {
		return ports.RecResult{}, err
	}
	payload, err := json.Marshal(recRequestBody{
		Vinculo: recVinculoBody{
			Contrato: req.Vinculo.Contrato,
			Devedor: recDevedorBody{
				CPF:  req.Vinculo.Devedor.CPF,
				CNPJ: req.Vinculo.Devedor.CNPJ,
				Nome: req.Vinculo.Devedor.Nome,
			},
			Objeto: req.Vinculo.Objeto,
		},
		Calendario: recCalendarioBody{
			DataInicial:   req.Calendario.DataInicial,
			Periodicidade: string(req.Calendario.Periodicidade),
		},
		PoliticaRetentativa: string(req.PoliticaRetentativa),
	})
	if err != nil {
		return ports.RecResult{}, &Error{Op: "create_rec", sentinel: shared.ErrValidation}
	}
	httpReq, err := p.authedJSONRequest(ctx, tenantID, "create_rec", http.MethodPost, p.baseURL+recPath, payload, req.IdempotencyKey)
	if err != nil {
		return ports.RecResult{}, err
	}
	var out struct {
		Data recResponseBody `json:"data"`
	}
	if err := p.do(httpReq, "create_rec", &out); err != nil {
		return ports.RecResult{}, err
	}
	return out.Data.toResult(), nil
}

// GetRec reconciles the authoritative mandate state from C6 (GET /v2/pix/rec/{idRec}),
// verifying the JWS signature before the body is trusted (never trust a webhook —
// threat W3).
func (p *Provider) GetRec(ctx context.Context, tenantID, idRec string) (ports.RecResult, error) {
	if strings.TrimSpace(idRec) == "" {
		return ports.RecResult{}, &Error{Op: "get_rec", sentinel: shared.ErrValidation}
	}
	payload, err := p.signedRead(ctx, tenantID, "get_rec", p.baseURL+recPath+"/"+url.PathEscape(idRec))
	if err != nil {
		return ports.RecResult{}, err
	}
	var b recResponseBody
	if err := decodeData(payload, &b); err != nil {
		return ports.RecResult{}, &Error{Op: "get_rec", sentinel: shared.ErrUnavailable, detail: "malformed signed body"}
	}
	return b.toResult(), nil
}

// CancelRec revokes a mandate (PATCH /v2/pix/rec/{idRec} status=CANCELADA) so no
// further debits can be originated. Idempotent on idRec; the idRec is forwarded as
// the Idempotency-Key so a retried cancel collapses to one effect.
func (p *Provider) CancelRec(ctx context.Context, tenantID, idRec string) (ports.RecResult, error) {
	if strings.TrimSpace(idRec) == "" {
		return ports.RecResult{}, &Error{Op: "cancel_rec", sentinel: shared.ErrValidation}
	}
	payload, err := json.Marshal(struct {
		Status string `json:"status"`
	}{Status: string(ports.RecCancelada)})
	if err != nil {
		return ports.RecResult{}, &Error{Op: "cancel_rec", sentinel: shared.ErrValidation}
	}
	httpReq, err := p.authedJSONRequest(ctx, tenantID, "cancel_rec", http.MethodPatch, p.baseURL+recPath+"/"+url.PathEscape(idRec), payload, idRec)
	if err != nil {
		return ports.RecResult{}, err
	}
	var out struct {
		Data recResponseBody `json:"data"`
	}
	if err := p.do(httpReq, "cancel_rec", &out); err != nil {
		return ports.RecResult{}, err
	}
	return out.Data.toResult(), nil
}

// ---- solicrec (solicitação de confirmação) ----

type solicRecDestinatarioBody struct {
	CPF              string `json:"cpf,omitempty"`
	CNPJ             string `json:"cnpj,omitempty"`
	Agencia          string `json:"agencia,omitempty"`
	Conta            string `json:"conta,omitempty"`
	ISPBParticipante string `json:"ispbParticipante,omitempty"`
}

type solicRecCalendarioBody struct {
	DataExpiracaoSolicitacao string `json:"dataExpiracaoSolicitacao"`
}

type solicRecRequestBody struct {
	IDRec        string                   `json:"idRec"`
	Calendario   solicRecCalendarioBody   `json:"calendario"`
	Destinatario solicRecDestinatarioBody `json:"destinatario"`
}

type solicRecResponseBody struct {
	IDSolicRec   string                   `json:"idSolicRec"`
	IDRec        string                   `json:"idRec"`
	Status       string                   `json:"status"`
	Calendario   solicRecCalendarioBody   `json:"calendario"`
	Destinatario solicRecDestinatarioBody `json:"destinatario"`
}

func (b solicRecResponseBody) toResult() ports.SolicRecResult {
	return ports.SolicRecResult{
		IDSolicRec: b.IDSolicRec,
		IDRec:      b.IDRec,
		Status:     b.Status,
		Destinatario: ports.SolicRecDestinatario{
			CPF:              b.Destinatario.CPF,
			CNPJ:             b.Destinatario.CNPJ,
			Agencia:          b.Destinatario.Agencia,
			Conta:            b.Destinatario.Conta,
			ISPBParticipante: b.Destinatario.ISPBParticipante,
		},
		ExpiraEm: parseInstant(b.Calendario.DataExpiracaoSolicitacao),
	}
}

// CreateSolicRec asks the payer's participant to confirm a mandate (POST
// /v2/pix/solicrec). The expiry must be present (BACEN CMT-APR-SOLI-016 also caps
// it at < 30 days); it is sent as an RFC3339 instant.
func (p *Provider) CreateSolicRec(ctx context.Context, tenantID string, req ports.CreateSolicRecRequest) (ports.SolicRecResult, error) {
	if strings.TrimSpace(req.IDRec) == "" || req.ExpiraEm.IsZero() {
		return ports.SolicRecResult{}, &Error{Op: "create_solicrec", sentinel: shared.ErrValidation}
	}
	payload, err := json.Marshal(solicRecRequestBody{
		IDRec:      req.IDRec,
		Calendario: solicRecCalendarioBody{DataExpiracaoSolicitacao: req.ExpiraEm.UTC().Format(time.RFC3339)},
		Destinatario: solicRecDestinatarioBody{
			CPF:              req.Destinatario.CPF,
			CNPJ:             req.Destinatario.CNPJ,
			Agencia:          req.Destinatario.Agencia,
			Conta:            req.Destinatario.Conta,
			ISPBParticipante: req.Destinatario.ISPBParticipante,
		},
	})
	if err != nil {
		return ports.SolicRecResult{}, &Error{Op: "create_solicrec", sentinel: shared.ErrValidation}
	}
	idem := req.IdempotencyKey
	if idem == "" {
		idem = req.IDRec
	}
	httpReq, err := p.authedJSONRequest(ctx, tenantID, "create_solicrec", http.MethodPost, p.baseURL+solicRecPath, payload, idem)
	if err != nil {
		return ports.SolicRecResult{}, err
	}
	var out struct {
		Data solicRecResponseBody `json:"data"`
	}
	if err := p.do(httpReq, "create_solicrec", &out); err != nil {
		return ports.SolicRecResult{}, err
	}
	return out.Data.toResult(), nil
}

// GetSolicRec reconciles the authoritative activation-request state from C6
// (GET /v2/pix/solicrec/{idSolicRec}), JWS-verified.
func (p *Provider) GetSolicRec(ctx context.Context, tenantID, idSolicRec string) (ports.SolicRecResult, error) {
	if strings.TrimSpace(idSolicRec) == "" {
		return ports.SolicRecResult{}, &Error{Op: "get_solicrec", sentinel: shared.ErrValidation}
	}
	payload, err := p.signedRead(ctx, tenantID, "get_solicrec", p.baseURL+solicRecPath+"/"+url.PathEscape(idSolicRec))
	if err != nil {
		return ports.SolicRecResult{}, err
	}
	var b solicRecResponseBody
	if err := decodeData(payload, &b); err != nil {
		return ports.SolicRecResult{}, &Error{Op: "get_solicrec", sentinel: shared.ErrUnavailable, detail: "malformed signed body"}
	}
	return b.toResult(), nil
}

// ---- cobr (cobrança recorrente) ----

type cobrCalendarioBody struct {
	DataDeVencimento string `json:"dataDeVencimento"`
}

type cobrValorReqBody struct {
	Original string `json:"original"`
}

type cobrRecebedorBody struct {
	Conta     string `json:"conta"`
	TipoConta string `json:"tipoConta"`
}

type cobrRequestBody struct {
	AjusteDiaUtil bool               `json:"ajusteDiaUtil"`
	Calendario    cobrCalendarioBody `json:"calendario"`
	// Devedor is an empty object: the payer is inherited from the mandate's vínculo,
	// and C6 rejects cpf/nome here (additionalProperties:false).
	Devedor   struct{}          `json:"devedor"`
	Valor     cobrValorReqBody  `json:"valor"`
	Recebedor cobrRecebedorBody `json:"recebedor"`
	IDRec     string            `json:"idRec"`
	// txid is NOT a body field: C6 rejects it (additionalProperties:false →
	// 400 RequisicaoInvalida "properties which are not allowed by the schema: [txid]",
	// confirmed live in SIN-66072). It is the resource key in the URL path
	// (PUT /v2/pix/cobr/{txid}), per the BACEN cob pattern.
}

type cobrResponseBody struct {
	TxID   string `json:"txid"`
	IDRec  string `json:"idRec"`
	Status string `json:"status"`
	Valor  struct {
		// Original arrives as the BACEN decimal string; brlDecimal parses it back to
		// integer centavos with no float (SIN-65953).
		Original brlDecimal `json:"original"`
	} `json:"valor"`
}

func (b cobrResponseBody) toResult() ports.CobRResult {
	return ports.CobRResult{
		TxID:       b.TxID,
		IDRec:      b.IDRec,
		Status:     b.Status,
		ValorCents: int64(b.Valor.Original),
	}
}

// buildCobRBody renders a CobR request body. valor.original is centavos rendered as
// the BACEN decimal string (no float; padrão brlDecimal). The txid is intentionally
// absent — it travels in the URL path, never the body (see cobrRequestBody).
func buildCobRBody(req ports.CreateCobRRequest) cobrRequestBody {
	return cobrRequestBody{
		AjusteDiaUtil: req.AjusteDiaUtil,
		Calendario:    cobrCalendarioBody{DataDeVencimento: req.DataVencimento},
		Valor:         cobrValorReqBody{Original: formatAmount(req.ValorCents)},
		Recebedor:     cobrRecebedorBody{Conta: req.Recebedor.Conta, TipoConta: string(req.Recebedor.TipoConta)},
		IDRec:         req.IDRec,
	}
}

// CreateCobR creates a recurring charge instance against an APROVADA mandate. The
// txid is the client-defined resource key, so the charge is created with an
// idempotent upsert against its own URL (PUT /v2/pix/cobr/{txid}) — the BACEN cob
// pattern. Sending txid in the body is rejected by C6 (400 RequisicaoInvalida,
// SIN-66072). Complete mediation at the money seam: an empty txid (the
// anti-double-bill anchor), empty idRec, or non-positive amount is never a valid
// charge and fails fast. The txid is forwarded as the Idempotency-Key so a retried
// create targets the same charge.
func (p *Provider) CreateCobR(ctx context.Context, tenantID string, req ports.CreateCobRRequest) (ports.CobRResult, error) {
	if strings.TrimSpace(req.TxID) == "" || strings.TrimSpace(req.IDRec) == "" || req.ValorCents <= 0 {
		return ports.CobRResult{}, &Error{Op: "create_cobr", sentinel: shared.ErrValidation}
	}
	payload, err := json.Marshal(buildCobRBody(req))
	if err != nil {
		return ports.CobRResult{}, &Error{Op: "create_cobr", sentinel: shared.ErrValidation}
	}
	idem := req.IdempotencyKey
	if idem == "" {
		idem = req.TxID
	}
	httpReq, err := p.authedJSONRequest(ctx, tenantID, "create_cobr", http.MethodPut, p.baseURL+cobrPath+"/"+url.PathEscape(req.TxID), payload, idem)
	if err != nil {
		return ports.CobRResult{}, err
	}
	var out struct {
		Data cobrResponseBody `json:"data"`
	}
	if err := p.do(httpReq, "create_cobr", &out); err != nil {
		return ports.CobRResult{}, err
	}
	return out.Data.toResult(), nil
}

// ReviseCobR updates a not-yet-settled charge instance (PUT /v2/pix/cobr/{txid}).
func (p *Provider) ReviseCobR(ctx context.Context, tenantID string, req ports.CreateCobRRequest) (ports.CobRResult, error) {
	if strings.TrimSpace(req.TxID) == "" || strings.TrimSpace(req.IDRec) == "" || req.ValorCents <= 0 {
		return ports.CobRResult{}, &Error{Op: "revise_cobr", sentinel: shared.ErrValidation}
	}
	payload, err := json.Marshal(buildCobRBody(req))
	if err != nil {
		return ports.CobRResult{}, &Error{Op: "revise_cobr", sentinel: shared.ErrValidation}
	}
	httpReq, err := p.authedJSONRequest(ctx, tenantID, "revise_cobr", http.MethodPut, p.baseURL+cobrPath+"/"+url.PathEscape(req.TxID), payload, req.TxID)
	if err != nil {
		return ports.CobRResult{}, err
	}
	var out struct {
		Data cobrResponseBody `json:"data"`
	}
	if err := p.do(httpReq, "revise_cobr", &out); err != nil {
		return ports.CobRResult{}, err
	}
	return out.Data.toResult(), nil
}

// RetryCobR schedules a retry of a failed charge per the mandate's política de
// retentativa (POST /v2/pix/cobr/{txid}/retentativa/{data}).
func (p *Provider) RetryCobR(ctx context.Context, tenantID, txID, dataRetentativa string) (ports.CobRResult, error) {
	if strings.TrimSpace(txID) == "" || strings.TrimSpace(dataRetentativa) == "" {
		return ports.CobRResult{}, &Error{Op: "retry_cobr", sentinel: shared.ErrValidation}
	}
	endpoint := p.baseURL + cobrPath + "/" + url.PathEscape(txID) + "/retentativa/" + url.PathEscape(dataRetentativa)
	httpReq, err := p.authedJSONRequest(ctx, tenantID, "retry_cobr", http.MethodPost, endpoint, nil, txID+":"+dataRetentativa)
	if err != nil {
		return ports.CobRResult{}, err
	}
	var out struct {
		Data cobrResponseBody `json:"data"`
	}
	if err := p.do(httpReq, "retry_cobr", &out); err != nil {
		return ports.CobRResult{}, err
	}
	return out.Data.toResult(), nil
}

// GetCobR reconciles the authoritative charge state from C6 (GET /v2/pix/cobr/{txid}),
// JWS-verified.
func (p *Provider) GetCobR(ctx context.Context, tenantID, txID string) (ports.CobRResult, error) {
	if strings.TrimSpace(txID) == "" {
		return ports.CobRResult{}, &Error{Op: "get_cobr", sentinel: shared.ErrValidation}
	}
	payload, err := p.signedRead(ctx, tenantID, "get_cobr", p.baseURL+cobrPath+"/"+url.PathEscape(txID))
	if err != nil {
		return ports.CobRResult{}, err
	}
	var b cobrResponseBody
	if err := decodeData(payload, &b); err != nil {
		return ports.CobRResult{}, &Error{Op: "get_cobr", sentinel: shared.ErrUnavailable, detail: "malformed signed body"}
	}
	return b.toResult(), nil
}

// ---- shared helpers ----

// signedRead performs a Recorrência read: GET with Accept: application/jose, maps a
// non-2xx into a domain error, then verifies the JWS and returns the decoded JSON
// payload. Without a configured RecurrenceVerifier it fails secure (ErrUnavailable)
// rather than trusting an unverified mandate document.
func (p *Provider) signedRead(ctx context.Context, tenantID, op, endpoint string) ([]byte, error) {
	if p.recVerifier == nil {
		return nil, &Error{Op: op, sentinel: shared.ErrUnavailable, detail: "recurrence read verifier not configured"}
	}
	token, err := p.tokens.token(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, transportError(op)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/jose")

	resp, err := p.httpc.Do(req)
	if err != nil {
		return nil, transportError(op)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if resp.StatusCode/100 != 2 {
		return nil, mapError(op, resp.StatusCode, body)
	}
	payload, err := p.recVerifier.VerifyJWS(ctx, body)
	if err != nil {
		return nil, &Error{Op: op, StatusCode: resp.StatusCode, sentinel: shared.ErrUnavailable, detail: "jws verification failed"}
	}
	return payload, nil
}

// decodeData unmarshals a Recorrência body that may be wrapped in the C6
// {"data":{...}} envelope or delivered bare (the verified JWS payload shape is not
// guaranteed to carry the envelope). It tries the envelope first, falling back to
// the raw payload.
func decodeData(payload []byte, dst any) error {
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(payload, &env); err == nil && len(env.Data) > 0 {
		return json.Unmarshal(env.Data, dst)
	}
	return json.Unmarshal(payload, dst)
}

// parseInstant parses an RFC3339 instant, returning the zero time on any malformed
// or empty value (the field stays optional at the port boundary).
func parseInstant(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

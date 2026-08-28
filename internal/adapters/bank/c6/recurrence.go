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
// (201); reads are plain application/json and go through recurrenceRead. This file
// replaces the chutado consent scaffold.
const (
	recPath      = "/v2/pix/rec"
	solicRecPath = "/v2/pix/solicrec"
	cobrPath     = "/v2/pix/cobr"
	locRecPath   = "/v2/pix/locrec"
)

// compile-time assertions that Provider satisfies the Recorrência ports.
var (
	_ ports.RecProvider      = (*Provider)(nil)
	_ ports.SolicRecProvider = (*Provider)(nil)
	_ ports.CobRProvider     = (*Provider)(nil)
	_ ports.LocRecProvider   = (*Provider)(nil)
)

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

// recDadosJornadaBody carries ativacao.dadosJornada.txid — the txid of the immediate
// charge a Jornada 3 composite QR settles alongside the authorization. BACEN requires
// it for Jornada 3 and forbids it for 1/2/4, so the whole ativacao object is a pointer
// and is omitted unless a journey txid was supplied.
type recDadosJornadaBody struct {
	TxID string `json:"txid"`
}

type recAtivacaoBody struct {
	DadosJornada recDadosJornadaBody `json:"dadosJornada"`
}

// recValorBody is the mandate's fixed amount.
//
// valorRec is a QUOTED decimal string on this wire ("99.00"), not a bare number: the
// contract types it `string` with pattern \d{1,10}\.\d{2}, and every money example in
// the captured spec is quoted. That is why it uses formatAmount (the same string
// renderer as cobr's valor.original) rather than brlDecimal, which marshals to a bare
// JSON number for the boleto surface. Both render from integer centavos — no float ever
// touches an amount (SIN-65953).
//
// Omitted entirely for a variable-value mandate, since C6 rejects an empty valorRec.
type recValorBody struct {
	ValorRec string `json:"valorRec"`
}

type recRequestBody struct {
	Vinculo             recVinculoBody    `json:"vinculo"`
	Calendario          recCalendarioBody `json:"calendario"`
	PoliticaRetentativa string            `json:"politicaRetentativa"`
	// Loc binds the mandate to a payload location (locrec) so the bank can compose the
	// QR. A pointer because 0 is not "no location" on the wire — the field must be
	// absent, not zero.
	Loc      *int64           `json:"loc,omitempty"`
	Ativacao *recAtivacaoBody `json:"ativacao,omitempty"`
	Valor    *recValorBody    `json:"valor,omitempty"`
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
	// Loc is the location bound to the mandate. C6 returns it as the bare integer id
	// on a create and as the expanded object on a read, so it is decoded leniently
	// (locRef) rather than as one shape that a contract drift would break.
	Loc   locRef `json:"loc"`
	Valor struct {
		ValorRec brlDecimal `json:"valorRec"`
	} `json:"valor"`
	// DadosQR is present only when the read asked the bank to compose a QR and every
	// parameter it needs was filled in (GET /rec/{idRec}?txid=...).
	DadosQR struct {
		Jornada       string `json:"jornada"`
		PixCopiaECola string `json:"pixCopiaECola"`
	} `json:"dadosQR"`
}

// locRef decodes the mandate's loc field in either shape C6 uses: the bare integer id
// (`"loc": 108`) or the expanded location object (`"loc": {"id": 108, "location":
// "..."}`). Decoding both here keeps the shape drift out of every call site; an
// unparseable value degrades to the zero location rather than failing the whole read,
// because the location is presentation metadata and never a money-bearing field.
type locRef struct {
	ID       int64
	Location string
}

func (l *locRef) UnmarshalJSON(b []byte) error {
	var id int64
	if err := json.Unmarshal(b, &id); err == nil {
		l.ID = id
		return nil
	}
	var obj struct {
		ID       int64  `json:"id"`
		Location string `json:"location"`
	}
	if err := json.Unmarshal(b, &obj); err != nil {
		return nil // absent/null/unknown shape → zero location, never a hard failure
	}
	l.ID, l.Location = obj.ID, obj.Location
	return nil
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
		LocID:               b.Loc.ID,
		Location:            b.Loc.Location,
		ValorRecCents:       int64(b.Valor.ValorRec),
		DadosQR: ports.RecDadosQR{
			Jornada:       b.DadosQR.Jornada,
			PixCopiaECola: b.DadosQR.PixCopiaECola,
		},
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
	if req.ValorRecCents < 0 {
		return ports.RecResult{}, &Error{Op: "create_rec", sentinel: shared.ErrValidation, detail: "valor_rec_cents must not be negative"}
	}
	// The three Jornada fields are optional on the wire and must be ABSENT rather than
	// zero when unused: a `loc: 0`, an empty `ativacao` or a `valorRec: "0.00"` are all
	// rejected by C6's schema. Build them as pointers so encoding/json omits them.
	var loc *int64
	if req.LocID > 0 {
		v := req.LocID
		loc = &v
	}
	var ativacao *recAtivacaoBody
	if txid := strings.TrimSpace(req.JornadaTxID); txid != "" {
		ativacao = &recAtivacaoBody{DadosJornada: recDadosJornadaBody{TxID: txid}}
	}
	var valor *recValorBody
	if req.ValorRecCents > 0 {
		valor = &recValorBody{ValorRec: formatAmount(req.ValorRecCents)}
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
		Loc:                 loc,
		Ativacao:            ativacao,
		Valor:               valor,
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
	payload, err := p.recurrenceRead(ctx, tenantID, "get_rec", p.baseURL+recPath+"/"+url.PathEscape(idRec))
	if err != nil {
		return ports.RecResult{}, err
	}
	var b recResponseBody
	if err := decodeData(payload, &b); err != nil {
		return ports.RecResult{}, &Error{Op: "get_rec", sentinel: shared.ErrUnavailable, detail: "malformed body"}
	}
	return b.toResult(), nil
}

// GetRecForQR reads the mandate asking C6 to compose the QR for a journey
// (GET /v2/pix/rec/{idRec}?txid={txid}). The txid selects which QR is composed: the
// txid of an immediate charge yields JORNADA_3 (the composite QR that settles the
// first charge AND authorizes the recurrence), the txid of a cobrança com vencimento
// yields JORNADA_4, and an empty txid yields JORNADA_2 (mandate parameters only).
//
// It is the same JWS-verified read as GetRec — the mandate document is the BACEN
// non-repudiation artifact whichever way it is fetched, and degrading THIS read to an
// unverified one would hand an attacker the QR the payer scans. C6 fills dadosQR only
// when every parameter the QR needs is present on both the mandate and the referenced
// charge; a missing dadosQR is therefore not an error here, it is "not composable
// yet", and the caller decides what to do about it.
func (p *Provider) GetRecForQR(ctx context.Context, tenantID, idRec, txID string) (ports.RecResult, error) {
	if strings.TrimSpace(idRec) == "" {
		return ports.RecResult{}, &Error{Op: "get_rec_qr", sentinel: shared.ErrValidation}
	}
	endpoint := p.baseURL + recPath + "/" + url.PathEscape(idRec)
	if txid := strings.TrimSpace(txID); txid != "" {
		endpoint += "?txid=" + url.QueryEscape(txid)
	}
	payload, err := p.recurrenceRead(ctx, tenantID, "get_rec_qr", endpoint)
	if err != nil {
		return ports.RecResult{}, err
	}
	var b recResponseBody
	if err := decodeData(payload, &b); err != nil {
		return ports.RecResult{}, &Error{Op: "get_rec_qr", sentinel: shared.ErrUnavailable, detail: "malformed body"}
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
	payload, err := p.recurrenceRead(ctx, tenantID, "get_solicrec", p.baseURL+solicRecPath+"/"+url.PathEscape(idSolicRec))
	if err != nil {
		return ports.SolicRecResult{}, err
	}
	var b solicRecResponseBody
	if err := decodeData(payload, &b); err != nil {
		return ports.SolicRecResult{}, &Error{Op: "get_solicrec", sentinel: shared.ErrUnavailable, detail: "malformed body"}
	}
	return b.toResult(), nil
}

// ---- cobr (cobrança recorrente) ----

// cobrStatusCancelada is the only value the BACEN cobr revision accepts
// (CobRStatusRevisada.status enum has exactly this one member).
const cobrStatusCancelada = "CANCELADA"

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

// CancelCobR cancels one scheduled charge instance: PATCH /v2/pix/cobr/{txid} with
// {"status":"CANCELADA"}.
//
// PATCH, not PUT. On this surface PUT /cobr/{txid} is the CREATE (201, full cobr body,
// txid defined by the client) and PATCH is the revision — whose only revisable field is
// `status` and whose only allowed value is CANCELADA. An earlier version of this method
// sent the full create body over PUT under the name "revise", which is the create call
// wearing another name: it could never amend anything, and against an existing txid it
// either no-ops or re-registers the instalment. The txid is forwarded as the
// Idempotency-Key so a retried cancel collapses to one effect.
func (p *Provider) CancelCobR(ctx context.Context, tenantID, txID string) (ports.CobRResult, error) {
	txID = strings.TrimSpace(txID)
	if txID == "" {
		return ports.CobRResult{}, &Error{Op: "cancel_cobr", sentinel: shared.ErrValidation}
	}
	payload, err := json.Marshal(struct {
		Status string `json:"status"`
	}{Status: cobrStatusCancelada})
	if err != nil {
		return ports.CobRResult{}, &Error{Op: "cancel_cobr", sentinel: shared.ErrValidation}
	}
	httpReq, err := p.authedJSONRequest(ctx, tenantID, "cancel_cobr", http.MethodPatch, p.baseURL+cobrPath+"/"+url.PathEscape(txID), payload, txID)
	if err != nil {
		return ports.CobRResult{}, err
	}
	var out struct {
		Data cobrResponseBody `json:"data"`
	}
	if err := p.do(httpReq, "cancel_cobr", &out); err != nil {
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
	payload, err := p.recurrenceRead(ctx, tenantID, "get_cobr", p.baseURL+cobrPath+"/"+url.PathEscape(txID))
	if err != nil {
		return ports.CobRResult{}, err
	}
	var b cobrResponseBody
	if err := decodeData(payload, &b); err != nil {
		return ports.CobRResult{}, &Error{Op: "get_cobr", sentinel: shared.ErrUnavailable, detail: "malformed body"}
	}
	return b.toResult(), nil
}

// ---- shared helpers ----

// recurrenceRead performs a Recorrência read: GET with Accept: application/json, maps
// a non-2xx into a domain error, and returns the body.
//
// It used to send `Accept: application/jose` and refuse to trust the body unless a JWS
// verified against a C6 JWKS. That was wrong, and provably so — C6 rejects the header
// outright (probed against the sandbox on 28/08/2026, cmd/c6-rec-probe):
//
//	Accept: application/json  → 200, Content-Type: application/json
//	Accept: application/jose  → 400 "Request Accept header '[application/jose]' does
//	                            not match any defined response types. Must be one of:
//	                            [application/json, application/problem+json]"
//
// So every recurrence read was failing, and no JWKS value could have fixed it: the
// request was refused before any signature could exist to verify. The contract agrees
// — these reads are declared application/json, and the single JWS in the whole C6 Pix
// Automático spec belongs to GET /rec/{recUrlAccessToken}: a PUBLIC endpoint on another
// host (qrcode-h.c6pix.com), signed under a BACEN `jku`, fetched and validated by the
// PAYER's PSP when it scans the QR. We are the recebedor; that document is not ours to
// verify, and we never request it.
//
// What authenticates these reads is therefore the channel, not the payload: OAuth2
// client_credentials over the per-tenant mTLS transport — exactly what already
// authenticates cob, cobv, boleto and checkout.
func (p *Provider) recurrenceRead(ctx context.Context, tenantID, op, endpoint string) ([]byte, error) {
	token, err := p.tokens.token(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(withTenant(ctx, tenantID), http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, transportError(op)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpc.Do(req)
	if err != nil {
		return nil, transportError(op)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if resp.StatusCode/100 != 2 {
		return nil, mapError(op, resp.StatusCode, body)
	}
	return body, nil
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

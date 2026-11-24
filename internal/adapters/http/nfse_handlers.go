package http

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/nfse"
	"github.com/ia-dev-sindireceita/payment/internal/nfse/a1import"
	"github.com/ia-dev-sindireceita/payment/internal/nfse/custody"
)

// --- Tenant API: NFS-e (padrão nacional / ADN) ---
//
// POST /v1/nfse                     emit (Idempotency-Key required)
// GET  /v1/nfse/{id}                the emission (tenant-scoped)
// GET  /v1/nfse/{id}/xml            the authorised NFS-e XML
// GET  /v1/nfse/{id}/pdf            the DANFSe, fetched from the ADN and cached
// PUT  /v1/nfse-certificates         custody the tenant's A1 for a CNPJ
// GET  /v1/nfse-certificates/{cnpj}  certificate metadata
//
// Free while no price is configured, but every authorised emission is counted
// in the billing ledger ("nfse.emit") and shows in the console reports.

// emitNFSeRequest is the boundary body of POST /v1/nfse. Unknown fields are
// rejected (anti mass-assignment).
type emitNFSeRequest struct {
	CNPJ string `json:"cnpj"`
	// Competencia is "YYYY-MM-DD" (dCompet) or "YYYY-MM"; empty means the
	// emission date.
	Competencia string `json:"competencia"`
	// Serie is the DPS série; empty means "1". The DPS number is the gateway's.
	Serie              string `json:"serie"`
	MunicipioPrestacao string `json:"municipio_prestacao"`
	MunicipioEmissor   string `json:"municipio_emissor"`
	CodigoServico      string `json:"codigo_servico"`
	// CodigoMunicipal is cTribMun (3 digits) and CodigoNBS is cNBS (9 digits):
	// optional, as the município requires.
	CodigoMunicipal    string          `json:"codigo_tributacao_municipal"`
	CodigoNBS          string          `json:"codigo_nbs"`
	Descricao          string          `json:"descricao"`
	ValorCents         int64           `json:"valor_cents"`
	SimplesNacional    string          `json:"simples_nacional"`
	AliquotaSimplesBps int             `json:"aliquota_simples_bps"`
	Tomador            *tomadorRequest `json:"tomador"`
}

type tomadorRequest struct {
	Documento string `json:"documento"`
	Nome      string `json:"nome"`
	Email     string `json:"email"`
}

// nfseEmissionView is the tenant-facing emission.
type nfseEmissionView struct {
	ID               string `json:"id"`
	Status           string `json:"status"`
	CNPJ             string `json:"cnpj"`
	Competencia      string `json:"competencia"`
	ValorCents       int64  `json:"valor_cents"`
	Serie            string `json:"serie,omitempty"`
	NumeroDPS        string `json:"numero_dps,omitempty"`
	TomadorDocumento string `json:"tomador_documento,omitempty"`
	TomadorNome      string `json:"tomador_nome,omitempty"`
	ChaveAcesso      string `json:"chave_acesso,omitempty"`
	NumeroNFSe       string `json:"numero_nfse,omitempty"`
	DPSID            string `json:"dps_id,omitempty"`
	RejeicaoCodigo   string `json:"rejeicao_codigo,omitempty"`
	RejeicaoMensagem string `json:"rejeicao_mensagem,omitempty"`
	CriadaEm         string `json:"criada_em"`
}

func toNFSeEmissionView(e nfse.Emission) nfseEmissionView {
	return nfseEmissionView{
		ID:               e.ID,
		Status:           string(e.Status),
		CNPJ:             e.EmitterCNPJ,
		Competencia:      formatCompetencia(e.Competencia),
		ValorCents:       e.ServiceValueCents,
		Serie:            e.Series,
		NumeroDPS:        e.Number,
		TomadorDocumento: e.TomadorDocument,
		TomadorNome:      e.TomadorName,
		ChaveAcesso:      e.ChaveAcesso,
		NumeroNFSe:       e.NFSeNumber,
		DPSID:            e.DPSID,
		RejeicaoCodigo:   e.RejectionCode,
		RejeicaoMensagem: e.RejectionMessage,
		CriadaEm:         e.CreatedAt.UTC().Format(time.RFC3339),
	}
}

func formatCompetencia(c nfse.Competencia) string {
	if c.Year == 0 {
		return ""
	}
	s := strconv.Itoa(c.Year) + "-" + leftPad2(c.Month)
	if c.Day != 0 {
		s += "-" + leftPad2(c.Day)
	}
	return s
}

func leftPad2(n int) string {
	if n < 10 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}

var competenciaRe = regexp.MustCompile(`^(\d{4})-(\d{2})(?:-(\d{2}))?$`)

// parseCompetencia accepts "YYYY-MM-DD", "YYYY-MM" or empty (zero value: the
// use-case fills in the emission date). Range checks are the domain's.
func parseCompetencia(s string) (nfse.Competencia, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nfse.Competencia{}, true
	}
	m := competenciaRe.FindStringSubmatch(s)
	if m == nil {
		return nfse.Competencia{}, false
	}
	y, _ := strconv.Atoi(m[1])
	mo, _ := strconv.Atoi(m[2])
	d, _ := strconv.Atoi(m[3]) // "" → 0: the month
	if m[3] != "" && d == 0 {
		return nfse.Competencia{}, false
	}
	return nfse.Competencia{Year: y, Month: mo, Day: d}, true
}

func parseRegime(s string) (nfse.SimplesNacional, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "mei":
		return nfse.SimplesMEI, true
	case "me_epp":
		return nfse.SimplesMEEPP, true
	}
	return 0, false
}

// nfseErrorBody is the error envelope of the NFS-e routes: a stable code for
// the client to branch on, plus the emission when the ADN rejected it.
type nfseErrorBody struct {
	Error    string            `json:"error"`
	Code     string            `json:"code"`
	Emission *nfseEmissionView `json:"emission,omitempty"`
}

func writeNFSeCoded(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, nfseErrorBody{Error: msg, Code: code})
}

func (s *Server) nfseAvailable(w http.ResponseWriter) bool {
	if s.nfse == nil {
		writeError(w, http.StatusServiceUnavailable, "nfse unavailable")
		return false
	}
	return true
}

func (s *Server) handleEmitNFSe(w http.ResponseWriter, r *http.Request) {
	if !s.nfseAvailable(w) {
		return
	}
	idemKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if idemKey == "" {
		writeError(w, http.StatusBadRequest, "missing Idempotency-Key header")
		return
	}
	var req emitNFSeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !nfse.ValidCNPJ(req.CNPJ) {
		writeNFSeCoded(w, http.StatusBadRequest, "nfse_invalid_cnpj", "invalid cnpj")
		return
	}
	comp, ok := parseCompetencia(req.Competencia)
	if !ok {
		writeNFSeCoded(w, http.StatusBadRequest, "nfse_invalid_competencia", "competencia must be YYYY-MM-DD or YYYY-MM")
		return
	}
	regime, ok := parseRegime(req.SimplesNacional)
	if !ok {
		writeNFSeCoded(w, http.StatusBadRequest, "nfse_invalid_regime", "simples_nacional must be mei or me_epp")
		return
	}
	in := app.EmitNFSeInput{
		TenantID:                tenantFromContext(r.Context()),
		AccountID:               accountFromContext(r.Context()),
		IdempotencyKey:          idemKey,
		EmitterCNPJ:             req.CNPJ,
		Series:                  strings.TrimSpace(req.Serie),
		Competencia:             comp,
		MunicipalityCode:        req.MunicipioPrestacao,
		EmitterMunicipalityCode: req.MunicipioEmissor,
		ServiceCode:             req.CodigoServico,
		Description:             req.Descricao,
		ValueCents:              req.ValorCents,
		Regime:                  regime,
		SimplesTaxRateBps:       req.AliquotaSimplesBps,
		MunicipalServiceCode:    req.CodigoMunicipal,
		NBSCode:                 req.CodigoNBS,
	}
	if t := req.Tomador; t != nil {
		in.Tomador = &nfse.Tomador{Document: t.Documento, Name: t.Nome, Email: t.Email}
	}
	em, err := s.nfse.Emit(r.Context(), in)
	if err != nil {
		writeNFSeError(w, r, em, err)
		return
	}
	writeJSON(w, http.StatusCreated, toNFSeEmissionView(em))
}

// writeNFSeError maps emission failures: client-fixable input is 400, a
// concurrent request on the same Idempotency-Key is 409, custody
// preconditions and ADN rejections are 422 (the rejected record is returned
// and stays readable at GET /v1/nfse/{id}), an ADN transport failure is 502.
func writeNFSeError(w http.ResponseWriter, r *http.Request, em nfse.Emission, err error) {
	for _, m := range []struct {
		target error
		status int
		code   string
	}{
		{nfse.ErrInvalidCompetencia, http.StatusBadRequest, "nfse_invalid_competencia"},
		{nfse.ErrNonPositiveValue, http.StatusBadRequest, "nfse_invalid_valor"},
		{nfse.ErrEmptyDescription, http.StatusBadRequest, "nfse_invalid_descricao"},
		{nfse.ErrInvalidMunicipality, http.StatusBadRequest, "nfse_invalid_municipio"},
		{nfse.ErrInvalidSeriesNumber, http.StatusBadRequest, "nfse_invalid_serie"},
		{nfse.ErrInvalidServiceCode, http.StatusBadRequest, "nfse_invalid_codigo_servico"},
		{nfse.ErrInvalidNBS, http.StatusBadRequest, "nfse_invalid_codigo_nbs"},
		{nfse.ErrInvalidRegime, http.StatusBadRequest, "nfse_invalid_regime"},
		{nfse.ErrInvalidSimplesTaxRate, http.StatusBadRequest, "nfse_invalid_aliquota_simples"},
		{nfse.ErrInvalidTomador, http.StatusBadRequest, "nfse_invalid_tomador"},
		{nfse.ErrEmptyEmitter, http.StatusBadRequest, "nfse_invalid_cnpj"},
		{nfse.ErrNoCertificate, http.StatusUnprocessableEntity, "nfse_no_certificate"},
		{nfse.ErrCertExpired, http.StatusUnprocessableEntity, "nfse_certificate_expired"},
		{nfse.ErrEmitterMismatch, http.StatusUnprocessableEntity, "nfse_certificate_cnpj_mismatch"},
		{custody.ErrNotProvisioned, http.StatusUnprocessableEntity, "nfse_no_certificate"},
	} {
		if errors.Is(err, m.target) {
			writeNFSeCoded(w, m.status, m.code, m.target.Error())
			return
		}
	}
	if errors.Is(err, nfse.ErrEmissionInFlight) {
		w.Header().Set("Retry-After", "5")
		writeNFSeCoded(w, http.StatusConflict, "nfse_in_flight", err.Error())
		return
	}
	if be, ok := nfse.AsBusinessError(err); ok {
		view := toNFSeEmissionView(em)
		if view.Status == "" {
			view.Status = string(nfse.StatusRejected)
		}
		writeJSON(w, http.StatusUnprocessableEntity, nfseErrorBody{Error: be.Error(), Code: "nfse_rejected", Emission: &view})
		return
	}
	var te *nfse.TransportError
	if errors.As(err, &te) {
		writeNFSeCoded(w, http.StatusBadGateway, "nfse_adn_unavailable", "adn transport error")
		return
	}
	if errors.Is(err, custody.ErrVaultTransport) {
		writeNFSeCoded(w, http.StatusServiceUnavailable, "nfse_custody_unavailable", "certificate custody unavailable")
		return
	}
	writeDomainError(w, r, err)
}

func (s *Server) handleGetNFSe(w http.ResponseWriter, r *http.Request) {
	if !s.nfseAvailable(w) {
		return
	}
	em, err := s.nfse.Get(r.Context(), tenantFromContext(r.Context()), chi.URLParam(r, "id"))
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toNFSeEmissionView(em))
}

func (s *Server) handleGetNFSeXML(w http.ResponseWriter, r *http.Request) {
	if !s.nfseAvailable(w) {
		return
	}
	em, err := s.nfse.Get(r.Context(), tenantFromContext(r.Context()), chi.URLParam(r, "id"))
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	if em.Status != nfse.StatusAuthorized || len(em.XML) == 0 {
		writeNFSeCoded(w, http.StatusNotFound, "nfse_xml_unavailable", "authorised XML unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="nfse-`+em.ChaveAcesso+`.xml"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(em.XML)
}

func (s *Server) handleGetNFSePDF(w http.ResponseWriter, r *http.Request) {
	if !s.nfseAvailable(w) {
		return
	}
	pdf, err := s.nfse.DANFSe(r.Context(), tenantFromContext(r.Context()), chi.URLParam(r, "id"))
	if err != nil {
		var te *nfse.TransportError
		switch {
		case errors.Is(err, nfse.ErrDANFSeUnavailable):
			writeNFSeCoded(w, http.StatusNotFound, "nfse_pdf_unavailable", "DANFSe unavailable")
		case errors.As(err, &te):
			writeNFSeCoded(w, http.StatusBadGateway, "nfse_adn_unavailable", "adn transport error")
		default:
			writeDomainError(w, r, err)
		}
		return
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", `inline; filename="danfse-`+chi.URLParam(r, "id")+`.pdf"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(pdf)
}

// --- A1 certificate custody ---

// maxNFSeCertBody fits a MaxPFXSize file in base64 plus the JSON envelope.
const maxNFSeCertBody = a1import.MaxPFXSize*4/3 + 4<<10

type putNFSeCertRequest struct {
	CNPJ      string `json:"cnpj"`
	PFXBase64 string `json:"pfx_base64"`
	Password  string `json:"password"`
}

// nfseCertView never carries key material: serial, subject and validity only.
type nfseCertView struct {
	CNPJ           string `json:"cnpj"`
	Serial         string `json:"serial"`
	Subject        string `json:"subject"`
	NotAfter       string `json:"not_after"`
	ExpiresInDays  int    `json:"expires_in_days"`
	ReplacedSerial string `json:"replaced_serial,omitempty"`
}

func toNFSeCertView(cnpj string, meta custody.A1Meta) nfseCertView {
	return nfseCertView{
		CNPJ:          cnpj,
		Serial:        meta.Serial,
		Subject:       meta.Subject,
		NotAfter:      meta.NotAfter.UTC().Format(time.RFC3339),
		ExpiresInDays: meta.ExpiresInDays(time.Now()),
	}
}

func (s *Server) handlePutNFSeCertificate(w http.ResponseWriter, r *http.Request) {
	if !s.nfseAvailable(w) {
		return
	}
	s.putNFSeCertificate(w, r, tenantFromContext(r.Context()))
}

// handleAdminPutNFSeCertificate custodies an A1 for the tenant in the path
// (operator onboarding, e.g. LHMOST's own certificate).
func (s *Server) handleAdminPutNFSeCertificate(w http.ResponseWriter, r *http.Request) {
	if !s.nfseAvailable(w) {
		return
	}
	s.putNFSeCertificate(w, r, chi.URLParam(r, "tenantID"))
}

// putNFSeCertificate is shared by the tenant route and the admin route.
func (s *Server) putNFSeCertificate(w http.ResponseWriter, r *http.Request, tenantID string) {
	r.Body = http.MaxBytesReader(w, r.Body, maxNFSeCertBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req putNFSeCertRequest
	if err := dec.Decode(&req); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeNFSeCoded(w, http.StatusRequestEntityTooLarge, "nfse_cert_too_large", a1import.ErrPFXTooLarge.Error())
			return
		}
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if !nfse.ValidCNPJ(req.CNPJ) {
		writeNFSeCoded(w, http.StatusBadRequest, "nfse_invalid_cnpj", "invalid cnpj")
		return
	}
	pfx, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.PFXBase64))
	req.PFXBase64 = ""
	if err != nil {
		writeNFSeCoded(w, http.StatusUnprocessableEntity, "nfse_cert_invalid_file", "pfx_base64 is not valid base64")
		return
	}
	res, err := s.nfse.ImportCertificate(r.Context(), tenantID, pfx, req.Password, req.CNPJ)
	clear(pfx)
	req.Password = ""
	if err != nil {
		writeNFSeCertError(w, r, err)
		return
	}
	view := toNFSeCertView(res.CNPJ, res.Meta)
	view.ReplacedSerial = res.RetiredSerial
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) handleGetNFSeCertificate(w http.ResponseWriter, r *http.Request) {
	if !s.nfseAvailable(w) {
		return
	}
	cnpj := chi.URLParam(r, "cnpj")
	if !nfse.ValidCNPJ(cnpj) {
		writeNFSeCoded(w, http.StatusBadRequest, "nfse_invalid_cnpj", "invalid cnpj")
		return
	}
	meta, err := s.nfse.Certificate(r.Context(), tenantFromContext(r.Context()), cnpj)
	if err != nil {
		if errors.Is(err, custody.ErrCertNotFound) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		writeNFSeCertError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toNFSeCertView(strings.Map(keepDigit, cnpj), meta))
}

func keepDigit(r rune) rune {
	if r >= '0' && r <= '9' {
		return r
	}
	return -1
}

// writeNFSeCertError maps import failures to stable codes: what the client can
// fix (file, password, CNPJ, validity) is 422 with a distinct code; a custody
// outage is 503 so the client retries instead of asking for another file.
func writeNFSeCertError(w http.ResponseWriter, r *http.Request, err error) {
	for _, m := range []struct {
		target error
		status int
		code   string
	}{
		{a1import.ErrPFXTooLarge, http.StatusRequestEntityTooLarge, "nfse_cert_too_large"},
		{a1import.ErrEmptyPFX, http.StatusUnprocessableEntity, "nfse_cert_invalid_file"},
		{a1import.ErrInvalidPFX, http.StatusUnprocessableEntity, "nfse_cert_invalid_file"},
		{a1import.ErrWrongPassword, http.StatusUnprocessableEntity, "nfse_cert_wrong_password"},
		{a1import.ErrNoCNPJ, http.StatusUnprocessableEntity, "nfse_cert_no_cnpj"},
		{a1import.ErrUntrustedChain, http.StatusUnprocessableEntity, "nfse_cert_untrusted"},
		{a1import.ErrOlderCertificate, http.StatusConflict, "nfse_cert_older"},
		{a1import.ErrCNPJMismatch, http.StatusUnprocessableEntity, "nfse_cert_cnpj_mismatch"},
		{a1import.ErrCertNotYetValid, http.StatusUnprocessableEntity, "nfse_cert_not_yet_valid"},
		{custody.ErrCertExpired, http.StatusUnprocessableEntity, "nfse_cert_expired"},
		{a1import.ErrNotSigningCert, http.StatusUnprocessableEntity, "nfse_cert_not_signing"},
		{custody.ErrUnsupportedKey, http.StatusUnprocessableEntity, "nfse_cert_unsupported_key"},
		{custody.ErrUnsupportedKeySize, http.StatusUnprocessableEntity, "nfse_cert_unsupported_key"},
		{custody.ErrKeyCertMismatch, http.StatusUnprocessableEntity, "nfse_cert_key_mismatch"},
		{custody.ErrKeyConflict, http.StatusConflict, "nfse_cert_conflict"},
		{custody.ErrVaultTransport, http.StatusServiceUnavailable, "nfse_custody_unavailable"},
		{app.ErrNFSeCertImportUnavailable, http.StatusServiceUnavailable, "nfse_custody_unavailable"},
	} {
		if errors.Is(err, m.target) {
			writeNFSeCoded(w, m.status, m.code, m.target.Error())
			return
		}
	}
	if errors.Is(err, shared.ErrValidation) {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	writeDomainError(w, r, err)
}

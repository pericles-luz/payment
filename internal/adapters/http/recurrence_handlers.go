package http

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// --- Tenant API: PIX Automático (recorrência) ---
//
// The composite-QR journey (Jornada 3) reads, end to end:
//
//	POST /v1/pix              → immediate charge, returns txid   (existing route)
//	POST /v1/pix/locrec       → payload location                 { id, location }
//	POST /v1/pix/rec          → mandate, bound to loc_id + txid  { id_rec, status }
//	GET  /v1/pix/rec/{idRec}  → composite QR to show the payer   { pix_copia_e_cola }
//	                            (the txid is remembered from the create, so the shop
//	                             does not have to thread it back)
//	POST /v1/pix/cobr         → one recurring charge per cycle, once the payer approved
//
// Every handler follows the house shape: the tenant comes from the authenticated
// context and never from the body (threat H1/P1), writes require an Idempotency-Key,
// bodies are decoded with unknown-field rejection, and errors go through
// writeDomainError so a cross-tenant object is a 404 rather than an existence oracle.

// recurrenceUnavailable answers 503 when the recurrence service is not wired. The
// routes only exist when the feature flag is on, but the flag and the service are
// independent knobs, so a flag-on/service-nil deployment must degrade rather than
// panic (same posture as handleTenantBankCapabilities).
func (s *Server) recurrenceUnavailable(w http.ResponseWriter) bool {
	if s.recurrence == nil {
		writeError(w, http.StatusServiceUnavailable, "recurrence unavailable")
		return true
	}
	return false
}

// requireIdempotencyKey reads the mandatory Idempotency-Key header for a write.
func requireIdempotencyKey(w http.ResponseWriter, r *http.Request) (string, bool) {
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if key == "" {
		writeError(w, http.StatusBadRequest, "missing Idempotency-Key header")
		return "", false
	}
	return key, true
}

// writeRecurrenceError maps a recurrence failure to a status. It delegates to
// writeDomainError for everything the whole API already agrees on, and adds ONE case:
// shared.ErrUnavailable answers 503, not 500.
//
// That case is not hypothetical: shared.ErrUnavailable is what the adapter returns when
// the bank dependency is unreachable, times out, rate-limits or 5xxs, and when a
// recurrence port is not wired in this deployment. Reporting any of those as 500 would
// tell an integrator we have a bug, and would page whoever watches 5xx rates, for a
// condition that is upstream and retryable; 503 says "this dependency is not available
// right now", which is true.
//
// It is scoped to this file on purpose: widening the mapping would silently change the
// documented status of every other endpoint in the API.
func writeRecurrenceError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, shared.ErrUnavailable) {
		writeError(w, http.StatusServiceUnavailable, "recurrence unavailable")
		return
	}
	writeDomainError(w, r, err)
}

// --- locrec ---

// locRecView is the payload location returned to the tenant. The id is what binds a
// mandate to this location on the next call; the location URL is what the composite QR
// points the payer's PSP at.
type locRecView struct {
	ID       int64  `json:"id"`
	Location string `json:"location"`
	Criacao  string `json:"criacao,omitempty"`
	IDRec    string `json:"id_rec,omitempty"`
}

func toLocRecView(res ports.LocRecResult) locRecView {
	v := locRecView{ID: res.ID, Location: res.Location, IDRec: res.IDRec}
	if !res.Criacao.IsZero() {
		v.Criacao = res.Criacao.UTC().Format(time.RFC3339)
	}
	return v
}

// handleCreateLocRec mints a payload location. It takes NO request body — the BACEN
// contract has none, and inventing one here would be a field a caller could use to
// steer where the QR points.
func (s *Server) handleCreateLocRec(w http.ResponseWriter, r *http.Request) {
	if s.recurrenceUnavailable(w) {
		return
	}
	idemKey, ok := requireIdempotencyKey(w, r)
	if !ok {
		return
	}
	res, err := s.recurrence.CreateLocRec(r.Context(), app.CreateLocRecInput{
		TenantID:       tenantFromContext(r.Context()),
		IdempotencyKey: idemKey,
	})
	if err != nil {
		writeRecurrenceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toLocRecView(res))
}

// --- rec (mandato) ---

// recDevedorReq is the payer bound to the mandate. tax_id is the CPF (11 digits) or
// CNPJ (14 digits); the core decides which from its length.
type recDevedorReq struct {
	TaxID string `json:"tax_id"`
	Name  string `json:"name"`
}

// createRecRequest is the boundary body for POST /v1/pix/rec. Unknown fields are
// rejected by decodeJSON (anti mass-assignment).
type createRecRequest struct {
	Contrato      string         `json:"contrato"`
	Objeto        string         `json:"objeto"`
	Devedor       *recDevedorReq `json:"devedor"`
	DataInicial   string         `json:"data_inicial"`
	Periodicidade string         `json:"periodicidade"`
	// RetryPolicy is the BACEN política de retentativa: NAO_PERMITE or PERMITE_3R_7D.
	RetryPolicy string `json:"retry_policy"`
	// LocID binds the mandate to a payload location so a QR can be composed.
	LocID int64 `json:"loc_id"`
	// JourneyTxID is the txid of the ALREADY-CREATED immediate charge the Jornada 3
	// composite QR settles. Supplying it is what makes this a Jornada 3 mandate.
	JourneyTxID string `json:"journey_txid"`
	// AmountCents is the fixed amount each cycle debits. Omit (0) for a variable-value
	// mandate whose amount is decided per cycle. When set, it is the ceiling every
	// recurring charge is capped at.
	AmountCents int64 `json:"amount_cents"`
	// Bank optionally selects which configured bank handles this mandate (multi-bank,
	// SIN-66022); empty keeps header/default routing, overrides X-Bank-Id (ADR-0007).
	Bank string `json:"bank"`
}

// recView is the mandate returned to the tenant. status is the BACEN lifecycle state;
// a freshly created mandate is CRIADA and is NOT chargeable until the payer approves it
// at their own bank — which is why journey_status (tipoJornada) is surfaced too.
type recView struct {
	IDRec         string `json:"id_rec"`
	Status        string `json:"status"`
	JourneyStatus string `json:"journey_status,omitempty"`
	Contrato      string `json:"contrato,omitempty"`
	DataInicial   string `json:"data_inicial,omitempty"`
	Periodicidade string `json:"periodicidade,omitempty"`
	RetryPolicy   string `json:"retry_policy,omitempty"`
	AmountCents   int64  `json:"amount_cents,omitempty"`
	LocID         int64  `json:"loc_id,omitempty"`
	Location      string `json:"location,omitempty"`
	// QR is present only on a read that asked for a composed QR and got one.
	QR *recQRView `json:"qr,omitempty"`
}

// recQRView is the composite QR the shop displays. jornada names which journey the
// bank composed, so a caller can tell a Jornada 3 QR (pay now + authorize) from a
// Jornada 2 one (authorize only) instead of assuming.
type recQRView struct {
	Jornada       string `json:"jornada"`
	PixCopiaECola string `json:"pix_copia_e_cola"`
}

// toRecView renders a mandate. The payer's document and name are deliberately NOT
// echoed: the caller supplied them, they are the only titular PII this service stores
// (ADR-0008), and every read that exposes them carries an art.13 access-register
// obligation. Nothing in this response needs them.
func toRecView(res ports.RecResult) recView {
	v := recView{
		IDRec:         res.IDRec,
		Status:        string(res.Status),
		JourneyStatus: res.TipoJornada,
		Contrato:      res.Vinculo.Contrato,
		DataInicial:   res.Calendario.DataInicial,
		Periodicidade: string(res.Calendario.Periodicidade),
		RetryPolicy:   string(res.PoliticaRetentativa),
		AmountCents:   res.ValorRecCents,
		LocID:         res.LocID,
		Location:      res.Location,
	}
	if res.DadosQR.PixCopiaECola != "" {
		v.QR = &recQRView{Jornada: res.DadosQR.Jornada, PixCopiaECola: res.DadosQR.PixCopiaECola}
	}
	return v
}

func (s *Server) handleCreateRec(w http.ResponseWriter, r *http.Request) {
	if s.recurrenceUnavailable(w) {
		return
	}
	idemKey, ok := requireIdempotencyKey(w, r)
	if !ok {
		return
	}
	var req createRecRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Devedor == nil {
		writeError(w, http.StatusBadRequest, "missing devedor")
		return
	}
	nr, okBank := s.rebindBank(w, r, req.Bank)
	if !okBank {
		return
	}
	r = nr

	rec, res, err := s.recurrence.CreateMandate(r.Context(), app.CreateMandateInput{
		TenantID:            tenantFromContext(r.Context()),
		AccountID:           accountFromContext(r.Context()),
		Contrato:            req.Contrato,
		Objeto:              req.Objeto,
		DevedorDoc:          req.Devedor.TaxID,
		DevedorNome:         req.Devedor.Name,
		DataInicial:         req.DataInicial,
		Periodicidade:       req.Periodicidade,
		PoliticaRetentativa: req.RetryPolicy,
		LocID:               req.LocID,
		JornadaTxID:         req.JourneyTxID,
		ValorRecCents:       req.AmountCents,
		IdempotencyKey:      idemKey,
	})
	if err != nil {
		writeRecurrenceError(w, r, err)
		return
	}
	// The durable aggregate is authoritative for the status we just recorded; the bank
	// result carries the registration echo. Prefer the former so the response can never
	// claim a state we did not persist.
	view := toRecView(res)
	view.Status = string(rec.Status())
	writeJSON(w, http.StatusCreated, view)
}

// handleGetRec reads a mandate. With ?qr=true it asks the bank to COMPOSE the QR for
// the journey instead of just reporting state.
//
// The txid defaults to the one the mandate was created against (persisted at creation),
// so the ordinary Jornada 3 case is a plain `?qr=true` and the shop never has to keep a
// mandate→charge mapping of its own. An explicit ?txid= overrides it, which is how a
// Jornada 4 QR (a due charge) is composed against the same mandate.
func (s *Server) handleGetRec(w http.ResponseWriter, r *http.Request) {
	if s.recurrenceUnavailable(w) {
		return
	}
	tenantID := tenantFromContext(r.Context())
	idRec := chi.URLParam(r, "idRec")

	if !strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("qr")), "true") {
		res, err := s.recurrence.GetMandate(r.Context(), tenantID, idRec)
		if err != nil {
			writeRecurrenceError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, toRecView(res))
		return
	}

	res, err := s.recurrence.GetMandateQR(r.Context(), tenantID, idRec, strings.TrimSpace(r.URL.Query().Get("txid")))
	if err != nil {
		writeRecurrenceError(w, r, err)
		return
	}
	view := toRecView(res)
	if view.QR == nil {
		// The bank had no QR to give: the mandate and the referenced charge do not yet
		// carry everything the composite QR needs. Saying so is the point — a 200 with an
		// empty pix_copia_e_cola would render as a broken QR in front of a payer.
		writeError(w, http.StatusConflict, "composite QR not available for this mandate yet")
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// handleCancelRec revokes a mandate so no further debits can be originated.
func (s *Server) handleCancelRec(w http.ResponseWriter, r *http.Request) {
	if s.recurrenceUnavailable(w) {
		return
	}
	res, err := s.recurrence.CancelMandate(r.Context(), tenantFromContext(r.Context()), "", chi.URLParam(r, "idRec"))
	if err != nil {
		writeRecurrenceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toRecView(res))
}

// --- solicrec (Jornada 1) ---

// createSolicRecRequest asks the payer's participant to confirm an existing mandate.
type createSolicRecRequest struct {
	IDRec string `json:"id_rec"`
	// Exactly one of tax_id shapes applies: 11 digits = CPF, 14 = CNPJ.
	TaxID            string `json:"tax_id"`
	Agencia          string `json:"agencia"`
	Conta            string `json:"conta"`
	ISPBParticipante string `json:"ispb_participante"`
	// ExpiresAt is RFC3339 and must be under 30 days ahead (BACEN CMT-APR-SOLI-016).
	ExpiresAt string `json:"expires_at"`
	Bank      string `json:"bank"`
}

type solicRecView struct {
	IDSolicRec string `json:"id_solic_rec"`
	IDRec      string `json:"id_rec"`
	Status     string `json:"status"`
	ExpiresAt  string `json:"expires_at,omitempty"`
}

func toSolicRecView(res ports.SolicRecResult) solicRecView {
	v := solicRecView{IDSolicRec: res.IDSolicRec, IDRec: res.IDRec, Status: res.Status}
	if !res.ExpiraEm.IsZero() {
		v.ExpiresAt = res.ExpiraEm.UTC().Format(time.RFC3339)
	}
	return v
}

func (s *Server) handleCreateSolicRec(w http.ResponseWriter, r *http.Request) {
	if s.recurrenceUnavailable(w) {
		return
	}
	idemKey, ok := requireIdempotencyKey(w, r)
	if !ok {
		return
	}
	var req createSolicRecRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	expires, okExp := parseRFC3339(req.ExpiresAt)
	if !okExp {
		writeError(w, http.StatusBadRequest, "invalid or missing expires_at (RFC3339)")
		return
	}
	nr, okBank := s.rebindBank(w, r, req.Bank)
	if !okBank {
		return
	}
	r = nr

	in := app.RequestConfirmationInput{
		TenantID:         tenantFromContext(r.Context()),
		IDRec:            req.IDRec,
		Agencia:          req.Agencia,
		Conta:            req.Conta,
		ISPBParticipante: req.ISPBParticipante,
		ExpiraEm:         expires,
		IdempotencyKey:   idemKey,
	}
	// The BACEN destinatário is a oneOf: the document's length decides which branch,
	// exactly as it does for the mandate's payer.
	if len(strings.TrimSpace(req.TaxID)) == 14 {
		in.CNPJ = strings.TrimSpace(req.TaxID)
	} else {
		in.CPF = strings.TrimSpace(req.TaxID)
	}

	res, err := s.recurrence.RequestConfirmation(r.Context(), in)
	if err != nil {
		writeRecurrenceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toSolicRecView(res))
}

func (s *Server) handleGetSolicRec(w http.ResponseWriter, r *http.Request) {
	if s.recurrenceUnavailable(w) {
		return
	}
	res, err := s.recurrence.GetConfirmation(r.Context(), tenantFromContext(r.Context()), chi.URLParam(r, "idSolicRec"))
	if err != nil {
		writeRecurrenceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toSolicRecView(res))
}

// --- cobr (cobrança recorrente) ---

// cobrRequest is the boundary body for originating or revising one recurring charge.
type cobrRequest struct {
	IDRec string `json:"id_rec"`
	// TxID is the anti-double-bill anchor. Optional on create (generated server-side
	// like cob/cobv when absent), accepted so a caller can drive its own conciliation
	// key; required in the URL on a revise.
	TxID string `json:"txid"`
	// DueDate is the yyyy-MM-dd charge date.
	DueDate     string `json:"due_date"`
	AmountCents int64  `json:"amount_cents"`
	Bank        string `json:"bank"`
}

type cobrView struct {
	TxID        string `json:"txid"`
	IDRec       string `json:"id_rec"`
	Status      string `json:"status"`
	DueDate     string `json:"due_date,omitempty"`
	AmountCents int64  `json:"amount_cents"`
}

func toCobRView(res ports.CobRResult) cobrView {
	return cobrView{TxID: res.TxID, IDRec: res.IDRec, Status: res.Status, AmountCents: res.ValorCents}
}

func (s *Server) handleCreateCobR(w http.ResponseWriter, r *http.Request) {
	if s.recurrenceUnavailable(w) {
		return
	}
	idemKey, ok := requireIdempotencyKey(w, r)
	if !ok {
		return
	}
	var req cobrRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	nr, okBank := s.rebindBank(w, r, req.Bank)
	if !okBank {
		return
	}
	r = nr

	cobr, err := s.recurrence.OriginateCobR(r.Context(), app.OriginateCobRInput{
		TenantID:       tenantFromContext(r.Context()),
		AccountID:      accountFromContext(r.Context()),
		IDRec:          req.IDRec,
		TxID:           req.TxID,
		Vencimento:     req.DueDate,
		ValorCents:     req.AmountCents,
		IdempotencyKey: idemKey,
	})
	if err != nil {
		writeRecurrenceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, cobrView{
		TxID:        cobr.TxID(),
		IDRec:       cobr.IDRec(),
		Status:      string(cobr.Status()),
		DueDate:     cobr.Vencimento(),
		AmountCents: cobr.ValorCents(),
	})
}

func (s *Server) handleGetCobR(w http.ResponseWriter, r *http.Request) {
	if s.recurrenceUnavailable(w) {
		return
	}
	res, err := s.recurrence.GetCobR(r.Context(), tenantFromContext(r.Context()), chi.URLParam(r, "txid"))
	if err != nil {
		writeRecurrenceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toCobRView(res))
}

// handleCancelCobR cancels ONE scheduled instalment, leaving the mandate standing.
//
// It is a DELETE rather than the PUT this route first shipped as. The earlier shape
// advertised "revise a not-yet-settled charge" with an amount in the body, which the
// bank cannot honour: on the cobr surface PUT /cobr/{txid} is the CREATE and the only
// revisable field is status=CANCELADA. A route that accepts a new amount and silently
// does not apply it is worse than one that does not exist — the caller believes the
// instalment changed. To charge a different amount: cancel here, originate a new charge.
func (s *Server) handleCancelCobR(w http.ResponseWriter, r *http.Request) {
	if s.recurrenceUnavailable(w) {
		return
	}
	res, err := s.recurrence.CancelCobR(r.Context(), tenantFromContext(r.Context()), "", chi.URLParam(r, "txid"))
	if err != nil {
		writeRecurrenceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toCobRView(res))
}

// handleRetryCobR schedules a retry of a failed debit on the date in the path, per the
// mandate's política de retentativa.
func (s *Server) handleRetryCobR(w http.ResponseWriter, r *http.Request) {
	if s.recurrenceUnavailable(w) {
		return
	}
	var req struct {
		IDRec string `json:"id_rec"`
		Bank  string `json:"bank"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	nr, okBank := s.rebindBank(w, r, req.Bank)
	if !okBank {
		return
	}
	r = nr

	res, err := s.recurrence.RetryCobR(r.Context(), tenantFromContext(r.Context()),
		req.IDRec, chi.URLParam(r, "txid"), chi.URLParam(r, "data"))
	if err != nil {
		writeRecurrenceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toCobRView(res))
}

// locRecIDFromPath parses the {id} path param of a location route. Locations are int64s
// in the BACEN contract, so a non-numeric id is a malformed request, not a lookup miss —
// answering 400 keeps it from being reported as "location not found", which would send a
// caller hunting for a location that was never asked for.
func locRecIDFromPath(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(strings.TrimSpace(chi.URLParam(r, "id")), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "invalid location id")
		return 0, false
	}
	return id, true
}

func (s *Server) handleGetLocRec(w http.ResponseWriter, r *http.Request) {
	if s.recurrenceUnavailable(w) {
		return
	}
	id, ok := locRecIDFromPath(w, r)
	if !ok {
		return
	}
	res, err := s.recurrence.GetLocRec(r.Context(), tenantFromContext(r.Context()), id)
	if err != nil {
		writeRecurrenceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toLocRecView(res))
}

func (s *Server) handleUnlinkLocRec(w http.ResponseWriter, r *http.Request) {
	if s.recurrenceUnavailable(w) {
		return
	}
	id, ok := locRecIDFromPath(w, r)
	if !ok {
		return
	}
	res, err := s.recurrence.UnlinkLocRec(r.Context(), tenantFromContext(r.Context()), id)
	if err != nil {
		writeRecurrenceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toLocRecView(res))
}

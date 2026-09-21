package http

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// --- Tenant API: as superfícies BACEN do PIX além de cob/cobv --------------------
//
// Locations de payload, PIX recebidos e suas devoluções, lotes de cobrança com
// vencimento, e a revisão/listagem que faltavam em cob e cobv.
//
// Como no resto do plano do tenant, o tenant vem SEMPRE do contexto autenticado e
// nunca do corpo ou da query: nenhuma rota daqui aceita escolher de quem é o PIX que se
// lê ou se devolve (ameaça H1/P1). Corpos são decodificados com DisallowUnknownFields
// (anti mass-assignment).

// --- Revisão da cobrança imediata ------------------------------------------------

// revisePixRequest é o corpo de PATCH /v1/pix/{txid}. Só o que vier é enviado: valor
// ausente deixa o valor como está, expiração ausente deixa o calendário como está.
type revisePixRequest struct {
	AmountCents      int64          `json:"amount_cents"`
	ExpiresInSeconds int            `json:"expires_in_seconds"`
	Devedor          *pixDevedorReq `json:"devedor"`
	CreditorKey      string         `json:"creditor_key"`
	// Bank escolhe qual banco configurado atende (multi-banco, ADR-0007).
	Bank string `json:"bank"`
}

// handleRevisePix emenda uma cobrança imediata já criada (PATCH /v1/pix/{txid} → 200).
//
// É operação de DINHEIRO: mudar o valor de uma cobrança que o pagador já tem na mão
// muda o que ele vai pagar. A Idempotency-Key é obrigatória como em toda escrita.
func (s *Server) handleRevisePix(w http.ResponseWriter, r *http.Request) {
	tenantID := tenantFromContext(r.Context())
	idemKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if idemKey == "" {
		writeError(w, http.StatusBadRequest, "missing Idempotency-Key header")
		return
	}
	var req revisePixRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	nr, ok := s.rebindBank(w, r, req.Bank)
	if !ok {
		return
	}
	r = nr

	in := app.ReviseImmediateChargeInput{
		TenantID:       tenantID,
		TxID:           chi.URLParam(r, "txid"),
		AmountCents:    req.AmountCents,
		ExpiresIn:      time.Duration(req.ExpiresInSeconds) * time.Second,
		CreditorKey:    req.CreditorKey,
		IdempotencyKey: idemKey,
	}
	if req.Devedor != nil {
		in.DebtorTaxID, in.DebtorName = req.Devedor.TaxID, req.Devedor.Name
	}

	res, err := s.pix.ReviseImmediateCharge(r.Context(), in)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toPixChargeView(res, res.ExpectedAmountCents))
}

// --- Revisão e listagem de cobv --------------------------------------------------

// handleRevisePixCobV emenda uma cobrança com vencimento (PATCH /v1/pix/cobv/{txid}
// → 200).
//
// Não é o mesmo que o PUT da mesma rota, e a diferença é dinheiro: o PUT manda o
// conjunto COMPLETO e substitui; este manda só o que mudou. Trocar um pelo outro apaga
// em silêncio o que foi omitido — a multa que o pagador já aceitou, o desconto
// prometido.
func (s *Server) handleRevisePixCobV(w http.ResponseWriter, r *http.Request) {
	tenantID := tenantFromContext(r.Context())
	idemKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if idemKey == "" {
		writeError(w, http.StatusBadRequest, "missing Idempotency-Key header")
		return
	}
	var req cobvRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	// A data de vencimento é opcional numa revisão: quem não a manda não a muda.
	var due time.Time
	if strings.TrimSpace(req.DueDate) != "" {
		parsed, ok := parseRFC3339(req.DueDate)
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid due_date (RFC3339)")
			return
		}
		due = parsed
	}
	nr, ok := s.rebindBank(w, r, req.Bank)
	if !ok {
		return
	}
	r = nr

	in := toDueChargeInput(tenantID, accountFromContext(r.Context()), idemKey, req, due)
	res, err := s.pixCobV.ReviseDueCharge(r.Context(), tenantID, chi.URLParam(r, "txid"), in)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toCobvView(res, res.ExpectedAmountCents))
}

// cobvListView é a página de cobranças com vencimento.
type cobvListView struct {
	Charges    []cobvView `json:"charges"`
	Page       int        `json:"page"`
	PageSize   int        `json:"page_size"`
	TotalItems int        `json:"total_items"`
	TotalPages int        `json:"total_pages"`
}

// handleListPixCobV lista as cobranças com vencimento da janela pedida
// (GET /v1/pix/cobv?start=&end= → 200).
func (s *Server) handleListPixCobV(w http.ResponseWriter, r *http.Request) {
	in := app.ListDueChargesInput{TenantID: tenantFromContext(r.Context())}
	if !bindPixWindow(w, r, &in.Start, &in.End, &in.Page, &in.PageSize) {
		return
	}
	list, err := s.pixCobV.ListDueCharges(r.Context(), in)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	views := make([]cobvView, 0, len(list.Charges))
	for _, c := range list.Charges {
		views = append(views, toCobvView(c, c.ExpectedAmountCents))
	}
	writeJSON(w, http.StatusOK, cobvListView{
		Charges: views, Page: list.Page, PageSize: list.PageSize,
		TotalItems: list.TotalItems, TotalPages: list.TotalPages,
	})
}

// bindPixWindow lê a janela obrigatória (start/end em RFC3339) e a paginação opcional,
// escrevendo o 400 e devolvendo false quando algo falta ou não parseia.
//
// Existe porque cinco listagens deste arquivo leem exatamente os mesmos quatro
// parâmetros, e cinco cópias da mesma leitura divergem.
func bindPixWindow(w http.ResponseWriter, r *http.Request, start, end *time.Time, page, pageSize *int) bool {
	q := r.URL.Query()
	s, ok := parseRFC3339(q.Get("start"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid or missing start (RFC3339)")
		return false
	}
	e, ok := parseRFC3339(q.Get("end"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid or missing end (RFC3339)")
		return false
	}
	p, ok := parseOptionalInt(q.Get("page"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid page")
		return false
	}
	ps, ok := parseOptionalInt(q.Get("page_size"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid page_size")
		return false
	}
	*start, *end, *page, *pageSize = s, e, p, ps
	return true
}

// parseOptionalBool lê um filtro booleano opcional. Ausente devolve nil, que é
// diferente de false: "não filtre por isto" não é "filtre pelos que não têm".
func parseOptionalBool(raw string) (*bool, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, true
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return nil, false
	}
	return &v, true
}

// --- Locations de payload --------------------------------------------------------

// pixLocationView é a representação JSON de uma location de payload.
type pixLocationView struct {
	ID       int64  `json:"id"`
	Location string `json:"location"`
	TipoCob  string `json:"tipo_cob"`
	// TxID é a cobrança vinculada; vazio quando não há nenhuma — e vazio é
	// exatamente o que o desvinculamento produz.
	TxID      string `json:"txid,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
}

func toPixLocationView(l ports.PixLocation) pixLocationView {
	v := pixLocationView{ID: l.ID, Location: l.Location, TipoCob: l.TipoCob, TxID: l.TxID}
	if !l.CreatedAt.IsZero() {
		v.CreatedAt = l.CreatedAt.UTC().Format(time.RFC3339)
	}
	return v
}

// createPixLocRequest é o corpo de POST /v1/pix/loc.
type createPixLocRequest struct {
	TipoCob string `json:"tipo_cob"`
	Bank    string `json:"bank"`
}

// handleCreatePixLoc cria uma location de payload (POST /v1/pix/loc → 201).
//
// Uma location existe INDEPENDENTEMENTE da cobrança: é isso que permite imprimir um QR
// antes de a cobrança que vai ser servida por ele existir.
func (s *Server) handleCreatePixLoc(w http.ResponseWriter, r *http.Request) {
	tenantID := tenantFromContext(r.Context())
	var req createPixLocRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	nr, ok := s.rebindBank(w, r, req.Bank)
	if !ok {
		return
	}
	r = nr

	loc, err := s.pixLoc.CreateLocation(r.Context(), tenantID, req.TipoCob)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toPixLocationView(loc))
}

// pixLocationListView é a página de locations.
type pixLocationListView struct {
	Locations  []pixLocationView `json:"locations"`
	Page       int               `json:"page"`
	PageSize   int               `json:"page_size"`
	TotalItems int               `json:"total_items"`
	TotalPages int               `json:"total_pages"`
}

// handleListPixLoc lista as locations da janela pedida (GET /v1/pix/loc → 200).
func (s *Server) handleListPixLoc(w http.ResponseWriter, r *http.Request) {
	in := app.ListLocationsInput{TenantID: tenantFromContext(r.Context())}
	if !bindPixWindow(w, r, &in.Start, &in.End, &in.Page, &in.PageSize) {
		return
	}
	q := r.URL.Query()
	in.TipoCob = q.Get("tipo_cob")
	present, ok := parseOptionalBool(q.Get("txid_present"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid txid_present")
		return
	}
	in.TxIDPresent = present

	list, err := s.pixLoc.ListLocations(r.Context(), in)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	views := make([]pixLocationView, 0, len(list.Locations))
	for _, l := range list.Locations {
		views = append(views, toPixLocationView(l))
	}
	writeJSON(w, http.StatusOK, pixLocationListView{
		Locations: views, Page: list.Page, PageSize: list.PageSize,
		TotalItems: list.TotalItems, TotalPages: list.TotalPages,
	})
}

// parseLocID lê o id numérico de uma location do caminho.
func parseLocID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		// Id malformado responde 400 e não 404 porque a location é endereçada por um
		// inteiro do PSP, não por um identificador opaco nosso: "isto não é um id" é a
		// resposta certa, e não revela nada sobre o que existe.
		writeError(w, http.StatusBadRequest, "invalid location id")
		return 0, false
	}
	return id, true
}

// handleGetPixLoc lê uma location, incluindo a cobrança vinculada
// (GET /v1/pix/loc/{id} → 200).
func (s *Server) handleGetPixLoc(w http.ResponseWriter, r *http.Request) {
	id, ok := parseLocID(w, r)
	if !ok {
		return
	}
	loc, err := s.pixLoc.GetLocation(r.Context(), tenantFromContext(r.Context()), id)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toPixLocationView(loc))
}

// handleUnlinkPixLoc desvincula a cobrança de uma location
// (DELETE /v1/pix/loc/{id}/txid → 200).
//
// NÃO cancela a cobrança: o status dela fica como está, ela só deixa de ser servida por
// aquele QR. Quem quer cancelar usa o caminho da cobrança.
func (s *Server) handleUnlinkPixLoc(w http.ResponseWriter, r *http.Request) {
	id, ok := parseLocID(w, r)
	if !ok {
		return
	}
	loc, err := s.pixLoc.UnlinkLocationTxID(r.Context(), tenantFromContext(r.Context()), id)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toPixLocationView(loc))
}

// --- PIX recebidos e devolução ---------------------------------------------------

// pixRefundView é a representação JSON de uma devolução.
type pixRefundView struct {
	ID          string `json:"id"`
	ReturnID    string `json:"return_id,omitempty"`
	AmountCents int64  `json:"amount_cents"`
	Nature      string `json:"nature,omitempty"`
	Description string `json:"description,omitempty"`
	// Status é o vocabulário do banco, verbatim: EM_PROCESSAMENTO, DEVOLVIDO,
	// NAO_REALIZADO. Reason é o único lugar onde um NAO_REALIZADO diz por quê.
	Status      string `json:"status"`
	Reason      string `json:"reason,omitempty"`
	RequestedAt string `json:"requested_at,omitempty"`
	SettledAt   string `json:"settled_at,omitempty"`
}

func toPixRefundView(rf ports.PixRefund) pixRefundView {
	v := pixRefundView{
		ID: rf.ID, ReturnID: rf.ReturnID, AmountCents: rf.AmountCents,
		Nature: string(rf.Nature), Description: rf.Description,
		Status: rf.Status, Reason: rf.Reason,
	}
	if !rf.RequestedAt.IsZero() {
		v.RequestedAt = rf.RequestedAt.UTC().Format(time.RFC3339)
	}
	if !rf.SettledAt.IsZero() {
		v.SettledAt = rf.SettledAt.UTC().Format(time.RFC3339)
	}
	return v
}

// receivedPixView é um PIX creditado na conta.
//
// Não há campo de pagador: o objeto do banco traz CPF/CNPJ e nome de quem pagou, e não
// carregá-los é como eles nunca chegam a log, erro ou resposta (ADR-0008). PayerInfo é
// a mensagem livre que o PAGADOR escolheu mandar.
type receivedPixView struct {
	EndToEndID string `json:"end_to_end_id"`
	// TxID é vazio num PIX pago contra chave estática — a conciliação tem de lidar
	// com isso em vez de supor que há cobrança.
	TxID        string          `json:"txid,omitempty"`
	AmountCents int64           `json:"amount_cents"`
	CreditorKey string          `json:"creditor_key,omitempty"`
	ReceivedAt  string          `json:"received_at,omitempty"`
	PayerInfo   string          `json:"payer_info,omitempty"`
	Refunds     []pixRefundView `json:"refunds,omitempty"`
}

func toReceivedPixView(p ports.ReceivedPix) receivedPixView {
	v := receivedPixView{
		EndToEndID: p.EndToEndID, TxID: p.TxID, AmountCents: p.AmountCents,
		CreditorKey: p.CreditorKey, PayerInfo: p.PayerInfo,
	}
	if !p.ReceivedAt.IsZero() {
		v.ReceivedAt = p.ReceivedAt.UTC().Format(time.RFC3339)
	}
	if len(p.Refunds) > 0 {
		v.Refunds = make([]pixRefundView, len(p.Refunds))
		for i, rf := range p.Refunds {
			v.Refunds[i] = toPixRefundView(rf)
		}
	}
	return v
}

// receivedPixListView é a página de PIX recebidos.
type receivedPixListView struct {
	Received   []receivedPixView `json:"received"`
	Page       int               `json:"page"`
	PageSize   int               `json:"page_size"`
	TotalItems int               `json:"total_items"`
	TotalPages int               `json:"total_pages"`
}

// handleListReceivedPix lista os PIX creditados na janela pedida
// (GET /v1/pix/received → 200).
func (s *Server) handleListReceivedPix(w http.ResponseWriter, r *http.Request) {
	in := app.ListReceivedPixInput{TenantID: tenantFromContext(r.Context())}
	if !bindPixWindow(w, r, &in.Start, &in.End, &in.Page, &in.PageSize) {
		return
	}
	q := r.URL.Query()
	in.TxID = q.Get("txid")
	in.PayerTaxID = q.Get("payer_tax_id")
	txidPresent, ok := parseOptionalBool(q.Get("txid_present"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid txid_present")
		return
	}
	refundPresent, ok := parseOptionalBool(q.Get("refund_present"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid refund_present")
		return
	}
	in.TxIDPresent, in.RefundPresent = txidPresent, refundPresent

	list, err := s.pixReceived.ListReceivedPix(r.Context(), in)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	views := make([]receivedPixView, 0, len(list.Received))
	for _, p := range list.Received {
		views = append(views, toReceivedPixView(p))
	}
	writeJSON(w, http.StatusOK, receivedPixListView{
		Received: views, Page: list.Page, PageSize: list.PageSize,
		TotalItems: list.TotalItems, TotalPages: list.TotalPages,
	})
}

// handleGetReceivedPix lê um PIX recebido pelo end-to-end id
// (GET /v1/pix/received/{e2eid} → 200).
func (s *Server) handleGetReceivedPix(w http.ResponseWriter, r *http.Request) {
	res, err := s.pixReceived.GetReceivedPix(r.Context(),
		tenantFromContext(r.Context()), chi.URLParam(r, "e2eid"))
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toReceivedPixView(res))
}

// refundRequest é o corpo de PUT /v1/pix/received/{e2eid}/refunds/{refundID}.
//
// O valor é obrigatório e explícito: não existe "devolve tudo" por omissão, porque
// devolver a mais é tão errado quanto devolver a menos.
type refundRequest struct {
	AmountCents int64  `json:"amount_cents"`
	Nature      string `json:"nature"`
	Description string `json:"description"`
	Bank        string `json:"bank"`
}

// handleRequestRefund solicita a devolução de um PIX recebido
// (PUT /v1/pix/received/{e2eid}/refunds/{refundID} → 201).
//
// O id da devolução está no CAMINHO, escolhido por quem chama, e é ele que torna a
// operação idempotente: o par (e2eid, refundID) endereça sempre a mesma devolução, então
// um reenvio não devolve duas vezes. É por isso que não há Idempotency-Key aqui — o
// próprio endereço já é a chave.
func (s *Server) handleRequestRefund(w http.ResponseWriter, r *http.Request) {
	tenantID := tenantFromContext(r.Context())
	var req refundRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	nr, ok := s.rebindBank(w, r, req.Bank)
	if !ok {
		return
	}
	r = nr

	res, err := s.pixReceived.RequestRefund(r.Context(), app.RequestRefundInput{
		TenantID:    tenantID,
		EndToEndID:  chi.URLParam(r, "e2eid"),
		RefundID:    chi.URLParam(r, "refundID"),
		AmountCents: req.AmountCents,
		Nature:      req.Nature,
		Description: req.Description,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toPixRefundView(res))
}

// handleGetRefund reconcilia o estado de uma devolução
// (GET /v1/pix/received/{e2eid}/refunds/{refundID} → 200).
//
// É aqui que se descobre se o dinheiro saiu: a criação responde que o PSP ACEITOU o
// pedido, e o status pode continuar EM_PROCESSAMENTO depois disso.
func (s *Server) handleGetRefund(w http.ResponseWriter, r *http.Request) {
	res, err := s.pixReceived.GetRefund(r.Context(), tenantFromContext(r.Context()),
		chi.URLParam(r, "e2eid"), chi.URLParam(r, "refundID"))
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toPixRefundView(res))
}

// --- Lotes de cobrança com vencimento --------------------------------------------

// batchChargeRequest é uma cobrança dentro do lote: a mesma forma de uma cobv avulsa,
// mais o txid.
//
// O txid é explícito só aqui. Numa cobv avulsa ele é derivado da âncora de
// idempotência; num lote o PSP endereça cada cobrança pelo txid do corpo, e é por ele
// que o resultado de cada uma volta.
type batchChargeRequest struct {
	TxID string `json:"txid"`
	cobvRequest
}

// batchRequest é o corpo de PUT/PATCH /v1/pix/lotecobv/{id}.
type batchRequest struct {
	Description string               `json:"description"`
	Charges     []batchChargeRequest `json:"charges"`
	Bank        string               `json:"bank"`
}

// bindBatch monta a entrada do caso de uso a partir do corpo, resolvendo a data de
// vencimento de cada cobrança.
func bindBatch(w http.ResponseWriter, r *http.Request, tenantID, idemKey string, req batchRequest) (app.BatchInput, bool) {
	in := app.BatchInput{
		TenantID:    tenantID,
		BatchID:     chi.URLParam(r, "id"),
		Description: req.Description,
		Charges:     make([]app.BatchChargeInput, len(req.Charges)),
	}
	for i, c := range req.Charges {
		due, ok := parseRFC3339(c.DueDate)
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid or missing due_date (RFC3339) in charge "+strconv.Itoa(i))
			return app.BatchInput{}, false
		}
		in.Charges[i] = app.BatchChargeInput{
			TxID:           c.TxID,
			DueChargeInput: toDueChargeInput(tenantID, accountFromContext(r.Context()), idemKey, c.cobvRequest, due),
		}
	}
	return in, true
}

// handleCreatePixBatch registra ou altera um lote de cobranças com vencimento
// (PUT /v1/pix/lotecobv/{id} → 202).
//
// **202, não 201.** O PSP ACEITA o lote e o processa depois: as cobranças ainda não
// existem, e o contrato é explícito de que uma cobrança EM_PROCESSAMENTO ou NEGADA "não
// existe de fato e não aparece em consultas". Por isso a resposta não traz lote nenhum —
// o resultado por cobrança só sai da leitura.
func (s *Server) handleCreatePixBatch(w http.ResponseWriter, r *http.Request) {
	s.writePixBatch(w, r, false)
}

// handleRevisePixBatch revisa cobranças dentro de um lote existente
// (PATCH /v1/pix/lotecobv/{id} → 202). A revisão só pode MANTER o conjunto original:
// acrescentar ou remover uma cobrança não é revisão, e o PSP recusa.
func (s *Server) handleRevisePixBatch(w http.ResponseWriter, r *http.Request) {
	s.writePixBatch(w, r, true)
}

func (s *Server) writePixBatch(w http.ResponseWriter, r *http.Request, revisao bool) {
	tenantID := tenantFromContext(r.Context())
	idemKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if idemKey == "" {
		writeError(w, http.StatusBadRequest, "missing Idempotency-Key header")
		return
	}
	var req batchRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	nr, ok := s.rebindBank(w, r, req.Bank)
	if !ok {
		return
	}
	r = nr

	in, ok := bindBatch(w, r, tenantID, idemKey, req)
	if !ok {
		return
	}
	var err error
	if revisao {
		err = s.pixBatch.ReviseBatch(r.Context(), in)
	} else {
		err = s.pixBatch.CreateBatch(r.Context(), in)
	}
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// batchItemView é o resultado do registro de UMA cobrança do lote.
type batchItemView struct {
	TxID string `json:"txid"`
	// Status é do REGISTRO, não do pagamento: CRIADA quer dizer que o PSP aceitou a
	// cobrança, não que alguém pagou.
	Status string `json:"status"`
	// Problem é o motivo de uma NEGADA — o único lugar onde ele sobrevive.
	Problem   string `json:"problem,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
}

// batchView é um lote lido de volta.
type batchView struct {
	ID          string          `json:"id"`
	Description string          `json:"description"`
	CreatedAt   string          `json:"created_at,omitempty"`
	Charges     []batchItemView `json:"charges"`
}

func toBatchView(b ports.PixDueChargeBatch) batchView {
	v := batchView{ID: b.ID, Description: b.Description, Charges: make([]batchItemView, len(b.Items))}
	if !b.CreatedAt.IsZero() {
		v.CreatedAt = b.CreatedAt.UTC().Format(time.RFC3339)
	}
	for i, it := range b.Items {
		item := batchItemView{TxID: it.TxID, Status: it.Status, Problem: it.Problem}
		if !it.CreatedAt.IsZero() {
			item.CreatedAt = it.CreatedAt.UTC().Format(time.RFC3339)
		}
		v.Charges[i] = item
	}
	return v
}

// handleGetPixBatch lê o estado de um lote, cobrança a cobrança
// (GET /v1/pix/lotecobv/{id} → 200).
func (s *Server) handleGetPixBatch(w http.ResponseWriter, r *http.Request) {
	res, err := s.pixBatch.GetBatch(r.Context(), tenantFromContext(r.Context()), chi.URLParam(r, "id"))
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toBatchView(res))
}

// batchListView é a página de lotes.
type batchListView struct {
	Batches    []batchView `json:"batches"`
	Page       int         `json:"page"`
	PageSize   int         `json:"page_size"`
	TotalItems int         `json:"total_items"`
	TotalPages int         `json:"total_pages"`
}

// handleListPixBatches lista os lotes criados na janela pedida
// (GET /v1/pix/lotecobv → 200).
func (s *Server) handleListPixBatches(w http.ResponseWriter, r *http.Request) {
	in := app.ListBatchesInput{TenantID: tenantFromContext(r.Context())}
	if !bindPixWindow(w, r, &in.Start, &in.End, &in.Page, &in.PageSize) {
		return
	}
	list, err := s.pixBatch.ListBatches(r.Context(), in)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	views := make([]batchView, 0, len(list.Batches))
	for _, b := range list.Batches {
		views = append(views, toBatchView(b))
	}
	writeJSON(w, http.StatusOK, batchListView{
		Batches: views, Page: list.Page, PageSize: list.PageSize,
		TotalItems: list.TotalItems, TotalPages: list.TotalPages,
	})
}

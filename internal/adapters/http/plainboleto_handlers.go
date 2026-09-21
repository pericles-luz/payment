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

// --- Tenant API: boleto simples, listagem do BolePix e extrato de adquirência ----
//
// `/v1/bank-slips` é o BOLETO SIMPLES, produto DIFERENTE do BolePix que vive em
// `/v1/boletos`. Os dois se chamam "boleto" e não são a mesma coisa: o simples aceita
// até TRÊS faixas de desconto (o BolePix expõe uma só), não emite QR, e a referência
// externa cabe em 10 caracteres em vez de 26.
//
// **E ele não cria cobrança no nosso razão.** É a superfície crua do banco: emite, lê,
// altera, baixa e renderiza. Um boleto emitido por aqui não liquida sozinho do nosso
// lado — quem precisa de liquidação usa `/v1/boletos`. O porquê está em
// app.PlainBoletoService.

// plainBoletoDiscount é uma faixa de desconto por antecipação.
type plainBoletoDiscount struct {
	DaysBeforeDue int   `json:"days_before_due"`
	Bps           int64 `json:"bps"`
	FixedCents    int64 `json:"fixed_cents"`
}

func toDiscountTiers(in []plainBoletoDiscount) []ports.BoletoDiscountTier {
	if len(in) == 0 {
		return nil
	}
	out := make([]ports.BoletoDiscountTier, len(in))
	for i, d := range in {
		out[i] = ports.BoletoDiscountTier{
			DaysBeforeDue: d.DaysBeforeDue, Bps: d.Bps, FixedCents: d.FixedCents,
		}
	}
	return out
}

// plainBoletoPayerReq é o sacado. O endereço aqui tem rua e NÚMERO separados, e não
// tem bairro — é a forma deste produto, diferente da do BolePix.
type plainBoletoPayerReq struct {
	Name    string `json:"name"`
	TaxID   string `json:"tax_id"`
	Street  string `json:"street"`
	Number  int    `json:"number"`
	City    string `json:"city"`
	State   string `json:"state"`
	ZipCode string `json:"zip_code"`
}

func (p plainBoletoPayerReq) toPort() ports.BoletoPayer {
	return ports.BoletoPayer{
		Name:  p.Name,
		TaxID: p.TaxID,
		Address: ports.BoletoAddress{
			Street: p.Street, Number: p.Number,
			City: p.City, State: p.State, ZipCode: p.ZipCode,
		},
	}
}

// createPlainBoletoRequest é o corpo de POST /v1/bank-slips.
type createPlainBoletoRequest struct {
	SlipID      string `json:"slip_id"`
	AmountCents int64  `json:"amount_cents"`
	Currency    string `json:"currency"`
	DueDate     string `json:"due_date"`
	// FineBps e FineFixedCents são mutuamente exclusivos: o banco carrega UM valor
	// com UM tipo.
	FineBps            int64                 `json:"fine_bps"`
	FineFixedCents     int64                 `json:"fine_fixed_cents"`
	MonthlyInterestBps int64                 `json:"monthly_interest_bps"`
	Discounts          []plainBoletoDiscount `json:"discounts"`
	Payer              plainBoletoPayerReq   `json:"payer"`
	Description        string                `json:"description"`
	Bank               string                `json:"bank"`
}

// handleCreatePlainBoleto emite um boleto simples (POST /v1/bank-slips → 201).
func (s *Server) handleCreatePlainBoleto(w http.ResponseWriter, r *http.Request) {
	tenantID := tenantFromContext(r.Context())
	idemKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if idemKey == "" {
		writeError(w, http.StatusBadRequest, "missing Idempotency-Key header")
		return
	}
	var req createPlainBoletoRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	due, ok := parseRFC3339(req.DueDate)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid or missing due_date (RFC3339)")
		return
	}
	nr, okBank := s.rebindBank(w, r, req.Bank)
	if !okBank {
		return
	}
	r = nr

	res, err := s.plainBoleto.CreatePlainBoleto(r.Context(), app.PlainBoletoInput{
		TenantID:           tenantID,
		SlipID:             req.SlipID,
		AmountCents:        req.AmountCents,
		Currency:           req.Currency,
		DueDate:            due,
		FineBps:            req.FineBps,
		FineFixedCents:     req.FineFixedCents,
		MonthlyInterestBps: req.MonthlyInterestBps,
		Discounts:          toDiscountTiers(req.Discounts),
		Payer:              req.Payer.toPort(),
		Description:        req.Description,
		IdempotencyKey:     idemKey,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toBoletoView(res, req.AmountCents))
}

// handleGetPlainBoleto reconcilia um boleto simples (GET /v1/bank-slips/{id} → 200).
//
// O {id} é o id FORTE do banco, devolvido na emissão — não a nossa referência externa.
func (s *Server) handleGetPlainBoleto(w http.ResponseWriter, r *http.Request) {
	res, err := s.plainBoleto.GetPlainBoleto(r.Context(),
		tenantFromContext(r.Context()), chi.URLParam(r, "id"))
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toBoletoView(res, res.AmountCents))
}

// updatePlainBoletoRequest é o corpo de PATCH /v1/bank-slips/{id}.
//
// Ponteiros porque a alteração é PARCIAL: um campo ausente quer dizer "deixa como
// está", nunca "zera". Um valor zero mandado como "sem mudança" pediria ao banco para
// tornar a cobrança gratuita.
type updatePlainBoletoRequest struct {
	AmountCents        *int64                `json:"amount_cents"`
	DueDate            *string               `json:"due_date"`
	FineBps            *int64                `json:"fine_bps"`
	FineFixedCents     *int64                `json:"fine_fixed_cents"`
	MonthlyInterestBps *int64                `json:"monthly_interest_bps"`
	Discounts          []plainBoletoDiscount `json:"discounts"`
	Bank               string                `json:"bank"`
}

// handleUpdatePlainBoleto altera um boleto simples (PATCH /v1/bank-slips/{id} → 200).
func (s *Server) handleUpdatePlainBoleto(w http.ResponseWriter, r *http.Request) {
	tenantID := tenantFromContext(r.Context())
	idemKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if idemKey == "" {
		writeError(w, http.StatusBadRequest, "missing Idempotency-Key header")
		return
	}
	var req updatePlainBoletoRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	in := app.PlainBoletoPatchInput{
		AmountCents:        req.AmountCents,
		FineBps:            req.FineBps,
		FineFixedCents:     req.FineFixedCents,
		MonthlyInterestBps: req.MonthlyInterestBps,
		Discounts:          toDiscountTiers(req.Discounts),
		IdempotencyKey:     idemKey,
	}
	if req.DueDate != nil {
		due, ok := parseRFC3339(*req.DueDate)
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid due_date (RFC3339)")
			return
		}
		in.DueDate = &due
	}
	nr, okBank := s.rebindBank(w, r, req.Bank)
	if !okBank {
		return
	}
	r = nr

	res, err := s.plainBoleto.UpdatePlainBoleto(r.Context(), tenantID, chi.URLParam(r, "id"), in)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toBoletoView(res, res.AmountCents))
}

// handleCancelPlainBoleto dá baixa num boleto simples
// (DELETE /v1/bank-slips/{id} → 204).
//
// O contrato do banco responde sem corpo, então não há estado para devolver: quem
// precisa do novo status lê de volta.
func (s *Server) handleCancelPlainBoleto(w http.ResponseWriter, r *http.Request) {
	if err := s.plainBoleto.CancelPlainBoleto(r.Context(),
		tenantFromContext(r.Context()), chi.URLParam(r, "id")); err != nil {
		writeDomainError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleGetPlainBoletoPDF renderiza o boleto simples para o pagador
// (GET /v1/bank-slips/{id}/pdf → 200).
func (s *Server) handleGetPlainBoletoPDF(w http.ResponseWriter, r *http.Request) {
	doc, err := s.plainBoleto.GetPlainBoletoPDF(r.Context(),
		tenantFromContext(r.Context()), chi.URLParam(r, "id"))
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeBoletoDocument(w, doc)
}

// writeBoletoDocument serve um boleto renderizado.
//
// O documento carrega PII do pagador (nome, CPF/CNPJ, endereço), então nenhum
// intermediário pode guardá-lo em cache.
func writeBoletoDocument(w http.ResponseWriter, doc ports.BoletoDocument) {
	contentType := doc.ContentType
	if contentType == "" {
		contentType = "application/pdf"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(doc.Content)))
	w.Header().Set("Content-Disposition", "inline; filename=\""+sanitizeFilename(doc.Filename)+"\"")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(doc.Content)
}

// --- Listagem das cobranças BolePix ----------------------------------------------

// boletoListView é a página de cobranças BolePix.
type boletoListView struct {
	Boletos    []boletoView `json:"boletos"`
	Page       int          `json:"page"`
	PageSize   int          `json:"page_size"`
	TotalItems int          `json:"total_items"`
	TotalPages int          `json:"total_pages"`
}

// handleListBoletos lista as cobranças BolePix emitidas (GET /v1/boletos → 200).
//
// Ao menos UM intervalo é obrigatório — `payment_date`, `due_date` ou `credit_date` —,
// cada um com as duas pontas e no máximo 60 dias. São perguntas diferentes ("o que foi
// pago", "o que vence", "o que cai na conta") e o banco as responde separadamente.
func (s *Server) handleListBoletos(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	in := app.ListBoletosInput{
		TenantID:            tenantFromContext(r.Context()),
		Status:              q.Get("status"),
		ExternalReferenceID: q.Get("external_reference_id"),
	}
	janelas := []struct {
		prefixo string
		de, ate *time.Time
	}{
		{"payment_date", &in.PaymentDateFrom, &in.PaymentDateTo},
		{"due_date", &in.DueDateFrom, &in.DueDateTo},
		{"credit_date", &in.CreditDateFrom, &in.CreditDateTo},
	}
	for _, j := range janelas {
		de, okDe := parseOptionalStmtDate(q.Get(j.prefixo + "_from"))
		ate, okAte := parseOptionalStmtDate(q.Get(j.prefixo + "_to"))
		if !okDe || !okAte {
			writeError(w, http.StatusBadRequest, "invalid "+j.prefixo+" range (YYYY-MM-DD)")
			return
		}
		*j.de, *j.ate = de, ate
	}
	page, ok := parseOptionalInt(q.Get("page"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid page")
		return
	}
	pageSize, ok := parseOptionalInt(q.Get("page_size"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid page_size")
		return
	}
	in.Page, in.PageSize = page, pageSize

	list, err := s.boleto.ListBoletos(r.Context(), in)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	views := make([]boletoView, 0, len(list.Boletos))
	for _, b := range list.Boletos {
		views = append(views, toBoletoView(b, b.AmountCents))
	}
	writeJSON(w, http.StatusOK, boletoListView{
		Boletos: views, Page: list.Page, PageSize: list.PageSize,
		TotalItems: list.TotalItems, TotalPages: list.TotalPages,
	})
}

// parseOptionalStmtDate lê uma data YYYY-MM-DD opcional. Ausente devolve o tempo zero
// com ok=true — é o que distingue "não filtre por esta janela" de "data inválida".
func parseOptionalStmtDate(raw string) (time.Time, bool) {
	if strings.TrimSpace(raw) == "" {
		return time.Time{}, true
	}
	return parseStmtDate(raw)
}

// --- Extrato de adquirência (transações e recebíveis) ----------------------------

// receivableView é uma parcela que o adquirente deve ao lojista.
//
// `fee` e `discount` chegam NEGATIVOS e assim ficam: são deduções, e inverter o sinal
// esconderia a direção do dinheiro.
type receivableView struct {
	ReceivableID     string `json:"receivable_id"`
	TransactionID    string `json:"transaction_id,omitempty"`
	LocalRef         string `json:"local_reference,omitempty"`
	BrandName        string `json:"brand_name,omitempty"`
	PaymentType      string `json:"payment_type,omitempty"`
	Type             string `json:"type,omitempty"`
	Status           string `json:"status,omitempty"`
	Origin           string `json:"origin,omitempty"`
	Installment      int    `json:"installment,omitempty"`
	Installments     int    `json:"installments,omitempty"`
	InterestType     string `json:"interest_type,omitempty"`
	GrossAmountCents int64  `json:"gross_amount_cents"`
	FeeCents         int64  `json:"fee_cents"`
	DiscountCents    int64  `json:"discount_cents"`
	NetAmountCents   int64  `json:"net_amount_cents"`
	// MDR vem do adquirente escalado por 100. O contrato NÃO diz se é percentual ou
	// valor, e o exemplo serve para os dois — por isso é transportado sem
	// interpretação, e nada aqui o usa para calcular nada.
	MDR             int64  `json:"mdr"`
	ExpectedDate    string `json:"expected_date,omitempty"`
	PaymentDate     string `json:"payment_date,omitempty"`
	TransactionTime string `json:"transaction_time,omitempty"`
}

func toReceivableView(rc ports.Receivable) receivableView {
	v := receivableView{
		ReceivableID: rc.ReceivableID, TransactionID: rc.TransactionID,
		LocalRef: rc.LocalRef, BrandName: rc.BrandName, PaymentType: rc.PaymentType,
		Type: rc.Type, Status: rc.Status, Origin: rc.Origin,
		Installment: rc.Installment, Installments: rc.Installments,
		InterestType:     rc.InterestType,
		GrossAmountCents: rc.GrossAmountCents, FeeCents: rc.FeeCents,
		DiscountCents: rc.DiscountCents, NetAmountCents: rc.NetAmountCents,
		MDR: rc.MDR,
	}
	if !rc.ExpectedDate.IsZero() {
		v.ExpectedDate = rc.ExpectedDate.UTC().Format(stmtDateFormat)
	}
	if !rc.PaymentDate.IsZero() {
		v.PaymentDate = rc.PaymentDate.UTC().Format(stmtDateFormat)
	}
	if !rc.TransactionTime.IsZero() {
		v.TransactionTime = rc.TransactionTime.UTC().Format(time.RFC3339)
	}
	return v
}

// cardTransactionView é uma autorização no adquirente.
//
// Não há nome do portador nem PAN mascarado: os dois vêm na resposta do banco, e não
// carregá-los é como eles nunca chegam a log, erro ou linha gravada (ADR-0008).
type cardTransactionView struct {
	ID            string `json:"id"`
	LocalRef      string `json:"local_reference,omitempty"`
	AuthCode      string `json:"authorization_code,omitempty"`
	AuthorizerRef string `json:"authorizer_reference,omitempty"`
	BrandName     string `json:"brand_name,omitempty"`
	PaymentType   string `json:"payment_type,omitempty"`
	Status        string `json:"status,omitempty"`
	Origin        string `json:"origin,omitempty"`
	EntryMode     string `json:"card_entry_mode,omitempty"`
	Installments  int    `json:"installments,omitempty"`
	InterestType  string `json:"interest_type,omitempty"`
	CurrencyCode  string `json:"currency_code,omitempty"`
	TerminalID    string `json:"terminal_id,omitempty"`
	FraudAnalysis string `json:"fraud_analysis,omitempty"`
	AmountCents   int64  `json:"amount_cents"`
	OccurredAt    string `json:"occurred_at,omitempty"`
}

func toCardTransactionView(tx ports.CardTransaction) cardTransactionView {
	v := cardTransactionView{
		ID: tx.ID, LocalRef: tx.LocalRef, AuthCode: tx.AuthCode,
		AuthorizerRef: tx.AuthorizerRef, BrandName: tx.BrandName,
		PaymentType: tx.PaymentType, Status: tx.Status, Origin: tx.Origin,
		EntryMode: tx.EntryMode, Installments: tx.Installments,
		InterestType: tx.InterestType, CurrencyCode: tx.CurrencyCode,
		TerminalID: tx.TerminalID, FraudAnalysis: tx.FraudAnalysis,
		AmountCents: tx.AmountCents,
	}
	if !tx.OccurredAt.IsZero() {
		v.OccurredAt = tx.OccurredAt.UTC().Format(time.RFC3339)
	}
	return v
}

// acquirerPageView é a paginação que o adquirente devolve. `items` é a contagem DESTA
// página, não um total geral — lê-lo como total subdeclara um extrato paginado.
type acquirerPageView struct {
	Page     int `json:"page"`
	LastPage int `json:"last_page"`
	Items    int `json:"items"`
}

type receivableListView struct {
	Receivables []receivableView `json:"receivables"`
	acquirerPageView
}

type cardTransactionListView struct {
	Transactions []cardTransactionView `json:"transactions"`
	acquirerPageView
}

// bindAcquirerWindow lê a janela do extrato de adquirência: `start_date` obrigatória,
// `end_date` opcional (o adquirente usa a de início nos dois extremos quando ela falta).
func bindAcquirerWindow(w http.ResponseWriter, r *http.Request) (app.AcquirerStatementInput, bool) {
	q := r.URL.Query()
	start, ok := parseStmtDate(q.Get("start_date"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid or missing start_date (YYYY-MM-DD)")
		return app.AcquirerStatementInput{}, false
	}
	end, ok := parseOptionalStmtDate(q.Get("end_date"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid end_date (YYYY-MM-DD)")
		return app.AcquirerStatementInput{}, false
	}
	page, ok := parseOptionalInt(q.Get("page"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid page")
		return app.AcquirerStatementInput{}, false
	}
	pageSize, ok := parseOptionalInt(q.Get("page_size"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid page_size")
		return app.AcquirerStatementInput{}, false
	}
	return app.AcquirerStatementInput{
		TenantID: tenantFromContext(r.Context()),
		Start:    start, End: end, Page: page, PageSize: pageSize,
	}, true
}

// handleListReceivables lista os recebíveis do adquirente
// (GET /v1/acquirer/receivables → 200).
//
// Recebível NÃO é transação: é uma parcela do LÍQUIDO que o adquirente vai pagar, em
// data futura, já descontados MDR e tarifa. O nosso razão liquida no BRUTO, e é nesta
// diferença que uma conciliação deixa de fechar.
func (s *Server) handleListReceivables(w http.ResponseWriter, r *http.Request) {
	in, ok := bindAcquirerWindow(w, r)
	if !ok {
		return
	}
	list, err := s.acquirer.ListReceivables(r.Context(), in)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	views := make([]receivableView, 0, len(list.Receivables))
	for _, rc := range list.Receivables {
		views = append(views, toReceivableView(rc))
	}
	writeJSON(w, http.StatusOK, receivableListView{
		Receivables: views,
		acquirerPageView: acquirerPageView{
			Page: list.Page, LastPage: list.LastPage, Items: list.Items,
		},
	})
}

// handleListCardTransactions lista as autorizações e cancelamentos do adquirente
// (GET /v1/acquirer/transactions → 200).
func (s *Server) handleListCardTransactions(w http.ResponseWriter, r *http.Request) {
	in, ok := bindAcquirerWindow(w, r)
	if !ok {
		return
	}
	list, err := s.acquirer.ListCardTransactions(r.Context(), in)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	views := make([]cardTransactionView, 0, len(list.Transactions))
	for _, tx := range list.Transactions {
		views = append(views, toCardTransactionView(tx))
	}
	writeJSON(w, http.StatusOK, cardTransactionListView{
		Transactions: views,
		acquirerPageView: acquirerPageView{
			Page: list.Page, LastPage: list.LastPage, Items: list.Items,
		},
	})
}

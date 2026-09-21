package app

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// As superfícies BACEN do PIX além de cob/cobv: locations de payload, PIX recebidos e
// suas devoluções, e lotes de cobrança com vencimento — mais a revisão e a listagem
// que faltavam em cob e cobv.
//
// # Nenhuma delas é faturada
//
// Diferente de criar uma cobrança, estas operações não passam por `resolvePriceOrFree`
// nem escrevem no razão. Não é esquecimento: preço por rota é decisão comercial, e
// ligar cobrança numa rota nova sem alguém decidir o preço criaria fatura silenciosa
// para todo integrador. Quando houver preço, o lugar de plugá-lo é aqui, do mesmo jeito
// que `PixService.CreateImmediateCharge` faz.
//
// # Todas conferem o tenant ativo primeiro
//
// É o mesmo portão deny-by-default do extrato e do agendamento. O tenant vem SEMPRE do
// chamador autenticado, nunca de parâmetro — nenhuma rota daqui aceita escolher de quem
// é o PIX que se lê ou se devolve (ameaça H1/P1).

// requireActiveTenantFor é o portão compartilhado pelos serviços deste arquivo.
func requireActiveTenantFor(ctx context.Context, tenants ports.TenantRepository, tenantID string) error {
	t, err := tenants.FindTenantByID(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("resolve tenant: %w", err)
	}
	if !t.Active() {
		return shared.NewValidationError("tenant", "tenant is not active")
	}
	return nil
}

// --- Revisão da cobrança imediata (PixService) ------------------------------------

// ReviseImmediateChargeInput é a entrada de uma revisão de cobrança imediata. Só os
// campos presentes são enviados: valor zero deixa o valor como está, expiração zero
// deixa o calendário como está.
//
// Não existe aqui o "criar sem txid" que a porta também oferece, e é de propósito: o
// txid das nossas cobranças nasce da âncora de idempotência, e é essa derivação que faz
// um reenvio acertar a mesma cobrança em vez de cobrar o comprador duas vezes. Deixar o
// banco escolher o txid jogaria isso fora — a porta existe porque o roteiro cobra o
// verbo, não porque o produto o queira.
type ReviseImmediateChargeInput struct {
	TenantID       string
	TxID           string
	AmountCents    int64
	ExpiresIn      time.Duration
	DebtorTaxID    string
	DebtorName     string
	CreditorKey    string
	IdempotencyKey string
}

// ReviseImmediateCharge emenda uma cobrança imediata já criada.
//
// É operação de DINHEIRO: mudar o valor de uma cobrança que o pagador já tem na mão
// muda o que ele vai pagar. Por isso o valor negativo é recusado aqui, antes do banco, e
// a revisão vazia também — uma revisão que não mandaria nada é campo perdido, e
// responder "ok" a ela relataria uma mudança que não aconteceu.
func (s *PixService) ReviseImmediateCharge(ctx context.Context, in ReviseImmediateChargeInput) (ports.PixChargeResult, error) {
	if s.reviser == nil {
		return ports.PixChargeResult{}, shared.ErrUnavailable
	}
	if err := requireActiveTenantFor(ctx, s.tenants, in.TenantID); err != nil {
		return ports.PixChargeResult{}, err
	}
	txID := strings.TrimSpace(in.TxID)
	if txID == "" {
		return ports.PixChargeResult{}, shared.NewValidationError("txid", "txid is required")
	}
	if in.AmountCents < 0 {
		return ports.PixChargeResult{}, shared.NewValidationError("amount_cents", "amount must not be negative")
	}
	if err := validateDebtor(in.DebtorTaxID, in.DebtorName); err != nil {
		return ports.PixChargeResult{}, err
	}
	if in.AmountCents == 0 && in.ExpiresIn <= 0 &&
		strings.TrimSpace(in.DebtorTaxID) == "" && strings.TrimSpace(in.CreditorKey) == "" {
		return ports.PixChargeResult{}, shared.NewValidationError("revision", "nothing to revise")
	}

	return s.reviser.ReviseImmediateCharge(ctx, in.TenantID, txID, ports.ChargeRequest{
		AmountCents:    in.AmountCents,
		DebtorTaxID:    strings.TrimSpace(in.DebtorTaxID),
		DebtorName:     strings.TrimSpace(in.DebtorName),
		CreditorKey:    strings.TrimSpace(in.CreditorKey),
		IdempotencyKey: in.IdempotencyKey,
	}, in.ExpiresIn)
}

// --- Revisão e listagem de cobv (PixDueChargeService) -----------------------------

// ReviseDueCharge emenda uma cobrança com vencimento registrada.
//
// É diferente de UpdateDueCharge, e a diferença é dinheiro: aquele manda o conjunto
// COMPLETO de parâmetros com PUT, que substitui; este manda só o que mudou, com PATCH.
// Usar um no lugar do outro apaga em silêncio os campos omitidos — a multa que o
// pagador já aceitou, o desconto que foi prometido.
func (s *PixDueChargeService) ReviseDueCharge(ctx context.Context, tenantID, txID string, in DueChargeInput) (ports.PixDueChargeResult, error) {
	if s.reviser == nil {
		return ports.PixDueChargeResult{}, shared.ErrUnavailable
	}
	if err := requireActiveTenantFor(ctx, s.tenants, tenantID); err != nil {
		return ports.PixDueChargeResult{}, err
	}
	txID = strings.TrimSpace(txID)
	if txID == "" {
		return ports.PixDueChargeResult{}, shared.NewValidationError("txid", "txid is required")
	}
	if in.AmountCents < 0 {
		return ports.PixDueChargeResult{}, shared.NewValidationError("amount_cents", "amount must not be negative")
	}
	return s.reviser.ReviseDueCharge(ctx, tenantID, txID, s.toRequest(in, txID))
}

// ListDueChargesInput é a janela de uma listagem de cobranças com vencimento.
type ListDueChargesInput struct {
	TenantID string
	Start    time.Time
	End      time.Time
	Page     int
	PageSize int
}

// ListDueCharges lista as cobranças com vencimento do tenant na janela pedida.
func (s *PixDueChargeService) ListDueCharges(ctx context.Context, in ListDueChargesInput) (ports.PixDueChargeList, error) {
	if s.lister == nil {
		return ports.PixDueChargeList{}, shared.ErrUnavailable
	}
	if err := requireActiveTenantFor(ctx, s.tenants, in.TenantID); err != nil {
		return ports.PixDueChargeList{}, err
	}
	if err := validatePixListWindow(in.Start, in.End, in.Page, in.PageSize); err != nil {
		return ports.PixDueChargeList{}, err
	}
	return s.lister.ListDueCharges(ctx, in.TenantID, ports.PixListFilter{
		Start: in.Start, End: in.End, Page: in.Page, PageSize: in.PageSize,
	})
}

// --- Locations de payload ---------------------------------------------------------

// PixLocationService gerencia as locations de payload: o QR endereçável que o PSP
// serve. Uma location existe INDEPENDENTEMENTE da cobrança, e é isso que permite
// imprimir um QR antes de a cobrança que vai ser servida por ele existir.
type PixLocationService struct {
	tenants   ports.TenantRepository
	locations ports.PixLocationProvider
}

// NewPixLocationService liga o serviço às portas.
func NewPixLocationService(d Deps) *PixLocationService {
	return &PixLocationService{tenants: d.Tenants, locations: d.PixLocation}
}

// CreateLocation cria uma location para o tipo de cobrança pedido ("cob" ou "cobv").
func (s *PixLocationService) CreateLocation(ctx context.Context, tenantID, tipoCob string) (ports.PixLocation, error) {
	if s.locations == nil {
		return ports.PixLocation{}, shared.ErrUnavailable
	}
	if err := requireActiveTenantFor(ctx, s.tenants, tenantID); err != nil {
		return ports.PixLocation{}, err
	}
	tipoCob = strings.ToLower(strings.TrimSpace(tipoCob))
	if tipoCob != "cob" && tipoCob != "cobv" {
		return ports.PixLocation{}, shared.NewValidationError("tipo_cob", "tipo_cob must be cob or cobv")
	}
	return s.locations.CreateLocation(ctx, tenantID, tipoCob)
}

// ListLocationsInput é a janela e os filtros de uma consulta de locations.
type ListLocationsInput struct {
	TenantID    string
	Start       time.Time
	End         time.Time
	TipoCob     string
	TxIDPresent *bool
	Page        int
	PageSize    int
}

// ListLocations lista as locations criadas na janela pedida.
func (s *PixLocationService) ListLocations(ctx context.Context, in ListLocationsInput) (ports.PixLocationList, error) {
	if s.locations == nil {
		return ports.PixLocationList{}, shared.ErrUnavailable
	}
	if err := requireActiveTenantFor(ctx, s.tenants, in.TenantID); err != nil {
		return ports.PixLocationList{}, err
	}
	if err := validatePixListWindow(in.Start, in.End, in.Page, in.PageSize); err != nil {
		return ports.PixLocationList{}, err
	}
	tipoCob := strings.ToLower(strings.TrimSpace(in.TipoCob))
	if tipoCob != "" && tipoCob != "cob" && tipoCob != "cobv" {
		return ports.PixLocationList{}, shared.NewValidationError("tipo_cob", "tipo_cob must be cob or cobv")
	}
	return s.locations.ListLocations(ctx, in.TenantID, ports.PixLocationFilter{
		Start: in.Start, End: in.End, TipoCob: tipoCob,
		TxIDPresent: in.TxIDPresent, Page: in.Page, PageSize: in.PageSize,
	})
}

// GetLocation lê uma location, incluindo a cobrança vinculada a ela.
func (s *PixLocationService) GetLocation(ctx context.Context, tenantID string, id int64) (ports.PixLocation, error) {
	if s.locations == nil {
		return ports.PixLocation{}, shared.ErrUnavailable
	}
	if err := requireActiveTenantFor(ctx, s.tenants, tenantID); err != nil {
		return ports.PixLocation{}, err
	}
	if id <= 0 {
		return ports.PixLocation{}, shared.NewValidationError("id", "location id must be positive")
	}
	return s.locations.GetLocation(ctx, tenantID, id)
}

// UnlinkLocationTxID desvincula a cobrança de uma location.
//
// Não cancela nada: o status da cobrança fica como está, ela só deixa de ser servida
// por aquele QR. Quem quiser cancelar usa o caminho da cobrança.
func (s *PixLocationService) UnlinkLocationTxID(ctx context.Context, tenantID string, id int64) (ports.PixLocation, error) {
	if s.locations == nil {
		return ports.PixLocation{}, shared.ErrUnavailable
	}
	if err := requireActiveTenantFor(ctx, s.tenants, tenantID); err != nil {
		return ports.PixLocation{}, err
	}
	if id <= 0 {
		return ports.PixLocation{}, shared.NewValidationError("id", "location id must be positive")
	}
	return s.locations.UnlinkLocationTxID(ctx, tenantID, id)
}

// --- PIX recebidos e devolução ----------------------------------------------------

// PixReceivedService lê os PIX creditados na conta e solicita devolução.
//
// A devolução é a ÚNICA operação de todo este arquivo que move dinheiro, e o desenho
// reflete isso: o id da devolução é de quem chama, o valor é obrigatório e explícito, e
// nada aqui devolve "o PIX inteiro" por omissão.
type PixReceivedService struct {
	tenants  ports.TenantRepository
	received ports.PixReceivedProvider
}

// NewPixReceivedService liga o serviço às portas.
func NewPixReceivedService(d Deps) *PixReceivedService {
	return &PixReceivedService{tenants: d.Tenants, received: d.PixReceived}
}

// GetReceivedPix lê um PIX recebido pelo seu end-to-end id.
func (s *PixReceivedService) GetReceivedPix(ctx context.Context, tenantID, endToEndID string) (ports.ReceivedPix, error) {
	if s.received == nil {
		return ports.ReceivedPix{}, shared.ErrUnavailable
	}
	if err := requireActiveTenantFor(ctx, s.tenants, tenantID); err != nil {
		return ports.ReceivedPix{}, err
	}
	endToEndID = strings.TrimSpace(endToEndID)
	if endToEndID == "" {
		return ports.ReceivedPix{}, shared.NewValidationError("e2eid", "end-to-end id is required")
	}
	return s.received.GetReceivedPix(ctx, tenantID, endToEndID)
}

// ListReceivedPixInput é a janela e os filtros de uma consulta de PIX recebidos.
type ListReceivedPixInput struct {
	TenantID      string
	Start         time.Time
	End           time.Time
	TxID          string
	TxIDPresent   *bool
	RefundPresent *bool
	PayerTaxID    string
	Page          int
	PageSize      int
}

// ListReceivedPix lista os PIX creditados na janela pedida.
func (s *PixReceivedService) ListReceivedPix(ctx context.Context, in ListReceivedPixInput) (ports.ReceivedPixList, error) {
	if s.received == nil {
		return ports.ReceivedPixList{}, shared.ErrUnavailable
	}
	if err := requireActiveTenantFor(ctx, s.tenants, in.TenantID); err != nil {
		return ports.ReceivedPixList{}, err
	}
	if err := validatePixListWindow(in.Start, in.End, in.Page, in.PageSize); err != nil {
		return ports.ReceivedPixList{}, err
	}
	if taxID := strings.TrimSpace(in.PayerTaxID); taxID != "" && !validTaxID(taxID) {
		return ports.ReceivedPixList{}, shared.NewValidationError("payer_tax_id",
			"payer tax id must be 11 (CPF) or 14 (CNPJ) digits")
	}
	return s.received.ListReceivedPix(ctx, in.TenantID, ports.ReceivedPixFilter{
		Start: in.Start, End: in.End,
		TxID:        strings.TrimSpace(in.TxID),
		TxIDPresent: in.TxIDPresent, RefundPresent: in.RefundPresent,
		PayerTaxID: strings.TrimSpace(in.PayerTaxID),
		Page:       in.Page, PageSize: in.PageSize,
	})
}

// RequestRefundInput é o pedido de devolução de um PIX recebido.
//
// RefundID é de QUEM CHAMA, e é o que torna a operação idempotente: o par
// (e2eid, refundID) endereça sempre a mesma devolução, então um reenvio não devolve
// duas vezes. Um id aleatório por tentativa desfaz exatamente essa garantia — por isso
// ele é obrigatório aqui e não é gerado internamente.
type RequestRefundInput struct {
	TenantID    string
	EndToEndID  string
	RefundID    string
	AmountCents int64
	Nature      string
	Description string
}

// RequestRefund solicita a devolução, total ou parcial, de um PIX recebido.
func (s *PixReceivedService) RequestRefund(ctx context.Context, in RequestRefundInput) (ports.PixRefund, error) {
	if s.received == nil {
		return ports.PixRefund{}, shared.ErrUnavailable
	}
	if err := requireActiveTenantFor(ctx, s.tenants, in.TenantID); err != nil {
		return ports.PixRefund{}, err
	}
	e2e := strings.TrimSpace(in.EndToEndID)
	refundID := strings.TrimSpace(in.RefundID)
	if e2e == "" {
		return ports.PixRefund{}, shared.NewValidationError("e2eid", "end-to-end id is required")
	}
	if refundID == "" {
		return ports.PixRefund{}, shared.NewValidationError("refund_id", "refund id is required")
	}
	if in.AmountCents <= 0 {
		// Não existe devolução de zero, e uma negativa seria um pagamento.
		return ports.PixRefund{}, shared.NewValidationError("amount_cents", "refund amount must be greater than zero")
	}
	nature, err := parseRefundNature(in.Nature)
	if err != nil {
		return ports.PixRefund{}, err
	}
	return s.received.RequestRefund(ctx, in.TenantID, e2e, refundID, ports.PixRefundRequest{
		AmountCents: in.AmountCents,
		Nature:      nature,
		Description: strings.TrimSpace(in.Description),
	})
}

// parseRefundNature valida a natureza da devolução. Vazio é aceito: o contrato assume
// ORIGINAL quando o campo é omitido, e repetir esse padrão aqui evita que a omissão
// vire uma escolha nossa.
func parseRefundNature(s string) (ports.PixRefundNature, error) {
	switch ports.PixRefundNature(strings.ToUpper(strings.TrimSpace(s))) {
	case "":
		return "", nil
	case ports.RefundOriginal:
		return ports.RefundOriginal, nil
	case ports.RefundWithdrawal:
		return ports.RefundWithdrawal, nil
	case ports.RefundMEDOperational:
		return ports.RefundMEDOperational, nil
	case ports.RefundMEDFraud:
		return ports.RefundMEDFraud, nil
	default:
		return "", shared.NewValidationError("nature", "unknown refund nature")
	}
}

// GetRefund lê o estado autoritativo de uma devolução.
//
// É aqui que se descobre se o dinheiro saiu: a criação responde que o PSP ACEITOU o
// pedido, e o status pode continuar EM_PROCESSAMENTO depois disso.
func (s *PixReceivedService) GetRefund(ctx context.Context, tenantID, endToEndID, refundID string) (ports.PixRefund, error) {
	if s.received == nil {
		return ports.PixRefund{}, shared.ErrUnavailable
	}
	if err := requireActiveTenantFor(ctx, s.tenants, tenantID); err != nil {
		return ports.PixRefund{}, err
	}
	endToEndID = strings.TrimSpace(endToEndID)
	refundID = strings.TrimSpace(refundID)
	if endToEndID == "" || refundID == "" {
		return ports.PixRefund{}, shared.NewValidationError("refund", "end-to-end id and refund id are required")
	}
	return s.received.GetRefund(ctx, tenantID, endToEndID, refundID)
}

// --- Lotes de cobrança com vencimento ---------------------------------------------

// maxBatchCharges limita quantas cobranças um lote pode carregar numa requisição.
// Sem teto, um corpo grande viraria um lote arbitrariamente grande no PSP.
const maxBatchCharges = 200

// PixBatchService cria e lê lotes de cobrança com vencimento.
//
// As escritas respondem "aceito", não "criado": o PSP processa o lote depois. Por isso
// elas não devolvem lote nenhum — quem precisa do resultado por cobrança lê o lote de
// volta. Tratar o aceite como "as cobranças existem" é a forma de errar aqui.
type PixBatchService struct {
	tenants ports.TenantRepository
	batches ports.PixDueChargeBatchProvider
	cobv    *PixDueChargeService
}

// NewPixBatchService liga o serviço às portas. Reaproveita o PixDueChargeService para
// montar cada cobrança do lote com as MESMAS validações de uma cobv avulsa — um lote
// não é lugar para regra mais frouxa.
func NewPixBatchService(d Deps) *PixBatchService {
	return &PixBatchService{
		tenants: d.Tenants,
		batches: d.PixDueChargeBatch,
		cobv:    NewPixDueChargeService(d),
	}
}

// BatchChargeInput é uma cobrança dentro de um lote: a mesma entrada de uma cobv
// avulsa, mais o txid.
//
// O txid é explícito aqui, e só aqui. Numa cobv avulsa ele é DERIVADO da âncora de
// idempotência, e é essa derivação que faz um reenvio acertar a mesma cobrança. Num
// lote não dá: o PSP endereça cada cobrança do lote pelo txid que veio no corpo, e é
// por ele que o resultado de cada uma volta.
type BatchChargeInput struct {
	TxID string
	DueChargeInput
}

// BatchInput é a criação ou revisão de um lote.
type BatchInput struct {
	TenantID    string
	BatchID     string
	Description string
	Charges     []BatchChargeInput
}

// CreateBatch registra ou altera um lote de cobranças com vencimento.
func (s *PixBatchService) CreateBatch(ctx context.Context, in BatchInput) error {
	return s.write(ctx, in, false)
}

// ReviseBatch revisa cobranças dentro de um lote existente.
//
// A revisão só pode MANTER o conjunto original de cobranças: acrescentar ou remover uma
// não é revisão, e o PSP recusa.
func (s *PixBatchService) ReviseBatch(ctx context.Context, in BatchInput) error {
	return s.write(ctx, in, true)
}

func (s *PixBatchService) write(ctx context.Context, in BatchInput, revisao bool) error {
	if s.batches == nil {
		return shared.ErrUnavailable
	}
	if err := requireActiveTenantFor(ctx, s.tenants, in.TenantID); err != nil {
		return err
	}
	batchID := strings.TrimSpace(in.BatchID)
	description := strings.TrimSpace(in.Description)
	if batchID == "" {
		return shared.NewValidationError("batch_id", "batch id is required")
	}
	if description == "" {
		return shared.NewValidationError("description", "description is required")
	}
	if len(in.Charges) == 0 {
		return shared.NewValidationError("charges", "at least one charge is required")
	}
	if len(in.Charges) > maxBatchCharges {
		return shared.NewValidationError("charges", "too many charges in a single batch")
	}

	reqs := make([]ports.PixDueChargeRequest, len(in.Charges))
	for i, c := range in.Charges {
		txID := strings.TrimSpace(c.TxID)
		if txID == "" {
			// O lote endereça suas cobranças por txid. Um em branco derrubaria uma
			// cobrança que quem chamou acredita ter enviado, em silêncio.
			return shared.NewValidationError("charges.txid", "every charge in a batch needs its own txid")
		}
		principal, err := shared.NewMoney(c.AmountCents, c.Currency)
		if err != nil {
			return err
		}
		if err := s.cobv.validateDueCharge(c.DueChargeInput, principal); err != nil {
			return err
		}
		reqs[i] = s.cobv.toRequest(c.DueChargeInput, txID)
	}

	if revisao {
		return s.batches.ReviseBatch(ctx, in.TenantID, batchID, description, reqs)
	}
	return s.batches.CreateBatch(ctx, in.TenantID, batchID, description, reqs)
}

// GetBatch lê o estado autoritativo de um lote, cobrança a cobrança. É o único lugar
// onde o resultado de um registro em lote aparece.
func (s *PixBatchService) GetBatch(ctx context.Context, tenantID, batchID string) (ports.PixDueChargeBatch, error) {
	if s.batches == nil {
		return ports.PixDueChargeBatch{}, shared.ErrUnavailable
	}
	if err := requireActiveTenantFor(ctx, s.tenants, tenantID); err != nil {
		return ports.PixDueChargeBatch{}, err
	}
	batchID = strings.TrimSpace(batchID)
	if batchID == "" {
		return ports.PixDueChargeBatch{}, shared.NewValidationError("batch_id", "batch id is required")
	}
	return s.batches.GetBatch(ctx, tenantID, batchID)
}

// ListBatchesInput é a janela de uma listagem de lotes.
type ListBatchesInput struct {
	TenantID string
	Start    time.Time
	End      time.Time
	Page     int
	PageSize int
}

// ListBatches lista os lotes criados na janela pedida.
func (s *PixBatchService) ListBatches(ctx context.Context, in ListBatchesInput) (ports.PixDueChargeBatchList, error) {
	if s.batches == nil {
		return ports.PixDueChargeBatchList{}, shared.ErrUnavailable
	}
	if err := requireActiveTenantFor(ctx, s.tenants, in.TenantID); err != nil {
		return ports.PixDueChargeBatchList{}, err
	}
	if err := validatePixListWindow(in.Start, in.End, in.Page, in.PageSize); err != nil {
		return ports.PixDueChargeBatchList{}, err
	}
	return s.batches.ListBatches(ctx, in.TenantID, ports.PixDueChargeBatchFilter{
		Start: in.Start, End: in.End, Page: in.Page, PageSize: in.PageSize,
	})
}

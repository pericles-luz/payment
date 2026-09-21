package app

import (
	"context"
	"strings"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// PlainBoletoService emite e administra o BOLETO SIMPLES — produto diferente do
// BolePix, ainda que os dois se chamem "boleto".
//
// O que difere, e por que existe uma porta separada, está em ports.PlainBoletoProvider.
// O resumo: o boleto simples aceita ATÉ TRÊS faixas de desconto (o BolePix expõe uma
// só), a multa e os juros têm forma própria, o endereço do pagador é outro, a
// referência externa cabe em 10 caracteres em vez de 26 — e ele não emite QR.
//
// # Ele NÃO cria cobrança no nosso razão, e isso é limitação, não descuido
//
// `BoletoService.RegisterBoleto` reserva um `payment` antes de chamar o banco e grava
// o razão junto do id da cobrança, atomicamente. É isso que permite a liquidação: o
// aviso do banco chega, a cobrança é reconciliada pela referência externa e o
// pagamento liquida.
//
// Este serviço não faz nada disso. Ele é a superfície CRUA do banco: emite, lê, altera,
// baixa e renderiza. Um boleto emitido por aqui não liquida sozinho no nosso lado.
//
// Fazer diferente exigiria uma decisão que não cabe num acréscimo de rota: ou este
// caminho passa a reservar `payment` como o BolePix — e aí precisa de preço, de razão e
// de um caminho de liquidação que saiba distinguir uma referência de 10 caracteres de
// uma de 26 —, ou o `/v1/boletos` existente passa a rotear por modalidade, o que muda em
// silêncio o que já está em produção. As duas são migração, não endpoint novo.
type PlainBoletoService struct {
	tenants ports.TenantRepository
	slips   ports.PlainBoletoProvider
}

// NewPlainBoletoService liga o serviço às portas.
func NewPlainBoletoService(d Deps) *PlainBoletoService {
	return &PlainBoletoService{tenants: d.Tenants, slips: d.PlainBoleto}
}

// PlainBoletoInput é a emissão de um boleto simples.
//
// SlipID é o identificador de quem chama: é dele que nasce a referência externa que o
// banco guarda, de forma determinística, então reenviar o mesmo id endereça a mesma
// referência em vez de emitir um segundo boleto.
type PlainBoletoInput struct {
	TenantID    string
	SlipID      string
	AmountCents int64
	Currency    string
	DueDate     time.Time
	// FineBps e FineFixedCents são mutuamente exclusivos: o banco carrega UM valor
	// com UM tipo, então mandar os dois não tem tradução certa.
	FineBps            int64
	FineFixedCents     int64
	MonthlyInterestBps int64
	// Discounts são até três faixas de desconto por antecipação, em prazos
	// ESTRITAMENTE decrescentes e todas na mesma forma (percentual ou valor). É a
	// capacidade que só este produto tem.
	Discounts      []ports.BoletoDiscountTier
	Payer          ports.BoletoPayer
	Description    string
	IdempotencyKey string
}

// maxPlainDiscountTiers é quantas faixas de desconto o produto carrega.
const maxPlainDiscountTiers = 3

// CreatePlainBoleto emite um boleto simples.
func (s *PlainBoletoService) CreatePlainBoleto(ctx context.Context, in PlainBoletoInput) (ports.BoletoResult, error) {
	if s.slips == nil {
		return ports.BoletoResult{}, shared.ErrUnavailable
	}
	if err := requireActiveTenantFor(ctx, s.tenants, in.TenantID); err != nil {
		return ports.BoletoResult{}, err
	}
	slipID := strings.TrimSpace(in.SlipID)
	if slipID == "" {
		return ports.BoletoResult{}, shared.NewValidationError("slip_id", "slip id is required")
	}
	if _, err := shared.NewMoney(in.AmountCents, in.Currency); err != nil {
		return ports.BoletoResult{}, err
	}
	if in.DueDate.IsZero() {
		return ports.BoletoResult{}, shared.NewValidationError("due_date", "due date is required")
	}
	if in.FineBps > 0 && in.FineFixedCents > 0 {
		return ports.BoletoResult{}, shared.NewValidationError("fine",
			"fine must be either a percentage or a fixed amount, never both")
	}
	if err := validatePlainDiscounts(in.Discounts); err != nil {
		return ports.BoletoResult{}, err
	}

	return s.slips.CreatePlainBoleto(ctx, in.TenantID, ports.BoletoRequest{
		TenantID:           in.TenantID,
		BoletoID:           slipID,
		AmountCents:        in.AmountCents,
		Currency:           in.Currency,
		DueDate:            in.DueDate,
		FineBps:            in.FineBps,
		FineFixedCents:     in.FineFixedCents,
		MonthlyInterestBps: in.MonthlyInterestBps,
		Discounts:          in.Discounts,
		Payer:              in.Payer,
		Description:        in.Description,
		IdempotencyKey:     in.IdempotencyKey,
		Modality:           ports.ModalityBoleto,
	})
}

// validatePlainDiscounts confere o que o banco exige do escalonamento: no máximo três
// faixas, todas na mesma forma, com prazos estritamente decrescentes.
//
// Misturar percentual com valor fixo é recusado aqui e não lá porque o banco não recusa
// de forma clara — ele aplica o tipo errado a alguma faixa, e o pagador paga a
// diferença.
func validatePlainDiscounts(tiers []ports.BoletoDiscountTier) error {
	if len(tiers) == 0 {
		return nil
	}
	if len(tiers) > maxPlainDiscountTiers {
		return shared.NewValidationError("discounts", "at most three discount tiers")
	}
	var percent, fixed bool
	prev := -1
	for _, t := range tiers {
		switch {
		case t.Bps > 0 && t.FixedCents > 0:
			return shared.NewValidationError("discounts",
				"a tier is either a percentage or a fixed amount, never both")
		case t.Bps > 0:
			percent = true
		case t.FixedCents > 0:
			fixed = true
		default:
			return shared.NewValidationError("discounts", "a tier worth nothing is not a discount")
		}
		if t.DaysBeforeDue < 0 {
			return shared.NewValidationError("discounts", "days before due must not be negative")
		}
		if prev >= 0 && t.DaysBeforeDue >= prev {
			return shared.NewValidationError("discounts",
				"tiers must be ordered with strictly decreasing days before due")
		}
		prev = t.DaysBeforeDue
	}
	if percent && fixed {
		return shared.NewValidationError("discounts",
			"every tier must use the same form: all percentages or all fixed amounts")
	}
	return nil
}

// GetPlainBoleto reconcilia o estado de um boleto simples registrado. slipID é o id
// FORTE do banco, devolvido na emissão — não a nossa referência externa.
func (s *PlainBoletoService) GetPlainBoleto(ctx context.Context, tenantID, slipID string) (ports.BoletoResult, error) {
	if s.slips == nil {
		return ports.BoletoResult{}, shared.ErrUnavailable
	}
	if err := requireActiveTenantFor(ctx, s.tenants, tenantID); err != nil {
		return ports.BoletoResult{}, err
	}
	slipID = strings.TrimSpace(slipID)
	if slipID == "" {
		return ports.BoletoResult{}, shared.NewValidationError("slip_id", "slip id is required")
	}
	return s.slips.GetPlainBoleto(ctx, tenantID, slipID)
}

// PlainBoletoPatchInput é uma alteração PARCIAL: um campo nil quer dizer "deixa como
// está", nunca "zera".
//
// Ponteiros, e não valores, porque as duas coisas não se distinguem de outro jeito e a
// diferença é dinheiro — um valor zero mandado como "sem mudança" pediria ao banco para
// tornar a cobrança gratuita.
type PlainBoletoPatchInput struct {
	AmountCents        *int64
	DueDate            *time.Time
	FineBps            *int64
	FineFixedCents     *int64
	MonthlyInterestBps *int64
	Discounts          []ports.BoletoDiscountTier
	IdempotencyKey     string
}

// UpdatePlainBoleto altera um boleto simples registrado. O contrato admite valor, data
// de vencimento e os blocos de encargo; uma alteração que só toque o resto é recusada
// aqui, em vez de virar um corpo vazio que o banco rejeita sem dizer o porquê.
func (s *PlainBoletoService) UpdatePlainBoleto(ctx context.Context, tenantID, slipID string, in PlainBoletoPatchInput) (ports.BoletoResult, error) {
	if s.slips == nil {
		return ports.BoletoResult{}, shared.ErrUnavailable
	}
	if err := requireActiveTenantFor(ctx, s.tenants, tenantID); err != nil {
		return ports.BoletoResult{}, err
	}
	slipID = strings.TrimSpace(slipID)
	if slipID == "" {
		return ports.BoletoResult{}, shared.NewValidationError("slip_id", "slip id is required")
	}
	if in.AmountCents != nil && *in.AmountCents <= 0 {
		return ports.BoletoResult{}, shared.NewValidationError("amount_cents", "amount must be greater than zero")
	}
	if in.DueDate != nil && in.DueDate.IsZero() {
		return ports.BoletoResult{}, shared.NewValidationError("due_date", "due date must be a real date")
	}
	if err := validatePlainDiscounts(in.Discounts); err != nil {
		return ports.BoletoResult{}, err
	}

	patch := ports.BoletoPatch{
		AmountCents:    in.AmountCents,
		DueDate:        in.DueDate,
		IdempotencyKey: in.IdempotencyKey,
	}
	// O banco substitui o objeto de encargos INTEIRO em vez de mesclar nele, então
	// quem toca em um encargo tem de declarar o quadro completo — deixar um de fora o
	// apagaria, mudando em silêncio o que o pagador deve.
	if in.FineBps != nil || in.FineFixedCents != nil || in.MonthlyInterestBps != nil || len(in.Discounts) > 0 {
		fees := ports.BoletoFeesPatch{Discounts: in.Discounts}
		if in.FineBps != nil {
			fees.FineBps = *in.FineBps
		}
		if in.FineFixedCents != nil {
			fees.FineFixedCents = *in.FineFixedCents
		}
		if in.MonthlyInterestBps != nil {
			fees.MonthlyInterestBps = *in.MonthlyInterestBps
		}
		if fees.FineBps > 0 && fees.FineFixedCents > 0 {
			return ports.BoletoResult{}, shared.NewValidationError("fine",
				"fine must be either a percentage or a fixed amount, never both")
		}
		patch.Fees = &fees
	}
	if patch.AmountCents == nil && patch.DueDate == nil && patch.Fees == nil {
		return ports.BoletoResult{}, shared.NewValidationError("patch", "nothing to update")
	}
	return s.slips.UpdatePlainBoleto(ctx, tenantID, slipID, patch)
}

// CancelPlainBoleto dá baixa num boleto simples registrado. O contrato responde sem
// corpo, então não há estado para devolver — quem precisa do novo status lê de volta.
func (s *PlainBoletoService) CancelPlainBoleto(ctx context.Context, tenantID, slipID string) error {
	if s.slips == nil {
		return shared.ErrUnavailable
	}
	if err := requireActiveTenantFor(ctx, s.tenants, tenantID); err != nil {
		return err
	}
	slipID = strings.TrimSpace(slipID)
	if slipID == "" {
		return shared.NewValidationError("slip_id", "slip id is required")
	}
	return s.slips.CancelPlainBoleto(ctx, tenantID, slipID)
}

// GetPlainBoletoPDF renderiza o boleto para o pagador.
func (s *PlainBoletoService) GetPlainBoletoPDF(ctx context.Context, tenantID, slipID string) (ports.BoletoDocument, error) {
	if s.slips == nil {
		return ports.BoletoDocument{}, shared.ErrUnavailable
	}
	if err := requireActiveTenantFor(ctx, s.tenants, tenantID); err != nil {
		return ports.BoletoDocument{}, err
	}
	slipID = strings.TrimSpace(slipID)
	if slipID == "" {
		return ports.BoletoDocument{}, shared.NewValidationError("slip_id", "slip id is required")
	}
	return s.slips.GetPlainBoletoPDF(ctx, tenantID, slipID)
}

// --- Listagem das cobranças BolePix (BoletoService) -------------------------------

// ListBoletosInput é a consulta de cobranças BolePix emitidas.
//
// Ao menos UM intervalo é obrigatório — pagamento, vencimento ou crédito —, cada um de
// no máximo 60 dias. Os três são perguntas diferentes ("o que foi pago", "o que vence",
// "o que cai na conta") e o banco as responde separadamente.
type ListBoletosInput struct {
	TenantID            string
	PaymentDateFrom     time.Time
	PaymentDateTo       time.Time
	DueDateFrom         time.Time
	DueDateTo           time.Time
	CreditDateFrom      time.Time
	CreditDateTo        time.Time
	Status              string
	ExternalReferenceID string
	Page                int
	PageSize            int
}

// maxBoletoListWindow é o intervalo mais largo que a listagem aceita.
const maxBoletoListWindow = 60 * 24 * time.Hour

// ListBoletos lista as cobranças BolePix emitidas pelo tenant.
func (s *BoletoService) ListBoletos(ctx context.Context, in ListBoletosInput) (ports.BoletoList, error) {
	if s.lister == nil {
		return ports.BoletoList{}, shared.ErrUnavailable
	}
	if err := requireActiveTenantFor(ctx, s.tenants, in.TenantID); err != nil {
		return ports.BoletoList{}, err
	}
	intervalos := [][2]time.Time{
		{in.PaymentDateFrom, in.PaymentDateTo},
		{in.DueDateFrom, in.DueDateTo},
		{in.CreditDateFrom, in.CreditDateTo},
	}
	algum := false
	for _, iv := range intervalos {
		de, ate := iv[0], iv[1]
		if de.IsZero() && ate.IsZero() {
			continue
		}
		// Intervalo meio-aberto é recusado: o banco responderia alguma coisa, e não
		// seria a janela que se quis.
		if de.IsZero() || ate.IsZero() || ate.Before(de) {
			return ports.BoletoList{}, shared.NewValidationError("range", "both ends of a date range are required")
		}
		if ate.Sub(de) > maxBoletoListWindow {
			return ports.BoletoList{}, shared.NewValidationError("range", "date range too large")
		}
		algum = true
	}
	if !algum {
		return ports.BoletoList{}, shared.NewValidationError("range",
			"at least one date range is required (payment, due or credit)")
	}
	if in.Page < 0 || in.PageSize < 0 {
		return ports.BoletoList{}, shared.NewValidationError("pagination", "page and page_size must not be negative")
	}

	return s.lister.ListBoletos(ctx, in.TenantID, ports.BoletoListFilter{
		PaymentDateFrom: in.PaymentDateFrom, PaymentDateTo: in.PaymentDateTo,
		DueDateFrom: in.DueDateFrom, DueDateTo: in.DueDateTo,
		CreditDateFrom: in.CreditDateFrom, CreditDateTo: in.CreditDateTo,
		Status:              strings.ToUpper(strings.TrimSpace(in.Status)),
		ExternalReferenceID: strings.TrimSpace(in.ExternalReferenceID),
		Page:                in.Page, PageSize: in.PageSize,
	})
}

package app

import (
	"context"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// maxAcquirerWindow é a janela mais larga que o extrato de adquirência aceita por
// requisição.
const maxAcquirerWindow = 60 * 24 * time.Hour

// AcquirerStatementService lê o extrato de adquirência: as TRANSAÇÕES que o terminal
// ou o checkout autorizaram, e os RECEBÍVEIS em que elas se liquidam.
//
// São duas leituras sobre a mesma janela e NÃO são o mesmo dinheiro. A transação é o
// bruto autorizado, de uma vez. O recebível é uma parcela do que o adquirente vai
// realmente pagar ao lojista, em data futura, já descontados o MDR e a tarifa por
// venda. O nosso razão liquida no BRUTO; a conta do lojista recebe o LÍQUIDO — e essa
// diferença é real (R$ 30,00 autorizados chegam como R$ 28,39, conforme
// docs/compliance/c6pay-recebiveis-notas.md). Este serviço é onde ela fica visível, em
// vez de aparecer numa conciliação que não fecha.
//
// Como as outras leituras de banco, não é faturado e o tenant vem sempre do chamador
// autenticado (ameaça H1/P1).
type AcquirerStatementService struct {
	tenants  ports.TenantRepository
	acquirer ports.AcquirerStatementProvider
}

// NewAcquirerStatementService liga o serviço às portas.
func NewAcquirerStatementService(d Deps) *AcquirerStatementService {
	return &AcquirerStatementService{tenants: d.Tenants, acquirer: d.AcquirerStatement}
}

// AcquirerStatementInput é a janela de uma consulta de extrato de adquirência.
//
// End vazio significa "o mesmo dia de Start", que é o padrão do próprio adquirente —
// repetido aqui para a omissão não virar uma escolha nossa.
type AcquirerStatementInput struct {
	TenantID string
	Start    time.Time
	End      time.Time
	Page     int
	PageSize int
}

// validate confere a janela antes de chamar o banco, para um erro de parâmetro voltar
// como 400 tipado em vez de um 400 opaco do adquirente.
func (in AcquirerStatementInput) validate() error {
	if in.Start.IsZero() {
		return shared.NewValidationError("start", "start date is required")
	}
	if !in.End.IsZero() {
		if in.End.Before(in.Start) {
			return shared.NewValidationError("end", "end must not be before start")
		}
		if in.End.Sub(in.Start) > maxAcquirerWindow {
			return shared.NewValidationError("range", "date range too large")
		}
	}
	if in.Page < 0 || in.PageSize < 0 {
		return shared.NewValidationError("pagination", "page and page_size must not be negative")
	}
	return nil
}

func (in AcquirerStatementInput) filter() ports.AcquirerStatementFilter {
	return ports.AcquirerStatementFilter{
		Start: in.Start, End: in.End, Page: in.Page, PageSize: in.PageSize,
	}
}

// ListReceivables lista os recebíveis agendados ou liquidados na janela pedida.
func (s *AcquirerStatementService) ListReceivables(ctx context.Context, in AcquirerStatementInput) (ports.ReceivableList, error) {
	if s.acquirer == nil {
		return ports.ReceivableList{}, shared.ErrUnavailable
	}
	if err := requireActiveTenantFor(ctx, s.tenants, in.TenantID); err != nil {
		return ports.ReceivableList{}, err
	}
	if err := in.validate(); err != nil {
		return ports.ReceivableList{}, err
	}
	return s.acquirer.ListReceivables(ctx, in.TenantID, in.filter())
}

// ListCardTransactions lista as autorizações e cancelamentos na janela pedida.
func (s *AcquirerStatementService) ListCardTransactions(ctx context.Context, in AcquirerStatementInput) (ports.CardTransactionList, error) {
	if s.acquirer == nil {
		return ports.CardTransactionList{}, shared.ErrUnavailable
	}
	if err := requireActiveTenantFor(ctx, s.tenants, in.TenantID); err != nil {
		return ports.CardTransactionList{}, err
	}
	if err := in.validate(); err != nil {
		return ports.CardTransactionList{}, err
	}
	return s.acquirer.ListCardTransactions(ctx, in.TenantID, in.filter())
}

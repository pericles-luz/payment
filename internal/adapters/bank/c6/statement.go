package c6

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// Account-statement (extrato) support for the C6 adapter (roteiro grupo 13).
//
// GetStatement reads the entries posted to the tenant's account within a date window
// (inicio/fim, máx. 30 dias). It lives here so the use-case never speaks HTTP/JSON or
// knows the PSP wire shape (Hexagonal).
//
// A forma abaixo é a que o C6 manda DE VERDADE em produção, capturada no fio em
// 02/09/2026. Antes daqui, o adaptador lia um "contrato interno limpo" (id, date,
// amount_cents, kind) que a Camada A usava como dublê e que a Camada B ia traduzir
// contra homologação. A tradução nunca chegou à produção, e o resultado era pior do que
// não existir: os campos caíam TODOS zerados, `kind` vazio reprovava na revalidação de
// domínio, e a rota devolvia 400 em qualquer janela de datas. Um extrato que nunca
// funcionou, falhando como se o pedido do cliente estivesse errado.
//
// Nenhum campo tinha o mesmo nome, exceto `entries` e `description`:
//
//	id           →  external_id
//	date         →  entry_date (data civil, não instante)
//	amount_cents →  amount (TEXTO em reais: "37.29")
//	kind         →  operation_type (INCOMING / OUTGOING)

// stmtDateFormat is the inicio/fim query format the extrato endpoint expects: a
// calendar date (an extrato window is bounded in days, not instants).
const stmtDateFormat = "2006-01-02"

// compile-time assertion that Provider satisfies the statement port.
var _ ports.StatementProvider = (*Provider)(nil)

// stmtEntryBody is one posted entry as the C6 extrato returns it.
//
// `amount` chega como TEXTO em reais ("37.29"), e é lido por brlDecimal — a mesma
// disciplina sem float do resto do adaptador. Um centavo perdido num extrato é um
// centavo que ninguém consegue explicar depois.
//
// `title` e `description` são duas metades do histórico ("CRED LOJ C CREDITO" e
// "CART. CREDIT - PAYGO ADMINISTR - Elo Cré"): a primeira nomeia a natureza do
// lançamento, a segunda a origem. Quem concilia precisa das duas, então elas são
// juntadas em vez de uma ser descartada.
type stmtEntryBody struct {
	ExternalID    string     `json:"external_id"`
	EntryDate     string     `json:"entry_date"`
	Amount        brlDecimal `json:"amount"`
	Title         string     `json:"title"`
	Description   string     `json:"description"`
	OperationType string     `json:"operation_type"`
	Reference     string     `json:"reference"`
}

// stmtResponse wraps the extrato list response.
type stmtResponse struct {
	Entries []stmtEntryBody `json:"entries"`
}

// C6 operation types on the extrato wire. INCOMING é dinheiro entrando, OUTGOING
// saindo; o port fala credit/debit.
const (
	stmtOperationIncoming = "INCOMING"
	stmtOperationOutgoing = "OUTGOING"
)

// stmtKind traduz o tipo de operação do C6 para o vocabulário do port.
//
// Um tipo desconhecido vira string vazia DE PROPÓSITO, para a revalidação de domínio
// recusar o extrato inteiro. É o oposto de adivinhar: se o banco inventar um terceiro
// tipo, é melhor a leitura falhar visivelmente do que classificar como crédito algo que
// talvez seja débito — num extrato, errar o sinal é errar o saldo.
func stmtKind(operationType string) string {
	switch strings.ToUpper(strings.TrimSpace(operationType)) {
	case stmtOperationIncoming:
		return "credit"
	case stmtOperationOutgoing:
		return "debit"
	default:
		return ""
	}
}

// stmtHistory junta as duas metades do histórico numa linha só, sem separador órfão
// quando uma delas vem vazia.
func stmtHistory(title, description string) string {
	title, description = strings.TrimSpace(title), strings.TrimSpace(description)
	switch {
	case title == "":
		return description
	case description == "":
		return title
	default:
		return title + " — " + description
	}
}

// toStatement maps the wire statement to the port type.
//
// A data vem como data CIVIL ("2026-09-02"), não instante: um lançamento pertence a um
// dia, e forçá-lo a um horário inventaria precisão que o banco não deu. Uma data
// ilegível vira o zero de time.Time, que a revalidação de domínio recusa — de novo,
// falhar visível em vez de chutar.
func toStatement(in stmtResponse) ports.Statement {
	entries := make([]ports.StatementEntry, len(in.Entries))
	for i, e := range in.Entries {
		var quando time.Time
		if t, err := time.Parse(stmtDateFormat, strings.TrimSpace(e.EntryDate)); err == nil {
			quando = t
		}
		entries[i] = ports.StatementEntry{
			ID:          e.ExternalID,
			Date:        quando,
			AmountCents: int64(e.Amount),
			Kind:        stmtKind(e.OperationType),
			Description: stmtHistory(e.Title, e.Description),
		}
	}
	return ports.Statement{Entries: entries}
}

// GetStatement reads the entries posted to the tenant's account within the requested
// date window (roteiro 13.a). The bearer token is attached per tenant; the read is
// tenant-scoped through it. Complete mediation: an absent inicio or fim is refused at
// the boundary (the use-case already validated the window, but the adapter does not
// trust an empty filter into the PSP).
func (p *Provider) GetStatement(ctx context.Context, tenantID string, filter ports.StatementFilter) (ports.Statement, error) {
	if filter.Start.IsZero() || filter.End.IsZero() {
		return ports.Statement{}, &Error{Op: "get_statement", sentinel: shared.ErrValidation}
	}
	// The C6 statement endpoint expects start_date / end_date (yyyy-MM-dd), NOT the
	// BACEN inicio/fim used by the PIX surface (SIN-65856, live-verified against the
	// sandbox problem+json).
	q := url.Values{}
	q.Set("start_date", filter.Start.UTC().Format(stmtDateFormat))
	q.Set("end_date", filter.End.UTC().Format(stmtDateFormat))
	endpoint := p.baseURL + "/v1/statement?" + q.Encode()
	httpReq, err := p.authedJSONRequest(ctx, tenantID, "get_statement", http.MethodGet, endpoint, nil, "")
	if err != nil {
		return ports.Statement{}, err
	}
	var out stmtResponse
	if err := p.do(httpReq, "get_statement", &out); err != nil {
		return ports.Statement{}, err
	}
	return toStatement(out), nil
}

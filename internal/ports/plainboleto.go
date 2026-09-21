package ports

import "context"

// Plain bank slip: the C6 "Boleto Bancário" v1 surface (/v1/bank_slips, roteiro grupo
// B), which is a DIFFERENT PRODUCT from the BolePix v2 surface BoletoProvider speaks.
//
// # Por que duas portas para "boleto"
//
// Elas não são versões uma da outra. O roteiro de homologação cobra as duas em blocos
// separados porque o banco as vende separadamente, e o contrato difere no que importa:
//
//   - **Desconto.** O v1 aceita ATÉ TRÊS faixas (first/second/third, prazos
//     decrescentes); o v2 expõe uma só (`first_discount_*`). A regra de negócio "10%
//     até 10 dias antes, 5% até 5 dias" simplesmente não cabe no v2.
//   - **Juros e multa.** O v1 é `{type, value, dead_line}` por bloco; o v2 é um objeto
//     único e achatado.
//   - **Endereço do pagador.** O v1 tem `street` + `number` numérico e NÃO tem
//     `neighborhood`; o v2 exige `neighborhood` e compõe o logradouro numa string só.
//   - **Referência externa.** O v1 admite 10 caracteres alfanuméricos; o v2, 26.
//   - **PIX.** Só o v2 emite QR. Um boleto v1 é boleto.
//
// Tentar servir as duas pela mesma porta faria uma delas mentir sobre o que aceita. Os
// TIPOS de request/result são compartilhados de propósito — o vocabulário de negócio é
// o mesmo —, e cada adapter recusa no seu limite o que o seu contrato não comporta.
//
// Nenhum fluxo de produto usa esta porta hoje: ela existe porque o bloco BOLETO do
// roteiro a cobra, e porque o desconto escalonado é a única forma de atender a regra de
// três faixas quando alguém pedir. Ver ports/pixbacen.go para o mesmo raciocínio.

// PlainBoletoProvider is the output port for the plain bank-slip lifecycle at the
// bank: register, read, amend, cancel (baixa) and render.
//
// Every method carries tenantID explicitly so the per-tenant credential isolation the
// adapter enforces is never bypassed (threat H1/P1). An id owned by another tenant is
// shared.ErrNotFound, never a distinct error.
type PlainBoletoProvider interface {
	// CreatePlainBoleto registers a slip (roteiro B_01–B_03). req.Discounts may carry
	// up to three tiers, ordered descending by DaysBeforeDue, and every tier must use
	// the SAME form (all percentage or all fixed) because the bank carries one
	// discount_type for the whole schedule.
	CreatePlainBoleto(ctx context.Context, tenantID string, req BoletoRequest) (BoletoResult, error)
	// GetPlainBoleto reconciles a registered slip (roteiro B_05). slipID is the bank's
	// own strong id, returned on create — not our external reference.
	GetPlainBoleto(ctx context.Context, tenantID, slipID string) (BoletoResult, error)
	// UpdatePlainBoleto amends a registered slip (roteiro B_04). It is a PARTIAL
	// update: a nil field in the patch means "leave this alone". The v1 contract only
	// admits amount, due date and the fee blocks — a patch touching anything else is
	// refused at the adapter boundary rather than silently dropped.
	UpdatePlainBoleto(ctx context.Context, tenantID, slipID string, patch BoletoPatch) (BoletoResult, error)
	// CancelPlainBoleto performs the baixa of a registered slip (roteiro B_08). The
	// contract answers 204, so there is no state to return — read it back if the new
	// status matters.
	CancelPlainBoleto(ctx context.Context, tenantID, slipID string) error
	// GetPlainBoletoPDF renders the slip for the payer (roteiro B_06).
	GetPlainBoletoPDF(ctx context.Context, tenantID, slipID string) (BoletoDocument, error)
}

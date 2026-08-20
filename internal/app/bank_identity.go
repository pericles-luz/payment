package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// Uma identidade bancária pertence a UMA empresa ativa de cada vez.
//
// São duas identidades, e as duas doem de jeitos diferentes porque o C6 registra cada
// canal de webhook por uma delas:
//
//	pix .................. pela CHAVE do recebedor
//	rec, cobr, checkout .. pela CONTA por trás do client_id
//
// Duas empresas ativas que dividem uma dessas se sobrescrevem a cada registro — há uma
// URL só por chave e uma só por conta. O aviso de pagamento chega por um ref que não é
// do dono da cobrança, é recusado, e a liquidação passa a depender de varredura. Foi o
// que a empresa 27 viveu (SIN-69368).
//
// Dividir a CHAVE quebra o PIX; dividir a CONTA quebra recorrência e CHECKOUT — ou
// seja, o aviso de pagamento com CARTÃO. Dar chaves diferentes a dois tenants da mesma
// empresa resolve só um quarto do problema; cada um precisa da própria conta C6.
//
// Estas funções vivem no pacote, não num serviço, porque há três caminhos de escrita em
// dois serviços (console, console por banco, e o admin que serve também o self-serve).
// Uma cópia por caminho divergiria.

// assertCreditorKeyUnclaimed rejects creditorKey when another ACTIVE tenant holds it.
//
// Um detentor SUSPENSO não bloqueia: ele não registra webhook nenhum (ver
// WebhookRegistrationService.tenantMayRegister), então não disputa — e barrar por causa
// dele impediria uma empresa de reaproveitar a própria chave depois de recadastrada.
//
// Falha fechado: sem conseguir verificar, não grava. Uma identidade gravada por engano é
// cara de descobrir e cara de desfazer; um erro transitório custa "tente de novo".
func assertCreditorKeyUnclaimed(ctx context.Context, sharing ports.CreditorKeySharingLookup, tenants tenantActiveLookup, tenantID, bankID, creditorKey string) error {
	if sharing == nil || creditorKey == "" {
		return nil
	}
	holders, err := sharing.FindTenantsByCreditorKey(ctx, bankID, creditorKey)
	if err != nil {
		return fmt.Errorf("check creditor key holders: %w", err)
	}
	taken, err := anyOtherActiveHolder(ctx, tenants, tenantID, holders)
	if err != nil {
		return fmt.Errorf("resolve creditor key holder: %w", err)
	}
	if taken {
		return shared.NewValidationError("creditor_key",
			"esta chave PIX já está registrada para outra empresa ativa")
	}
	return nil
}

// assertClientIDUnclaimed rejects clientID when another ACTIVE tenant is registered
// under the same PSP account. Same posture as the creditor key: suspended holders do
// not block, and it fails closed.
func assertClientIDUnclaimed(ctx context.Context, sharing ports.CreditorKeySharingLookup, tenants tenantActiveLookup, tenantID, bankID, clientID string) error {
	if sharing == nil || clientID == "" {
		return nil
	}
	holders, err := sharing.FindTenantsByClientID(ctx, bankID, clientID)
	if err != nil {
		return fmt.Errorf("check client id holders: %w", err)
	}
	taken, err := anyOtherActiveHolder(ctx, tenants, tenantID, holders)
	if err != nil {
		return fmt.Errorf("resolve client id holder: %w", err)
	}
	if taken {
		return shared.NewValidationError("client_id",
			"esta conta do banco já está registrada para outra empresa ativa")
	}
	return nil
}

// anyOtherActiveHolder reports whether holders contains an ACTIVE tenant other than
// tenantID. A holder that no longer exists counts as inactive: an orphan credential row
// must not block a legitimate write.
func anyOtherActiveHolder(ctx context.Context, tenants tenantActiveLookup, tenantID string, holders []string) (bool, error) {
	for _, other := range holders {
		if other == tenantID {
			continue
		}
		t, err := tenants.FindTenantByID(ctx, other)
		if err != nil {
			if errors.Is(err, shared.ErrNotFound) {
				continue
			}
			return false, err
		}
		if t.Active() {
			return true, nil
		}
	}
	return false, nil
}

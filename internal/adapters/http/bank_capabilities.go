package http

import (
	"errors"
	"net/http"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

// bankCapabilitiesView tells an empresa-cliente which payment methods its OWN bank
// credential authorises, so its checkout screen can offer only what the bank will
// actually accept — and explain the rest instead of failing mid-purchase.
type bankCapabilitiesView struct {
	TenantID string `json:"tenant_id"`
	// Configured is false when the tenant has no bank credential at all. It separates
	// "não configurado" from "configurado, mas a conta não contratou o produto" — dois
	// estados que exigem mensagens diferentes de quem administra a empresa.
	Configured bool `json:"configured"`
	PIX        bool `json:"pix"`
	Card       bool `json:"card"`
}

// handleTenantBankCapabilities answers GET /v1/bank-capabilities for the authenticated
// tenant.
//
// Existe por causa de uma compra real que falhou no pior lugar. A conta C6 de uma
// empresa não tinha o produto Checkout contratado; nada no nosso sistema sabia disso, a
// loja ofereceu o botão de cartão, e o comprador só descobriu quando o C6 respondeu 403
// com o cartão na mão. O escopo concedido no token diz o mesmo fato ANTES, e de graça:
// a resposta vem do token que a próxima cobrança usaria de qualquer jeito.
//
// Postura de segurança, espelhando as outras rotas self-serve:
//   - A01 por construção: o tenant vem do contexto autenticado, NUNCA de caminho, corpo
//     ou query. Sem seletor de tenant no contrato, um token só enxerga a si mesmo.
//   - Não vaza vocabulário do PSP: devolve as capacidades no nosso modelo, não a lista
//     de escopos do banco.
//   - Tenant sem credencial responde 200 com configured=false, não 404: "ainda não
//     configurou" é um estado legítimo da tela, não um erro.
func (s *Server) handleTenantBankCapabilities(w http.ResponseWriter, r *http.Request) {
	tenantID := tenantFromContext(r.Context())
	if s.bankCaps == nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	caps, err := s.bankCaps.BankCapabilities(r.Context(), tenantID)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			writeJSON(w, http.StatusOK, bankCapabilitiesView{TenantID: tenantID})
			return
		}
		writeDomainError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, bankCapabilitiesView{
		TenantID:   tenantID,
		Configured: true,
		PIX:        caps.PIX,
		Card:       caps.Card,
	})
}

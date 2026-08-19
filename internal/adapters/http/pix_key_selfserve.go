package http

import "net/http"

// setCreditorKeyRequest is the self-serve PIX-key payload: the tenant's registered
// receiving key (chave do recebedor). There is NO tenant field, deliberately — see
// handleTenantSetCreditorKey.
type setCreditorKeyRequest struct {
	CreditorKey string `json:"creditor_key"`
}

// creditorKeyView confirms the write WITHOUT echoing the key.
//
// The key is not a secret — it is the account's public PIX identifier — but it IS
// fund-routing data, so it is treated like the credential: written, never read back.
// Echoing it would make this endpoint a way to enumerate where a tenant's money goes.
type creditorKeyView struct {
	TenantID string `json:"tenant_id"`
	Status   string `json:"status"`
}

// handleTenantSetCreditorKey lets an empresa-cliente register its OWN PIX receiving
// key with its tenant token (PUT /v1/pix-key), gated by the same flag as the
// credential and certificate intakes.
//
// It exists because the key was only settable from the operator console, so a tenant
// could provision its credential and certificate and still be stuck: without the key
// the adapter does not know which account to route funds to, and the PIX webhook has
// no chave to register under. The self-serve trilogy was missing its third leg.
//
// Security posture mirrors handleTenantSetBankCredential:
//   - A01 by construction: the tenant comes from the authenticated context, NEVER
//     from path, body or query. With no tenant selector in the contract, a token can
//     only ever write its own key.
//   - No oracle: creating and replacing return the identical 200 and body, so
//     nothing reveals whether a key was already registered.
//   - Write-only: the response never carries the key.
//   - Fail closed: an unwired console service refuses rather than silently
//     accepting a write that goes nowhere.
func (s *Server) handleTenantSetCreditorKey(w http.ResponseWriter, r *http.Request) {
	tenantID := tenantFromContext(r.Context())
	var req setCreditorKeyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if s.console == nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	if err := s.console.SetCreditorKeySelfServe(r.Context(), tenantID, req.CreditorKey); err != nil {
		writeDomainError(w, err)
		return
	}
	// Registering the key may complete the credential+key pair — the same in-flow C6
	// webhook registration the credential write attempts. Best-effort by contract:
	// TryRegister never errors, so a PSP hiccup cannot fail an accepted write.
	if s.webhookReg != nil {
		s.webhookReg.TryRegister(r.Context(), tenantID)
	}
	writeJSON(w, http.StatusOK, creditorKeyView{TenantID: tenantID, Status: "ok"})
}

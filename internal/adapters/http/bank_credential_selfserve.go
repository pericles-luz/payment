package http

import (
	"net/http"

	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// selfServeBankAllowlist is the DEDICATED set of banks a tenant may self-provision
// a credential for through the self-serve intake (SIN-69196 Q4). It is
// intentionally SEPARATE from the platform-wide ports.IsKnownBankID set: onboarding
// a new bank platform-wide must NOT implicitly open self-serve credential intake
// for it (least-privilege / defense-in-depth — self-serve is a narrower, tenant-
// driven surface than the admin plane). Today it is exactly {c6}; widening it is a
// deliberate, reviewable change here, not a side effect elsewhere.
var selfServeBankAllowlist = map[string]struct{}{
	ports.BankIDC6: {},
}

// isSelfServeBank reports whether bankID (already NormalizeBankID-resolved, so ""
// has become c6) is permitted for self-serve intake. Deny-by-default: anything not
// explicitly allow-listed is rejected.
func isSelfServeBank(bankID string) bool {
	_, ok := selfServeBankAllowlist[bankID]
	return ok
}

// handleTenantSetBankCredential is the self-serve credential intake (SIN-69196,
// gated by PAYMENT_SELFSERVE_CRED_INTAKE). It lets an empresa-cliente rotate its
// OWN bank (PSP) credential using its tenant token, on the tenant plane
// (PUT /v1/bank-credential), in addition to the existing admin-plane write.
//
// Security posture (threat model docs/security/threat-model-self-serve-credential-
// intake.md, gate SIN-69195):
//   - A01 by construction: the tenant is taken from the authenticated context
//     (tenantFromContext), NEVER from the path/body/query. There is no tenant
//     selector in the contract, so a token can only ever write its own credential —
//     the whole broken-access-control class is designed out, not merely checked.
//   - Q4 dedicated allow-list: after NormalizeBankID, the bank must be in the
//     self-serve allow-list (isSelfServeBank, currently {c6}); anything else → 400.
//     Empty resolves to c6 (retro-compat with the single-bank default).
//   - Write-only secret: the secret is forwarded to the store and NEVER echoed,
//     logged or returned. The response mirrors the admin path's bankCredentialView
//     (tenant, bank, client id, status) — no secret field exists on it.
//   - Q5 no oracle: the response for a CREATE and for a ROTATE/overwrite is
//     byte-identical (same 200 + same view). Nothing reveals whether a credential
//     already existed. A validation error never echoes the offending input.
//   - Q2 idempotency: the write is last-writer-wins and byte-identical, so a
//     double-submit is naturally safe. An optional Idempotency-Key header is
//     accepted (ignored: unknown header, not an unknown body field) but not
//     required — retries need no dedicated key.
//   - Audit: the write is recorded via the app service with origin=self-serve
//     (SIN-69196 R1), account_id derived server-side, and never the secret/client
//     secret (threat C1/C4).
//
// The rate limit (Q1, a dedicated inbound per-tenant bucket) and the flag gate are
// applied as route middleware in server.go, so this handler stays a thin, testable
// mirror of handleSetBankCredential.
func (s *Server) handleTenantSetBankCredential(w http.ResponseWriter, r *http.Request) {
	// A01: the tenant is the authenticated caller, never client-supplied.
	tenantID := tenantFromContext(r.Context())
	var req setBankCredentialRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	// Q4: self-serve is restricted to its OWN allow-list (c6 today), independent of
	// the platform-wide known-bank set. Empty → c6; anything else → 400 (no echo).
	bank := ports.NormalizeBankID(req.Bank)
	if !isSelfServeBank(bank) {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if err := s.admin.SetBankCredentialSelfServe(r.Context(), tenantID, bank, req.ClientID, req.Secret); err != nil {
		writeDomainError(w, err)
		return
	}
	// Echo only non-secret fields — identical shape to the admin path — so create
	// and rotate are indistinguishable (Q5) and the secret never leaves the store.
	writeJSON(w, http.StatusOK, bankCredentialView{TenantID: tenantID, Bank: bank, ClientID: req.ClientID, Status: "ok"})
}

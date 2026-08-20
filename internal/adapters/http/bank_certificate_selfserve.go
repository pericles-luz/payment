package http

import (
	"net/http"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// handleTenantSetBankCertificate is the self-serve mTLS certificate intake
// (SIN-69346), gated by PAYMENT_SELFSERVE_CRED_INTAKE (the SAME toggle as the
// self-serve credential intake — both are the one Verz onboarding surface; there is
// no operational case to enable one without the other). It lets an empresa-cliente
// provision/rotate its OWN per-bank client certificate using its tenant token, on
// the tenant plane (PUT /v1/bank-certificate), in addition to the existing
// admin-plane write. It is the certificate sibling of handleTenantSetBankCredential.
//
// Security posture (threat model docs/security/threat-model-self-serve-credential-
// intake.md, §"Private key in transit"):
//   - A01 by construction: the tenant is taken from the authenticated context
//     (tenantFromContext), NEVER from the path/body/query. There is no tenant
//     selector in the contract, so a token can only ever write its own certificate —
//     the whole broken-access-control class is designed out, not merely checked.
//   - Q4 dedicated allow-list: after NormalizeBankID, the bank must be in the
//     self-serve allow-list (isSelfServeBank, currently {c6}); anything else → 400.
//     Empty resolves to c6 (retro-compat with the single-bank default).
//   - Private key write-only: the PEM key pair is validated server-side (parse +
//     expiry-at-upload + cert/key match in the use-case) and forwarded to the vault;
//     the private key is NEVER echoed, logged or returned. The response is ONLY the
//     public certificate metadata (fingerprint, subject, validity window) — the same
//     bankCertificateView the admin path returns; no key field exists on it. A
//     private key in transit is MORE sensitive than a client_secret, so this handler
//     stays a thin mirror with a single exit that serializes metadata only.
//   - Idempotency / create==rotate: the write is last-writer-wins and the response
//     is derived purely from the (public) parsed certificate, so re-uploading the
//     same cert/key is byte-identical — nothing reveals whether one already existed.
//     An optional Idempotency-Key header is accepted (ignored: unknown header, not an
//     unknown body field) but not required; retries need no dedicated key.
//   - Audit: the write is recorded via the app service with origin=self-serve (a
//     dedicated audit constructor), operator derived server-side, fingerprint (a
//     public id) in tx_id, and NEVER the private key (threat C1/C4).
//
// The rate limit (a dedicated inbound per-tenant bucket) and the flag gate are
// applied as route middleware in server.go, so this handler stays a thin, testable
// mirror of handleSetBankCertificate.
func (s *Server) handleTenantSetBankCertificate(w http.ResponseWriter, r *http.Request) {
	// A01: the tenant is the authenticated caller, never client-supplied.
	tenantID := tenantFromContext(r.Context())
	var req setBankCertificateRequest
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
	meta, err := s.admin.SetBankCertificateSelfServe(r.Context(), tenantID, bank, req.CertPEM, req.KeyPEM)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	// The mTLS cert is what lets the live C6 handshake succeed, so a cert write can be
	// the last piece enabling the in-flow webhook registration (SIN-69560 / F2).
	// Best-effort: TryRegister never errors; unwired (nil) or an incomplete cred+key
	// pair is a silent no-op.
	if s.webhookReg != nil {
		s.webhookReg.TryRegister(r.Context(), tenantID)
	}
	// Echo ONLY the public certificate metadata — identical shape to the admin path.
	// The private key never leaves the vault and is never serialized into a response,
	// so create and rotate are indistinguishable and the key is never exposed.
	writeJSON(w, http.StatusOK, bankCertificateView{
		TenantID:          meta.TenantID,
		Bank:              meta.BankID,
		SubjectCN:         meta.SubjectCN,
		Issuer:            meta.Issuer,
		SerialNumber:      meta.SerialNumber,
		FingerprintSHA256: meta.FingerprintSHA256,
		NotBefore:         meta.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:          meta.NotAfter.UTC().Format(time.RFC3339),
		Status:            "ok",
	})
}

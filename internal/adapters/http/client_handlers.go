package http

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
)

// ClientProvisioner provisions a new empresa-cliente (tenant) owned by an Account
// and returns it (model (b), ADR-0011 §4 / SIN-69281). It is the app-layer port the
// account-plane /v1/clients route depends on (accept-narrow: the adapter needs only
// the provisioning surface). Satisfied by app.ClientProvisioningService.
//
// Security contract: accountID is the AUTHENTICATED caller's Account, derived from
// the account-key context by the handler — never from the request body. The
// service binds the new tenant to exactly that Account (set-once), so a Conta can
// only ever provision empresas-clientes under itself (A01/T6 designed out).
type ClientProvisioner interface {
	ProvisionClient(ctx context.Context, accountID, name, idemKey string) (*tenant.Tenant, error)
}

// createClientRequest is the (optional) provisioning body. It carries ONLY an
// optional name: there is deliberately no account_id field, and DisallowUnknownFields
// makes a body that tries to smuggle one a 400 rather than a silently-ignored field
// (A01/T6 — the Account always comes from the key).
type createClientRequest struct {
	Name string `json:"name"`
}

// clientView is the provisioning response: the new empresa-cliente's tenant id (for
// the X-Client-Tenant selector), its owning Account (echoed from the key, never
// client input) and its name.
type clientView struct {
	TenantID  string `json:"tenant_id"`
	AccountID string `json:"account_id"`
	Name      string `json:"name"`
}

// handleProvisionClient is the account-plane self-serve provisioning route (POST
// /v1/clients): a reseller Conta, authenticated by its account-key
// (accountKeyAuthMiddleware put the authenticated account id on the context),
// creates a new empresa-cliente bound to ITS OWN Account. The account id is taken
// from the authenticated context, NEVER from the path/body — a Conta can only ever
// provision under itself (A01/T6 designed out, mirroring the self-serve credential
// intake and the account-key self-rotation).
func (s *Server) handleProvisionClient(w http.ResponseWriter, r *http.Request) {
	accountID := accountFromContext(r.Context())
	if accountID == "" {
		// Only reachable via a wiring bug (route not behind accountKeyAuthMiddleware);
		// fail closed rather than provision for an unauthenticated caller.
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if s.clientProvisioner == nil {
		writeError(w, http.StatusServiceUnavailable, "client provisioning unavailable")
		return
	}
	idemKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if idemKey == "" {
		writeError(w, http.StatusBadRequest, "missing Idempotency-Key header")
		return
	}
	// The body is OPTIONAL (at most a name). Decode it when present but reject an
	// unknown field — critically an `account_id`: the Account is derived from the key
	// server-side (A01/T6), so a body naming one is a 400, never honored. An empty
	// body (no name) is accepted; the service defaults the name.
	var req createClientRequest
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	t, err := s.clientProvisioner.ProvisionClient(r.Context(), accountID, req.Name, idemKey)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, clientView{TenantID: t.ID(), AccountID: t.AccountID(), Name: t.Name()})
}

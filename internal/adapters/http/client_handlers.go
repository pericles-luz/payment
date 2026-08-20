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

// ClientWebhookProvisioner is the webhook-aware superset of ClientProvisioner
// (SIN-69559 / F1): it provisions the empresa-cliente AND mints a durable per-tenant C6
// webhook callback ref, returning the plaintext ref DISPLAY-ONCE. The handler prefers
// this method when the wired provisioner implements it (so a fresh client can receive
// webhooks with no operator edit and no restart) and falls back to ProvisionClient
// otherwise. The ref is a capability secret: it is returned to the caller exactly once
// and is never logged.
type ClientWebhookProvisioner interface {
	ProvisionClientWithWebhook(ctx context.Context, accountID, name, idemKey string) (t *tenant.Tenant, webhookRef string, err error)
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
// client input), its name, and — DISPLAY-ONCE — the minted webhook ref and its callback
// path (SIN-69559 / F1). WebhookRef is a capability secret: it is present only on the
// first successful provision (an idempotent replay omits it) and MUST be stored by the
// caller / registered with C6; the server never returns it again. Both webhook fields
// are omitempty so the legacy no-webhook wiring (and replays) render an unchanged body.
type clientView struct {
	TenantID    string `json:"tenant_id"`
	AccountID   string `json:"account_id"`
	Name        string `json:"name"`
	WebhookRef  string `json:"webhook_ref,omitempty"`
	WebhookPath string `json:"webhook_path,omitempty"`
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
	// Prefer the webhook-aware provisioning path (SIN-69559 / F1): it mints a durable
	// per-tenant C6 callback ref so the fresh client can receive webhooks with no
	// operator edit and no restart. The plaintext ref is returned DISPLAY-ONCE below and
	// never logged. Fall back to the plain path when no webhook provisioner is wired.
	var (
		t          *tenant.Tenant
		webhookRef string
		err        error
	)
	if wp, ok := s.clientProvisioner.(ClientWebhookProvisioner); ok {
		t, webhookRef, err = wp.ProvisionClientWithWebhook(r.Context(), accountID, req.Name, idemKey)
	} else {
		t, err = s.clientProvisioner.ProvisionClient(r.Context(), accountID, req.Name, idemKey)
	}
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	view := clientView{TenantID: t.ID(), AccountID: t.AccountID(), Name: t.Name()}
	if webhookRef != "" {
		view.WebhookRef = webhookRef
		view.WebhookPath = "/webhooks/c6/" + webhookRef
	}
	writeJSON(w, http.StatusCreated, view)
}

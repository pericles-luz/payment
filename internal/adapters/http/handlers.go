package http

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/payment"
)

// maxBodyBytes caps request bodies to bound memory use (threat H3/W4).
const maxBodyBytes = 1 << 20 // 1 MiB

// decodeJSON strictly decodes a JSON body into v, rejecting unknown fields
// (anti mass-assignment, threat H4) and oversized bodies.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return false
	}
	if dec.More() {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return false
	}
	return true
}

// --- Tenant API: charges ---

type createChargeRequest struct {
	Endpoint    string `json:"endpoint"`
	AmountCents int64  `json:"amount_cents"`
	Currency    string `json:"currency"`
}

type paymentView struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
	Endpoint string `json:"endpoint"`
	Amount   int64  `json:"amount_cents"`
	Currency string `json:"currency"`
	Status   string `json:"status"`
	TxID     string `json:"tx_id"`
}

func toPaymentView(p *payment.Payment) paymentView {
	return paymentView{
		ID:       p.ID(),
		TenantID: p.TenantID(),
		Endpoint: p.Endpoint(),
		Amount:   p.Amount().Cents(),
		Currency: p.Amount().Currency(),
		Status:   string(p.Status()),
		TxID:     p.TxID(),
	}
}

func (s *Server) handleCreateCharge(w http.ResponseWriter, r *http.Request) {
	tenantID := tenantFromContext(r.Context())
	idemKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if idemKey == "" {
		writeError(w, http.StatusBadRequest, "missing Idempotency-Key header")
		return
	}
	var req createChargeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	p, err := s.charges.CreateCharge(r.Context(), app.CreateChargeInput{
		TenantID:       tenantID,
		Endpoint:       req.Endpoint,
		AmountCents:    req.AmountCents,
		Currency:       req.Currency,
		IdempotencyKey: idemKey,
	})
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, toPaymentView(p))
}

func (s *Server) handleGetCharge(w http.ResponseWriter, r *http.Request) {
	tenantID := tenantFromContext(r.Context())
	id := chi.URLParam(r, "id")
	p, err := s.charges.GetPayment(r.Context(), tenantID, id)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toPaymentView(p))
}

// --- Admin plane ---

type createTenantRequest struct {
	Name string `json:"name"`
}

type tenantView struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Active bool   `json:"active"`
}

func (s *Server) handleCreateTenant(w http.ResponseWriter, r *http.Request) {
	var req createTenantRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	t, err := s.admin.CreateTenant(r.Context(), req.Name)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, tenantView{ID: t.ID(), Name: t.Name(), Active: t.Active()})
}

type setPriceRequest struct {
	Endpoint   string `json:"endpoint"`
	PriceCents int64  `json:"price_cents"`
}

type priceView struct {
	TenantID   string `json:"tenant_id"`
	Endpoint   string `json:"endpoint"`
	PriceCents int64  `json:"price_cents"`
}

func (s *Server) handleSetPrice(w http.ResponseWriter, r *http.Request) {
	tenantID := chi.URLParam(r, "tenantID")
	var req setPriceRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	p, err := s.admin.SetEndpointPrice(r.Context(), tenantID, req.Endpoint, req.PriceCents)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, priceView{TenantID: p.TenantID(), Endpoint: p.Endpoint(), PriceCents: p.PriceCents()})
}

// setBankCredentialRequest carries a tenant's PSP credential. The secret is
// write-only: it is accepted here and forwarded to the secret store, never read
// back, logged or echoed in any response (threat C1/C4).
type setBankCredentialRequest struct {
	ClientID string `json:"client_id"`
	Secret   string `json:"secret"`
}

// bankCredentialView confirms a credential write WITHOUT the secret.
type bankCredentialView struct {
	TenantID string `json:"tenant_id"`
	ClientID string `json:"client_id"`
	Status   string `json:"status"`
}

func (s *Server) handleSetBankCredential(w http.ResponseWriter, r *http.Request) {
	tenantID := chi.URLParam(r, "tenantID")
	var req setBankCredentialRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.admin.SetBankCredential(r.Context(), tenantID, req.ClientID, req.Secret); err != nil {
		writeDomainError(w, err)
		return
	}
	// Echo only non-secret fields so the secret never leaves the secret store.
	writeJSON(w, http.StatusOK, bankCredentialView{TenantID: tenantID, ClientID: req.ClientID, Status: "ok"})
}

// --- C6 bank webhook ---

// maxWebhookBytes caps the inbound webhook body. The webhook is pre-authenticated
// only by the opaque URL, so the body is parsed from an unauthenticated network
// peer; an unbounded read is a resource-consumption DoS (OWASP API4). A C6
// notification is a few hundred bytes — 64 KiB is generous. Oversize → 413.
const maxWebhookBytes = 64 << 10

// webhookServiceCheckout is the c6WebhookNotification.service value that marks a
// checkout-session status notification (roteiro 12). Matched case-insensitively; any
// other service is reconciled as a PIX/charge.
const webhookServiceCheckout = "checkout"

// c6WebhookNotification is the inbound C6 callback body (notificações.yaml,
// WebhookNotification). It is UNTRUSTED: the tenant comes from the authenticated
// channel (never client_id), and settlement reconciles the authoritative state
// via GetCharge rather than trusting status. Only the fields the adapter needs are
// decoded; unknown fields are rejected (anti mass-assignment).
type c6WebhookNotification struct {
	ExternalID string `json:"external_id"` // C6 charge id → reconcile key (txID)
	ClientID   string `json:"client_id"`   // C6 merchant id → cross-checked, not trusted
	Service    string `json:"service"`     // e.g. pix — part of the idempotency key
	Status     string `json:"status"`      // advisory only; never the settle decision
}

// handleC6Webhook receives a C6 payment notification on a tenant's opaque callback
// URL (/webhooks/c6/{tenantRef}). Security posture (ADR-0002 / F4):
//   - the tenant is derived from the authenticated channel (the unguessable ref),
//     never from the body — closing cross-tenant anti-replay poisoning at the source;
//   - the body is size-capped before it is read (pre-auth DoS);
//   - the body's client_id is cross-checked against the channel tenant and a
//     divergence is rejected and logged as a security event (never trusted);
//   - the event is deduplicated and reconciled in the app layer's unit of work
//     (anti-replay + reconcile-before-settle), which is the financial backstop.
func (s *Server) handleC6Webhook(w http.ResponseWriter, r *http.Request) {
	// 1. Authenticate the channel. The opaque ref in the path IS the credential
	//    (the C6 webhook is unsigned). Unknown and malformed refs both yield the
	//    SAME generic 401 — no tenant-existence oracle. The ref is a capability
	//    secret: it is never written to logs (only the resolved tenant id is).
	id, ok := s.webhookAuth.AuthenticateWebhook(chi.URLParam(r, "tenantRef"))
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	// 2. Cap and decode the untrusted body. Oversize → 413 (distinct from a
	//    malformed body's 400) so the cap is observable.
	r.Body = http.MaxBytesReader(w, r.Body, maxWebhookBytes)
	var note c6WebhookNotification
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&note); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if dec.More() {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// 3. Defense-in-depth cross-check: the body may not claim a different tenant
	//    than the channel. The channel is authoritative regardless; a divergence is
	//    an attack indicator. Log it as a security event WITHOUT the ref/secret or
	//    raw body — only the resolved tenant id and the (untrusted) claimed id,
	//    which slog escapes. An absent client_id is allowed (channel is the truth).
	if note.ClientID != "" && id.ClientID != "" && note.ClientID != id.ClientID {
		slog.Warn("c6 webhook tenant mismatch: body client_id diverges from channel",
			slog.String("channel_tenant", id.TenantID),
			slog.String("claimed_client_id", note.ClientID))
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	if strings.TrimSpace(note.ExternalID) == "" {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// 4. Dispatch with the CHANNEL tenant. EventKey distinguishes state transitions
	//    of the same charge (e.g. pending→paid) while collapsing exact redeliveries,
	//    so anti-replay dedup (processed_events) suppresses duplicates without
	//    dropping a genuine settle. Retention of processed_events is INDEFINITE: the
	//    C6 contract signs nothing (no timestamp), so dedup is the only replay
	//    barrier and pruning a key would reopen a replay window. A bounded
	//    signed-timestamp window is deferred to SIN-64762 (if C6 ever signs).
	//
	//    The service field selects which authoritative state to reconcile before
	//    settling: a checkout notification reconciles the checkout session (roteiro
	//    12), every other service the PIX/charge. Both paths share the same dedup +
	//    reconcile-before-settle unit of work and the EventKey carries the service, so
	//    a checkout and a charge event for the same external id never collide.
	ev := app.PaymentEvent{
		TenantID: id.TenantID,
		TxID:     note.ExternalID,
		EventKey: note.ExternalID + "|" + note.Service + "|" + note.Status,
	}
	var err error
	if strings.EqualFold(strings.TrimSpace(note.Service), webhookServiceCheckout) {
		err = s.webhooks.HandleCheckoutEvent(r.Context(), ev)
	} else {
		err = s.webhooks.HandlePaymentEvent(r.Context(), ev)
	}
	if err != nil {
		writeDomainError(w, err)
		return
	}
	// 202: accepted; reconciliation/settlement already attempted synchronously.
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
}

package http

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/payment"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
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
	// Bank optionally selects which configured bank handles this charge (multi-bank,
	// SIN-66022). Empty keeps the header/default routing. It overrides the X-Bank-Id
	// header when both are present (the body field is the canonical write selector,
	// ADR-0007).
	Bank string `json:"bank"`
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
	nr, ok := s.rebindBank(w, r, req.Bank)
	if !ok {
		return
	}
	r = nr
	p, err := s.charges.CreateCharge(r.Context(), app.CreateChargeInput{
		TenantID:       tenantID,
		AccountID:      accountFromContext(r.Context()),
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

// setBankCredentialRequest carries a tenant's PSP credential for one bank. The
// bank slug selects which bank the credential is stored under (ADR-0007); it is
// optional and defaults to BankIDC6 for backward compatibility with the legacy
// single-bank callers. The secret is write-only: it is accepted here and forwarded
// to the secret store, never read back, logged or echoed in any response (threat
// C1/C4).
type setBankCredentialRequest struct {
	Bank     string `json:"bank"`
	ClientID string `json:"client_id"`
	Secret   string `json:"secret"`
}

// bankCredentialView confirms a credential write WITHOUT the secret. It echoes the
// resolved (normalized) bank so the caller/UX can confirm which bank was written.
type bankCredentialView struct {
	TenantID string `json:"tenant_id"`
	Bank     string `json:"bank"`
	ClientID string `json:"client_id"`
	Status   string `json:"status"`
}

func (s *Server) handleSetBankCredential(w http.ResponseWriter, r *http.Request) {
	tenantID := chi.URLParam(r, "tenantID")
	var req setBankCredentialRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	// Boundary validation (deny-by-default): normalize the optional bank slug and
	// reject an unknown bank with a 400 before reaching the use-case. The
	// AdminService re-validates (defense-in-depth); both layers resolve "" to c6.
	bank := ports.NormalizeBankID(req.Bank)
	if !ports.IsKnownBankID(bank) {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if err := s.admin.SetBankCredential(r.Context(), tenantID, bank, req.ClientID, req.Secret); err != nil {
		writeDomainError(w, err)
		return
	}
	// A credential write may complete the cred+PIX-key pair — attempt the in-flow C6
	// webhook registration exactly as the self-serve path does (SIN-69588 / B3). Prod
	// creds are provisioned through THIS admin Bearer intake (runbook), so without this
	// the go-live registration path was uncovered. Best-effort by contract: TryRegister
	// never errors, so a PSP failure cannot turn this successful write into a failure for
	// the operator. When unwired (nil) or the pair is not yet complete it is a no-op.
	if s.webhookReg != nil {
		s.webhookReg.TryRegister(r.Context(), tenantID)
	}
	// Echo only non-secret fields so the secret never leaves the secret store.
	writeJSON(w, http.StatusOK, bankCredentialView{TenantID: tenantID, Bank: bank, ClientID: req.ClientID, Status: "ok"})
}

// setBankCertificateRequest carries a tenant's per-bank mTLS client certificate
// (SIN-66087). cert_pem is the PUBLIC leaf certificate; key_pem is its private key
// and is write-only — accepted here, validated server-side, forwarded to the vault,
// and NEVER read back, logged or echoed in any response (threat C1/C4). The bank
// slug selects the bank (ADR-0007); optional, defaults to BankIDC6.
type setBankCertificateRequest struct {
	Bank    string `json:"bank"`
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
}

// bankCertificateView confirms a certificate write with ONLY the public metadata
// of the certificate — never the private key. Timestamps are RFC3339 UTC so the
// UI can render the validity window and badge a not-yet-valid/expiring cert.
type bankCertificateView struct {
	TenantID          string `json:"tenant_id"`
	Bank              string `json:"bank"`
	SubjectCN         string `json:"subject_cn"`
	Issuer            string `json:"issuer"`
	SerialNumber      string `json:"serial_number"`
	FingerprintSHA256 string `json:"fingerprint_sha256"`
	NotBefore         string `json:"not_before"`
	NotAfter          string `json:"not_after"`
	Status            string `json:"status"`
}

func (s *Server) handleSetBankCertificate(w http.ResponseWriter, r *http.Request) {
	tenantID := chi.URLParam(r, "tenantID")
	var req setBankCertificateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	// Boundary validation (deny-by-default): normalize the optional bank slug and
	// reject an unknown bank with a 400 before reaching the use-case. The
	// AdminService re-validates (defense-in-depth); both layers resolve "" to c6.
	bank := ports.NormalizeBankID(req.Bank)
	if !ports.IsKnownBankID(bank) {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	meta, err := s.admin.SetBankCertificate(r.Context(), tenantID, bank, req.CertPEM, req.KeyPEM)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	// A certificate write may complete the mTLS half needed to reach C6 — attempt the
	// in-flow webhook registration like the self-serve path (SIN-69588 / B3). Best-effort:
	// TryRegister never errors, so a PSP failure cannot fail this successful write. No-op
	// when unwired (nil) or the cred+key pair is not yet complete.
	if s.webhookReg != nil {
		s.webhookReg.TryRegister(r.Context(), tenantID)
	}
	// Echo only the public certificate metadata; the private key never leaves the
	// vault and is never serialized into a response.
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

// --- C6 bank webhook ---

// maxWebhookBytes caps the inbound webhook body. The webhook is pre-authenticated
// only by the opaque URL, so the body is parsed from an unauthenticated network
// peer; an unbounded read is a resource-consumption DoS (OWASP API4). A C6
// notification is a few hundred bytes — 64 KiB is generous. Oversize → 413.
const maxWebhookBytes = 64 << 10

// Service discriminators that change how a notification is routed. BANK_SLIP and
// BANK_SLIP_PIX need no constant: they reconcile as ordinary charges, which is the
// default branch. PIX is the odd one — same channel, different envelope entirely (see
// c6WebhookNotification).
const (
	webhookServicePix      = "pix"
	webhookServiceCheckout = "checkout"

	// Labels for the two recurrence streams, used in the event key.
	webhookLabelRec  = "rec"
	webhookLabelCobR = "cobr"
)

// c6WebhookNotification is the union of the FOUR documented inbound shapes. C6 fronts
// every callback on the same opaque channel, but the payloads are genuinely different
// contracts, not one envelope with optional fields:
//
//	proprietary (BANK_SLIP, BANK_SLIP_PIX, CHECKOUT)
//	    external_id, date_time, client_id, partner_id, service, status
//	PIX (WebhookNotificationPix)
//	    date_time, status, service=PIX, key, tax_id, information
//	    — NO external_id; the settled ids live inside `information`, which is a STRING
//	      carrying JSON.
//	recorrência (RecNotification / CobRNotification, BACEN shape)
//	    idRec [, txid], status, atualizacao — NO service discriminator at all.
//
// It is UNTRUSTED: the tenant comes from the authenticated channel (never client_id),
// and settlement reconciles the authoritative state rather than trusting `status`.
//
// Unknown fields are ACCEPTED (they were previously rejected). Rejecting them made the
// receiver refuse every real notification — the documented envelope already carries
// date_time and partner_id, which the old struct did not declare — and would break again
// on any additive PSP change. The mass-assignment concern it guarded against does not
// apply: this is a fixed struct, so an unknown field binds to nothing. The controls that
// actually matter stay: the 64 KiB cap, the channel-derived tenant, and authoritative
// reconciliation.
type c6WebhookNotification struct {
	ExternalID string `json:"external_id"` // proprietary: object id → reconcile key
	ClientID   string `json:"client_id"`   // C6 merchant id → cross-checked, not trusted
	Service    string `json:"service"`     // PIX | BANK_SLIP | BANK_SLIP_PIX | CHECKOUT
	Status     string `json:"status"`      // advisory only; never the settle decision

	// Information is the PIX envelope's payload: a JSON document carried AS A STRING.
	Information string `json:"information"`
	// Pix is the same payload UNWRAPPED. Both registrations point at this one URL — the
	// BACEN one (PUT /v2/pix/webhook/{chave}) and the proprietary one — so the received
	// PIX may arrive either nested in `information` or as a top-level array.
	Pix []pixReceived `json:"pix"`

	// IDRec/TxID discriminate the two recurrence streams, which carry no `service`.
	IDRec string `json:"idRec"`
	TxID  string `json:"txid"`
}

// pixReceived is one received PIX. Only the end-to-end id is read: it is the reconcile
// key, and everything else in the payload is advisory.
type pixReceived struct {
	EndToEndID string `json:"endToEndId"`
}

// pixInformation is the JSON nested inside WebhookNotificationPix.information.
type pixInformation struct {
	Pix []pixReceived `json:"pix"`
}

// firstEndToEndID returns the first non-empty end-to-end id in a received-PIX list.
func firstEndToEndID(list []pixReceived) string {
	for _, p := range list {
		if e2e := strings.TrimSpace(p.EndToEndID); e2e != "" {
			return e2e
		}
	}
	return ""
}

// webhookKind is the resolved routing decision for one notification.
type webhookKind int

const (
	webhookKindPayment webhookKind = iota
	webhookKindCheckout
	webhookKindRec
	webhookKindCobR
)

// resolveWebhook classifies an inbound notification and extracts its reconcile id.
// Routing is by the DOCUMENTED discriminators: `service` for the proprietary envelope and
// PIX, and the presence of idRec/txid for the two BACEN recurrence streams. It reports
// ok=false when nothing identifies the event, which the caller turns into a 400 — better
// than reconciling against an empty id.
func resolveWebhook(note c6WebhookNotification) (kind webhookKind, id, label string, ok bool) {
	switch {
	case strings.EqualFold(note.Service, webhookServicePix):
		// The documented PIX envelope has NO external_id: the end-to-end id is the
		// reconcile key. It can reach us three ways, so all three are accepted rather
		// than betting on one — a settled PIX that cannot be identified is money we
		// never reconcile.
		if e2e := firstEndToEndID(note.Pix); e2e != "" {
			return webhookKindPayment, e2e, webhookServicePix, true
		}
		if note.Information != "" {
			var info pixInformation
			if err := json.Unmarshal([]byte(note.Information), &info); err == nil {
				if e2e := firstEndToEndID(info.Pix); e2e != "" {
					return webhookKindPayment, e2e, webhookServicePix, true
				}
			}
		}
		if note.ExternalID != "" {
			return webhookKindPayment, note.ExternalID, webhookServicePix, true
		}
		return 0, "", "", false
	case note.IDRec != "" && note.TxID != "":
		return webhookKindCobR, note.TxID, webhookLabelCobR, true
	case note.IDRec != "":
		return webhookKindRec, note.IDRec, webhookLabelRec, true
	// The recurrence streams carry idRec/txid in the published contract and no `service`.
	// These two service tokens were assumed before that contract was available and were
	// never confirmed against the bank; they are kept as a fallback so a deployment that
	// does receive them keeps working, but the cases above are the documented path.
	case strings.EqualFold(note.Service, webhookLabelRec) && note.ExternalID != "":
		return webhookKindRec, note.ExternalID, webhookLabelRec, true
	case strings.EqualFold(note.Service, webhookLabelCobR) && note.ExternalID != "":
		return webhookKindCobR, note.ExternalID, webhookLabelCobR, true
	case strings.EqualFold(note.Service, webhookServiceCheckout):
		return webhookKindCheckout, note.ExternalID, webhookServiceCheckout, note.ExternalID != ""
	case note.ExternalID != "":
		// BANK_SLIP / BANK_SLIP_PIX and anything else identified by external_id.
		return webhookKindPayment, note.ExternalID, strings.ToLower(note.Service), true
	}
	return 0, "", "", false
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
	//    Prefer the context-aware resolution (SIN-69559 / F1) so a ref minted after
	//    boot is resolved from the durable store with the request context propagated;
	//    fall back to the legacy context-free method for authenticators without a store.
	ref := chi.URLParam(r, "tenantRef")
	var id WebhookIdentity
	var ok bool
	if ca, isCtx := s.webhookAuth.(ContextualWebhookAuthenticator); isCtx {
		id, ok = ca.AuthenticateWebhookCtx(r.Context(), ref)
	} else {
		id, ok = s.webhookAuth.AuthenticateWebhook(ref)
	}
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	// 2. Cap and decode the untrusted body. Oversize → 413 (distinct from a
	//    malformed body's 400) so the cap is observable.
	r.Body = http.MaxBytesReader(w, r.Body, maxWebhookBytes)
	var note c6WebhookNotification
	dec := json.NewDecoder(r.Body)
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

	// 4. Dispatch with the CHANNEL tenant. EventKey distinguishes state transitions
	//    of the same object (e.g. pending→paid) while collapsing exact redeliveries,
	//    so anti-replay dedup (processed_events) suppresses duplicates without
	//    dropping a genuine settle. Retention of processed_events is INDEFINITE: the
	//    C6 contract signs nothing (no timestamp), so dedup is the only replay
	//    barrier and pruning a key would reopen a replay window. A bounded
	//    signed-timestamp window is deferred to SIN-64762 (if C6 ever signs).
	//
	//    The resolved kind selects which authoritative state to reconcile before
	//    settling. Every path shares the same dedup + reconcile-before-settle unit of
	//    work, and the EventKey carries the kind label, so a checkout and a charge event
	//    for the same id never collide.
	kind, objectID, label, ok := resolveWebhook(note)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	eventKey := objectID + "|" + label + "|" + note.Status

	var err error
	switch kind {
	case webhookKindCheckout:
		err = s.webhooks.HandleCheckoutEvent(r.Context(), app.PaymentEvent{
			TenantID: id.TenantID, TxID: objectID, EventKey: eventKey,
		})
	case webhookKindRec:
		err = s.webhooks.HandleRecEvent(r.Context(), app.RecEvent{
			TenantID: id.TenantID, IDRec: objectID, EventKey: eventKey,
		})
	case webhookKindCobR:
		err = s.webhooks.HandleCobREvent(r.Context(), app.CobREvent{
			TenantID: id.TenantID, TxID: objectID, EventKey: eventKey,
		})
	default:
		err = s.webhooks.HandlePaymentEvent(r.Context(), app.PaymentEvent{
			TenantID: id.TenantID, TxID: objectID, EventKey: eventKey,
		})
	}
	if err != nil {
		writeDomainError(w, err)
		return
	}
	// 202: accepted; reconciliation/settlement already attempted synchronously.
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
}

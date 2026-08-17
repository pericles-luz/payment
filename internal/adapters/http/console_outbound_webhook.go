package http

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/adminweb"
	"github.com/ia-dev-sindireceita/payment/internal/domain/account"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

// console_outbound_webhook.go is the server-rendered HTMX console for a Conta's
// OUTBOUND webhook configuration (SIN-69490, F0 of SIN-69486, model (b) ADR-0011). It
// is DARK behind PAYMENT_ACCOUNT_OUTBOUND_WEBHOOK: when off the routes here are not
// registered and the card is hidden, so the current flow is entirely unaffected.
//
// Every route joins the existing /console admin mutation group, so it inherits
// deny-by-default admin auth, session + CSRF and the per-admin rate limit — nothing
// here re-implements security. The config is account-scoped: the account id comes from
// the path and is validated (and refused for a derived self-account) by the app
// service, so one Conta can never read or write another's endpoint (OWASP A01). The
// signing secret is WRITE-ONLY — it is shown display-once on set/rotate and NEVER
// rendered from a read (no read path echoes it); output is auto-escaped by
// html/template and no secret is logged.

// outboundWebhookCardEnabled reports whether the "Webhook de saída" card should render
// for account a: only when the dark flag is on AND a is a real Conta. A derived
// self-account (the legacy 1:1 backfill) has no outbound webhook — the app service
// refuses it — so its card is hidden (defense-in-depth alongside the service guard).
func (s *Server) outboundWebhookCardEnabled(a *account.Account) bool {
	return s.accountOutboundWebhook && !account.IsSelfAccountID(a.ID())
}

// outboundWebhookCardView assembles the card view-model for a Conta from the current
// config state (empty when none). It never surfaces the signing secret (write-only).
func (s *Server) outboundWebhookCardView(ctx context.Context, acctID string) (adminweb.OutboundWebhookCardView, error) {
	cfg, ok, err := s.console.GetOutboundWebhook(ctx, acctID)
	if err != nil {
		return adminweb.OutboundWebhookCardView{}, err
	}
	return adminweb.ToOutboundWebhookCardView(acctID, cfg, ok), nil
}

// consoleOutboundWebhookCard renders the card region on demand (e.g. a lazy fragment
// load). It is account-scoped: a bad/self account 404s cleanly via the service guard.
func (s *Server) consoleOutboundWebhookCard(w http.ResponseWriter, r *http.Request) {
	acctID := chi.URLParam(r, "acctId")
	view, err := s.outboundWebhookCardView(r.Context(), acctID)
	if err != nil {
		s.consoleError(w, err)
		return
	}
	s.ui.Partial(w, http.StatusOK, "outbound_webhook_card", view)
}

// parseCheckbox reads an HTML checkbox form value: present + truthy ("on"/"1"/"true")
// means checked, absent/anything-else means unchecked (a checkbox omits its value when
// unchecked, so absence is the correct "false").
func parseCheckbox(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "on", "1", "true", "yes":
		return true
	default:
		return false
	}
}

// consoleSetOutboundWebhook creates or updates a Conta's outbound webhook endpoint
// (URL + enabled) from the card form. On FIRST provisioning the app mints a signing
// secret and this returns the display-once result region; on an update it swaps the
// refreshed card plus a toast. A validation error (bad/non-https URL) re-renders the
// card inline (422) with the field error, echoing the submitted URL. A bad/self
// account 404s and a wiring gap 503s via consoleError.
func (s *Server) consoleSetOutboundWebhook(w http.ResponseWriter, r *http.Request) {
	acctID := chi.URLParam(r, "acctId")
	rawURL := strings.TrimSpace(r.PostFormValue("url"))
	enabled := parseCheckbox(r.PostFormValue("enabled"))
	cfg, secret, err := s.console.SetOutboundWebhook(r.Context(), acctID, rawURL, enabled)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) || isServiceError(err) {
			s.consoleError(w, err)
			return
		}
		// Validation error (URL): re-render the card inline with the field error,
		// echoing the submitted URL so the operator can fix it in place.
		card := adminweb.OutboundWebhookCardView{
			Webhook: adminweb.OutboundWebhookView{AccountID: strings.TrimSpace(acctID), URL: rawURL, Enabled: enabled},
			Errors:  fieldErrors(err, "url"),
		}
		s.ui.Partial(w, http.StatusUnprocessableEntity, "outbound_webhook_card", card)
		return
	}
	card := adminweb.ToOutboundWebhookCardView(cfg.AccountID(), cfg, true)
	if secret != "" {
		// First provisioning: show the signing secret EXACTLY once. no-store so a
		// back/refresh/cache never resurfaces it.
		w.Header().Set("Cache-Control", "no-store")
		s.ui.Partial(w, http.StatusOK, "outbound_webhook_result",
			adminweb.OutboundWebhookResultView{Secret: secret, Card: card})
		return
	}
	// Update: swap the refreshed card and toast (no secret changed).
	s.ui.Partials(w, http.StatusOK,
		adminweb.OOBPart{Name: "outbound_webhook_card", Data: card},
		adminweb.OOBPart{Name: "toast_oob", Data: adminweb.ToastData{Kind: "success", Message: "Webhook de saída atualizado."}})
}

// consoleRotateOutboundWebhookSecret mints a NEW signing secret for an already-
// configured Conta, invalidating the previous one, and returns the display-once
// result region. A missing endpoint 404s (nothing to rotate); a bad/self account 404s.
func (s *Server) consoleRotateOutboundWebhookSecret(w http.ResponseWriter, r *http.Request) {
	acctID := chi.URLParam(r, "acctId")
	cfg, secret, err := s.console.RotateOutboundWebhookSecret(r.Context(), acctID)
	if err != nil {
		s.consoleError(w, err)
		return
	}
	// The response carries the plaintext exactly once; never let it be cached/replayed.
	w.Header().Set("Cache-Control", "no-store")
	s.ui.Partial(w, http.StatusOK, "outbound_webhook_result",
		adminweb.OutboundWebhookResultView{Secret: secret, Card: adminweb.ToOutboundWebhookCardView(cfg.AccountID(), cfg, true)})
}

// consoleRemoveOutboundWebhook hard-deletes a Conta's outbound webhook config
// (idempotent) and swaps the empty-state card plus a toast. A bad/self account 404s.
func (s *Server) consoleRemoveOutboundWebhook(w http.ResponseWriter, r *http.Request) {
	acctID := chi.URLParam(r, "acctId")
	if err := s.console.RemoveOutboundWebhook(r.Context(), acctID); err != nil {
		s.consoleError(w, err)
		return
	}
	card := adminweb.ToOutboundWebhookCardView(strings.TrimSpace(acctID), nil, false)
	s.ui.Partials(w, http.StatusOK,
		adminweb.OOBPart{Name: "outbound_webhook_card", Data: card},
		adminweb.OOBPart{Name: "toast_oob", Data: adminweb.ToastData{Kind: "success", Message: "Webhook de saída removido."}})
}

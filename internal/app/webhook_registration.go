package app

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/domain/webhookref"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// webhookCallbackPathPrefix is the inbound C6 callback path the registered URL is
// built from: /webhooks/c6/{ref}. The trailing segment is the secret per-tenant ref,
// so a full URL under this prefix MUST NEVER be logged (only that a registration was
// attempted/succeeded, plus the masked PIX key). It mirrors the path the one-shot
// cmd/register-webhook and the inbound receiver already use.
const webhookCallbackPathPrefix = "/webhooks/c6/"

// WebhookRegistrationService registers a self-serve empresa-cliente's PIX settlement
// webhook with C6 IN-FLOW, the moment its credential and PIX creditor key are both in
// place (SIN-69560 / F2 of SIN-69558). It closes the self-serve settlement gap
// (SIN-69557): a client provisioned through model (b) — POST /v1/clients then a
// self-serve credential/certificate write and an operator PIX-key set — is registered
// at the PSP with NO manual cmd run and NO restart.
//
// It is deliberately BEST-EFFORT (mirroring the outbound-webhook forward, internal/app/
// webhook.go): a PSP-side failure NEVER aborts the provisioning write nor surfaces an
// error to the HTTP caller — TryRegister returns nothing. The happy path of the
// self-serve write must never regress because the bank is briefly unavailable; the
// operator can re-run cmd/register-webhook (F3) or a later self-serve write retries.
//
// Ref availability (design note for review — the F1/F2 seam). F1's durable store keeps
// ONLY sha256(ref)→tenant; the plaintext ref is display-once at mint (POST /v1/clients)
// and is unrecoverable afterwards. The convergence point where cred+key complete is a
// LATER request, so the original plaintext is gone. To build the callback URL here we
// therefore MINT a fresh ref through the same F1 mint service (which persists its hash
// and returns the plaintext once, in-process). Every minted ref's hash resolves to the
// same tenant inbound, so multiple refs are all valid capability URLs for that tenant.
// To keep that set from growing on every write, registration is GATED on a GET: if C6
// already holds a callback under our base origin for this key, we skip WITHOUT minting.
// So the steady state is exactly one ref per (tenant, PIX key) — first convergence mints
// and registers, later ones are no-ops. This is NOT user-facing ref rotation (the
// plaintext never leaves the process; it is consumed only to PUT at C6).
//
// SECURITY: the minted ref and the full /webhooks/c6/{ref} URL are secrets — they are
// never logged, never returned, never put in an error. The PIX key is masked in logs.
// The tenant id (a non-secret grouping id) is logged so an operator can correlate.
type WebhookRegistrationService struct {
	creds        ports.CredentialStore
	registrar    ports.PixWebhookRegistrar
	recRegistrar ports.RecurrenceWebhookRegistrar
	svcRegistrar ports.ServiceWebhookRegistrar
	services     []string
	minter       webhookRefMinter
	refs         webhookRefLookup
	baseURL      string
	logger       *slog.Logger
}

// webhookRefLookup is the narrow slice of ports.WebhookRefStore the idempotency gate
// needs: resolve a ref's sha256 to its owning tenant. Revoked refs do not resolve, which
// is exactly the property the gate relies on to tell a live registration from a stale one.
type webhookRefLookup interface {
	LookupWebhookRef(ctx context.Context, refSHA []byte) (tenantID string, ok bool, err error)
}

// registrationState classifies what C6 currently holds for a tenant's PIX key.
type registrationState int

const (
	// registrationLive: the registered URL carries an ACTIVE ref of this tenant, so
	// callbacks through it authenticate. Nothing to do.
	registrationLive registrationState = iota
	// registrationStale: no ref, a foreign origin, a revoked/superseded ref, or a ref
	// owned by another tenant. Callbacks through it are dead — replace the registration.
	registrationStale
	// registrationUnknown: the ref store could not answer. Neither conclusion is safe.
	registrationUnknown
)

// registrationState reports whether the URL C6 holds is one this tenant can actually be
// reached through. With no ref lookup wired it degrades to the historical prefix check, so
// a deployment without the durable store behaves exactly as before.
func (s *WebhookRegistrationService) registrationState(ctx context.Context, tenantID, registeredURL string) registrationState {
	prefix := s.baseURL + webhookCallbackPathPrefix
	if !strings.HasPrefix(registeredURL, prefix) {
		return registrationStale
	}
	ref := strings.TrimPrefix(registeredURL, prefix)
	if ref == "" {
		return registrationStale
	}
	if s.refs == nil {
		return registrationLive // pre-F1 behaviour: origin prefix is all we can check
	}
	sum := webhookref.Sum(ref)
	owner, ok, err := s.refs.LookupWebhookRef(ctx, sum[:])
	if err != nil {
		return registrationUnknown
	}
	if !ok || owner != tenantID {
		return registrationStale
	}
	return registrationLive
}

// NewWebhookRegistrationService wires the in-flow registrar over the credential store
// (to resolve the PIX key from the vault), the PSP webhook-registrar port, the F1 ref
// minter, and the public callback base origin. If ANY dependency is missing (nil store/
// registrar/minter or an empty/blank baseURL) TryRegister is an inert no-op — a
// stripped-down deployment (stub bank, feature not wired) never attempts a registration
// and never errors. A nil logger falls back to slog.Default.
func NewWebhookRegistrationService(creds ports.CredentialStore, registrar ports.PixWebhookRegistrar, minter webhookRefMinter, baseURL string, logger *slog.Logger) *WebhookRegistrationService {
	if logger == nil {
		logger = slog.Default()
	}
	return &WebhookRegistrationService{
		creds:     creds,
		registrar: registrar,
		minter:    minter,
		baseURL:   strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		logger:    logger,
	}
}

// WithRefLookup wires the durable ref store so the idempotency gate can tell a LIVE
// registration (active ref of this tenant) from a stale one (revoked, superseded or
// foreign ref). Optional by design: without it the gate keeps the historical
// origin-prefix behaviour, so existing wiring and tests are unaffected.
func (s *WebhookRegistrationService) WithRefLookup(refs webhookRefLookup) *WebhookRegistrationService {
	if s != nil {
		s.refs = refs
	}
	return s
}

// WithRecurrenceRegistrar adds the two BACEN recurrence channels (mandate + recurring
// charge) to the set registered in-flow. Optional: unwired, those channels are simply not
// part of the tenant's channel set, and behaviour is exactly as before.
func (s *WebhookRegistrationService) WithRecurrenceRegistrar(r ports.RecurrenceWebhookRegistrar) *WebhookRegistrationService {
	if s != nil {
		s.recRegistrar = r
	}
	return s
}

// WithServiceRegistrar adds PSP-proprietary, per-service channels (checkout, boleto) to
// the set registered in-flow. The service list is EXPLICIT rather than "everything the
// PSP supports": registering a channel whose inbound flow does not exist yet would make
// the PSP deliver notifications the receiver cannot process. Optional; an empty list
// leaves the proprietary channels alone.
func (s *WebhookRegistrationService) WithServiceRegistrar(r ports.ServiceWebhookRegistrar, services ...string) *WebhookRegistrationService {
	if s != nil && len(services) > 0 {
		s.svcRegistrar = r
		s.services = services
	}
	return s
}

// ready reports whether every dependency needed to attempt a registration is wired.
// When false TryRegister returns immediately (no-op), so callers can invoke it
// unconditionally without a nil check.
func (s *WebhookRegistrationService) ready() bool {
	return s != nil && s.creds != nil && s.registrar != nil && s.minter != nil && s.baseURL != ""
}

// TryRegister attempts to register (and confirm) tenantID's PIX settlement webhook with
// C6, best-effort. It NEVER returns an error and NEVER panics on a missing dependency —
// a caller wires it into a self-serve write path and ignores the outcome. The steps:
//
//  1. Resolve the tenant's C6 credential from the vault. ErrNotFound (no credential yet)
//     or an empty creditor key means the cred+key pair is not complete — skip silently.
//  2. Read EVERY wired channel (PIX settlement, the two recurrence callbacks, and any
//     proprietary per-service ones). Skip WITHOUT minting only when all of them carry an
//     ACTIVE ref of THIS tenant. A NotFound, a foreign origin, or a ref that is
//     revoked/superseded/owned by someone else means callbacks through it are dead, so we
//     re-register. Any PSP read error — or a ref-store fault — is ambiguous, so we skip
//     rather than mint a ref on every pass.
//  3. Mint ONE fresh ref (hash persisted by F1), build the callback URL, and write it to
//     every channel, confirming each by readback. All channels share the ref because the
//     PSP routes by the service discriminator in the notification, not by the URL — which
//     is also why a mint must be followed by re-registering ALL of them: the superseded
//     ref is dead everywhere at once. Per-channel failures are logged (masked key and
//     channel, NEVER the ref/URL) and swallowed, so one bad channel cannot abort the rest.
func (s *WebhookRegistrationService) TryRegister(ctx context.Context, tenantID string) {
	if !s.ready() {
		return
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return
	}

	cred, err := s.creds.GetBankCredential(ctx, tenantID, ports.BankIDC6)
	if err != nil {
		if !errors.Is(err, shared.ErrNotFound) {
			// A real infrastructure error reading the vault — surface it (masked) but do
			// not fail the caller. A missing credential (ErrNotFound) is the normal
			// "not complete yet" case and is silent.
			s.logger.WarnContext(ctx, "webhook in-flow registration: credential lookup failed",
				slog.String("tenant_id", tenantID), slog.String("error", err.Error()))
		}
		return
	}
	chave := strings.TrimSpace(cred.CreditorKey)
	if chave == "" {
		// Credential present but no PIX key yet — the pair is not complete. Skip.
		return
	}

	channels := s.channelsFor(tenantID, chave)

	// Idempotency gate, evaluated across EVERY channel. Skipping requires all of them to
	// be reachable — one ref serves them all, so a mint replaces the ref for all of them
	// at once and any channel still holding the superseded ref is dead. Checking only the
	// PIX channel (the pre-SIN-69580 behaviour) let the others rot silently.
	//
	// A channel is reachable only when the ref in the URL C6 holds is an ACTIVE ref of this
	// tenant. A URL merely sitting under our origin is not enough: a revoked, superseded or
	// foreign ref satisfies a prefix check while every callback through it 404s at the
	// receiver, and the registration could then never self-heal.
	switch s.gate(ctx, tenantID, chave, channels) {
	case gateSatisfied:
		return
	case gateAmbiguous:
		// Either the PSP or the ref store could not answer. Registering now would mint a
		// fresh ref on every sweep (churn) against an unknown state — skip and re-evaluate
		// on the next pass.
		return
	case gateNeedsRegistration:
	}

	// ONE mint for every channel. This supersedes the tenant's previous active ref, so
	// every channel below MUST be re-registered — including ones that were already live.
	ref, err := s.minter.MintWebhookRef(ctx, tenantID)
	if err != nil {
		s.logger.WarnContext(ctx, "webhook in-flow registration: mint ref failed",
			slog.String("tenant_id", tenantID), slog.String("error", err.Error()))
		return
	}
	callbackURL := s.baseURL + webhookCallbackPathPrefix + ref

	var registered, failed int
	for _, ch := range channels {
		if s.registerChannel(ctx, tenantID, chave, ch, callbackURL) {
			registered++
			continue
		}
		failed++
	}

	// One summary line per attempt. Per-channel failures are already logged individually;
	// this makes "3 of 4 channels are live" visible without correlating lines.
	attrs := []any{
		slog.String("tenant_id", tenantID),
		slog.String("pix_key", maskPixKey(chave)),
		slog.Int("channels_registered", registered),
		slog.Int("channels_failed", failed),
	}
	if failed > 0 {
		s.logger.WarnContext(ctx, "webhook in-flow registration: partially registered", attrs...)
		return
	}
	s.logger.InfoContext(ctx, "webhook in-flow registration: registered and confirmed", attrs...)
}

// webhookChannel is one PSP notification channel. All of a tenant's channels point at the
// SAME callback URL — the PSP routes by the service discriminator it echoes in the
// notification body, which the inbound receiver switches on.
type webhookChannel struct {
	name     string
	get      func(context.Context) (ports.WebhookRegistration, error)
	register func(context.Context, string) error
}

// channelsFor builds the channel set this deployment can actually drive. The recurrence
// and proprietary registrars are optional dependencies, so a deployment that has not wired
// them keeps exactly the previous single-channel behaviour.
func (s *WebhookRegistrationService) channelsFor(tenantID, chave string) []webhookChannel {
	channels := []webhookChannel{{
		name: "pix",
		get: func(ctx context.Context) (ports.WebhookRegistration, error) {
			return s.registrar.GetWebhook(ctx, tenantID, chave)
		},
		register: func(ctx context.Context, url string) error {
			return s.registrar.RegisterWebhook(ctx, tenantID, chave, url)
		},
	}}
	if s.recRegistrar != nil {
		channels = append(channels,
			webhookChannel{
				name: "rec",
				get: func(ctx context.Context) (ports.WebhookRegistration, error) {
					return s.recRegistrar.GetRecWebhook(ctx, tenantID)
				},
				register: func(ctx context.Context, url string) error {
					return s.recRegistrar.RegisterRecWebhook(ctx, tenantID, url)
				},
			},
			webhookChannel{
				name: "cobr",
				get: func(ctx context.Context) (ports.WebhookRegistration, error) {
					return s.recRegistrar.GetCobRWebhook(ctx, tenantID)
				},
				register: func(ctx context.Context, url string) error {
					return s.recRegistrar.RegisterCobRWebhook(ctx, tenantID, url)
				},
			})
	}
	if s.svcRegistrar != nil {
		for _, svc := range s.services {
			svc := svc
			channels = append(channels, webhookChannel{
				name: strings.ToLower(svc),
				get: func(ctx context.Context) (ports.WebhookRegistration, error) {
					return s.svcRegistrar.GetServiceWebhook(ctx, tenantID, svc)
				},
				register: func(ctx context.Context, url string) error {
					return s.svcRegistrar.RegisterServiceWebhook(ctx, tenantID, svc, url)
				},
			})
		}
	}
	return channels
}

// gateDecision is the aggregate verdict over every channel.
type gateDecision int

const (
	// gateSatisfied: every channel is reachable through an active ref — nothing to do.
	gateSatisfied gateDecision = iota
	// gateNeedsRegistration: at least one channel is unregistered or stale.
	gateNeedsRegistration
	// gateAmbiguous: some channel could not be classified; acting would risk ref churn.
	gateAmbiguous
)

func (s *WebhookRegistrationService) gate(ctx context.Context, tenantID, chave string, channels []webhookChannel) gateDecision {
	needs := false
	for _, ch := range channels {
		existing, err := ch.get(ctx)
		switch {
		case errors.Is(err, shared.ErrNotFound):
			needs = true
			continue
		case err != nil:
			s.logger.WarnContext(ctx, "webhook in-flow registration: readback failed, skipping",
				slog.String("tenant_id", tenantID), slog.String("channel", ch.name),
				slog.String("pix_key", maskPixKey(chave)), slog.String("error", err.Error()))
			return gateAmbiguous
		}
		switch s.registrationState(ctx, tenantID, existing.WebhookURL) {
		case registrationLive:
		case registrationStale:
			needs = true
		case registrationUnknown:
			s.logger.WarnContext(ctx, "webhook in-flow registration: ref lookup failed, skipping",
				slog.String("tenant_id", tenantID), slog.String("channel", ch.name),
				slog.String("pix_key", maskPixKey(chave)))
			return gateAmbiguous
		}
	}
	if needs {
		return gateNeedsRegistration
	}
	return gateSatisfied
}

// registerChannel registers one channel and confirms it by readback. It reports success;
// every failure is logged (masked key and channel name, NEVER the ref or the URL) and
// swallowed, so one bad channel cannot abort the others.
func (s *WebhookRegistrationService) registerChannel(ctx context.Context, tenantID, chave string, ch webhookChannel, callbackURL string) bool {
	logAttrs := func(extra ...any) []any {
		return append([]any{
			slog.String("tenant_id", tenantID),
			slog.String("channel", ch.name),
			slog.String("pix_key", maskPixKey(chave)),
		}, extra...)
	}
	if err := ch.register(ctx, callbackURL); err != nil {
		s.logger.WarnContext(ctx, "webhook in-flow registration: register failed",
			logAttrs(slog.String("error", err.Error()))...)
		return false
	}
	got, err := ch.get(ctx)
	if err != nil {
		s.logger.WarnContext(ctx, "webhook in-flow registration: registered but confirm failed",
			logAttrs(slog.String("error", err.Error()))...)
		return false
	}
	if got.WebhookURL != callbackURL {
		// The PSP holds a DIFFERENT URL than we just wrote — surface it WITHOUT printing
		// either URL (both embed the secret ref).
		s.logger.WarnContext(ctx, "webhook in-flow registration: confirmation mismatch", logAttrs()...)
		return false
	}
	return true
}

// maskPixKey renders a PIX key for logs without exposing the full routing-sensitive
// value (a CPF/CNPJ/email/EVP is PII / fund-routing data, threat C4). It keeps the
// first and last character and masks the middle; a short key is fully masked. It
// mirrors cmd/register-webhook's maskKey so the two surfaces log keys identically.
func maskPixKey(key string) string {
	if len(key) <= 4 {
		return "****"
	}
	return key[:1] + "***" + key[len(key)-1:]
}

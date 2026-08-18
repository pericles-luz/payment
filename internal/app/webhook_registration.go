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
	creds     ports.CredentialStore
	registrar ports.PixWebhookRegistrar
	minter    webhookRefMinter
	refs      webhookRefLookup
	baseURL   string
	logger    *slog.Logger
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
//  2. GET the currently-registered webhook for the key. Skip WITHOUT minting only when
//     the registered URL carries an ACTIVE ref of THIS tenant (idempotent, bounds ref
//     proliferation). A NotFound, a foreign origin, or a ref that is revoked/superseded/
//     owned by someone else means callbacks through it are dead, so we replace it. Any
//     other GET error — or a ref-store fault — is ambiguous, so we skip rather than mint
//     a ref on every pass.
//  3. Mint a fresh ref (hash persisted by F1), build the callback URL, PUT it, then GET
//     to confirm the readback matches. Every failure is logged (masked key, NEVER the
//     ref/URL) and swallowed.
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

	// Idempotency gate: skip only when C6 holds a callback that this tenant can actually
	// be reached through — i.e. one whose ref is an ACTIVE ref of this tenant. A URL that
	// merely sits under our origin is not enough (SIN-69580): a revoked, superseded or
	// foreign ref would satisfy a prefix check while every callback through it 404s at the
	// receiver, and the registration could then never self-heal — defeating the reconcile
	// sweep it is supposed to make idempotent.
	if existing, gerr := s.registrar.GetWebhook(ctx, tenantID, chave); gerr == nil {
		switch s.registrationState(ctx, tenantID, existing.WebhookURL) {
		case registrationLive:
			return
		case registrationUnknown:
			// Ref-store fault: re-registering would mint a fresh ref on every sweep
			// (churn). Skip; the next sweep re-evaluates.
			s.logger.WarnContext(ctx, "webhook in-flow registration: ref lookup failed, skipping",
				slog.String("tenant_id", tenantID), slog.String("pix_key", maskPixKey(chave)))
			return
		case registrationStale:
			// Registered URL is not reachable for this tenant — fall through and replace it.
		}
	} else if !errors.Is(gerr, shared.ErrNotFound) {
		// Ambiguous PSP state (transport/5xx): do not mint a ref against an unknown
		// registration state — skip and let a later write retry.
		s.logger.WarnContext(ctx, "webhook in-flow registration: readback failed, skipping",
			slog.String("tenant_id", tenantID), slog.String("pix_key", maskPixKey(chave)),
			slog.String("error", gerr.Error()))
		return
	}

	ref, err := s.minter.MintWebhookRef(ctx, tenantID)
	if err != nil {
		s.logger.WarnContext(ctx, "webhook in-flow registration: mint ref failed",
			slog.String("tenant_id", tenantID), slog.String("error", err.Error()))
		return
	}
	callbackURL := s.baseURL + webhookCallbackPathPrefix + ref

	if err := s.registrar.RegisterWebhook(ctx, tenantID, chave, callbackURL); err != nil {
		s.logger.WarnContext(ctx, "webhook in-flow registration: register failed",
			slog.String("tenant_id", tenantID), slog.String("pix_key", maskPixKey(chave)),
			slog.String("error", err.Error()))
		return
	}

	// Confirm by GET (same readback the one-shot cmd does) — a registration that cannot
	// be confirmed is reported (masked) but still not fatal.
	got, err := s.registrar.GetWebhook(ctx, tenantID, chave)
	if err != nil {
		s.logger.WarnContext(ctx, "webhook in-flow registration: registered but confirm failed",
			slog.String("tenant_id", tenantID), slog.String("pix_key", maskPixKey(chave)),
			slog.String("error", err.Error()))
		return
	}
	if got.WebhookURL != callbackURL {
		// The PSP holds a DIFFERENT URL than we just PUT — surface it WITHOUT printing
		// either URL (both embed the secret ref).
		s.logger.WarnContext(ctx, "webhook in-flow registration: confirmation mismatch",
			slog.String("tenant_id", tenantID), slog.String("pix_key", maskPixKey(chave)))
		return
	}

	s.logger.InfoContext(ctx, "webhook in-flow registration: registered and confirmed",
		slog.String("tenant_id", tenantID), slog.String("pix_key", maskPixKey(chave)))
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

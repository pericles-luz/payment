package app

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
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
	baseURL   string
	logger    *slog.Logger
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
//  2. GET the currently-registered webhook for the key. If C6 already holds a callback
//     under our base origin, the registration is already in place — skip WITHOUT minting
//     (idempotent, bounds ref proliferation). A NotFound or a foreign URL means we
//     (re)register; any other GET error is ambiguous, so we skip rather than risk minting
//     a duplicate ref.
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

	// Idempotency gate: if C6 already holds a callback under our origin for this key,
	// the webhook is registered — do nothing (and mint nothing).
	if existing, gerr := s.registrar.GetWebhook(ctx, tenantID, chave); gerr == nil {
		if strings.HasPrefix(existing.WebhookURL, s.baseURL+webhookCallbackPathPrefix) {
			return
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

// Command register-webhook is a one-shot operator entrypoint that registers the
// PIX settlement webhook URL with C6 for every configured tenant, then reads it
// back to confirm. It MUST run from the receiver VPS, where the mTLS client
// certificate (PAYMENT_C6_CLIENT_CERT/KEY) is mounted — the cert is a secret that
// never leaves that host (threat C1), so registration cannot be done by curl from
// anywhere else. It reuses the same mTLS C6 adapter the API serves with, so the
// wire/auth path is exactly the one proven in production.
//
// It is idempotent: the C6 webhook is keyed by PIX key (chave do recebedor), so a
// re-run PUTs the same URL and replaces rather than duplicates. The callback URL
// embeds a secret per-tenant ref (/webhooks/c6/{ref}) and is NEVER logged; only
// non-sensitive identifiers (tenant id, a masked PIX key) and the outcome are
// emitted.
//
// Durable sources (SIN-69561 / F3). A self-serve client provisioned via the model-(b)
// self-serve flow keeps its OAuth credential AND its PIX creditor key in the durable,
// encrypted vault (migration 0012), and its webhook ref binding in the durable
// WebhookRefStore (migration 0016 / F1) — not in the bootstrap envs. When
// PAYMENT_BANK_VAULT_KEY is set this command opens that vault and resolves BOTH the
// bearer-token credential and the chave from it FIRST, falling back to the env bootstrap
// (PAYMENT_BANK_CREDS / PAYMENT_BANK_CREDITOR_KEYS) — so the command sees self-serve
// clients too. The plaintext ref stays operator-supplied via PAYMENT_WEBHOOK_REFS (the
// durable store holds only the ref's hash, by F1's bearer-capability design); each such
// ref is bound to its AUTHORITATIVE tenant via the durable store before registration.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/bank/c6"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/system"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/platform/config"
	"github.com/ia-dev-sindireceita/payment/internal/platform/persistence"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// defaultWebhookBaseURL is the receiver's public origin. The callback path is
// /webhooks/c6/{tenantRef} (the inbound surface from SIN-65856/65858). Overridable
// via PAYMENT_WEBHOOK_BASE_URL for staging.
const defaultWebhookBaseURL = "https://payment.lmhost.com.br"

func main() {
	if err := run(log.New(os.Stdout, "", log.LstdFlags)); err != nil {
		log.Fatalf("register-webhook: %v", err)
	}
}

// run wires the mTLS C6 adapter from the environment and registers+confirms the
// webhook for every configured tenant ref. logger is injected so the flow is
// testable without touching process globals; configuration is read from the
// environment via config.FromEnv (the same loader the api/worker use).
func run(logger *log.Logger) error {
	cfg := config.FromEnv()

	if cfg.C6.BaseURL == "" {
		return errors.New("PAYMENT_C6_BASE_URL not set: refusing to run against the bank stub")
	}
	// mTLS is mandatory: C6 requires a client certificate on the connection in
	// addition to the OAuth2 bearer (secure-by-default). Refuse to run without it
	// rather than silently connecting cert-less.
	if cfg.C6.ClientCertPath == "" || cfg.C6.ClientKeyPath == "" {
		return errors.New("PAYMENT_C6_CLIENT_CERT and PAYMENT_C6_CLIENT_KEY are required (mTLS)")
	}
	if len(cfg.WebhookRefs) == 0 {
		return errors.New("PAYMENT_WEBHOOK_REFS empty: nothing to register (provisioning gate)")
	}

	// Resolve credentials from the durable vault FIRST (self-serve clients) and the env
	// bootstrap SECOND. When no vault KEK is configured this collapses to the env-only
	// store, preserving the pre-F3 behaviour. refResolver is nil in that case, so refs
	// resolve to their env-declared tenant unchanged.
	credStore, refResolver, closeDB, err := durableSources(context.Background(), cfg, logger)
	if err != nil {
		return err
	}
	defer closeDB()

	httpc, err := c6.MTLSHTTPClient(cfg.C6.ClientCertPath, cfg.C6.ClientKeyPath, cfg.C6.Timeout)
	if err != nil {
		return err
	}
	provider, err := c6.New(c6.Config{
		BaseURL:    cfg.C6.BaseURL,
		TokenURL:   cfg.C6.TokenURL,
		Scope:      cfg.C6.Scope,
		Timeout:    cfg.C6.Timeout,
		HTTPClient: httpc,
	}, credStore)
	if err != nil {
		return err
	}

	baseURL := strings.TrimRight(os.Getenv("PAYMENT_WEBHOOK_BASE_URL"), "/")
	if baseURL == "" {
		baseURL = defaultWebhookBaseURL
	}

	// Bind each operator-supplied plaintext ref to its authoritative tenant via the
	// durable store (falling back to the env-declared tenant), producing the effective
	// ref -> tenant map both registration passes consume. A durable-store fault fails the
	// affected ref closed rather than registering against a possibly-wrong binding.
	effectiveRefs, resolveFailures := resolveEffectiveRefs(context.Background(), refResolver, cfg.WebhookRefs, logger)

	// Pre-resolve each tenant's C6 credential (including the chave) from the vault-first
	// store into a tenant-keyed map, exactly the shape registerAll consumes. A self-serve
	// tenant resolves from the durable vault; an env bootstrap tenant from the fallback. A
	// store fault is logged masked and drops the tenant from the map (registerAll then
	// reports the provisioning gap, failing that tenant closed).
	c6Creds := resolveCredsForTenants(context.Background(), credStore, effectiveRefs, logger)

	ctx := context.Background()
	var errs []error
	if resolveFailures > 0 {
		errs = append(errs, fmt.Errorf("%d webhook ref(s) could not be resolved to a tenant", resolveFailures))
	}
	if err := registerAll(ctx, provider, effectiveRefs, c6Creds, baseURL, logger); err != nil {
		errs = append(errs, err)
	}
	// PIX Automático (recorrência) callbacks (SIN-66036): the two singleton
	// recurrence webhooks (webhookrec/webhookcobr) point at the SAME opaque
	// per-tenant channel as the PIX webhook — C6 distinguishes the streams by the
	// service field in the notification body, not by URL. Registering them is keyed
	// by the tenant (no chave), so registerRecurrenceAll only needs the ref→tenant
	// map. Failures are aggregated with the PIX pass so one stream's gap does not
	// hide the other's outcome.
	if err := registerRecurrenceAll(ctx, provider, effectiveRefs, baseURL, logger); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// durableSources builds the credential store and webhook-ref resolver the command reads
// from. When PAYMENT_BANK_VAULT_KEY is set it opens the durable SQLite vault + ref store
// (migrations 0012 / 0016) and returns a vault-first credential store (self-serve clients
// resolve from the vault, env bootstrap as fallback) plus a resolver over the durable ref
// store. When the KEK is unset it returns the plain env-only store and a nil resolver, so
// the command keeps working in pure-bootstrap mode. The returned closer is always safe to
// call (a no-op when no DB was opened).
func durableSources(ctx context.Context, cfg config.Config, logger *log.Logger) (ports.CredentialStore, *app.WebhookRefResolver, func(), error) {
	envStore := secret.NewStore(cfg.BankCreds)
	if cfg.BankVaultKey == "" {
		logger.Printf("durable vault disabled (PAYMENT_BANK_VAULT_KEY unset): resolving credentials and refs from env bootstrap only")
		return envStore, nil, func() {}, nil
	}
	cipher, err := decodeCipher(cfg.BankVaultKey)
	if err != nil {
		return nil, nil, func() {}, fmt.Errorf("PAYMENT_BANK_VAULT_KEY invalid: %w", err)
	}
	db, err := persistence.Open(ctx, cfg.DBDSN, cfg.DBPath)
	if err != nil {
		return nil, nil, func() {}, err
	}
	closer := func() { _ = db.Close() }
	clock := system.Clock{}
	// Vault first, env bootstrap second: a self-serve client resolves from the vault; an
	// env-only bootstrap tenant still resolves via the fallback (SIN-69366 discipline).
	credStore := secret.NewFallbackStore(db.CredentialVault(cipher, clock), envStore)
	refResolver := app.NewWebhookRefResolver(db.WebhookRefStore(clock))
	logger.Printf("durable vault enabled: resolving credentials from the encrypted vault and ref bindings from the durable store, env as fallback")
	return credStore, refResolver, closer, nil
}

// resolveEffectiveRefs maps each env-declared (ref -> tenant) entry to its effective
// tenant using the durable store (authoritative), falling back to the env tenant. It
// returns the resolved ref -> tenant map and the count of refs that could NOT be resolved
// (a durable-store fault or an unbound ref) — those are dropped from the map so no webhook
// is registered against an unknown/uncertain tenant (fail closed). Neither the ref nor any
// URL is ever logged; a binding mismatch is reported by tenant id only.
func resolveEffectiveRefs(ctx context.Context, resolver *app.WebhookRefResolver, envRefs map[string]string, logger *log.Logger) (map[string]string, int) {
	if resolver == nil {
		// No durable store wired: env mapping is authoritative as-is.
		return envRefs, 0
	}
	resolved := make(map[string]string, len(envRefs))
	var failures int
	for ref, envTenant := range envRefs {
		res, err := resolver.Resolve(ctx, ref, envTenant)
		if err != nil {
			logger.Printf("ref (masked): FAILED to resolve tenant binding from durable store: %v", err)
			failures++
			continue
		}
		if res.TenantID == "" {
			logger.Printf("ref (masked): FAILED — not bound to any tenant (unregistered ref)")
			failures++
			continue
		}
		if res.Mismatch {
			logger.Printf("ref (masked): env-declared tenant=%s DIFFERS from durable binding tenant=%s — using the durable binding (source of truth)", envTenant, res.TenantID)
		}
		resolved[ref] = res.TenantID
	}
	return resolved, failures
}

// resolveCredsForTenants pre-resolves the C6 credential (identity + secret + chave) for
// every distinct tenant referenced by refs, reading from the vault-first credential store
// (durable vault for self-serve clients, env bootstrap as fallback). It returns a
// tenant-keyed map in exactly the shape registerAll consumes. A tenant absent from the
// store (shared.ErrNotFound) is simply omitted — registerAll then reports the provisioning
// gap. Any OTHER store error (an infrastructure fault, e.g. a decrypt failure) is logged
// masked and the tenant is omitted, so the command fails that tenant CLOSED rather than
// registering against an unresolved credential. No secret ever reaches the log.
func resolveCredsForTenants(ctx context.Context, store ports.CredentialStore, refs map[string]string, logger *log.Logger) map[string]ports.BankCredential {
	out := make(map[string]ports.BankCredential, len(refs))
	for _, tenantID := range refs {
		if _, done := out[tenantID]; done {
			continue
		}
		cred, err := store.GetBankCredential(ctx, tenantID, ports.BankIDC6)
		if err != nil {
			if !errors.Is(err, shared.ErrNotFound) {
				logger.Printf("tenant=%s: credential store error resolving C6 credential: %v", tenantID, err)
			}
			continue
		}
		out[tenantID] = cred
	}
	return out
}

// registerAll registers and confirms the webhook for every (tenantRef -> tenantID)
// entry. For each, it resolves the tenant's PIX creditor key (the chave the
// webhook is keyed under) from the per-tenant credential, PUTs the callback URL,
// then GETs it back to confirm the registered URL matches (idempotent
// confirmation). Per-tenant failures are collected and surfaced together so one
// bad tenant does not abort the rest; the secret ref and full URL are never
// logged. It returns a non-nil error when any tenant failed.
//
// Refs are processed in a stable (sorted by tenantRef) order so a re-run logs
// deterministically. A tenant with no configured creditor key cannot be keyed at
// the PSP and is reported as a failure (a provisioning gap), not silently skipped.
func registerAll(ctx context.Context, reg ports.PixWebhookRegistrar, refs map[string]string, creds map[string]ports.BankCredential, baseURL string, logger *log.Logger) error {
	tenantRefs := make([]string, 0, len(refs))
	for ref := range refs {
		tenantRefs = append(tenantRefs, ref)
	}
	sort.Strings(tenantRefs)

	var failures int
	for _, ref := range tenantRefs {
		tenantID := refs[ref]
		chave := strings.TrimSpace(creds[tenantID].CreditorKey)
		if chave == "" {
			logger.Printf("tenant=%s: FAILED — no PIX creditor key configured (provisioning gap)", tenantID)
			failures++
			continue
		}
		// The callback URL embeds the secret ref; it is built here but never logged.
		webhookURL := baseURL + "/webhooks/c6/" + ref

		if err := reg.RegisterWebhook(ctx, tenantID, chave, webhookURL); err != nil {
			logger.Printf("tenant=%s key=%s: FAILED to register: %v", tenantID, maskKey(chave), err)
			failures++
			continue
		}
		got, err := reg.GetWebhook(ctx, tenantID, chave)
		if err != nil {
			logger.Printf("tenant=%s key=%s: registered but FAILED to confirm: %v", tenantID, maskKey(chave), err)
			failures++
			continue
		}
		if got.WebhookURL != webhookURL {
			// Mismatch means the PSP holds a DIFFERENT URL than we just PUT — surface
			// it as a failure WITHOUT printing either URL (both embed the secret ref).
			logger.Printf("tenant=%s key=%s: confirmation MISMATCH — registered URL differs from readback", tenantID, maskKey(chave))
			failures++
			continue
		}
		logger.Printf("tenant=%s key=%s: OK (registered + confirmed)", tenantID, maskKey(chave))
	}

	if failures > 0 {
		return fmt.Errorf("%d of %d webhook registration(s) failed", failures, len(tenantRefs))
	}
	logger.Printf("all %d webhook(s) registered and confirmed", len(tenantRefs))
	return nil
}

// registerRecurrenceAll registers and confirms the two singleton recurrence
// callbacks (webhookrec, webhookcobr) for every (tenantRef -> tenantID) entry. Both
// point at the same per-tenant channel URL (/webhooks/c6/{ref}); C6 routes by the
// service field, not the URL. Unlike the PIX webhook these are NOT keyed by a chave
// (singleton per recebedor), so no creditor-key lookup is needed. Per-tenant/-stream
// failures are aggregated so one bad tenant or stream does not abort the rest; the
// secret ref and full URL are never logged. Refs are processed in a stable order.
func registerRecurrenceAll(ctx context.Context, reg ports.RecurrenceWebhookRegistrar, refs map[string]string, baseURL string, logger *log.Logger) error {
	tenantRefs := make([]string, 0, len(refs))
	for ref := range refs {
		tenantRefs = append(tenantRefs, ref)
	}
	sort.Strings(tenantRefs)

	type stream struct {
		name     string
		register func(ctx context.Context, tenantID, webhookURL string) error
		confirm  func(ctx context.Context, tenantID string) (ports.WebhookRegistration, error)
	}
	streams := []stream{
		{"webhookrec", reg.RegisterRecWebhook, reg.GetRecWebhook},
		{"webhookcobr", reg.RegisterCobRWebhook, reg.GetCobRWebhook},
	}

	var failures int
	for _, ref := range tenantRefs {
		tenantID := refs[ref]
		// The callback URL embeds the secret ref; built here but never logged.
		webhookURL := baseURL + "/webhooks/c6/" + ref
		for _, st := range streams {
			if err := st.register(ctx, tenantID, webhookURL); err != nil {
				logger.Printf("tenant=%s %s: FAILED to register: %v", tenantID, st.name, err)
				failures++
				continue
			}
			got, err := st.confirm(ctx, tenantID)
			if err != nil {
				logger.Printf("tenant=%s %s: registered but FAILED to confirm: %v", tenantID, st.name, err)
				failures++
				continue
			}
			if got.WebhookURL != webhookURL {
				logger.Printf("tenant=%s %s: confirmation MISMATCH — registered URL differs from readback", tenantID, st.name)
				failures++
				continue
			}
			logger.Printf("tenant=%s %s: OK (registered + confirmed)", tenantID, st.name)
		}
	}

	if failures > 0 {
		return fmt.Errorf("%d recurrence webhook registration(s) failed", failures)
	}
	logger.Printf("all recurrence webhook(s) registered and confirmed for %d tenant(s)", len(tenantRefs))
	return nil
}

// decodeCipher builds an AES-256-GCM sealing cipher from a hex-encoded 32-byte KEK,
// without ever echoing the key material into an error (mirrors cmd/vault-reseal).
func decodeCipher(hexKey string) (*secret.Cipher, error) {
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("not valid hex")
	}
	c, err := secret.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// maskKey renders a PIX key for logs without exposing the full routing-sensitive
// value (a CPF/CNPJ/email/EVP is PII / fund-routing data, threat C4). It keeps the
// first and last character and replaces the middle with a fixed marker; a very
// short key is fully masked.
func maskKey(key string) string {
	if len(key) <= 4 {
		return "****"
	}
	return key[:1] + "***" + key[len(key)-1:]
}

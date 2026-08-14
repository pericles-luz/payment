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
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/bank/c6"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/platform/config"
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
	}, secret.NewStore(cfg.BankCreds))
	if err != nil {
		return err
	}

	baseURL := strings.TrimRight(os.Getenv("PAYMENT_WEBHOOK_BASE_URL"), "/")
	if baseURL == "" {
		baseURL = defaultWebhookBaseURL
	}

	// cfg.BankCreds is now keyed by the composite (tenant, bank) pair (ADR-0007).
	// register-webhook targets the C6 PIX webhook only, so project each tenant's C6
	// credential into a tenant-keyed map for registerAll, which resolves the chave
	// per tenant for the single (C6) bank.
	c6Creds := make(map[string]ports.BankCredential, len(cfg.BankCreds))
	for _, cred := range cfg.BankCreds {
		if cred.BankID == ports.BankIDC6 {
			c6Creds[cred.TenantID] = cred
		}
	}

	ctx := context.Background()
	var errs []error
	if err := registerAll(ctx, provider, cfg.WebhookRefs, c6Creds, baseURL, logger); err != nil {
		errs = append(errs, err)
	}
	// PIX Automático (recorrência) callbacks (SIN-66036): the two singleton
	// recurrence webhooks (webhookrec/webhookcobr) point at the SAME opaque
	// per-tenant channel as the PIX webhook — C6 distinguishes the streams by the
	// service field in the notification body, not by URL. Registering them is keyed
	// by the tenant (no chave), so registerRecurrenceAll only needs the ref→tenant
	// map. Failures are aggregated with the PIX pass so one stream's gap does not
	// hide the other's outcome.
	if err := registerRecurrenceAll(ctx, provider, cfg.WebhookRefs, baseURL, logger); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
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

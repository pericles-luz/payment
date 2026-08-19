// Command c6-webhook-sync converges ALL of a tenant's C6 notification channels onto a
// SINGLE live callback ref, in one pass.
//
// Why it exists. A tenant's callback URL is /webhooks/c6/{ref}, and one ref serves every
// channel — the PSP routes by the service discriminator in the notification body, not by
// the URL. But the ref store keeps only sha256(ref): the plaintext is unrecoverable after
// mint, so whoever registers must be the one who minted. The in-flow path (SIN-69560)
// mints and registers the immediate-PIX channel ONLY, which leaves the recurrence and
// proprietary channels pointing at whatever ref was current when they were last written —
// and a later mint supersedes that ref, silently killing them. This command closes that
// gap operationally: mint once, register every channel with that same ref, confirm each.
//
// It deliberately registers the PIX channel too, even when already registered. That keeps
// the API's in-flow gate satisfied (it sees an ACTIVE ref of this tenant) so the reconcile
// sweep does not immediately mint a competing ref and strand the other channels again.
//
// It runs on the receiver VPS, as the payment user, with the service environment sourced:
// the mTLS client certificate never leaves that host (threat C1), and the credential plus
// the PIX creditor key are read from the SAME durable vault the API charges with.
//
// Secrets: the ref and the full callback URL are NEVER printed — only which channel was
// registered and confirmed, plus a masked PIX key.
//
//	c6-webhook-sync <tenantID> [--dry-run]
package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/bank/c6"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/sqlite"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/system"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/platform/config"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

const callbackPathPrefix = "/webhooks/c6/"

// defaultCallbackBaseURL mirrors cmd/api and cmd/register-webhook; overridable with
// PAYMENT_WEBHOOK_BASE_URL so staging and production agree with the running service.
const defaultCallbackBaseURL = "https://payment.lmhost.com.br"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "\nc6-webhook-sync: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		return errors.New("usage: c6-webhook-sync <tenantID> [--dry-run]")
	}
	tenantID := strings.TrimSpace(os.Args[1])
	dryRun := len(os.Args) > 2 && os.Args[2] == "--dry-run"

	cfg := config.FromEnv()
	if cfg.C6.BaseURL == "" || cfg.C6.TokenURL == "" {
		return errors.New("PAYMENT_C6_BASE_URL and PAYMENT_C6_TOKEN_URL are required (refusing to run against the stub)")
	}
	if cfg.BankVaultKey == "" {
		return errors.New("PAYMENT_BANK_VAULT_KEY is required: the credential, the PIX key and the ref store all live in the durable vault")
	}

	ctx := context.Background()
	key, err := hex.DecodeString(cfg.BankVaultKey)
	if err != nil {
		return errors.New("PAYMENT_BANK_VAULT_KEY is not valid hex")
	}
	cipher, err := secret.NewCipher(key)
	if err != nil {
		return fmt.Errorf("PAYMENT_BANK_VAULT_KEY invalid: %w", err)
	}
	db, err := sqlite.Open(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer func() { _ = db.Close() }()

	clock := system.Clock{}
	credVault := sqlite.NewCredentialVault(db, cipher, clock)
	certVault := sqlite.NewCertificateVault(db, cipher, clock)
	refStore := sqlite.NewWebhookRefStore(db, clock)

	cred, err := credVault.GetBankCredential(ctx, tenantID, ports.BankIDC6)
	if err != nil {
		return fmt.Errorf("resolve credential from vault: %w", err)
	}
	chave := strings.TrimSpace(cred.CreditorKey)
	fmt.Printf("tenant       : %s\n", tenantID)
	fmt.Printf("client_id    : %s\n", cred.ClientID)
	fmt.Printf("chave PIX    : %s\n", maskKey(chave))

	// The live transport picks the tenant's certificate per request via an unexported
	// context key; from outside the adapter package we bind it directly instead, so the
	// handshake presents the same identity the API uses for this tenant.
	httpc, err := c6.MTLSHTTPClient(cfg.C6.ClientCertPath, cfg.C6.ClientKeyPath, cfg.C6.Timeout)
	if err != nil {
		return fmt.Errorf("build mTLS client: %w", err)
	}
	if tenantCert, cerr := certVault.LoadTLSCertificate(ctx, tenantID, ports.BankIDC6); cerr == nil {
		httpc.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{*tenantCert}
		fmt.Println("cert mTLS    : do cofre (por-tenant)")
	} else {
		fmt.Printf("cert mTLS    : do arquivo §8 (tenant sem cert no cofre: %v)\n", cerr)
	}

	provider, err := c6.New(c6.Config{
		BaseURL:    cfg.C6.BaseURL,
		TokenURL:   cfg.C6.TokenURL,
		Scope:      cfg.C6.Scope,
		Timeout:    cfg.C6.Timeout,
		HTTPClient: httpc,
	}, credVault)
	if err != nil {
		return fmt.Errorf("build C6 provider: %w", err)
	}

	base := strings.TrimRight(strings.TrimSpace(os.Getenv("PAYMENT_WEBHOOK_BASE_URL")), "/")
	if base == "" {
		base = defaultCallbackBaseURL
	}

	if dryRun {
		fmt.Println("\n-- dry-run: nada sera mintado nem registrado --")
		reportCurrent(ctx, provider, tenantID, chave)
		return nil
	}

	// ONE mint for every channel. Minting supersedes this tenant's previous active ref,
	// so the channels must all be re-registered below — which is exactly the point.
	ref, err := app.NewWebhookRefMintService(refStore).MintWebhookRef(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("mint webhook ref: %w", err)
	}
	callback := base + callbackPathPrefix + ref
	fmt.Printf("\nref mintada  : (nao exibida) — callback sob %s%s\n", base, callbackPathPrefix)

	type channel struct {
		name     string
		register func() error
		confirm  func() (ports.WebhookRegistration, error)
		skip     string
	}
	channels := []channel{
		{
			name:     "PIX imediato (liquidacao)",
			register: func() error { return provider.RegisterWebhook(ctx, tenantID, chave, callback) },
			confirm:  func() (ports.WebhookRegistration, error) { return provider.GetWebhook(ctx, tenantID, chave) },
			skip:     skipIfNoKey(chave),
		},
		{
			name:     "recorrencia: mandato (webhookrec)",
			register: func() error { return provider.RegisterRecWebhook(ctx, tenantID, callback) },
			confirm:  func() (ports.WebhookRegistration, error) { return provider.GetRecWebhook(ctx, tenantID) },
		},
		{
			name:     "recorrencia: cobranca (webhookcobr)",
			register: func() error { return provider.RegisterCobRWebhook(ctx, tenantID, callback) },
			confirm:  func() (ports.WebhookRegistration, error) { return provider.GetCobRWebhook(ctx, tenantID) },
		},
		{
			name:     "checkout (superficie propria)",
			register: func() error { return provider.RegisterServiceWebhook(ctx, tenantID, c6.ServiceCheckout, callback) },
			confirm: func() (ports.WebhookRegistration, error) {
				return provider.GetServiceWebhook(ctx, tenantID, c6.ServiceCheckout)
			},
		},
	}

	var failures int
	for _, ch := range channels {
		if ch.skip != "" {
			fmt.Printf("  [PULADO ] %-38s %s\n", ch.name, ch.skip)
			continue
		}
		if err := ch.register(); err != nil {
			fmt.Printf("  [FALHOU ] %-38s registrar: %v\n", ch.name, err)
			failures++
			continue
		}
		got, err := ch.confirm()
		switch {
		case err != nil:
			fmt.Printf("  [PARCIAL] %-38s registrado, confirmacao falhou: %v\n", ch.name, err)
			failures++
		case got.WebhookURL != callback:
			// Never print either URL: both embed the secret ref.
			fmt.Printf("  [DIVERGE] %-38s PSP guarda URL diferente da enviada\n", ch.name)
			failures++
		default:
			fmt.Printf("  [OK     ] %-38s registrado e confirmado\n", ch.name)
		}
	}
	if failures > 0 {
		return fmt.Errorf("%d de %d canais falharam", failures, len(channels))
	}
	fmt.Println("\ntodos os canais convergidos para a mesma ref viva")
	return nil
}

// reportCurrent prints what the PSP holds today, without printing any URL.
func reportCurrent(ctx context.Context, p *c6.Provider, tenantID, chave string) {
	show := func(name string, get func() (ports.WebhookRegistration, error)) {
		_, err := get()
		switch {
		case err == nil:
			fmt.Printf("  %-38s registrado\n", name)
		case errors.Is(err, shared.ErrNotFound):
			fmt.Printf("  %-38s NAO registrado\n", name)
		default:
			fmt.Printf("  %-38s erro: %v\n", name, err)
		}
	}
	if chave != "" {
		show("PIX imediato", func() (ports.WebhookRegistration, error) { return p.GetWebhook(ctx, tenantID, chave) })
	}
	show("recorrencia: mandato", func() (ports.WebhookRegistration, error) { return p.GetRecWebhook(ctx, tenantID) })
	show("recorrencia: cobranca", func() (ports.WebhookRegistration, error) { return p.GetCobRWebhook(ctx, tenantID) })
	show("checkout", func() (ports.WebhookRegistration, error) {
		return p.GetServiceWebhook(ctx, tenantID, c6.ServiceCheckout)
	})
}

func skipIfNoKey(chave string) string {
	if chave == "" {
		return "tenant sem chave PIX do recebedor"
	}
	return ""
}

// maskKey renders the PIX key without exposing the full fund-routing value.
func maskKey(k string) string {
	if len(k) <= 4 {
		return "****"
	}
	return k[:1] + "***" + k[len(k)-1:]
}

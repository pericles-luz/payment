// Command api is the HTTP entrypoint: it wires the adapters (SQLite persistence,
// bank stub, in-memory bus) behind the application services and serves the
// tenant API, admin plane and bank webhook with graceful shutdown.
//
// Adapter plugability: switching persistence from SQLite to the in-memory store
// (or the bus to RabbitMQ) is a change here only — the domain and use-cases are
// untouched.
package main

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"log/slog"
	mrand "math/rand/v2"
	stdhttp "net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/adminweb"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/bank"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/bank/c6"
	consoleauthstore "github.com/ia-dev-sindireceita/payment/internal/adapters/consoleauth"
	httpadapter "github.com/ia-dev-sindireceita/payment/internal/adapters/http"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/messaging/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/outbound"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/sqlite"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/system"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/platform/config"
	"github.com/ia-dev-sindireceita/payment/internal/platform/stgseed"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
	"github.com/ia-dev-sindireceita/payment/migrations"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("api: %v", err)
	}
}

func run() error {
	cfg := config.FromEnv()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	db, err := sqlite.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	if err := sqlite.Migrate(ctx, db, migrations.FS); err != nil {
		return err
	}

	store := sqlite.NewStore(db)
	// Account-key store (ADR-0011 §3, B1/SIN-69278): durable, hash-at-rest bearer
	// keys keyed by Account. Wired as the choke-point's AccountKeyAuth; it only ever
	// runs when the PAYMENT_ACCOUNT_KEY_SELECTOR flag is on (model (b)), so building
	// it here is inert in the default model (a) deployment.
	accountKeys := sqlite.NewAccountKeyStore(db, system.Clock{})
	// Bank OAuth-credential and mTLS-certificate vaults. With PAYMENT_BANK_VAULT_KEY
	// set (a 32-byte AES-256 KEK, hex), both are the DURABLE, encrypted-at-rest
	// SQLite adapters (SIN-69366): a runtime-configured C6 credential/cert survives a
	// restart, and the env seeds a fresh deployment once (env-as-bootstrap,
	// DB-as-durable-source). With the key unset they fall back to the in-memory vaults
	// (previous behaviour, fully backward compatible) — runtime edits then do NOT
	// survive a restart. A set-but-malformed key fails the boot closed rather than
	// silently degrading to in-memory.
	// Build the sealing cipher once (nil when PAYMENT_BANK_VAULT_KEY is unset) and
	// share it across every encrypted-at-rest vault: the bank credential/cert vaults
	// AND the durable console credential store (SIN-69432). One KEK for all secrets
	// at rest; a set-but-malformed key fails the boot closed.
	vaultCipher, err := newVaultCipher(cfg)
	if err != nil {
		return err
	}
	creds, certs, err := newBankVaults(ctx, cfg, db, vaultCipher)
	if err != nil {
		return err
	}
	// Durable, append-only audit trail for privileged admin-plane and money-movement
	// actions (SIN-66025): the SQLite Store implements ports.AuditLog, so entries
	// survive a restart and — when appended through the unit of work — commit
	// atomically with the triggering write. Wiring it here is mandatory: AdminService
	// and WebhookService degrade to a no-op log when Audit is nil, which must never
	// happen in prod.

	// Bank registry (multi-bank, SIN-66022): one ProviderSet per wired bank — the
	// real C6 adapter when its endpoints are configured, otherwise the in-memory stub
	// (local dev / tests). The C6 adapter rejects non-HTTPS endpoints, so a
	// misconfigured URL fails startup rather than silently downgrading the transport.
	registry, err := newBankRegistry(cfg, creds, certs)
	if err != nil {
		return err
	}
	// Derive the C6 PIX-webhook registrar from the wired registry for the self-serve
	// in-flow registration (SIN-69560 / F2). Nil for the stub (no webhook wire), which
	// makes the registration service inert — exactly the safe default in dev/tests.
	var webhookRegistrar ports.PixWebhookRegistrar
	var recWebhookRegistrar ports.RecurrenceWebhookRegistrar
	var svcWebhookRegistrar ports.ServiceWebhookRegistrar
	var webhookDeregistrar ports.WebhookDeregistrar
	if set, ok := registry.Get(ports.BankIDC6); ok {
		webhookRegistrar = set.PixWebhook
		recWebhookRegistrar = set.RecurrenceWebhook
		svcWebhookRegistrar = set.ServiceWebhook
		webhookDeregistrar = set.WebhookDeregistrar
	}
	// The per-port routers dispatch each request to the bank resolved at the HTTP
	// boundary (carried on the context). The application services depend on these,
	// not on a single bank instance, so adding a bank is a wiring change only.
	routers := bank.NewRouters(registry)
	// Credential-cache invalidator (ADR-0003): fans a tenant's token-cache eviction
	// out to every wired bank that caches credential state (the C6 settlement wrapper
	// forwards InvalidateToken; the stub caches nothing). Nil when no bank caches
	// anything, so the admin services fall back to a no-op evictor.
	credInvalidator := registry.CredentialInvalidator()
	// Recurrence reconcile-read ports for the PIX Automático webhook dispatch
	// (SIN-66036). PIX Automático is a C6/BACEN feature; the C6 raw provider (and the
	// stub) implement the Rec/CobR read ports. Derived from the C6 ProviderSet's raw
	// provider rather than a router because recurrence ports are not yet part of the
	// per-bank routing surface — that moves into the registry routers when a second
	// bank gains PIX Automático (SIN-66022).
	recReader, cobrReader := recurrenceReaders(registry)

	// Outbound webhook attribution (SIN-69491, F1 of SIN-69486): on a settled inbound
	// event, resolve the owning Conta SERVER-SIDE and materialise the event onto that
	// Conta's durable outbox (or dead-letter it when unattributable). DARK behind the
	// same PAYMENT_ACCOUNT_OUTBOUND_WEBHOOK flag as F0 and best-effort — a no-op unless
	// the flag is on. The outbox holds no secret/PII so it needs no cipher (unlike the
	// F0 config store); it is always durable (sqlite over the shared db). The resolver
	// reads the tenant's owning Account from the same store the choke-point uses, but
	// surfaces read errors so an indeterminable owner fails-closed to a dead-letter.
	outboundDeliveries := sqlite.NewOutboundDeliveryStore(db)
	outboundAttributor := app.NewOutboundAttributor(app.OutboundAttributorDeps{
		Enabled:     cfg.AccountOutboundWebhook,
		Resolver:    app.NewStoreAccountResolver(store),
		Queue:       outboundDeliveries,
		DeadLetters: outboundDeliveries,
		Clock:       system.Clock{},
		IDs:         system.IDProvider{},
	})

	deps := app.Deps{
		Payments:           store,
		Tenants:            store,
		Pricing:            store,
		Ledger:             store,
		Processed:          store,
		Recs:               store,
		CobRs:              store,
		Bus:                inmemory.NewBus(),
		Bank:               routers.Bank,
		Pix:                routers.Pix,
		PixDueCharge:       routers.PixDueCharge,
		Checkout:           routers.Checkout,
		Boleto:             routers.Boleto,
		DDA:                routers.DDA,
		Statement:          routers.Statement,
		RecReader:          recReader,
		CobRReader:         cobrReader,
		OutboundAttributor: outboundAttributor,
		Credentials:        creds,
		CredWriter:         creds,
		CertWriter:         certs,
		CredInvalidator:    credInvalidator,
		Audit:              store,
		Clock:              system.Clock{},
		IDs:                system.IDProvider{},
		// Transactional boundary for the multi-write use-cases (charge creation,
		// webhook settlement) — required for financial integrity (SIN-64719).
		UoW: store,
	}

	// Derive admin roles server-side from configured tokens (least privilege):
	// PAYMENT_ADMIN_TOKENS → full admin, PAYMENT_OPERATOR_TOKENS → read-only.
	adminRoles := make(map[string]httpadapter.Role, len(cfg.AdminTokens)+len(cfg.OperatorTokens))
	for _, t := range cfg.AdminTokens {
		adminRoles[t] = httpadapter.RoleAdmin
	}
	for _, t := range cfg.OperatorTokens {
		// An operator token that is also an admin token keeps the stronger admin
		// role (do not downgrade).
		if _, isAdmin := adminRoles[t]; !isAdmin {
			adminRoles[t] = httpadapter.RoleOperator
		}
	}
	// Per-tenant webhook identities: join each opaque callback ref (ref→tenant)
	// with the tenant's C6 client_id (from its bank credential) so the webhook
	// handler can cross-check the untrusted body's client_id against the channel.
	// A tenant without a configured credential simply has an empty client_id and
	// the cross-check is skipped (the channel remains authoritative).
	webhookRefs := make(map[string]httpadapter.WebhookIdentity, len(cfg.WebhookRefs))
	for ref, tenantID := range cfg.WebhookRefs {
		// The C6 webhook cross-check uses the tenant's C6 client_id; resolve the
		// (tenant, c6) credential from the store (cfg.BankCreds is now composite-keyed,
		// ADR-0007). A tenant without one yields an empty client_id and the cross-check
		// is skipped (the channel remains authoritative).
		var clientID string
		if cred, err := creds.GetBankCredential(context.Background(), tenantID, ports.BankIDC6); err == nil {
			clientID = cred.ClientID
		}
		webhookRefs[ref] = httpadapter.WebhookIdentity{
			TenantID: tenantID,
			ClientID: clientID,
		}
	}
	// Durable per-tenant webhook-ref store (SIN-69559 / F1): env-as-bootstrap /
	// DB-as-durable. PAYMENT_WEBHOOK_REFS still seeds the in-memory map above; this store
	// holds refs MINTED after boot (POST /v1/clients), so a fresh empresa-cliente can
	// receive C6 webhooks with no operator edit and no restart. It stores ONLY the ref's
	// sha256 (never the ref) — no secret to seal — so it is wired unconditionally (unlike
	// the vault-gated credential stores). The authenticator falls back to it on a map miss.
	webhookRefStore := sqlite.NewWebhookRefStore(db, system.Clock{})
	auth := httpadapter.NewStaticTokenAuthWithRoles(cfg.TenantTokens, adminRoles, webhookRefs).
		WithWebhookRefStore(webhookRefStore).
		WithCredentialStore(creds) // B4 (SIN-69585): populate ClientID on durable-ref path

	// Admin HTML console (SIN-64727): parse templates up-front so a bad template
	// fails startup, not the first request.
	ui, err := adminweb.New()
	if err != nil {
		return err
	}
	// Per-Conta outbound webhook config store (SIN-69490, F0 of SIN-69486). Durable +
	// encrypted-at-rest ONLY when the vault cipher is present (PAYMENT_BANK_VAULT_KEY
	// set) — the HMAC signing secret must be sealed at rest, so with no KEK we leave
	// the store nil and the use-cases return 503 (the feature is dark behind
	// PAYMENT_ACCOUNT_OUTBOUND_WEBHOOK anyway). Reuses the SAME KEK as the bank/console
	// vaults.
	var outboundWebhooks app.OutboundWebhookStore
	if vaultCipher != nil {
		outboundWebhooks = sqlite.NewOutboundWebhookVault(db, vaultCipher, system.Clock{})
	}

	// Outbound webhook FORWARD (SIN-69492, F2 of SIN-69486): a background consumer of the
	// F1 outbox that delivers each attributed event to its owning Conta's endpoint, signed
	// per-Conta over an SSRF-safe client (threat model SIN-69489). Best-effort and DARK
	// behind the same PAYMENT_ACCOUNT_OUTBOUND_WEBHOOK flag — the processor is inert unless
	// the flag is on AND the config store exists (it needs the sealed signing secret, so it
	// is nil without a KEK). Running out-of-band of the inbound handler keeps the C6 ACK
	// fully decoupled from delivery (threat D3). The forwarder/limiter own all SSRF
	// hardening (dial-time IP guard, no redirects, timeouts); this layer never touches net.
	outboundProcessor := app.NewOutboundProcessor(app.OutboundProcessorDeps{
		Enabled:     cfg.AccountOutboundWebhook,
		Outbox:      outboundDeliveries,
		Configs:     outboundWebhooks,
		Forwarder:   outbound.NewForwarder(),
		Limiter:     outbound.NewPerAccountLimiter(),
		DeadLetters: outboundDeliveries,
		Audit:       store,
		Clock:       system.Clock{},
		IDs:         system.IDProvider{},
		Rand:        mrand.Float64,
	})

	console := app.NewConsoleService(app.ConsoleDeps{
		Tenants:        store,
		Accounts:       store,
		Pricing:        store,
		Ledger:         store,
		CredWriter:     creds,
		CreditorWriter: creds,
		CredReader:     creds,
		CertWriter:     certs,
		CertReader:     certs,
		CredDeleter:    creds,
		CertDeleter:    certs,
		// Removing a bank configuration must also stop the PSP from calling us: without
		// this the bank keeps POSTing notifications whose credential we just deleted
		// (SIN-69580). Nil for the stub, which speaks no webhook wire.
		WebhookDeregistrar: webhookDeregistrar,
		Creds:              creds,
		Sharing:            creds,
		Invoices:           store,
		OutboundWebhooks:   outboundWebhooks,
		CredInvalidator:    credInvalidator,
		Audit:              store,
		Clock:              system.Clock{},
		IDs:                system.IDProvider{},
	})

	// Self-contained console login (ADR-0001 Opção B, SIN-69265): username +
	// password + TOTP over a first-party session cookie, so /console is reachable by
	// a browser without the edge injecting a bearer. Bootstrap is failure-closed: with
	// PAYMENT_CONSOLE_BOOTSTRAP_TOKEN unset, first-access provisioning is disabled
	// entirely, so it can never be an anonymous land-grab. The existing admin Bearer
	// transport keeps working.
	//
	// Durability (SIN-69432): with the vault cipher present (PAYMENT_BANK_VAULT_KEY
	// set) the CREDENTIAL and TOTP replay guard are the durable, encrypted-at-rest
	// SQLite adapters, so the provisioned credential SURVIVES a restart — the board's
	// console access no longer breaks on every CD redeploy (caveat SIN-69261 closed).
	// SESSIONS stay in-memory (losing a session on restart just means re-login, a
	// minor annoyance; the credential is the load-bearing state). Without the cipher
	// there is no KEK to seal the TOTP secret at rest, so we fall back to the fully
	// in-memory store (previous behaviour) — a restart then re-drops the credential,
	// which the bank-vault log line above already flags.
	consoleSessions := consoleauthstore.NewMemStore()
	var consoleCreds app.ConsoleCredentialStore = consoleSessions
	var consoleReplay app.TOTPReplayStore = consoleSessions
	if vaultCipher != nil {
		consoleCreds = sqlite.NewConsoleCredentialVault(db, vaultCipher, system.Clock{})
		consoleReplay = sqlite.NewConsoleReplayStore(db, system.Clock{})
		log.Print("api: durable encrypted-at-rest console credential store ENABLED — the console login survives a restart")
	} else {
		log.Print("api: console credential store is IN-MEMORY (PAYMENT_BANK_VAULT_KEY unset) — /console/bootstrap must be re-run after each restart")
	}
	consoleAuth := app.NewConsoleAuthService(consoleCreds, consoleSessions, consoleReplay, system.Clock{}, app.ConsoleAuthConfig{
		Username:       cfg.ConsoleUsername,
		BootstrapToken: cfg.ConsoleBootstrapToken,
	})

	// Staging-stub demo seed (SIN-69226): triple-gated (PAYMENT_STG_SEED set AND
	// stub bank AND empty store) so it is inert in every real deployment and
	// idempotent across restarts. It reuses the console use-cases and the ledger
	// port — no SQL here, no migration. A gate miss is a silent no-op; only an
	// underlying use-case failure aborts startup (a broken seed on a stub is a
	// misconfiguration worth surfacing loudly).
	if _, err := stgseed.Apply(ctx, stgseed.Config{
		Enabled:  cfg.STGSeed,
		StubMode: cfg.C6.BaseURL == "",
	}, stgseed.Deps{
		Console:  console,
		Accounts: store,
		Tenants:  store,
		Ledger:   store,
		Clock:    system.Clock{},
		IDs:      system.IDProvider{},
	}); err != nil {
		return err
	}

	// Webhook registration service: shared between the in-flow server hooks (F2) and
	// the periodic reconcile sweep (B2 / SIN-69585). Built here so both consumers
	// reference the same instance (idempotent GET-gate keeps concurrent calls safe).
	// WithRefLookup lets the idempotency gate distinguish a LIVE registration (the URL C6
	// holds carries an active ref of this tenant) from a stale one (revoked, superseded or
	// foreign ref). Without it a prefix match alone would mark a dead registration as done,
	// and neither a self-serve write nor the reconcile sweep could ever heal it (SIN-69580).
	// Multi-channel by construction (SIN-69580): one ref serves the PIX settlement
	// callback, both recurrence callbacks and the proprietary per-service ones, because
	// the PSP routes by the service discriminator in the notification body. Registering
	// only PIX — the pre-multi-channel behaviour — left the others pointing at whatever
	// ref was current when they were last written, and the next mint killed them
	// silently. CHECKOUT is listed explicitly; BANK_SLIP is deliberately absent until the
	// boleto flow exists, so the PSP is never told to deliver what we cannot process.
	webhookRegSvc := app.NewWebhookRegistrationService(
		creds, webhookRegistrar, app.NewWebhookRefMintService(webhookRefStore),
		webhookCallbackBaseURL(), slog.Default()).
		WithRefLookup(webhookRefStore).
		WithTenants(store).
		WithRecurrenceRegistrar(recWebhookRegistrar).
		WithServiceRegistrar(svcWebhookRegistrar, c6.ServiceCheckout)

	srv := httpadapter.NewServer(httpadapter.Config{
		Charges:     app.NewChargeService(deps),
		Pix:         app.NewPixService(deps),
		PixCobV:     app.NewPixDueChargeService(deps),
		Checkout:    app.NewCheckoutService(deps),
		Boleto:      app.NewBoletoService(deps),
		DDA:         app.NewDDAService(deps),
		Statement:   app.NewStatementService(deps),
		Admin:       app.NewAdminService(deps),
		Console:     console,
		ConsoleAuth: consoleAuth,
		UI:          ui,
		Webhooks:    app.NewWebhookService(deps),
		TenantAuth:  auth,
		AdminAuth:   auth,
		WebhookAuth: auth,
		// Two-level tenancy (SIN-69222): resolve each authenticated tenant's REAL
		// owning Account from the tenant store at the choke-point, so the account
		// stamped on the ledger reflects the admin grouping (tenants.account_id) and
		// "Uso por Conta" shows the multi-empresa rollup. A tenant with no assigned
		// account keeps its self-account default (retrocompat).
		AccountResolver: httpadapter.NewStoreAccountResolver(store),
		// Multi-bank selector (SIN-66022): resolve+validate the per-request bank
		// against the wired registry and the tenant's configured credentials
		// (deny-by-default, no oracle). The tenant plane reads X-Bank-Id / the DTO
		// `bank` field and routes accordingly.
		BankResolver:     httpadapter.NewBankResolver(registry.Banks(), creds),
		SecureCookies:    cfg.SecureCookies,
		TrustedProxyHops: cfg.TrustedProxyHops,
		// Self-serve credential intake (SIN-69196), default-off dark-ship.
		SelfServeCredIntake: cfg.SelfServeCredIntake,
		WebhookLogPayload:   cfg.WebhookLogPayload,
		// Model (b) account-key + per-request client selector (ADR-0011 §2 /
		// SIN-69279), default-off dark-ship: consulted only when AccountKeySelector
		// is on and the bearer has the ak_ shape; otherwise inert (model (a)).
		AccountKeyAuth:     accountKeys,
		AccountKeySelector: cfg.AccountKeySelector,
		// Model (b) key emission/rotation (ADR-0011 §3 / SIN-69280): mints/rotates an
		// Account's bearer key for POST /v1/account-key (self-rotate) and POST
		// /admin/accounts/{id}/account-key (bootstrap). Backed by the same durable,
		// hash-at-rest account-key store; the plaintext is returned once and never
		// stored/logged (display-once).
		// Audit the mint from the shared choke-point (SIN-69386) so both write
		// surfaces (this admin bootstrap route + the HTML console) leave one
		// account-scoped account.key_mint trail entry per real mint —
		// who/which-Conta/when, never the secret. The durable SQLite store
		// implements ports.AuditLog.
		AccountKeyMint: app.NewAccountKeyService(accountKeys, system.Clock{},
			app.WithAccountKeyAudit(store, system.IDProvider{})),
		// Per-Conta outbound webhook config console CRUD (SIN-69490, F0 of SIN-69486),
		// default-off dark-ship: off hides the card and leaves the routes unregistered.
		AccountOutboundWebhook: cfg.AccountOutboundWebhook,
		// Model (b) empresa-cliente provisioning (ADR-0011 §4 / SIN-69281): a reseller
		// Conta creates a new empresa-cliente via POST /v1/clients, bound to the Account
		// resolved from its account-key (server-side, never the body — A01/T6). Backed by
		// the same durable tenant repository as the admin plane; Idempotency-Key dedups
		// retries so a lost-response retry does not create a duplicate empresa-cliente.
		// The webhook-ref minter (SIN-69559 / F1) makes provisioning ALSO mint a durable C6
		// callback ref (display-once) into webhookRefStore, closing the self-serve settlement
		// gap (SIN-69557): the new client can receive webhooks immediately, no restart.
		ClientProvisioner: app.NewClientProvisioningService(deps.Tenants, deps.IDs, system.Clock{}).
			WithWebhookRefMinter(app.NewWebhookRefMintService(webhookRefStore)),
		// In-flow C6 webhook registration (SIN-69560 / F2 of SIN-69558): the moment a
		// self-serve client's credential + PIX key complete (a self-serve credential/
		// certificate write or an operator PIX-key set), register its PIX settlement
		// webhook with C6, resolving the PIX key from the SAME durable credential vault
		// the API charges with and confirming by GET. Best-effort — a PSP failure never
		// regresses the write. Wired only in real-C6 mode (webhookRegistrar is nil for the
		// stub, which makes the service inert). The callback base origin mirrors
		// cmd/register-webhook (PAYMENT_WEBHOOK_BASE_URL, default the receiver VPS).
		WebhookRegistrar: webhookRegSvc,
	})

	httpServer := &stdhttp.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           srv.Router(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// F2 outbound-forward worker: tick the outbox consumer on a fixed interval, bound to
	// the signal context so it stops cleanly on shutdown (no goroutine leak). The processor
	// is a no-op while the flag is off, so this loop is inert until the feature is enabled.
	go runOutboundForwardWorker(ctx, outboundProcessor, 2*time.Second)

	// B2 webhook reconcile worker (SIN-69585): periodic sweep that re-attempts C6 PIX
	// webhook registration for every tenant with a C6 credential. Fixes the silent-failure
	// gap: if in-flow TryRegister (F2) failed due to a transient C6 outage, the next sweep
	// picks it up. Inert when PAYMENT_WEBHOOK_RECONCILE is false. No goroutine leak
	// (honours ctx). Shares the same WebhookRegistrationService as the in-flow path.
	reconcileWorker := app.NewWebhookReconcileWorker(cfg.WebhookReconcile, creds, webhookRegSvc, slog.Default())
	go runWebhookReconcileWorker(ctx, reconcileWorker, cfg.WebhookReconcileInterval)

	errCh := make(chan error, 1)
	go func() {
		log.Printf("api: listening on %s", cfg.HTTPAddr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, stdhttp.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		log.Print("api: shutdown signal received")
	case err := <-errCh:
		return err
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return httpServer.Shutdown(shutdownCtx)
}

// runWebhookReconcileWorker drives the B2 webhook-reconcile sweep on a fixed interval
// until ctx is cancelled (SIN-69585). When the flag is off Sweep() is a cheap no-op so
// this goroutine is always safe to start.
func runWebhookReconcileWorker(ctx context.Context, w *app.WebhookReconcileWorker, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := w.Sweep(ctx); err != nil {
				log.Printf("api: webhook reconcile sweep error: %v", err)
			}
		}
	}
}

// runOutboundForwardWorker drives the F2 outbound-forward processor on a fixed interval
// until ctx is cancelled. A per-tick error (e.g. a transient outbox read failure) is only
// logged — the loop keeps ticking — and per-delivery failures never surface here (they are
// dead-lettered inside the processor). When the flag is off the processor is inert, so this
// loop costs one cheap claim per tick and originates no I/O.
func runOutboundForwardWorker(ctx context.Context, p *app.OutboundProcessor, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := p.ProcessPending(ctx); err != nil {
				log.Printf("api: outbound forward tick: %v", err)
			}
		}
	}
}

// credentialAdapter is the union of bank OAuth-credential ports the wiring depends
// on. Both the in-memory secret.Store and the durable sqlite.CredentialVault satisfy
// it, so newBankVaults can return either behind this one type.
type credentialAdapter interface {
	ports.CredentialStore
	ports.CredentialWriter
	ports.CredentialDeleter
	ports.CreditorKeyWriter
	ports.CredentialEnumerator
	// CreditorKeySharingLookup keeps a PIX key / PSP account from being claimed by two
	// ACTIVE empresas at once, and stops a removal from tearing down a webhook that
	// still belongs to another one (SIN-69368). Both vaults implement it.
	ports.CreditorKeySharingLookup
}

// certificateAdapter is the union of mTLS-certificate ports the wiring depends on.
// Both the in-memory secret.CertStore and the durable sqlite.CertificateVault satisfy
// it. It also carries c6.CertProvider (LoadTLSCertificate) so the live C6 transport
// can source its client certificate from the vault, keyed per tenant (SIN-69368);
// the compile-time assertion that this union satisfies c6.CertProvider is the call
// to newBankRegistry, which passes a certificateAdapter where a c6.CertProvider is
// expected.
type certificateAdapter interface {
	ports.BankCertificateWriter
	ports.BankCertificateReader
	ports.BankCertificateDeleter
	c6.CertProvider
}

// newVaultCipher builds the AES-256-GCM sealing cipher from PAYMENT_BANK_VAULT_KEY,
// the single KEK shared by every encrypted-at-rest vault (bank credentials, bank
// certificates, and the console credential store — SIN-69432). It returns a nil
// cipher (no error) when the key is UNSET, which every caller reads as "keep the
// in-memory adapter" (previous behaviour, fully backward compatible). A SET-but-
// malformed key (bad hex or wrong length) fails the boot CLOSED rather than silently
// degrading to in-memory — a deployment that meant to encrypt at rest must not run
// unencrypted by accident. The key value is never echoed in an error (it is key
// material).
func newVaultCipher(cfg config.Config) (*secret.Cipher, error) {
	if cfg.BankVaultKey == "" {
		return nil, nil
	}
	key, err := hex.DecodeString(cfg.BankVaultKey)
	if err != nil {
		return nil, fmt.Errorf("api: PAYMENT_BANK_VAULT_KEY is not valid hex")
	}
	cipher, err := secret.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("api: PAYMENT_BANK_VAULT_KEY invalid: %w", err)
	}
	return cipher, nil
}

// newBankVaults selects the bank credential + certificate vault adapters (SIN-69366).
// With a non-nil cipher (PAYMENT_BANK_VAULT_KEY set) it returns the DURABLE,
// encrypted-at-rest SQLite vaults — seeding the credential vault from env ONLY where a
// (tenant, bank) row is absent (env-as-bootstrap, DB-as-durable-source). With a nil
// cipher it returns the in-memory vaults (previous behaviour), logging the
// restart-durability caveat so an operator running a real deployment without a key
// sees it. The cipher is built once by newVaultCipher and shared across all vaults.
func newBankVaults(ctx context.Context, cfg config.Config, db *sql.DB, cipher *secret.Cipher) (credentialAdapter, certificateAdapter, error) {
	if cipher == nil {
		log.Print("api: bank secret vault is IN-MEMORY (PAYMENT_BANK_VAULT_KEY unset) — runtime-configured credentials/certificates do NOT survive a restart")
		return secret.NewStore(cfg.BankCreds), secret.NewCertStore(), nil
	}
	credVault := sqlite.NewCredentialVault(db, cipher, system.Clock{})
	if err := credVault.Seed(ctx, cfg.BankCreds); err != nil {
		return nil, nil, fmt.Errorf("api: seed durable credential vault: %w", err)
	}
	certVault := sqlite.NewCertificateVault(db, cipher, system.Clock{})
	log.Print("api: durable encrypted-at-rest bank secret vault ENABLED (PAYMENT_BANK_VAULT_KEY set) — credentials/certificates survive a restart")
	return credVault, certVault, nil
}

// defaultWebhookCallbackBaseURL is the receiver's public origin the in-flow C6
// webhook callback URL (/webhooks/c6/{ref}) is built from. It mirrors
// cmd/register-webhook's default so the one-shot cmd (F3) and the in-flow registration
// (F2) target the same origin. Overridable via PAYMENT_WEBHOOK_BASE_URL for staging.
const defaultWebhookCallbackBaseURL = "https://payment.lmhost.com.br"

// webhookCallbackBaseURL resolves the public callback origin for the in-flow C6
// webhook registration (SIN-69560), reading PAYMENT_WEBHOOK_BASE_URL and falling back
// to the receiver VPS. The trailing slash is trimmed so the app service can append the
// canonical /webhooks/c6/{ref} path.
func webhookCallbackBaseURL() string {
	if v := strings.TrimRight(strings.TrimSpace(os.Getenv("PAYMENT_WEBHOOK_BASE_URL")), "/"); v != "" {
		return v
	}
	return defaultWebhookCallbackBaseURL
}

// newBankRegistry builds the multi-bank registry (SIN-66022): one ProviderSet per
// wired bank. Today the platform integrates a single bank, C6 — the real adapter
// when its endpoints are configured (OAuth2 + HTTPS transport + error mapping),
// otherwise the in-memory stub so local dev and tests still boot. Adding a second
// bank is a Register call here; nothing downstream changes (the services depend on
// the routers, not on a bank instance).
//
// For C6 the settlement reconcile read is routed through the BACEN-verified PIX
// immediate-charge read (GetImmediateCharge / GET …/v1/pix/{txid}), NOT the
// speculative generic GET /charges/{txid} (SIN-64780 routing decision, CTO on
// SIN-64791). The C6 provider satisfies both BankProvider and PixProvider, so it is
// wrapped in PixSettlementProvider for the generic Bank port (charge creation +
// settlement reconcile via the verified PIX shape) while the raw provider backs the
// immediate-PIX-charge port (PixService must speak the BACEN PIX shape directly).
func newBankRegistry(cfg config.Config, creds ports.CredentialStore, certs c6.CertProvider) (*bank.Registry, error) {
	reg := bank.NewRegistry()
	if cfg.C6.BaseURL == "" {
		log.Print("api: PAYMENT_C6_BASE_URL not set — using in-memory bank stub")
		stub := bank.NewStubProvider(creds)
		if err := reg.Register(ports.BankIDC6, buildProviderSet(stub, stub)); err != nil {
			return nil, err
		}
		return reg, nil
	}
	c6cfg := c6.Config{
		BaseURL:            cfg.C6.BaseURL,
		TokenURL:           cfg.C6.TokenURL,
		Scope:              cfg.C6.Scope,
		Timeout:            cfg.C6.Timeout,
		RateLimitPerSecond: cfg.C6.RateLimitRPS,
		RateLimitBurst:     cfg.C6.RateLimitBurst,
		MaxRetries:         cfg.C6.MaxRetries,
		BillingScheme:      cfg.C6.BillingScheme,
	}
	// C6 requires an mTLS client certificate on the connection. The transport now
	// sources that certificate from the DURABLE vault, selected PER REQUEST by tenant
	// (SIN-69368), so a self-serve cert (PUT /v1/bank-certificate) actually feeds the
	// live handshake — durability now equals consumption. A tenant with no vault row
	// falls back to the §8 path certificate (env-as-bootstrap, mirroring the credential
	// vault); a load failure of that path fails the boot closed. Both the vault and the
	// §8 path empty ⇒ no client cert presented, preserving stub/dev behaviour. The
	// per-tenant transports keep tenant identities off each other's connections.
	httpc, err := c6.NewVaultMTLSClient(certs, ports.BankIDC6, cfg.C6.ClientCertPath, cfg.C6.ClientKeyPath, cfg.C6.Timeout)
	if err != nil {
		return nil, err
	}
	c6cfg.HTTPClient = httpc
	if cfg.C6.ClientCertPath != "" || cfg.C6.ClientKeyPath != "" {
		log.Print("api: C6 mTLS transport wired (vault-per-tenant with §8 path bootstrap fallback)")
	} else {
		log.Print("api: C6 mTLS transport wired (vault-per-tenant; no §8 path bootstrap configured)")
	}
	// PIX Automático (Recorrência) reads are JWS-signed; wire the concrete verifier
	// when a JWKS URL is configured. The verifier reuses the C6 HTTP client (so a
	// JWKS served behind the same mTLS connection is reached with the client cert);
	// when nil it builds its own TLS-1.2+ client. A bad JWKS URL fails the boot
	// closed. When PAYMENT_C6_REC_JWKS_URL is unset the verifier stays nil and the
	// recurrence reads fail secure (ErrUnavailable) — the correct interim until F4
	// go-live (SIN-66061).
	//
	// The JWKS endpoint is process-wide with no natural tenant, so its request stamps
	// none and the vault mTLS transport would fall back to the §8 bootstrap cert; on a
	// vault-only deployment that cert is absent and the handshake fails closed
	// (SIN-69375). PAYMENT_C6_REC_JWKS_MTLS_TENANT designates a tenant whose vault cert
	// is presented on the fetch so recurrence verification works without a §8 bootstrap
	// cert. Empty keeps the prior tenantless behaviour.
	if cfg.C6.RecJWKSURL != "" {
		var vopts []c6.VerifierOption
		if cfg.C6.RecJWKSMTLSTenant != "" {
			vopts = append(vopts, c6.WithMTLSTenant(cfg.C6.RecJWKSMTLSTenant))
		}
		verifier, err := c6.NewJWSVerifier(cfg.C6.RecJWKSURL, c6cfg.HTTPClient, vopts...)
		if err != nil {
			return nil, err
		}
		c6cfg.RecurrenceVerifier = verifier
		if cfg.C6.RecJWKSMTLSTenant != "" {
			log.Print("api: C6 recurrence JWS verifier configured (JWKS fetch uses designated mTLS tenant)")
		} else {
			log.Print("api: C6 recurrence JWS verifier configured")
		}
	}
	c6p, err := c6.New(c6cfg, creds)
	if err != nil {
		return nil, err
	}
	if err := reg.Register(ports.BankIDC6, buildProviderSet(bank.NewPixSettlementProvider(c6p, c6p), c6p)); err != nil {
		return nil, err
	}
	return reg, nil
}

// buildProviderSet assembles one bank's ProviderSet from its generic BankProvider
// (charge creation + settlement reconcile) and its raw PixProvider. The segregated
// product ports (cobv, checkout, boleto, DDA, statement) are derived from the raw
// provider — the same instance implements them all in both the C6 and stub cases —
// while the credential-cache invalidator is derived from the generic provider (the
// C6 settlement wrapper forwards InvalidateToken; the stub implements neither, so
// its set carries nil and the admin services fall back to a no-op evictor, ADR-0003).
// A port the bank does not implement is left nil and the router fails closed for it.
func buildProviderSet(generic ports.BankProvider, raw ports.PixProvider) bank.ProviderSet {
	set := bank.ProviderSet{Bank: generic, Pix: raw}
	if v, ok := raw.(ports.PixDueChargeProvider); ok {
		set.PixDueCharge = v
	}
	if v, ok := raw.(ports.CheckoutProvider); ok {
		set.Checkout = v
	}
	if v, ok := raw.(ports.BoletoProvider); ok {
		set.Boleto = v
	}
	if v, ok := raw.(ports.DDAProvider); ok {
		set.DDA = v
	}
	if v, ok := raw.(ports.StatementProvider); ok {
		set.Statement = v
	}
	if v, ok := generic.(ports.CredentialInvalidator); ok {
		set.CredInvalidator = v
	}
	// The C6 raw provider satisfies ports.PixWebhookRegistrar (the stub does not); expose
	// it so the self-serve in-flow webhook registration (SIN-69560 / F2) can PUT/GET the
	// PSP webhook over the same transport. Nil for the stub ⇒ registration is a no-op.
	if v, ok := raw.(ports.PixWebhookRegistrar); ok {
		set.PixWebhook = v
	}
	// The recurrence and PSP-proprietary callbacks share the SAME per-tenant URL as the
	// PIX one — one ref serves every channel. Exposing them here lets the in-flow
	// registration keep all of them pointing at the current ref: a mint supersedes the
	// ref for all at once, so a channel left behind is a silently dead one (SIN-69580).
	if v, ok := raw.(ports.RecurrenceWebhookRegistrar); ok {
		set.RecurrenceWebhook = v
	}
	if v, ok := raw.(ports.ServiceWebhookRegistrar); ok {
		set.ServiceWebhook = v
	}
	if v, ok := raw.(ports.WebhookDeregistrar); ok {
		set.WebhookDeregistrar = v
	}
	return set
}

// recurrenceReaders derives the PIX Automático reconcile-read ports (Rec/CobR) for
// the webhook dispatch (SIN-66036) from the C6 bank's raw provider, which (like the
// stub) implements them. They are read off the ProviderSet's raw Pix provider rather
// than a router because recurrence ports are not yet routed per-bank; that wiring
// moves into the registry routers when a second bank gains PIX Automático
// (SIN-66022). A bank that does not implement the read ports yields nil, leaving the
// recurrence webhook dispatch unwired (it then fails closed) rather than panicking.
func recurrenceReaders(reg *bank.Registry) (ports.RecProvider, ports.CobRProvider) {
	set, ok := reg.Get(ports.BankIDC6)
	if !ok || set.Pix == nil {
		return nil, nil
	}
	recReader, _ := set.Pix.(ports.RecProvider)
	cobrReader, _ := set.Pix.(ports.CobRProvider)
	return recReader, cobrReader
}

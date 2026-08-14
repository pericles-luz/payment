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
	"errors"
	"log"
	stdhttp "net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/adminweb"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/bank"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/bank/c6"
	httpadapter "github.com/ia-dev-sindireceita/payment/internal/adapters/http"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/messaging/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/sqlite"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/system"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/platform/config"
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
	creds := secret.NewStore(cfg.BankCreds)
	// Per-(tenant,bank) mTLS certificate vault (SIN-66087): the admin console writes
	// the cert/key here as write-only material with public metadata exposed. It is
	// in-memory like the OAuth credential store today; an encrypted-at-rest backing
	// is a separable follow-up. The live C6 mTLS transport still loads from the
	// runbook §8 disk path until the transport-swap follow-up lands.
	certs := secret.NewCertStore()
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
	registry, err := newBankRegistry(cfg, creds)
	if err != nil {
		return err
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

	deps := app.Deps{
		Payments:        store,
		Tenants:         store,
		Pricing:         store,
		Ledger:          store,
		Processed:       store,
		Recs:            store,
		CobRs:           store,
		Bus:             inmemory.NewBus(),
		Bank:            routers.Bank,
		Pix:             routers.Pix,
		PixDueCharge:    routers.PixDueCharge,
		Checkout:        routers.Checkout,
		Boleto:          routers.Boleto,
		DDA:             routers.DDA,
		Statement:       routers.Statement,
		RecReader:       recReader,
		CobRReader:      cobrReader,
		Credentials:     creds,
		CredWriter:      creds,
		CertWriter:      certs,
		CredInvalidator: credInvalidator,
		Audit:           store,
		Clock:           system.Clock{},
		IDs:             system.IDProvider{},
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
	auth := httpadapter.NewStaticTokenAuthWithRoles(cfg.TenantTokens, adminRoles, webhookRefs)

	// Admin HTML console (SIN-64727): parse templates up-front so a bad template
	// fails startup, not the first request.
	ui, err := adminweb.New()
	if err != nil {
		return err
	}
	console := app.NewConsoleService(app.ConsoleDeps{
		Tenants:         store,
		Accounts:        store,
		Pricing:         store,
		Ledger:          store,
		CredWriter:      creds,
		CreditorWriter:  creds,
		CredReader:      creds,
		CertWriter:      certs,
		CertReader:      certs,
		Invoices:        store,
		CredInvalidator: credInvalidator,
		Audit:           store,
		Clock:           system.Clock{},
		IDs:             system.IDProvider{},
	})
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
	})

	httpServer := &stdhttp.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           srv.Router(),
		ReadHeaderTimeout: 10 * time.Second,
	}

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
func newBankRegistry(cfg config.Config, creds ports.CredentialStore) (*bank.Registry, error) {
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
	}
	// C6 requires an mTLS client certificate on the connection. When a cert/key
	// path is configured, build a client-cert transport and inject it; a load
	// failure fails the boot closed (explicit error) rather than silently
	// connecting without the cert. Both paths empty ⇒ no client cert (the default
	// transport), preserving stub/dev behaviour.
	if cfg.C6.ClientCertPath != "" || cfg.C6.ClientKeyPath != "" {
		httpc, err := c6.MTLSHTTPClient(cfg.C6.ClientCertPath, cfg.C6.ClientKeyPath, cfg.C6.Timeout)
		if err != nil {
			return nil, err
		}
		c6cfg.HTTPClient = httpc
		log.Print("api: C6 mTLS client certificate loaded")
	}
	// PIX Automático (Recorrência) reads are JWS-signed; wire the concrete verifier
	// when a JWKS URL is configured. The verifier reuses the C6 HTTP client (so a
	// JWKS served behind the same mTLS connection is reached with the client cert);
	// when nil it builds its own TLS-1.2+ client. A bad JWKS URL fails the boot
	// closed. When PAYMENT_C6_REC_JWKS_URL is unset the verifier stays nil and the
	// recurrence reads fail secure (ErrUnavailable) — the correct interim until F4
	// go-live (SIN-66061).
	if cfg.C6.RecJWKSURL != "" {
		verifier, err := c6.NewJWSVerifier(cfg.C6.RecJWKSURL, c6cfg.HTTPClient)
		if err != nil {
			return nil, err
		}
		c6cfg.RecurrenceVerifier = verifier
		log.Print("api: C6 recurrence JWS verifier configured")
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

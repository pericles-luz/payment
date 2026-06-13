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
	auditlog "github.com/ia-dev-sindireceita/payment/internal/adapters/audit/inmemory"
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
	// Append-only audit trail for privileged admin-plane actions. The in-memory
	// log is the foundation default; swap for a persisted append-only adapter
	// without touching the use-cases. Wiring it here is mandatory — AdminService
	// degrades to a no-op log when Audit is nil, which must never happen in prod.
	audit := auditlog.NewLog()

	// Bank provider: use the real C6 adapter when its endpoints are configured,
	// otherwise fall back to the in-memory stub (local dev / tests). The C6
	// adapter rejects non-HTTPS endpoints, so a misconfigured URL fails startup
	// rather than silently downgrading the transport.
	bankProvider, err := newBankProvider(cfg, creds)
	if err != nil {
		return err
	}

	deps := app.Deps{
		Payments:    store,
		Tenants:     store,
		Pricing:     store,
		Ledger:      store,
		Processed:   store,
		Bus:         inmemory.NewBus(),
		Bank:        bankProvider,
		Credentials: creds,
		CredWriter:  creds,
		Audit:       audit,
		Clock:       system.Clock{},
		IDs:         system.IDProvider{},
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
		webhookRefs[ref] = httpadapter.WebhookIdentity{
			TenantID: tenantID,
			ClientID: cfg.BankCreds[tenantID].ClientID,
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
		Tenants:    store,
		Pricing:    store,
		Ledger:     store,
		CredWriter: creds,
		Clock:      system.Clock{},
		IDs:        system.IDProvider{},
	})
	srv := httpadapter.NewServer(httpadapter.Config{
		Charges:       app.NewChargeService(deps),
		Admin:         app.NewAdminService(deps),
		Console:       console,
		UI:            ui,
		Webhooks:      app.NewWebhookService(deps),
		TenantAuth:    auth,
		AdminAuth:     auth,
		WebhookAuth:   auth,
		SecureCookies: cfg.SecureCookies,
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

// newBankProvider selects the bank adapter. When the C6 base URL is configured it
// builds the real C6 provider (OAuth2 + HTTPS transport + error mapping);
// otherwise it returns the in-memory stub so local dev and tests still boot.
func newBankProvider(cfg config.Config, creds ports.CredentialStore) (ports.BankProvider, error) {
	if cfg.C6.BaseURL == "" {
		log.Print("api: PAYMENT_C6_BASE_URL not set — using in-memory bank stub")
		return bank.NewStubProvider(creds), nil
	}
	return c6.New(c6.Config{
		BaseURL:  cfg.C6.BaseURL,
		TokenURL: cfg.C6.TokenURL,
		Scope:    cfg.C6.Scope,
		Timeout:  cfg.C6.Timeout,
	}, creds)
}

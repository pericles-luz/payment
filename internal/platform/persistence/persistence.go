// Package persistence picks the durable storage engine and builds its adapters.
//
// The rest of the program never names an engine. Wiring asks for a Store and the
// per-feature vaults; whether the rows land in a SQLite file or in PostgreSQL is
// decided once, here, by whether PAYMENT_DB_DSN is set:
//
//	DSN set    -> PostgreSQL (migrations/pg), the deployed configuration
//	DSN unset  -> SQLite at PAYMENT_DB_PATH (migrations/), dev, CI and the
//	              rollback path during the lmhost migration
//
// The two adapters are line-for-line siblings — same queries, same ports — so the
// only thing that varies below is which constructor is called.
package persistence

import (
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/postgres"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/sqlite"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/domain/access"
	"github.com/ia-dev-sindireceita/payment/internal/domain/account"
	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
	"github.com/ia-dev-sindireceita/payment/internal/domain/billing"
	"github.com/ia-dev-sindireceita/payment/internal/domain/consoleauth"
	"github.com/ia-dev-sindireceita/payment/internal/domain/invoice"
	"github.com/ia-dev-sindireceita/payment/internal/domain/outboundqueue"
	"github.com/ia-dev-sindireceita/payment/internal/domain/outboundwebhook"
	"github.com/ia-dev-sindireceita/payment/internal/domain/payment"
	"github.com/ia-dev-sindireceita/payment/internal/domain/recurrence"
	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
	"github.com/ia-dev-sindireceita/payment/internal/domain/termsconsent"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
	migrations "github.com/ia-dev-sindireceita/payment/migrations"
	pgmigrations "github.com/ia-dev-sindireceita/payment/migrations/pg"
)

// Store is the full persistence surface wiring hands to the services: every
// repository port plus the listing and unit-of-work methods the console needs.
// Both *sqlite.Store and *postgres.Store satisfy it (asserted below), which is
// what lets the engine be a runtime choice rather than a compile-time one.
type Store interface {
	Append(ctx context.Context, e audit.Entry) error
	AppendLedgerEntry(ctx context.Context, e billing.LedgerEntry) error
	FindAccountByID(ctx context.Context, id string) (*account.Account, error)
	FindCobRByTxID(ctx context.Context, tenantID, txID string) (*recurrence.CobR, error)
	FindInvoiceByID(ctx context.Context, tenantID, id string) (invoice.Invoice, error)
	FindLatestConsent(ctx context.Context, tenantID, subject, termsVersion string) (*termsconsent.Record, error)
	FindPaymentByID(ctx context.Context, tenantID, id string) (*payment.Payment, error)
	FindPaymentByIdempotencyKey(ctx context.Context, tenantID, key string) (*payment.Payment, error)
	FindPaymentByTxID(ctx context.Context, tenantID, txID string) (*payment.Payment, error)
	FindRecByID(ctx context.Context, tenantID, idRec string) (*recurrence.Rec, error)
	FindTenantByID(ctx context.Context, id string) (*tenant.Tenant, error)
	GetEndpointPrice(ctx context.Context, tenantID, endpoint string) (billing.EndpointPricing, error)
	ListAccounts(ctx context.Context) ([]*account.Account, error)
	ListCobRByRec(ctx context.Context, tenantID, idRec string) ([]*recurrence.CobR, error)
	ListConsents(ctx context.Context, tenantID, subject string) ([]*termsconsent.Record, error)
	ListEndpointPrices(ctx context.Context, tenantID string) ([]billing.EndpointPricing, error)
	ListInvoices(ctx context.Context, tenantID string) ([]invoice.Invoice, error)
	ListLedgerEntries(ctx context.Context, tenantID string) ([]billing.LedgerEntry, error)
	ListLedgerEntriesByAccount(ctx context.Context, accountID string) ([]billing.LedgerEntry, error)
	ListTenants(ctx context.Context) ([]*tenant.Tenant, error)
	MarkProcessed(ctx context.Context, tenantID, eventKey string) (bool, error)
	PurgePIIAccessBefore(ctx context.Context, cutoff time.Time) (int64, error)
	RecordConsent(ctx context.Context, rec *termsconsent.Record) error
	RecordPIIAccess(ctx context.Context, e access.Entry) error
	SaveAccount(ctx context.Context, a *account.Account) error
	SaveCobR(ctx context.Context, c *recurrence.CobR) error
	SaveInvoice(ctx context.Context, inv invoice.Invoice) error
	SavePayment(ctx context.Context, p *payment.Payment) error
	SaveRec(ctx context.Context, rec *recurrence.Rec) error
	SaveTenant(ctx context.Context, t *tenant.Tenant) error
	UpsertEndpointPrice(ctx context.Context, p billing.EndpointPricing) error
	WithinTx(ctx context.Context, fn func(ports.Repository) error) error
}

// Both engines expose the same surface. If a query is added to one adapter and not
// the other, this is what fails the build instead of a deployment.
var (
	_ Store                 = (*sqlite.Store)(nil)
	_ Store                 = (*postgres.Store)(nil)
	_ OutboundDeliveryStore = (*sqlite.OutboundDeliveryStore)(nil)
	_ OutboundDeliveryStore = (*postgres.OutboundDeliveryStore)(nil)
	_ AccountKeyStore       = (*sqlite.AccountKeyStore)(nil)
	_ AccountKeyStore       = (*postgres.AccountKeyStore)(nil)
	_ WebhookRefStore       = (*sqlite.WebhookRefStore)(nil)
	_ WebhookRefStore       = (*postgres.WebhookRefStore)(nil)

	_ CredentialVault        = (*sqlite.CredentialVault)(nil)
	_ CredentialVault        = (*postgres.CredentialVault)(nil)
	_ CertificateVault       = (*sqlite.CertificateVault)(nil)
	_ CertificateVault       = (*postgres.CertificateVault)(nil)
	_ OutboundWebhookVault   = (*sqlite.OutboundWebhookVault)(nil)
	_ OutboundWebhookVault   = (*postgres.OutboundWebhookVault)(nil)
	_ ConsoleCredentialVault = (*sqlite.ConsoleCredentialVault)(nil)
	_ ConsoleCredentialVault = (*postgres.ConsoleCredentialVault)(nil)
	_ ConsoleReplayStore     = (*sqlite.ConsoleReplayStore)(nil)
	_ ConsoleReplayStore     = (*postgres.ConsoleReplayStore)(nil)
)

// OutboundDeliveryStore is the durable per-Conta outbox surface: the F1 attributor
// enqueues and dead-letters, the F2 forwarder claims and deletes, and the console
// lists. Both engines satisfy it.
type OutboundDeliveryStore interface {
	EnqueueDelivery(ctx context.Context, d *outboundqueue.Delivery) error
	DeadLetter(ctx context.Context, dl *outboundqueue.DeadLetter) error
	PendingDeliveries(ctx context.Context, accountID string) ([]*outboundqueue.Delivery, error)
	ClaimPendingDeliveries(ctx context.Context, limit int) ([]*outboundqueue.Delivery, error)
	DeleteDelivery(ctx context.Context, id string) error
	DeadLetters(ctx context.Context) ([]*outboundqueue.DeadLetter, error)
}

// AccountKeyStore is the durable, hash-at-rest account-key surface (ADR-0011 §3).
type AccountKeyStore interface {
	PutKey(ctx context.Context, accountID string) (string, error)
	Rotate(ctx context.Context, accountID string) (string, error)
	AuthenticateAccountKey(ctx context.Context, secret string) (string, bool)
}

// WebhookRefStore is the durable per-tenant webhook-ref surface (SIN-69559).
// Refs are stored as SHA-256 only, so nothing here hands back a plaintext ref.
type WebhookRefStore interface {
	PutWebhookRef(ctx context.Context, refSHA []byte, tenantID string) error
	RevokeWebhookRefs(ctx context.Context, tenantID string) (int, error)
	LookupWebhookRef(ctx context.Context, refSHA []byte) (string, bool, error)
}

// CredentialVault is the durable, encrypted-at-rest bank OAuth-credential vault
// (migration 0012). Secrets are sealed with the KEK under an AAD bound to
// (tenantID, bankID), so a row cannot be decrypted after being moved.
type CredentialVault interface {
	Seed(ctx context.Context, creds map[string]ports.BankCredential) error
	GetBankCredential(ctx context.Context, tenantID, bankID string) (ports.BankCredential, error)
	SetBankCredential(ctx context.Context, tenantID, bankID, clientID, secretVal string) error
	DeleteBankCredential(ctx context.Context, tenantID, bankID string) error
	SetCreditorKey(ctx context.Context, tenantID, creditorKey string) error
	ListTenantsWithC6Credential(ctx context.Context) ([]string, error)
	FindTenantsByCreditorKey(ctx context.Context, bankID, creditorKey string) ([]string, error)
	FindTenantsByClientID(ctx context.Context, bankID, clientID string) ([]string, error)
	Reseal(ctx context.Context, oldCipher *secret.Cipher) (int, error)
}

// CertificateVault is the durable, encrypted-at-rest mTLS certificate vault. The
// private key is write-only: it leaves only inside an opaque *tls.Certificate.
type CertificateVault interface {
	SetBankCertificate(ctx context.Context, cert ports.BankCertificate) error
	DeleteBankCertificate(ctx context.Context, tenantID, bankID string) error
	GetBankCertificateMeta(ctx context.Context, tenantID, bankID string) (ports.BankCertificateMeta, error)
	LoadTLSCertificate(ctx context.Context, tenantID, bankID string) (*tls.Certificate, error)
	Reseal(ctx context.Context, oldCipher *secret.Cipher) (int, error)
}

// OutboundWebhookVault is the per-Conta outbound endpoint config (F0). The HMAC
// signing secret is sealed, not hashed, because delivery has to reproduce it.
type OutboundWebhookVault interface {
	GetOutboundWebhook(ctx context.Context, accountID string) (*outboundwebhook.Config, error)
	UpsertOutboundWebhook(ctx context.Context, cfg *outboundwebhook.Config) error
	DeleteOutboundWebhook(ctx context.Context, accountID string) error
}

// ConsoleCredentialVault is the durable console login (argon2id password hash plus
// sealed TOTP secret, migration 0013).
type ConsoleCredentialVault interface {
	GetCredential(ctx context.Context) (consoleauth.Credential, bool, error)
	SaveCredential(ctx context.Context, c consoleauth.Credential) error
}

// ConsoleReplayStore is the single-use guard for RFC6238 steps: a login must
// present a step strictly later than the last one consumed.
type ConsoleReplayStore interface {
	LastStep(ctx context.Context, subject string) (int64, error)
	SetLastStep(ctx context.Context, subject string, step int64) error
}

// Engine names the selected backend, for logs and for the health endpoint.
type Engine string

// The two supported engines.
const (
	EngineSQLite   Engine = "sqlite"
	EnginePostgres Engine = "postgres"
)

// DB is an opened database plus the adapter constructors bound to its engine.
// Close it when done; the caller owns it.
type DB struct {
	Engine Engine
	SQL    *sql.DB
}

// Open opens the engine selected by the config values and applies its migrations.
//
// dsn wins over path when both are set: a deployment that has been pointed at
// PostgreSQL must never silently fall back to a local file, which would come up
// empty and look like data loss.
func Open(ctx context.Context, dsn, path string) (*DB, error) {
	if dsn != "" {
		db, err := postgres.Open(dsn)
		if err != nil {
			return nil, err
		}
		if err := postgres.Migrate(ctx, db, pgmigrations.FS); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("migrate postgres: %w", err)
		}
		return &DB{Engine: EnginePostgres, SQL: db}, nil
	}
	db, err := sqlite.Open(path)
	if err != nil {
		return nil, err
	}
	if err := sqlite.Migrate(ctx, db, migrations.FS); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate sqlite: %w", err)
	}
	return &DB{Engine: EngineSQLite, SQL: db}, nil
}

// Close releases the underlying handle.
func (d *DB) Close() error { return d.SQL.Close() }

// Store builds the main repository/unit-of-work adapter.
func (d *DB) Store() Store {
	if d.Engine == EnginePostgres {
		return postgres.NewStore(d.SQL)
	}
	return sqlite.NewStore(d.SQL)
}

// AccountKeyStore builds the durable, hash-at-rest account-key store (ADR-0011).
func (d *DB) AccountKeyStore(clock ports.Clock) AccountKeyStore {
	if d.Engine == EnginePostgres {
		return postgres.NewAccountKeyStore(d.SQL, clock)
	}
	return sqlite.NewAccountKeyStore(d.SQL, clock)
}

// WebhookRefStore builds the durable per-tenant webhook-ref store (SIN-69559).
func (d *DB) WebhookRefStore(clock ports.Clock) WebhookRefStore {
	if d.Engine == EnginePostgres {
		return postgres.NewWebhookRefStore(d.SQL, clock)
	}
	return sqlite.NewWebhookRefStore(d.SQL, clock)
}

// OutboundDeliveryStore builds the per-Conta outbox (F1/F2).
func (d *DB) OutboundDeliveryStore() OutboundDeliveryStore {
	if d.Engine == EnginePostgres {
		return postgres.NewOutboundDeliveryStore(d.SQL)
	}
	return sqlite.NewOutboundDeliveryStore(d.SQL)
}

// CredentialVault builds the durable bank-credential vault. The caller must have a
// KEK: with a nil cipher the in-memory vaults are the right choice, not this one.
func (d *DB) CredentialVault(cipher *secret.Cipher, clock ports.Clock) CredentialVault {
	if d.Engine == EnginePostgres {
		return postgres.NewCredentialVault(d.SQL, cipher, clock)
	}
	return sqlite.NewCredentialVault(d.SQL, cipher, clock)
}

// CertificateVault builds the durable mTLS certificate vault.
func (d *DB) CertificateVault(cipher *secret.Cipher, clock ports.Clock) CertificateVault {
	if d.Engine == EnginePostgres {
		return postgres.NewCertificateVault(d.SQL, cipher, clock)
	}
	return sqlite.NewCertificateVault(d.SQL, cipher, clock)
}

// OutboundWebhookVault builds the per-Conta outbound endpoint config store (F0).
func (d *DB) OutboundWebhookVault(cipher *secret.Cipher, clock ports.Clock) OutboundWebhookVault {
	if d.Engine == EnginePostgres {
		return postgres.NewOutboundWebhookVault(d.SQL, cipher, clock)
	}
	return sqlite.NewOutboundWebhookVault(d.SQL, cipher, clock)
}

// ConsoleCredentialVault builds the durable console login store.
func (d *DB) ConsoleCredentialVault(cipher *secret.Cipher, clock ports.Clock) ConsoleCredentialVault {
	if d.Engine == EnginePostgres {
		return postgres.NewConsoleCredentialVault(d.SQL, cipher, clock)
	}
	return sqlite.NewConsoleCredentialVault(d.SQL, cipher, clock)
}

// ConsoleReplayStore builds the TOTP single-use guard.
func (d *DB) ConsoleReplayStore(clock ports.Clock) ConsoleReplayStore {
	if d.Engine == EnginePostgres {
		return postgres.NewConsoleReplayStore(d.SQL, clock)
	}
	return sqlite.NewConsoleReplayStore(d.SQL, clock)
}

// ResealAll re-encrypts every sealed credential and certificate row from oldCipher
// to newCipher inside ONE transaction, so a rotation is all-or-nothing. It builds
// the two vaults itself because the engine's ResealAll requires both to share a
// single database handle. Used by cmd/vault-reseal.
func (d *DB) ResealAll(ctx context.Context, newCipher, oldCipher *secret.Cipher, clock ports.Clock) (credN, certN int, err error) {
	if d.Engine == EnginePostgres {
		return postgres.ResealAll(ctx,
			postgres.NewCredentialVault(d.SQL, newCipher, clock),
			postgres.NewCertificateVault(d.SQL, newCipher, clock),
			oldCipher)
	}
	return sqlite.ResealAll(ctx,
		sqlite.NewCredentialVault(d.SQL, newCipher, clock),
		sqlite.NewCertificateVault(d.SQL, newCipher, clock),
		oldCipher)
}

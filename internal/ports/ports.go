// Package ports declares the output ports (driven interfaces) the application
// core depends on. Adapters live in internal/adapters and implement these.
// Interfaces are kept small (accept broad / return narrow) and every data
// operation is tenant-scoped to enforce isolation at the boundary.
package ports

import (
	"context"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/billing"
	"github.com/ia-dev-sindireceita/payment/internal/domain/payment"
	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
)

// Clock abstracts time so the domain stays deterministic and testable.
type Clock interface {
	Now() time.Time
}

// IDProvider abstracts id generation (ULID/UUID in production). IDs must be
// non-sequential to avoid enumeration (threat H5).
type IDProvider interface {
	NewID() string
}

// PaymentRepository persists Payment aggregates. Every read is scoped by
// tenantID — callers pass the tenant derived from the authenticated credential,
// never from client input (threat H1/P1 IDOR).
type PaymentRepository interface {
	SavePayment(ctx context.Context, p *payment.Payment) error
	FindPaymentByID(ctx context.Context, tenantID, id string) (*payment.Payment, error)
	// FindPaymentByIdempotencyKey returns ErrNotFound when no prior request used
	// the key. Used to make charge creation idempotent.
	FindPaymentByIdempotencyKey(ctx context.Context, tenantID, key string) (*payment.Payment, error)
	FindPaymentByTxID(ctx context.Context, tenantID, txID string) (*payment.Payment, error)
}

// TenantRepository persists Tenant aggregates (admin plane).
//
// Read-side listing for the admin console (ListTenants) is declared by the
// narrow app.TenantStore port rather than widened here, so this canonical port
// stays minimal and existing test doubles need not implement console-only reads.
type TenantRepository interface {
	SaveTenant(ctx context.Context, t *tenant.Tenant) error
	FindTenantByID(ctx context.Context, id string) (*tenant.Tenant, error)
}

// PricingRepository resolves and stores per-endpoint pricing. The admin-console
// listing (ListEndpointPrices) is declared by app.PricingStore, keeping this
// port narrow (the concrete stores implement both).
type PricingRepository interface {
	// GetEndpointPrice returns the price for a tenant × endpoint, or ErrNotFound.
	GetEndpointPrice(ctx context.Context, tenantID, endpoint string) (billing.EndpointPricing, error)
	UpsertEndpointPrice(ctx context.Context, p billing.EndpointPricing) error
}

// LedgerRepository appends billable events atomically. Append-only. The
// console's read side (ListLedgerEntries) is declared by app.LedgerReader so
// this write port stays focused on the append path.
type LedgerRepository interface {
	AppendLedgerEntry(ctx context.Context, e billing.LedgerEntry) error
}

// Repository is the tenant-scoped persistence surface that can take part in a
// single unit of work. It bundles the individual repository ports so a use-case
// can perform several writes that must commit or roll back together — the
// transactional boundary financial integrity depends on (no payment without its
// ledger entry, no event marked processed without its settlement).
type Repository interface {
	PaymentRepository
	TenantRepository
	PricingRepository
	LedgerRepository
	ProcessedEventStore
}

// UnitOfWork runs fn inside one atomic transaction. Every write performed through
// the supplied Repository commits together when fn returns nil and rolls back
// together when fn returns a non-nil error (or panics). Multi-write use-cases
// (charge creation, webhook settlement) wrap their writes in WithinTx so a
// partial failure can never leave the system in an inconsistent state.
//
// A SavePayment that would violate the per-tenant idempotency-key uniqueness must
// surface shared.ErrConflict so callers can resolve the race to the winning
// payment instead of double-charging.
type UnitOfWork interface {
	WithinTx(ctx context.Context, fn func(r Repository) error) error
}

// ProcessedEventStore records which external events (webhooks) have already been
// handled, providing webhook idempotency / anti-replay (threat W2).
type ProcessedEventStore interface {
	// MarkProcessed atomically records an event key for a tenant. It returns
	// (false, nil) if the key was already present (duplicate/replay), (true, nil)
	// when newly recorded.
	MarkProcessed(ctx context.Context, tenantID, eventKey string) (firstTime bool, err error)
}

// Message is a tenant-scoped event carried over the bus. Payload is opaque bytes
// (e.g. JSON). IdempotencyKey lets consumers dedupe (threat Q3).
type Message struct {
	TenantID       string
	Type           string
	IdempotencyKey string
	Payload        []byte
}

// MessageHandler processes a delivered message. A nil return acks the message.
type MessageHandler func(ctx context.Context, m Message) error

// MessageBus is the output port for async messaging. Adapters: RabbitMQ and an
// in-memory bus for tests/dev.
type MessageBus interface {
	Publish(ctx context.Context, topic string, m Message) error
	Subscribe(ctx context.Context, topic string, h MessageHandler) error
}

// BankCredential is a tenant's bank (PSP) credential reference. The secret value
// is fetched via the store at use time and never stored in domain state or logs
// (threat C1).
type BankCredential struct {
	TenantID string
	ClientID string
	// Secret is populated only transiently when resolved from the store.
	Secret string
}

// CredentialStore isolates bank credentials per tenant behind a secret store.
// No secret ever lives in code; the adapter reads from config/vault (threat C1/C4).
type CredentialStore interface {
	GetBankCredential(ctx context.Context, tenantID string) (BankCredential, error)
}

// CredentialWriter is the write path for per-tenant bank credentials (admin
// plane). It is kept separate from CredentialStore (the reader) so use-cases
// depend only on the capability they need (ISP). The secret transits straight to
// the store: it MUST NOT enter domain state, logs, errors or URLs (threat C1/C4).
type CredentialWriter interface {
	SetBankCredential(ctx context.Context, tenantID, clientID, secret string) error
}

// ChargeRequest is the input to create a charge at the bank.
type ChargeRequest struct {
	TenantID    string
	PaymentID   string
	AmountCents int64
	Currency    string
}

// ChargeResult is the bank's response to a charge creation.
type ChargeResult struct {
	TxID   string
	Status string
}

// BankProvider is the output port for the bank/PSP (C6 first). A stub
// implementation backs the foundation; the real C6 adapter is a later workstream
// and re-passes the threat model (mTLS, OAuth, webhook authenticity).
type BankProvider interface {
	CreateCharge(ctx context.Context, tenantID string, req ChargeRequest) (ChargeResult, error)
	// GetCharge reconciles the authoritative state of a charge (never trust a raw
	// webhook — threat W3).
	GetCharge(ctx context.Context, tenantID, txID string) (ChargeResult, error)
}

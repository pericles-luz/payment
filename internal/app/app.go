// Package app contains the application services (use-cases / input ports). They
// orchestrate the pure domain and the output ports. This layer MUST NOT import
// database/sql, net/http or vendor SDKs — only domain types and ports.
package app

import "github.com/ia-dev-sindireceita/payment/internal/ports"

// Topics published by the application services.
const (
	TopicPaymentCreated = "payment.created"
	TopicPaymentPaid    = "payment.paid"
)

// Deps bundles the output ports the application services depend on. Each service
// takes only the narrow set it needs; Deps is a convenience for wiring in cmd.
type Deps struct {
	Payments    ports.PaymentRepository
	Tenants     ports.TenantRepository
	Pricing     ports.PricingRepository
	Ledger      ports.LedgerRepository
	Processed   ports.ProcessedEventStore
	Bus         ports.MessageBus
	Bank        ports.BankProvider
	Credentials ports.CredentialStore
	// CredWriter is the admin-plane write path for per-tenant bank credentials.
	// Kept separate from Credentials (the reader) so each service depends only on
	// the capability it needs.
	CredWriter ports.CredentialWriter
	// UoW is the transactional boundary used by multi-write use-cases. Production
	// wiring MUST supply one (the SQLite adapter implements it) so charge creation
	// and settlement are atomic. When nil, services fall back to an autocommit
	// unit of work (each write commits on its own) — acceptable only for unit
	// tests that inject per-port fakes, never for storage-backed production use.
	UoW ports.UnitOfWork
	// Audit is the append-only audit trail for privileged admin-plane actions.
	// When nil, AdminService falls back to a no-op log (foundation default) — a
	// footgun: production MUST wire a real audit log so privileged actions are
	// recorded for forensics/compliance.
	Audit ports.AuditLog
	Clock ports.Clock
	IDs   ports.IDProvider
}

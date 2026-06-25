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
	Payments  ports.PaymentRepository
	Tenants   ports.TenantRepository
	Pricing   ports.PricingRepository
	Ledger    ports.LedgerRepository
	Processed ports.ProcessedEventStore
	Bus       ports.MessageBus
	Bank      ports.BankProvider
	// Pix is the immediate-PIX-charge port (cobrança imediata). It is segregated
	// from Bank (ISP): PixService depends only on it. In production it is the C6
	// provider itself (the raw PixProvider, NOT the settlement wrapper); in stub mode
	// it is the in-memory StubProvider. When nil, PixService is simply not wired.
	Pix ports.PixProvider
	// PixDueCharge is the PIX cobrança-com-vencimento (cobv) port. Segregated from
	// Pix (ISP): PixDueChargeService depends only on it. In production it is the C6
	// provider; in stub mode the in-memory StubProvider. When nil, the service is
	// simply not wired.
	PixDueCharge ports.PixDueChargeProvider
	// Checkout is the unified C6 hosted-checkout port (roteiro 9). Segregated from
	// Bank/Pix (ISP): CheckoutService depends only on it. In production it is the C6
	// provider; in stub mode the in-memory StubProvider. When nil, CheckoutService is
	// simply not wired.
	Checkout ports.CheckoutProvider
	// Boleto is the BolePix boleto port (roteiro grupos 1–6). Segregated from
	// Bank/Pix/Checkout (ISP): BoletoService depends only on it. In production it is
	// the C6 provider; in stub mode the in-memory StubProvider. When nil, BoletoService
	// is simply not wired.
	Boleto ports.BoletoProvider
	// DDA is the DDA / agendamento-de-pagamentos port (roteiro grupo 8). Segregated
	// from the other bank ports (ISP): DDAService depends only on it. In production it
	// is the C6 provider; in stub mode the in-memory StubProvider. When nil, DDAService
	// is simply not wired.
	DDA ports.DDAProvider
	// Statement is the account-statement (extrato) port (roteiro grupo 13). Segregated
	// from the other bank ports (ISP): StatementService depends only on it. In
	// production it is the C6 provider; in stub mode the in-memory StubProvider. When
	// nil, StatementService is simply not wired.
	Statement   ports.StatementProvider
	Credentials ports.CredentialStore
	// CredWriter is the admin-plane write path for per-tenant bank credentials.
	// Kept separate from Credentials (the reader) so each service depends only on
	// the capability it needs.
	CredWriter ports.CredentialWriter
	// CredInvalidator evicts cached state keyed on a tenant's credential (the C6
	// OAuth2 token cache) right after a credential write, closing the
	// token-revocation lag (ADR-0003). Optional: when nil the admin services use a
	// no-op (e.g. the in-memory bank stub has no token cache to evict).
	CredInvalidator ports.CredentialInvalidator
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

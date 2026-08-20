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
	// Recs / CobRs are the PIX Automático (recorrência) durable repositories
	// (SIN-66037). They are bundled into the transactional Repository so a mandate
	// status transition and its audit entry commit atomically. Optional in unit
	// tests using per-port fakes; production wires the storage adapter as UoW (which
	// implements them), so the autocommit fallback rarely uses these directly.
	Recs  ports.RecRepository
	CobRs ports.CobRRepository
	Bus   ports.MessageBus
	Bank  ports.BankProvider
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
	Statement ports.StatementProvider
	// RecReader / CobRReader are the recurrence reconcile-read ports (PIX Automático,
	// SIN-66036). The recurrence webhook handler reconciles the authoritative mandate
	// (GetRec) / charge (GetCobR) state before acting on an inbound notification —
	// never trusting the raw webhook body (threat W3). Segregated from the create
	// ports (ISP): WebhookService depends only on the narrow readers. When nil, the
	// recurrence webhook dispatch is not wired. In production both are the C6
	// provider; in stub mode the in-memory StubProvider.
	RecReader   ports.RecProvider
	CobRReader  ports.CobRProvider
	Credentials ports.CredentialStore
	// CredWriter is the admin-plane write path for per-tenant bank credentials.
	// Kept separate from Credentials (the reader) so each service depends only on
	// the capability it needs.
	CredWriter ports.CredentialWriter
	// Sharing keeps a bank identity (PIX key / PSP account) from being claimed by two
	// ACTIVE empresas at once. Optional; nil disables the guard. See bank_identity.go.
	Sharing ports.CreditorKeySharingLookup
	// CertWriter is the admin-plane write path for per-(tenant,bank) mTLS client
	// certificates (SIN-66087). Kept separate from CredWriter (a different secret
	// aggregate) so the AdminService depends only on the capability it needs. When
	// nil, the certificate write use-case is unavailable (the endpoint is only wired
	// when a store is provided).
	CertWriter ports.BankCertificateWriter
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
	// PIIAccess is the append-only LGPD / art.13 register of READ access to a
	// titular's personal data at rest (ADR-0008, SIN-68748). It is bundled into the
	// unit of work so a mediated read of local PII and its access record commit
	// atomically (Complete Mediation). When nil, PIIAccessService falls back to a
	// no-op recorder (unit tests) — a footgun: production MUST wire a real
	// append-only recorder so PII reads are recorded for LGPD compliance.
	PIIAccess ports.PIIAccessRecorder
	// OutboundAttributor materialises a settled inbound event onto its owning Conta's
	// outbound-delivery outbox (SIN-69491, F1 of SIN-69486). When nil (or disabled via
	// the PAYMENT_ACCOUNT_OUTBOUND_WEBHOOK flag) the WebhookService simply does not
	// attribute — the feature is dark and the settle path is unchanged. It is
	// best-effort: an attribution failure never affects the webhook ACK to the bank.
	OutboundAttributor *OutboundAttributor
	Clock              ports.Clock
	IDs                ports.IDProvider
}

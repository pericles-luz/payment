// Package ports declares the output ports (driven interfaces) the application
// core depends on. Adapters live in internal/adapters and implement these.
// Interfaces are kept small (accept broad / return narrow) and every data
// operation is tenant-scoped to enforce isolation at the boundary.
package ports

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
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

// AuditLog is the append-only output port for the privileged admin-plane audit
// trail. Implementations MUST treat entries as immutable (append-only) and MUST
// NOT persist or log any secret value — an audit.Entry carries only who/what/
// tenant/when by construction. When backed by a persisted store, the append
// should share the triggering operation's transaction so the action and its
// audit record commit atomically (threat: forensic gaps).
type AuditLog interface {
	Append(ctx context.Context, e audit.Entry) error
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

// String implements fmt.Stringer so a credential can never leak its secret
// through %v/%s/%+v formatting in logs or errors (defense-in-depth, threat C1).
func (c BankCredential) String() string {
	return fmt.Sprintf("BankCredential{TenantID:%s ClientID:%s Secret:[REDACTED]}", c.TenantID, c.ClientID)
}

// LogValue implements slog.LogValuer so structured logging emits the credential
// without its secret, even when logged as an attribute value (threat C1/C4).
func (c BankCredential) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("tenant_id", c.TenantID),
		slog.String("client_id", c.ClientID),
		slog.String("secret", "[REDACTED]"),
	)
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

// CredentialInvalidator is the optional hook the admin plane invokes right after
// a tenant's bank credential is (re)written, so an adapter that caches state
// keyed on that credential — notably the C6 OAuth2 client_credentials token
// cache — can evict the tenant's entry immediately instead of serving a bearer
// minted under the old secret until it expires (token-revocation lag; ADR-0003 /
// SIN-64764). It is intentionally separate from CredentialWriter: the writer
// persists the secret, the invalidator only drops volatile caches, and a write
// path that has no cache to evict (e.g. the in-memory bank stub) simply omits it.
//
// InvalidateToken MUST be safe to call for an unknown tenant (no-op). It is
// best-effort and local, and so carries neither context nor error: dropping an
// in-memory entry cannot fail and MUST never fail the credential write that
// already succeeded. Eviction is per-process; in a multi-replica deployment each
// replica evicts the cache on the write it serves and other replicas still
// converge within the token TTL (see ADR-0003).
type CredentialInvalidator interface {
	InvalidateToken(tenantID string)
}

// ChargeRequest is the input to create a charge at the bank.
type ChargeRequest struct {
	TenantID    string
	PaymentID   string
	AmountCents int64
	Currency    string
	// IdempotencyKey is the tenant's idempotency key for this charge. The real C6
	// adapter MUST forward it to the PSP (e.g. as the provider's Idempotency-Key)
	// so the bank itself deduplicates retried/concurrent CreateCharge calls. This
	// is defense-in-depth for double-charge (F3b): it complements the local
	// reservation done before the bank call (F3a, SIN-64719) so a crash window
	// between charging the bank and persisting the key cannot bill twice — the PSP
	// collapses the duplicate even when the caller cannot. Empty means the caller
	// did not supply one; adapters MUST then fall back to a deterministic key
	// (e.g. PaymentID) and never silently drop idempotency.
	IdempotencyKey string
	// DebtorTaxID and DebtorName identify the payer (devedor) on an immediate PIX
	// charge (homologação roteiro 7.2). Both are OPTIONAL — a PIX charge may omit
	// the devedor entirely — and apply ONLY to the PIX immediate-charge port; the
	// generic BankProvider charge path ignores them. DebtorTaxID, when present, is an
	// all-digit CPF (11) or CNPJ (14); the use-case validates the format at its
	// boundary before it reaches the adapter, so the adapter only maps it into the
	// PSP's devedor block. DebtorName is the payer's name and is never logged.
	DebtorTaxID string
	DebtorName  string
}

// ChargeResult is the bank's response to a generic charge (the non-PIX charge
// surface, e.g. C6 GET /charges/{txid}). It carries the reconciled lifecycle
// status plus the money needed to reconcile a settlement.
//
//   - Status is the PSP's charge status verbatim ("paid", "pending", ...).
//     Settlement reads this from GetCharge, never from a raw webhook
//     (reconcile-before-settle, threat W3).
//   - ExpectedAmountCents is the charge's original amount (valor.original) in
//     cents — what the payer was asked to pay.
//   - ReceivedAmountCents is the amount actually received in cents (the sum of
//     the reconciled receipts). It is zero while the charge is unpaid and equals
//     the expected amount on a correctly paid charge.
//
// Reconciling only Status proves the charge is marked paid; it does NOT prove the
// payer paid the right amount. Settlement MUST also assert the money adds up
// (AmountReconciled) before liquidating — a partial payment, an adjustable charge
// paid to a different value, or manipulation would otherwise settle for the wrong
// amount (reconcile-before-settle, threat W3).
//
// It is intentionally kept distinct from PixChargeResult (ISP): a PIX charge
// carries QR lifecycle data a generic charge does not, so the two result types are
// not collapsed even though both now carry expected/received cents.
type ChargeResult struct {
	TxID                string
	Status              string
	ExpectedAmountCents int64
	ReceivedAmountCents int64
}

// AmountReconciled reports whether the amount received on this charge exactly
// matches the amount that was expected (original). It mirrors
// PixChargeResult.AmountReconciled: a non-positive expected amount is never
// reconciled (a degenerate charge would otherwise fail open), and overpayment
// (received > expected) is a divergence too, so the check is strict equality.
//
// The generic webhook settlement path asserts this inside its transactional
// boundary, in addition to a paid status, before liquidating; a false result is a
// divergence (shared.ErrAmountMismatch territory) that blocks settlement and
// raises an audit event.
func (r ChargeResult) AmountReconciled() bool {
	return r.ExpectedAmountCents > 0 && r.ReceivedAmountCents == r.ExpectedAmountCents
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

// PixChargeResult is the bank's representation of an immediate PIX charge
// (cobrança imediata): its reconciled lifecycle status plus the QR-code material
// and the instant the QR expires.
//
//   - Status is the PSP's charge status verbatim (e.g. "ATIVA", "CONCLUIDA",
//     "REMOVIDA_PELO_PSP"). Settlement decisions read this from GetImmediateCharge,
//     never from a raw webhook (reconcile-before-settle, threat W3).
//   - QRCodePayload is the BACEN "PIX copia e cola" (EMV) string the payer pastes
//     into their bank app.
//   - QRCodeLocation is the URL from which the QR-code image can be rendered.
//   - ExpiresAt is the instant the QR/charge expires; the zero value means the PSP
//     did not return an expiry. Callers treat now > ExpiresAt as an expired QR.
//   - ExpectedAmountCents is the charge's original amount (valor.original) in
//     cents — what the payer was asked to pay.
//   - ReceivedAmountCents is the sum of the reconciled PIX receipts (the pix[]
//     array, each pix.valor) in cents — what was actually received. It is zero
//     while the charge is unpaid (ATIVA) and equals the expected amount on a
//     correctly paid CONCLUIDA charge.
//
// Reconciling only Status proves the charge is marked paid; it does NOT prove the
// payer paid the right amount. Settlement MUST also assert the money adds up
// (AmountReconciled) before liquidating, otherwise a charge paid to a lesser value
// (partial payment, adjustable cob, manipulation) would settle for the wrong
// amount (reconcile-before-settle, threat W3).
//
// It is intentionally distinct from ChargeResult: a PIX charge carries QR
// lifecycle data a plain charge does not, and keeping it separate avoids widening
// the generic charge result with PIX-only fields.
type PixChargeResult struct {
	TxID                string
	Status              string
	QRCodePayload       string
	QRCodeLocation      string
	ExpiresAt           time.Time
	ExpectedAmountCents int64
	ReceivedAmountCents int64
}

// AmountReconciled reports whether the amount received on this charge exactly
// matches the amount that was expected (original). It is the money half of
// reconcile-before-settle: a settlement use-case asserts this — inside its
// transactional boundary (WithinTx) and in addition to a CONCLUIDA, non-expired
// status — before liquidating, treating a false result as a divergence
// (shared.ErrAmountMismatch) that blocks settlement and raises an audit event.
//
// A non-positive expected amount is never reconciled: it is a degenerate charge,
// and settling against it would fail open. Overpayment (received > expected) is a
// divergence too, so the check is strict equality rather than ">=".
func (r PixChargeResult) AmountReconciled() bool {
	return r.ExpectedAmountCents > 0 && r.ReceivedAmountCents == r.ExpectedAmountCents
}

// PixProvider is the output port for immediate PIX charges at the bank/PSP,
// satisfied by the C6 adapter. It is kept separate from BankProvider (ISP) so a
// use-case that only needs generic charges does not depend on PIX QR semantics.
type PixProvider interface {
	// CreateImmediateCharge idempotently creates an immediate PIX charge and
	// returns its QR code and expiry. req.IdempotencyKey (falling back to the
	// PaymentID) anchors idempotency: a re-submit with the same key resolves to the
	// same charge and never creates a duplicate. expiresIn is the QR lifetime; a
	// non-positive value lets the adapter apply its default.
	CreateImmediateCharge(ctx context.Context, tenantID string, req ChargeRequest, expiresIn time.Duration) (PixChargeResult, error)
	// GetImmediateCharge reconciles the authoritative state of a PIX charge — the
	// source of truth for settlement (never trust a raw webhook — threat W3).
	GetImmediateCharge(ctx context.Context, tenantID, txID string) (PixChargeResult, error)
	// ListImmediateCharges returns the immediate PIX charges created within the
	// filter's date window (BACEN GET /cob by interval, homologação roteiro 7.4),
	// paginated. It is a pure read and never mutates a charge. The tenant is explicit
	// so per-tenant credential isolation is never bypassed (threat H1/P1).
	ListImmediateCharges(ctx context.Context, tenantID string, filter PixListFilter) (PixChargeList, error)
}

// PixListFilter is the date-window + pagination filter for listing immediate PIX
// charges. Start and End are the BACEN inicio/fim bounds (required); Page and
// PageSize map to paginacao.paginaAtual / paginacao.itensPorPagina (optional — a
// zero value lets the adapter/PSP apply its default).
type PixListFilter struct {
	Start    time.Time
	End      time.Time
	Page     int
	PageSize int
}

// PixChargeList is a page of immediate PIX charges plus the pagination echo from
// the PSP so a caller can iterate the full window.
type PixChargeList struct {
	Charges    []PixChargeResult
	Page       int
	PageSize   int
	TotalItems int
	TotalPages int
}

// The product-specific bank ports below (PIX Automático consent, BolePix boleto,
// unified checkout) are deliberately kept SEPARATE from BankProvider rather than
// widening it. Interface Segregation: a use-case that only creates boletos should
// not be forced to depend on consent or checkout methods, and existing
// BankProvider consumers/test-doubles are unaffected. The C6 adapter implements
// all of them; a stub backs them for tests. Each carries tenantID explicitly so
// the per-tenant credential/token isolation the C6 adapter enforces is never
// bypassed (the tenant is derived from the authenticated caller, never client
// input — threat H1/P1).

// ConsentRequest is the input to register a recurring-debit (PIX Automático)
// consent at the bank. Amount and window mirror the domain consent; the adapter
// only transports them. IdempotencyKey, when present, is forwarded so the PSP
// collapses retried/concurrent registrations into one consent.
type ConsentRequest struct {
	TenantID       string
	ConsentID      string
	DebtorTaxID    string
	MaxAmountCents int64
	Currency       string
	Frequency      string
	StartAt        time.Time
	EndAt          time.Time // zero => open-ended
	IdempotencyKey string
}

// ConsentResult is the bank's response to a consent operation.
type ConsentResult struct {
	ConsentID string
	Status    string
}

// ConsentProvider is the output port for PIX Automático recurring-debit consents:
// register, reconcile and cancel. Cancellation must be supported because a payer
// can revoke authorization at any time.
type ConsentProvider interface {
	CreateConsent(ctx context.Context, tenantID string, req ConsentRequest) (ConsentResult, error)
	// GetConsent reconciles the authoritative consent state from the bank (never
	// trust a raw webhook — threat W3).
	GetConsent(ctx context.Context, tenantID, consentID string) (ConsentResult, error)
	// CancelConsent revokes a consent so no further debits can be originated.
	CancelConsent(ctx context.Context, tenantID, consentID string) (ConsentResult, error)
}

// BoletoRequest is the input to register a BolePix boleto at the bank. The fine
// and interest RATES are transported so the bank registers them, but the amount
// owed at any instant is computed by the boleto domain, never here (Hexagonal).
type BoletoRequest struct {
	TenantID           string
	BoletoID           string
	AmountCents        int64
	Currency           string
	DueDate            time.Time
	FineBps            int64
	MonthlyInterestBps int64
	PayerTaxID         string
	IdempotencyKey     string
}

// BoletoResult is the bank's response to a boleto registration. It carries the
// scannable artifacts (the PIX EMV "copia e cola" payload and the boleto's
// barcode/linha digitável) the caller renders for the payer.
type BoletoResult struct {
	BoletoID    string
	TxID        string
	Status      string
	QRCode      string // PIX EMV copy-and-paste payload (BolePix)
	Barcode     string // boleto linha digitável / barcode
	AmountCents int64  // principal the bank registered
}

// BoletoProvider is the output port for BolePix boleto registration.
type BoletoProvider interface {
	CreateBoleto(ctx context.Context, tenantID string, req BoletoRequest) (BoletoResult, error)
}

// CheckoutItem is one line of a checkout request (transport mirror of the
// checkout domain Item).
type CheckoutItem struct {
	Description string
	AmountCents int64
}

// CheckoutRequest is the input to open a unified C6 hosted checkout session.
type CheckoutRequest struct {
	TenantID  string
	SessionID string
	Currency  string
	Items     []CheckoutItem
	ExpiresAt time.Time
	// CardType is the permitted card payment method ("credit"|"debit"); the hosted
	// page routes the payer accordingly (roteiro 9.a–9.c).
	CardType string
	// RequireAuthentication asks the hosted page to authenticate the payer (step-up
	// / 3-DS) before capture (roteiro 9.c).
	RequireAuthentication bool
	IdempotencyKey        string
}

// CheckoutResult is the bank's response to opening a checkout session. RedirectURL
// is the hosted page the caller sends the payer to.
type CheckoutResult struct {
	SessionID   string
	Status      string
	RedirectURL string
	AmountCents int64
	// CardType / RequireAuthentication echo the permitted payment method back so the
	// caller's response is self-describing (the C6 create response does not echo
	// them; the adapter sets them from the request).
	CardType              string
	RequireAuthentication bool
}

// CheckoutProvider is the output port for the unified C6 checkout session.
type CheckoutProvider interface {
	CreateCheckoutSession(ctx context.Context, tenantID string, req CheckoutRequest) (CheckoutResult, error)
}

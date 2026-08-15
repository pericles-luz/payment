// Package ports declares the output ports (driven interfaces) the application
// core depends on. Adapters live in internal/adapters and implement these.
// Interfaces are kept small (accept broad / return narrow) and every data
// operation is tenant-scoped to enforce isolation at the boundary.
package ports

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/access"
	"github.com/ia-dev-sindireceita/payment/internal/domain/account"
	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
	"github.com/ia-dev-sindireceita/payment/internal/domain/billing"
	"github.com/ia-dev-sindireceita/payment/internal/domain/payment"
	"github.com/ia-dev-sindireceita/payment/internal/domain/recurrence"
	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
	"github.com/ia-dev-sindireceita/payment/internal/domain/termsconsent"
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

// AccountRepository persists Account aggregates — the API user / reseller that
// owns tenants in the two-level tenancy model (ADR-0009, SIN-69119 §3.1). Kept
// deliberately minimal and separate from TenantRepository: an account is
// attribution-only and never carries a bank credential. Reads are keyed by the
// opaque account id (an account spans tenants, so it is not tenant-scoped);
// isolation between accounts is enforced by the auth choke-point (F1) and by
// deny-by-default listings (F3), not by this write/lookup port.
type AccountRepository interface {
	SaveAccount(ctx context.Context, a *account.Account) error
	FindAccountByID(ctx context.Context, id string) (*account.Account, error)
}

// AccountKeyStore persists and authenticates the rotatable bearer key that an
// Account presents in the model (b) access path (ADR-0011 §3, SIN-69278/B1). It is
// deliberately separate from AccountRepository and from the financial Repository
// bundle: an account key is a credential (hash-at-rest), never an aggregate that
// touches money, so it does not participate in the payment unit-of-work.
//
// Ships DARK: this port exists and has adapters, but nothing calls it yet — the
// choke-point wiring and the flag are phase B2.
//
// Signatures carry only opaque strings so the plaintext secret never crosses the
// port as a domain type, and the interface stays swappable (in-memory ⇄ durable
// sqlite) with identical behaviour.
type AccountKeyStore interface {
	// PutKey mints a fresh key for accountID and returns the plaintext ONCE. It is
	// idempotent in the create==rotate sense (SIN-69196): whether or not the account
	// already has a key, the call replaces it with a new active key and invalidates
	// the previous one immediately. The plaintext is returned only here and must
	// never be logged or persisted in the clear.
	PutKey(ctx context.Context, accountID string) (plaintext string, err error)
	// Rotate is the explicit rotation entrypoint; it has the same effect as PutKey
	// (mint new, invalidate previous) and is provided as an intention-revealing name
	// for callers that are rotating an existing key.
	Rotate(ctx context.Context, accountID string) (plaintext string, err error)
	// AuthenticateAccountKey resolves a presented plaintext secret to its owning
	// account id. It returns ("", false) for any unknown, malformed, or superseded
	// secret — a single non-oracle failure mode, mirroring AuthenticateWebhook.
	AuthenticateAccountKey(ctx context.Context, secret string) (accountID string, ok bool)
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

// RecRepository persists PIX Automático recurring-debit mandates (recurrence.Rec).
// Every read is tenant-scoped — the tenant comes from the authenticated credential,
// never from client input (threat P1 IDOR). Save is an upsert keyed by idRec so a
// reconciled status transition (Rec.Transition) is persisted by re-saving the
// aggregate; pairing the save with its audit entry inside one WithinTx makes the
// transition and its forensic record atomic.
type RecRepository interface {
	SaveRec(ctx context.Context, r *recurrence.Rec) error
	FindRecByID(ctx context.Context, tenantID, idRec string) (*recurrence.Rec, error)
}

// CobRRepository persists the recurring charge instances (recurrence.CobR) of a
// mandate's cycle. Tenant-scoped like RecRepository; Save is an upsert keyed by
// the charge txid (the anti-double-bill anchor). The cycle-listing read
// (ListCobRByRec) is kept off this port — like ListLedgerEntries — so the write
// surface bundled into the transactional Repository stays minimal and runs on a
// single-row tx handle; the concrete store exposes the listing for the cycle view.
type CobRRepository interface {
	SaveCobR(ctx context.Context, c *recurrence.CobR) error
	FindCobRByTxID(ctx context.Context, tenantID, txID string) (*recurrence.CobR, error)
}

// Repository is the tenant-scoped persistence surface that can take part in a
// single unit of work. It bundles the individual repository ports so a use-case
// can perform several writes that must commit or roll back together — the
// transactional boundary financial integrity depends on (no payment without its
// ledger entry, no event marked processed without its settlement, no recurrence
// transition without its audit entry).
type Repository interface {
	PaymentRepository
	TenantRepository
	PricingRepository
	LedgerRepository
	ProcessedEventStore
	RecRepository
	CobRRepository
	// AuditLog is bundled into the unit of work so a privileged action and its
	// audit record commit (or roll back) together: the append runs on the SAME
	// transaction handle as the triggering write (SaveTenant, MarkProcessed),
	// closing the forensic-gap window where the action persisted but its audit
	// record did not (or vice-versa). The standalone Deps.Audit port remains for
	// callers that append outside a transaction (SIN-66025 / SIN-66016).
	AuditLog
	// PIIAccessRecorder is bundled so the art.13 / LGPD access record for reading a
	// titular's PII AT REST (today: pix_rec.devedor_*) commits in the SAME
	// transaction as the read that materialised it. This makes the access log a
	// Complete-Mediation choke-point: if the append fails, the read is rolled back,
	// so there is no unlogged read of local PII (ADR-0008 §5/§6). The standalone
	// Deps.PIIAccess port remains for best-effort logging of pass-through bank reads.
	PIIAccessRecorder
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

// TermsConsentStore is the durable, append-only output port for LGPD consent to
// the Solution's terms of use (C6 Termo 3.5 / B9, SIN-68743). It is a DISTINCT
// concern from the PIX Automático mandate ports above: it records legal consent to
// terms, not an authorization to move money.
//
// Implementations MUST be append-only — RecordConsent only ever INSERTs; there is
// no update or delete path, so a captured consent is immutable and re-consent adds
// a NEW row rather than overwriting the prior one (the forensic property, OWASP
// A09). Every method is tenant-scoped so one tenant can never read another's
// consents (threat P1). A termsconsent.Record carries PII (subject/IP/user-agent)
// which these adapters persist but never log (Record.LogValue redacts it).
type TermsConsentStore interface {
	// RecordConsent durably appends one consent event (append-only INSERT). The
	// Record's id is the opaque primary key, so distinct captures never collide and
	// re-consent to the same version is preserved as a separate row.
	RecordConsent(ctx context.Context, r *termsconsent.Record) error
	// FindLatestConsent returns the most recent consent for (tenant, subject,
	// version), or shared.ErrNotFound when the subject never consented to that
	// version. Tenant-scoped: a subject/version owned by another tenant reads as
	// ErrNotFound (no cross-tenant oracle).
	FindLatestConsent(ctx context.Context, tenantID, subject, termsVersion string) (*termsconsent.Record, error)
	// ListConsents returns a subject's full consent history for a tenant, newest
	// first (granted_at desc, id desc tie-break). It exposes the append-only trail
	// so the immutability of prior captures is observable. Tenant-scoped.
	ListConsents(ctx context.Context, tenantID, subject string) ([]*termsconsent.Record, error)
}

// PIIAccessRecorder is the append-only output port for the LGPD / Decreto
// 8.771/2016 art.13 register of READ access to a titular's personal data in the
// data plane (Termo C6 B10-v; ADR-0008). Implementations MUST treat entries as
// immutable (append-only) and MUST NOT persist or log any plaintext PII — an
// access.Entry carries only a pseudonymous subject_ref by construction (ADR-0008
// §4). When backed by a persisted store, the append should share the mediated
// read's transaction so a read of local PII and its access record commit
// atomically (Complete Mediation): a read whose append fails is rolled back, so
// PII at rest cannot be read without being recorded.
type PIIAccessRecorder interface {
	RecordPIIAccess(ctx context.Context, e access.Entry) error
}

// PIIAccessPurger expires access-log entries by retention policy. This is the ONLY
// delete permitted on the otherwise append-only pii_access_log — LGPD
// minimisation: the register is kept only as long as needed to evidence art.13
// compliance (default bounded, ADR-0008 §3). PurgePIIAccessBefore removes entries
// strictly older than cutoff and returns how many were removed. It runs on the
// connection pool (a maintenance routine), not inside a business transaction, so
// it is kept off the bundled Repository surface.
type PIIAccessPurger interface {
	PurgePIIAccessBefore(ctx context.Context, cutoff time.Time) (int64, error)
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

// BankIDC6 is the canonical, non-secret slug for the C6 bank. It is also the
// retro-compatible DEFAULT bankID applied wherever a bank is not explicitly
// specified (legacy single-bank config, internal pre-multi-bank calls, an empty
// selector). Resolving an unspecified bank to "c6" preserves 100% of the current
// single-bank behaviour while the credential boundary becomes keyed by the
// composite (tenantID, bankID) pair (ADR-0007 / SIN-66015).
const BankIDC6 = "c6"

// knownBankIDs is the closed allow-list of bank slugs the platform has a wired
// adapter for. A credential may be written only for a bank in this set
// (deny-by-default, ADR-0007): an unknown slug is rejected at the admin boundary
// rather than silently persisted under a bank that can never route a charge. The
// set grows as adapters land; today only C6 is integrated.
var knownBankIDs = map[string]struct{}{
	BankIDC6: {},
}

// NormalizeBankID canonicalises a bank slug for the (tenantID, bankID) key: it
// trims surrounding space and lowercases, and applies the retro-compat default —
// an empty selector resolves to BankIDC6. So "C6", " c6 " and "" all key the same
// bank. It is the single place the default is applied on the admin write path so
// the persisted key and the audited bank_id agree.
func NormalizeBankID(bankID string) string {
	bankID = strings.ToLower(strings.TrimSpace(bankID))
	if bankID == "" {
		return BankIDC6
	}
	return bankID
}

// CanonicalBankID canonicalises a request- or wiring-influenced bank slug to its
// store/registry key form and fails closed on anything non-canonical. It lowercases
// and trims surrounding space, then reports ok=false for an empty result or a slug
// carrying NUL or any other control char (< 0x20 or 0x7f). Unlike NormalizeBankID it
// applies NO retro-compat default — an empty selector is reported as not-ok so the
// caller treats it as "no explicit bank", never as a valid slug.
//
// It is the single, shared canonicaliser for the strict slug-key boundaries: the
// HTTP per-request bank selector and the provider Registry key. The credential store
// keys on tenantID + "\x00" + bankID, so a NUL- or control-char-bearing slug must be
// refused BEFORE it can become a key fragment and forge/collide a composite key
// (SIN-66040 / SIN-66056, ADR-0007). Keep this distinct from NormalizeBankID, which
// applies the admin write-path default and relies on the IsKnownBankID allow-list to
// reject unknown slugs.
func CanonicalBankID(bankID string) (string, bool) {
	bankID = strings.ToLower(strings.TrimSpace(bankID))
	if bankID == "" {
		return "", false
	}
	for i := 0; i < len(bankID); i++ {
		if c := bankID[i]; c < 0x20 || c == 0x7f {
			return "", false
		}
	}
	return bankID, true
}

// IsKnownBankID reports whether bankID names a bank the platform supports. Pass a
// value already run through NormalizeBankID. It is the boundary guard for the
// admin credential-write path: an unknown bank MUST be rejected as a validation
// error (deny-by-default) so a credential is never written under a bank with no
// adapter to route it.
func IsKnownBankID(bankID string) bool {
	_, ok := knownBankIDs[bankID]
	return ok
}

// KnownBankIDs returns the closed allow-list of supported bank slugs, sorted for
// deterministic rendering. It is the read side of the same allow-list IsKnownBankID
// guards: the admin console enumerates it to show, per tenant, which supported
// banks have a credential configured (✓) and which are still pending (—), and to
// populate the closed add-bank selector. The returned slice is a fresh copy, so a
// caller can never mutate the allow-list (ADR-0007 deny-by-default).
func KnownBankIDs() []string {
	out := make([]string, 0, len(knownBankIDs))
	for id := range knownBankIDs {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// BankCredential is a tenant's bank (PSP) credential reference, keyed inside the
// credential store by the composite pair (TenantID, BankID): a single tenant may
// hold independent credentials at more than one bank (ADR-0007). The secret value
// is fetched via the store at use time and never stored in domain state or logs
// (threat C1).
type BankCredential struct {
	TenantID string
	// BankID is the non-secret routing slug of the bank this credential belongs to
	// (e.g. "c6"). It is part of the credential's identity — the store keys on
	// (TenantID, BankID) — and is exposed in String()/LogValue() alongside TenantID
	// and ClientID so audit/log can reconstruct which bank routed a charge. It is NOT
	// a secret and never relaxes the tenant scope, it only subdivides it (ADR-0007,
	// threat T2/T4). An empty BankID is treated as the default BankIDC6 by the store
	// (retro-compat); callers SHOULD set it explicitly.
	BankID   string
	ClientID string
	// Secret is populated only transiently when resolved from the store.
	Secret string
	// CreditorKey is the tenant's registered PIX key (chave do recebedor) the
	// adapter injects into a cob/cobv when the request does not carry one. It is
	// NOT a secret — it is the account's public PIX identifier — but it IS
	// sensitive to fund routing: it belongs to the same identity aggregate as
	// ClientID (the tenant's bank identity) and sourcing it from per-tenant config
	// instead of per-request input constrains fund routing to the tenant's
	// registered account (OWASP A01, confused-deputy defense; ADR-0004, SIN-65862).
	// It is redacted from String()/LogValue() so an error or log path that prints a
	// credential cannot leak account-routing data (threat C1/C4).
	CreditorKey string
}

// String implements fmt.Stringer so a credential can never leak its secret
// (or the routing-sensitive creditor key) through %v/%s/%+v formatting in logs
// or errors (defense-in-depth, threat C1/C4; ADR-0004).
func (c BankCredential) String() string {
	return fmt.Sprintf("BankCredential{TenantID:%s BankID:%s ClientID:%s Secret:[REDACTED] CreditorKey:[REDACTED]}", c.TenantID, c.BankID, c.ClientID)
}

// LogValue implements slog.LogValuer so structured logging emits the credential
// without its secret or its routing-sensitive creditor key, even when logged as
// an attribute value (threat C1/C4; ADR-0004).
func (c BankCredential) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("tenant_id", c.TenantID),
		slog.String("bank_id", c.BankID),
		slog.String("client_id", c.ClientID),
		slog.String("secret", "[REDACTED]"),
		slog.String("creditor_key", "[REDACTED]"),
	)
}

// CredentialStore isolates bank credentials per tenant AND per bank behind a
// secret store, keyed by the composite (tenantID, bankID) pair. No secret ever
// lives in code; the adapter reads from config/vault (threat C1/C4).
type CredentialStore interface {
	// GetBankCredential resolves the credential for the EXACT (tenantID, bankID)
	// pair. The tenantID always comes from the authenticated caller, never client
	// input (threat T1/H1); bankID is a non-secret selector WITHIN that tenant's
	// configured banks. The lookup is exact-match with NO fallback: a missing pair
	// returns ErrNotFound and never resolves to another bank or another tenant's
	// credential (deny-by-default, ADR-0007 T1/T2). An empty bankID is treated as the
	// default BankIDC6 (retro-compat).
	GetBankCredential(ctx context.Context, tenantID, bankID string) (BankCredential, error)
}

// CredentialWriter is the write path for per-tenant, per-bank bank credentials
// (admin plane). It is kept separate from CredentialStore (the reader) so use-cases
// depend only on the capability they need (ISP). The secret transits straight to
// the store: it MUST NOT enter domain state, logs, errors or URLs (threat C1/C4).
type CredentialWriter interface {
	// SetBankCredential persists the credential for the (tenantID, bankID) pair. An
	// empty bankID is stored under the default BankIDC6 (retro-compat). Empty
	// tenantID/clientID/secret are rejected as a validation error WITHOUT echoing the
	// secret value (threat C1/C4).
	SetBankCredential(ctx context.Context, tenantID, bankID, clientID, secret string) error
}

// CreditorKeyWriter is the admin-plane write path for a tenant's registered PIX
// creditor key (chave do recebedor). It is kept deliberately separate from
// CredentialWriter so the secret-rotation capability and the fund-routing
// capability are granted independently (ISP, least privilege): the credential
// writer rotates the OAuth secret, this writer points the tenant's funds at a PIX
// key. The creditor key is NOT a secret — it is the account's public PIX
// identifier — but it IS routing-sensitive (OWASP A01 confused-deputy; ADR-0004,
// SIN-65862), so a use-case that only needs to set the key never gains the power
// to rotate the secret and vice versa. The key belongs to the tenant's
// BankCredential aggregate (default bank BankIDC6, the single allow-listed bank);
// the adapter resolves it read-modify-write so a creditor-key write never clobbers
// the secret/client id (ADR-0008).
type CreditorKeyWriter interface {
	// SetCreditorKey records the tenant's PIX creditor key (chave do recebedor) on
	// the tenant's existing bank credential. The adapter MUST preserve the
	// credential's secret and client id (read-modify-write). A tenant with no
	// existing credential is rejected (ErrNotFound): a creditor key without a bank
	// identity is meaningless and a half-credential invites the confused-deputy gap.
	// Empty tenantID/creditorKey and a creditorKey that is not a syntactically valid
	// PIX key are rejected as a validation error WITHOUT echoing the value (the key
	// is routing-sensitive; threat C1/C4).
	SetCreditorKey(ctx context.Context, tenantID, creditorKey string) error
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

// BankCertificate is the per-(tenant,bank) mTLS client certificate material an
// admin uploads through the console (SIN-66087). CertPEM is the PUBLIC leaf
// certificate; KeyPEM is its private key and is a SECRET: write-only, held only
// transiently on the write path, and NEVER returned, logged or audited. Both
// String() and LogValue() redact KeyPEM so the key can never leak through
// %v/%s/%+v formatting or structured logging (threat C1/C4), mirroring
// BankCredential. An empty BankID is stored under the default BankIDC6 (retro-compat).
type BankCertificate struct {
	TenantID string
	BankID   string
	CertPEM  string // public leaf certificate (PEM)
	KeyPEM   string // SECRET private key (PEM) — write-only, transient
}

// String redacts the private key so a certificate value can never leak it through
// %v/%s/%+v formatting in logs or errors (defense-in-depth, threat C1/C4). The
// public certificate is reported only as present/absent, never inlined.
func (c BankCertificate) String() string {
	return fmt.Sprintf("BankCertificate{TenantID:%s BankID:%s CertPEM:%s KeyPEM:[REDACTED]}", c.TenantID, c.BankID, certPresence(c.CertPEM))
}

// LogValue redacts the private key under structured logging, even when the value
// is logged as an attribute (threat C1/C4), mirroring BankCredential.
func (c BankCertificate) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("tenant_id", c.TenantID),
		slog.String("bank_id", c.BankID),
		slog.String("cert_pem", certPresence(c.CertPEM)),
		slog.String("key_pem", "[REDACTED]"),
	)
}

// certPresence reports whether the public certificate is present without inlining
// it, keeping log/error lines compact and uniform (the cert is public, but a PEM
// block does not belong in a log line).
func certPresence(certPEM string) string {
	if certPEM == "" {
		return "[absent]"
	}
	return "[present]"
}

// BankCertificateMeta is the PUBLIC, non-secret metadata of a stored certificate.
// It is what the admin UI displays and what the write endpoint echoes back; it
// carries NO private-key material by construction.
type BankCertificateMeta struct {
	TenantID          string
	BankID            string
	SubjectCN         string
	Issuer            string
	SerialNumber      string
	FingerprintSHA256 string
	NotBefore         time.Time
	NotAfter          time.Time
}

// BankCertificateWriter is the admin-plane write path for a per-(tenant,bank) mTLS
// certificate. Kept separate from the reader (ISP) so a use-case depends only on
// the capability it needs. The private key transits straight to the store: beyond
// the transient BankCertificate it MUST NOT enter domain state, logs, errors or
// URLs (threat C1/C4). The use-case parses and validates the material BEFORE
// calling; an empty BankID is stored under the default BankIDC6 (retro-compat).
type BankCertificateWriter interface {
	SetBankCertificate(ctx context.Context, cert BankCertificate) error
}

// BankCertificateReader returns ONLY the public metadata of a stored certificate,
// never the private key. The tenantID always comes from the authenticated caller
// (never client input); bankID is a non-secret selector. A missing (tenantID,
// bankID) pair returns ErrNotFound (deny-by-default). An empty bankID resolves to
// the default BankIDC6 (retro-compat).
type BankCertificateReader interface {
	GetBankCertificateMeta(ctx context.Context, tenantID, bankID string) (BankCertificateMeta, error)
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
	// CreditorKey is the recebedor's PIX key (chave) the immediate charge is
	// registered under at the PSP. The real C6 BACEN PIX v2 cob create
	// (PUT /v2/pix/cob/{txid}) requires it to route the funds and mint the QR; the
	// adapter forwards it as the BACEN "chave" field. OPTIONAL on the port (a
	// stub/test charge may omit it, and the omitempty wire field then drops it); a
	// real homologação/production charge MUST carry the tenant's registered key.
	// No app surface (HTTP DTO / HTMX form) populates it: the C6 adapter injects
	// the tenant's configured key (BankCredential.CreditorKey) when this field is
	// empty, so the client boundary never carries fund-routing data (opção (a),
	// ADR-0004 / SIN-65862). A non-empty value here is an optional per-request
	// override, reserved for a future multi-key hook, and wins over the config.
	CreditorKey string
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

// PixDueChargeRequest is the input to register or amend a PIX charge with a due
// date (cobrança com vencimento, cobv — roteiro 7.5/7.7). It carries the fine,
// interest and discount RATES so the bank registers them; the amount owed at any
// instant is computed by the pixcobv domain, never here (Hexagonal). The devedor
// (DebtorTaxID/DebtorName) and the creditor PIX key are required for a cobv, unlike
// an immediate charge. The tenant is explicit so per-tenant credential isolation is
// never bypassed (threat H1/P1).
type PixDueChargeRequest struct {
	TenantID    string
	TxID        string
	AmountCents int64
	Currency    string
	DueDate     time.Time
	// ValidityDays is the number of days after the due date the charge may still be
	// paid (validade após vencimento, roteiro 7.5). Zero means payable only up to the
	// due date.
	ValidityDays       int
	FineBps            int64
	MonthlyInterestBps int64
	// DiscountBps and DiscountFixedCents are the mutually exclusive early-payment
	// discount forms (desconto). At most one is non-zero.
	DiscountBps        int64
	DiscountFixedCents int64
	DebtorTaxID        string
	DebtorName         string
	// CreditorKey is the recebedor's PIX key (chave) the charge is registered under.
	CreditorKey string
	// IdempotencyKey, when present, is forwarded so the PSP collapses retried/
	// concurrent registrations into one charge.
	IdempotencyKey string
}

// PixDueChargeResult is the bank's response to a cobv register/read/amend. It
// carries the QR material (the BACEN "PIX copia e cola" string + render location)
// the payer scans, the reconciled lifecycle status, the due date / validity echoed
// back for reconciliation (roteiro 7.6), and the money needed to reconcile a
// settlement (expected vs received).
//
//   - Status is the PSP's charge status verbatim (e.g. "ATIVA", "CONCLUIDA").
//     Settlement decisions read this from GetDueCharge, never from a raw webhook
//     (reconcile-before-settle, threat W3).
//   - ExpectedAmountCents is the charge's original amount (valor.original) in cents.
//   - ReceivedAmountCents is the amount actually received in cents (zero while
//     unpaid). AmountReconciled asserts the two add up before settling.
type PixDueChargeResult struct {
	TxID                string
	Status              string
	QRCodePayload       string
	QRCodeLocation      string
	DueDate             time.Time
	ValidityDays        int
	FineBps             int64
	MonthlyInterestBps  int64
	DiscountBps         int64
	DiscountFixedCents  int64
	ExpectedAmountCents int64
	ReceivedAmountCents int64
}

// AmountReconciled reports whether the amount received exactly matches the expected
// (original) amount. It mirrors PixChargeResult.AmountReconciled: a non-positive
// expected amount is never reconciled and overpayment is a divergence too, so the
// check is strict equality.
func (r PixDueChargeResult) AmountReconciled() bool {
	return r.ExpectedAmountCents > 0 && r.ReceivedAmountCents == r.ExpectedAmountCents
}

// PixDueChargeProvider is the output port for PIX charges with a due date (cobv,
// roteiro 7.5–7.7): register, reconcile-read and amend. It is kept SEPARATE from
// PixProvider (ISP) rather than widening it: a cobv carries a richer request shape
// (due date, validity window, fine/interest/discount, devedor, creditor key) that
// the immediate-charge port does not, and an immediate-charge consumer must not be
// forced to depend on cobv semantics — exactly the segregation BoletoProvider
// follows for the BolePix slip, of which cobv is the PIX analogue. The C6 adapter
// implements both; a stub backs them for tests. Each carries tenantID explicitly so
// the per-tenant credential isolation the adapter enforces is never bypassed.
type PixDueChargeProvider interface {
	// CreateDueCharge idempotently registers a cobv charge and returns its QR code.
	// req.IdempotencyKey (falling back to the TxID) anchors idempotency: a re-submit
	// with the same anchor resolves to the same charge and never creates a duplicate.
	CreateDueCharge(ctx context.Context, tenantID string, req PixDueChargeRequest) (PixDueChargeResult, error)
	// GetDueCharge reconciles the authoritative state of a cobv charge — the source
	// of truth for settlement (never trust a raw webhook — threat W3). An unknown
	// txid within the tenant is shared.ErrNotFound; the read is tenant-scoped.
	GetDueCharge(ctx context.Context, tenantID, txID string) (PixDueChargeResult, error)
	// UpdateDueCharge amends a registered cobv's parameters (roteiro 7.7). req carries
	// the full new parameter set. An unknown txid within the tenant is
	// shared.ErrNotFound; the operation is tenant-scoped so one tenant can never amend
	// another's charge.
	UpdateDueCharge(ctx context.Context, tenantID, txID string, req PixDueChargeRequest) (PixDueChargeResult, error)
}

// WebhookRegistration is the registered PIX notification callback read back from
// the PSP (roteiro: outbound webhook registration). WebhookURL is the HTTPS
// callback C6 POSTs settlement notifications to for a recebedor key; CreatedAt is
// the PSP-assigned creation instant (an opaque echo, zero when the PSP omits it).
//
// WebhookURL embeds the unguessable per-tenant callback ref (/webhooks/c6/{ref}),
// which IS the per-tenant credential for the unsigned C6 webhook (ADR-0002/F4) —
// it is a SECRET and must never be logged. It is returned so a caller can confirm,
// in memory, that the registered URL matches the one it intended to register
// (idempotent confirmation) without printing it.
type WebhookRegistration struct {
	WebhookURL string
	CreatedAt  time.Time
}

// PixWebhookRegistrar is the output port for registering and reading the PSP-side
// PIX notification webhook (BACEN PIX v2 webhook-by-key). It is kept SEPARATE from
// the charge ports (ISP): registering the outbound callback URL is a distinct
// concern from creating/reconciling a charge, and a charge consumer must not be
// forced to depend on webhook-registration semantics. The C6 adapter implements
// it; each method carries tenantID explicitly so the per-tenant OAuth2 credential
// isolation the adapter enforces is never bypassed.
type PixWebhookRegistrar interface {
	// RegisterWebhook idempotently registers (PUTs) the HTTPS webhookURL the PSP
	// will notify for the recebedor key pixKey. A re-run with the same URL replaces
	// rather than duplicates (the registration is keyed by pixKey at the PSP). A
	// non-HTTPS webhookURL, or an empty tenantID/pixKey, is shared.ErrValidation.
	RegisterWebhook(ctx context.Context, tenantID, pixKey, webhookURL string) error
	// GetWebhook reads back the webhook currently registered for pixKey so a caller
	// can confirm the registration idempotently. An unregistered key is
	// shared.ErrNotFound; the read is tenant-scoped through the per-tenant bearer.
	GetWebhook(ctx context.Context, tenantID, pixKey string) (WebhookRegistration, error)
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

// BoletoDiscountTier is the transport mirror of a boleto early-payment discount step
// (roteiro grupo 3). Exactly one of Bps/FixedCents is set; DaysBeforeDue is the
// minimum number of whole days before the due date the payment must occur for the
// tier to apply.
type BoletoDiscountTier struct {
	DaysBeforeDue int
	Bps           int64
	FixedCents    int64
}

// BoletoAddress is the payer's address. Number is an int because the real C6
// contract (POST /v1/bank_slips) models the address number as an integer; see
// ADR-0005 "Riscos conhecidos" for the "S/N"/alphanumeric homologation question.
// These are plain Go types — transport tags and wire formatting live in the adapter.
type BoletoAddress struct {
	Street  string
	Number  int
	City    string
	State   string // UF, 2 letters
	ZipCode string // CEP, digits only
}

// BoletoPayer identifies the sacado/pagador of a boleto. It is the domain mirror of
// the `payer` object the real C6 contract requires for POST /v1/bank_slips. It is a
// per-charge value object (each boleto has a different payer), so it flows from the
// boundary — it is not adapter/tenant config (ADR-0005). Plain Go types, no transport
// tags: the JSON shape and mandatory-field validation are the C6 adapter's job.
type BoletoPayer struct {
	Name    string
	TaxID   string // CPF/CNPJ, digits only
	Address BoletoAddress
}

// BoletoRequest is the input to register a BolePix boleto at the bank. The fine,
// interest and discount RATES are transported so the bank registers them, but the
// amount owed at any instant is computed by the boleto domain, never here
// (Hexagonal).
type BoletoRequest struct {
	TenantID    string
	BoletoID    string
	AmountCents int64
	Currency    string
	DueDate     time.Time
	// ValidUntil is the last day the boleto may be paid (data limite de pagamento,
	// roteiro 5.b). Zero when unset.
	ValidUntil time.Time
	FineBps    int64
	// FineFixedCents is the late-payment fine as a fixed amount (roteiro 2.c). It is
	// mutually exclusive with FineBps; zero when the fine is a percentage or absent.
	FineFixedCents     int64
	MonthlyInterestBps int64
	// Discounts is the early-payment discount schedule (roteiro grupo 3), ordered
	// descending by DaysBeforeDue. Empty when the boleto carries no discount.
	Discounts []BoletoDiscountTier
	// Payer is the boleto's sacado/pagador. The real C6 contract requires the full
	// payer (name + tax id + address) on POST /v1/bank_slips; mandatory-field
	// validation lives in the C6 adapter so the stub stays lenient (ADR-0005).
	Payer          BoletoPayer
	IdempotencyKey string
}

// BoletoResult is the bank's response to a boleto registration or read. It carries
// the scannable artifacts (the PIX EMV "copia e cola" payload and the boleto's
// barcode/linha digitável) the caller renders for the payer, plus the registered
// parameters echoed back for reconciliation/homologação evidence (roteiro 6.a).
type BoletoResult struct {
	BoletoID string
	// TxID is the bank's registration reference (C6 bank_slips `id`). The app treats a
	// non-empty TxID as the billing-finalized marker, so the C6 adapter MUST populate it on
	// create — an empty TxID would let a retry/concurrent registration re-bill (duplicate
	// ledger entry).
	TxID   string
	Status string
	QRCode string // PIX EMV copy-and-paste payload (BolePix)
	// OurNumber is C6's "nosso número" (bank_slips `our_number`), reconciliation evidence
	// (roteiro 6.a). DigitableLine is the linha digitável (bank_slips `digitable_line`),
	// distinct from the numeric Barcode (`bar_code`). Both zero until the bank returns them.
	OurNumber          string
	DigitableLine      string
	Barcode            string    // boleto linha digitável / barcode
	AmountCents        int64     // principal the bank registered
	DueDate            time.Time // registered due date (vencimento); zero when unknown
	ValidUntil         time.Time // registered payment-validity limit (roteiro 5.b); zero when unset
	FineBps            int64     // registered one-time fine rate
	FineFixedCents     int64     // registered fixed fine (roteiro 2.c); zero when percentage
	MonthlyInterestBps int64     // registered monthly mora interest rate
	Discounts          []BoletoDiscountTier
}

// BoletoProvider is the output port for the BolePix boleto lifecycle: register, read,
// cancel (baixa) and amend (alteração).
type BoletoProvider interface {
	CreateBoleto(ctx context.Context, tenantID string, req BoletoRequest) (BoletoResult, error)
	// GetBoleto reconciles the authoritative state of a registered boleto for the
	// tenant (roteiro 6.a). An unknown id within the tenant is shared.ErrNotFound;
	// the read is tenant-scoped so one tenant can never observe another's boleto.
	GetBoleto(ctx context.Context, tenantID, boletoID string) (BoletoResult, error)
	// CancelBoleto performs the baixa/cancelamento of a registered boleto (roteiro
	// grupo 4), whether still due (4.a) or overdue (4.b). It is idempotent: cancelling
	// an already-cancelled boleto succeeds and returns the cancelled state. An unknown
	// id within the tenant is shared.ErrNotFound; the operation is tenant-scoped.
	CancelBoleto(ctx context.Context, tenantID, boletoID string) (BoletoResult, error)
	// UpdateBoleto amends a registered boleto's parameters (roteiro grupo 5): due date
	// (5.a), validity (5.b) and amount/fine/interest (5.c). req carries the full new
	// parameter set. An unknown id within the tenant is shared.ErrNotFound; the
	// operation is tenant-scoped so one tenant can never amend another's boleto.
	UpdateBoleto(ctx context.Context, tenantID, boletoID string, req BoletoRequest) (BoletoResult, error)
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

// CheckoutResult is the bank's response to a checkout-session operation (open,
// reconcile, cancel). RedirectURL is the hosted page the caller sends the payer to
// (only meaningful while a session is open).
//
// For settlement (the checkout webhook, roteiro 12) the money is reconciled, not only
// the status (threat W3, mirroring ChargeResult): AmountCents is the session's
// authorized total (the expected amount) and ReceivedAmountCents is what the PSP
// reports as actually captured. AmountReconciled asserts the two add up before a
// payment is liquidated, so a partial/over capture or a manipulated notification can
// never settle for the wrong amount.
type CheckoutResult struct {
	SessionID   string
	Status      string
	RedirectURL string
	// AmountCents is the session's authorized total in cents (the expected amount).
	AmountCents int64
	// ReceivedAmountCents is the amount the PSP reports as captured for the session in
	// cents (zero while the session is open/unpaid). AmountReconciled compares it to
	// AmountCents before settlement.
	ReceivedAmountCents int64
	// CardType / RequireAuthentication echo the permitted payment method back so the
	// caller's response is self-describing (the C6 create response does not echo
	// them; the adapter sets them from the request).
	CardType              string
	RequireAuthentication bool
}

// AmountReconciled reports whether the amount captured on the session exactly matches
// its authorized total. It mirrors ChargeResult.AmountReconciled: a non-positive
// expected total is never reconciled, so an absent/garbled amount fails closed
// (settlement refused) rather than liquidating for zero.
func (r CheckoutResult) AmountReconciled() bool {
	return r.AmountCents > 0 && r.ReceivedAmountCents == r.AmountCents
}

// CheckoutProvider is the output port for the unified C6 checkout session: open a
// session (roteiro 9), reconcile its authoritative state (roteiro 10) and cancel it
// (roteiro 11). Each method carries tenantID explicitly so per-tenant credential
// isolation is never bypassed.
type CheckoutProvider interface {
	CreateCheckoutSession(ctx context.Context, tenantID string, req CheckoutRequest) (CheckoutResult, error)
	// GetCheckoutSession reconciles the authoritative state of a checkout session
	// (roteiro 10). The read is tenant-scoped (per-tenant token); an unknown id within
	// the tenant is shared.ErrNotFound, so one tenant can never observe another's
	// session. It is the source of truth for settlement (never trust a raw webhook).
	GetCheckoutSession(ctx context.Context, tenantID, sessionID string) (CheckoutResult, error)
	// CancelCheckoutSession cancels a checkout session (roteiro 11). It is idempotent:
	// cancelling an already-cancelled session succeeds and returns the cancelled state.
	// An unknown id within the tenant is shared.ErrNotFound (no cross-tenant oracle).
	CancelCheckoutSession(ctx context.Context, tenantID, sessionID string) (CheckoutResult, error)
}

// CheckoutReconciler is the narrow read-only view of CheckoutProvider the webhook
// settlement path depends on (ISP): it only needs to reconcile a session's
// authoritative state before settling, not to open or cancel one.
type CheckoutReconciler interface {
	GetCheckoutSession(ctx context.Context, tenantID, sessionID string) (CheckoutResult, error)
}

// DDABoleto is one boleto open in a client's DDA (Débito Direto Autorizado, roteiro
// 8.1): the bank's boleto id, the scannable barcode / linha digitável, the amount in
// cents, the due date and the beneficiary name. It is a read projection the adapter
// transports from the bank.
type DDABoleto struct {
	ID              string
	Barcode         string
	AmountCents     int64
	DueDate         time.Time
	BeneficiaryName string
}

// DDAItem is one payment line of a DDA payment group (transport mirror of the domain
// dda.Item): the bank's item id, the boleto barcode, the amount and due date the bank
// resolved for it.
type DDAItem struct {
	ID          string
	Barcode     string
	AmountCents int64
	DueDate     time.Time
}

// DDAGroup is a DDA payment group's transported state: its bank id (the txid returned
// on create), its lifecycle status verbatim ("consultando"/"aprovado") and the items
// currently in it. The use-case maps it onto the domain PaymentGroup to enforce the
// transition rules before any mutation.
type DDAGroup struct {
	ID     string
	Status string
	Items  []DDAItem
}

// DDAGroupRequest is the input to submit a payment group for the initial consult
// (roteiro 8.2). Barcodes are the boletos the client selects into the group; the bank
// resolves each into an item with its amount and due date. IdempotencyKey, when
// present, is forwarded so the PSP collapses retried/concurrent submissions into one
// group.
type DDAGroupRequest struct {
	TenantID       string
	Barcodes       []string
	IdempotencyKey string
}

// DDAProvider is the output port for the DDA / agendamento de pagamentos surface
// (roteiro grupo 8). It is kept SEPARATE from the other bank ports (ISP): a use-case
// that schedules DDA payments must not be forced to depend on PIX/boleto/checkout
// semantics, and those consumers must not depend on DDA. The C6 adapter implements it;
// a stub backs it for tests. Every method carries tenantID explicitly so the
// per-tenant credential/token isolation the adapter enforces is never bypassed — the
// tenant is derived from the authenticated caller, never client input (threat H1/P1).
// An id owned by another tenant is shared.ErrNotFound (no cross-tenant existence
// oracle), never a distinct error.
type DDAProvider interface {
	// ListOpenBoletos returns the boletos currently open in the tenant's DDA
	// (roteiro 8.1). Pure read; never mutates state.
	ListOpenBoletos(ctx context.Context, tenantID string) ([]DDABoleto, error)
	// CreatePaymentGroup submits a group of boletos (by barcode) for the initial
	// consult (roteiro 8.2) and returns the resulting consultando group with its txid
	// and resolved items. Idempotent on req.IdempotencyKey: a re-submit with the same
	// (tenant, key) resolves to the same group and never creates a duplicate.
	CreatePaymentGroup(ctx context.Context, tenantID string, req DDAGroupRequest) (DDAGroup, error)
	// GetPaymentGroup reconciles the authoritative state (status + items) of a payment
	// group for the tenant (roteiro 8.3, and the source of truth the use-case reads
	// before 8.4/8.5/8.6). An unknown id within the tenant is shared.ErrNotFound.
	GetPaymentGroup(ctx context.Context, tenantID, groupID string) (DDAGroup, error)
	// RemovePaymentGroupItems removes a list of items from a group (roteiro 8.4). It is
	// tenant-scoped; an unknown group is shared.ErrNotFound. The transition legality
	// (group not yet approved) is enforced by the domain in the use-case before this
	// call; the adapter only applies the removal.
	RemovePaymentGroupItems(ctx context.Context, tenantID, groupID string, itemIDs []string) error
	// RemovePaymentGroupItem removes a single item from a group (roteiro 8.5). Same
	// tenant-scoping and not-found semantics as RemovePaymentGroupItems.
	RemovePaymentGroupItem(ctx context.Context, tenantID, groupID, itemID string) error
	// SubmitPaymentGroup submits a consulting group for approval (roteiro 8.6). idemKey
	// (when present) is forwarded so a retried submit collapses to one effect.
	// Tenant-scoped; an unknown group is shared.ErrNotFound.
	SubmitPaymentGroup(ctx context.Context, tenantID, groupID, idemKey string) error
}

// StatementEntry is one posted line of an account statement (extrato, roteiro
// 13.a): the bank's entry id, the posting date, the amount in cents, its direction
// ("credit"/"debit" verbatim) and a short description (histórico). It is a read
// projection the adapter transports from the bank; the amount is always positive and
// the direction carries the sign meaning.
type StatementEntry struct {
	ID          string
	Date        time.Time
	AmountCents int64
	Kind        string
	Description string
}

// Statement is a tenant's account statement over a period: the entries posted within
// the requested window. The use-case maps it onto the domain statement.Statement to
// re-validate the entries (defense in depth) before surfacing it.
type Statement struct {
	Entries []StatementEntry
}

// StatementFilter is the date window for an extrato query (roteiro 13.a). Start and
// End are the inicio/fim bounds; both are required and the use-case validates the
// window (fim >= inicio, <= 30 days) through the domain before this reaches the
// adapter.
type StatementFilter struct {
	Start time.Time
	End   time.Time
}

// StatementProvider is the output port for the account-statement surface (extrato,
// roteiro grupo 13). It is kept SEPARATE from the other bank ports (ISP): a use-case
// that reads an extrato must not be forced to depend on PIX/boleto/checkout/DDA
// semantics, and those consumers must not depend on the statement read. The C6
// adapter implements it; a stub backs it for tests. The single method carries
// tenantID explicitly so the per-tenant credential/token isolation the adapter
// enforces is never bypassed — the tenant is derived from the authenticated caller,
// never client input (threat H1/P1).
type StatementProvider interface {
	// GetStatement returns the entries posted to the tenant's account within the
	// filter's date window (roteiro 13.a). Pure read; never mutates state. The window
	// is already validated by the use-case (the domain caps it at 30 days); the
	// adapter only transports it.
	GetStatement(ctx context.Context, tenantID string, filter StatementFilter) (Statement, error)
}

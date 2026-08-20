package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/account"
	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
	"github.com/ia-dev-sindireceita/payment/internal/domain/bankcert"
	"github.com/ia-dev-sindireceita/payment/internal/domain/billing"
	"github.com/ia-dev-sindireceita/payment/internal/domain/invoice"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// ConsoleService implements the server-rendered admin console use-cases: tenant
// lifecycle + listing, per-endpoint pricing CRUD, per-tenant bank-credential
// writes, and the read-only consumption audit. It is separate from AdminService
// (the programmatic JSON admin API) so the human console and the machine API
// evolve independently; both are privileged and RBAC-gated at the HTTP boundary.
//
// The service depends only on narrow, segregated input ports (accept-narrow):
// the concrete sqlite/inmemory stores satisfy them, but the console declares
// exactly the capabilities it uses and nothing more.
type ConsoleService struct {
	tenants       TenantStore
	accounts      AccountStore
	pricing       PricingStore
	ledger        LedgerReader
	credWriter    ports.CredentialWriter
	creditorWrite ports.CreditorKeyWriter
	credReader    ports.CredentialStore
	credEvictor   ports.CredentialInvalidator
	// certWriter / certReader are the per-(tenant,bank) mTLS certificate vault ports
	// (SIN-66087 / SIN-66088). The console uses them ONLY to store an uploaded
	// cert/key pair (write-only key) and to project a stored certificate's PUBLIC
	// metadata into the bank screens — the private key is never read back (threat
	// C1/C4). Both are optional: a nil reader degrades to "no bank reports a
	// certificate"; a nil writer disables the upload path (the screens still render).
	certWriter ports.BankCertificateWriter
	certReader ports.BankCertificateReader
	// credDeleter / certDeleter hard-delete a tenant's per-bank configuration (the
	// credential and the certificate for a (tenant, bank) pair) on "Remover banco"
	// (ADR-0012 §5). Both are idempotent and zeroise the secret material before the
	// delete. Optional: a nil deleter degrades to a no-op for that half (RemoveBankConfig
	// still removes whichever half is wired), so wiring-light tests keep working.
	credDeleter ports.CredentialDeleter
	certDeleter ports.BankCertificateDeleter
	// webhookDeregistrar stops the PSP from calling us for a tenant whose bank
	// configuration is being removed. Optional: nil leaves the previous behaviour, where
	// removal deleted our side and left the PSP registered.
	webhookDeregistrar ports.WebhookDeregistrar
	// creds resolves the PIX key the PIX-webhook deregistration is keyed by. It must be
	// read BEFORE the credential is deleted.
	creds ports.CredentialStore
	// sharing answers which OTHER tenants hold the same PIX key / PSP account, so one
	// empresa can neither take a key another ACTIVE empresa is using nor, on removal,
	// tear down that empresa's live webhook. Optional: nil leaves the historical
	// behaviour (no exclusivity check, unconditional deregistration), which keeps
	// wiring-light tests working — but cmd/api DOES wire it.
	sharing ports.CreditorKeySharingLookup
	// invoices is the append-only Fatura store (SIN-69121). The console generates
	// an invoice by freezing a consumption window and reads them back for the
	// "Faturas" screen and the CSV download. Optional: a nil store disables the
	// invoice use-cases (GenerateInvoice/ListInvoices return ErrNotConfigured) so
	// wiring-light tests that don't exercise billing keep working.
	invoices InvoiceStore
	// webhooks is the durable, encrypted-at-rest outbound-webhook config store per
	// Conta (SIN-69490, F0 of SIN-69486). Optional: a nil store disables the
	// outbound-webhook use-cases (they return ErrOutboundWebhookUnavailable, mapped to
	// 503) so wiring-light tests and the vault-less fallback keep working. The whole
	// surface is dark behind PAYMENT_ACCOUNT_OUTBOUND_WEBHOOK at the HTTP boundary.
	webhooks OutboundWebhookStore
	audit    ports.AuditLog
	clock    ports.Clock
	ids      ports.IDProvider
	// invoiceGuard collapses accidental double-submits of the account-level batch
	// invoice generation (SIN-69184) keyed by a caller-supplied idempotency token.
	// See GenerateAccountInvoices for the semantics; a fresh render always
	// carries a fresh token, so a deliberate regeneration is never collapsed and
	// the append-only invariant (SIN-69121) stands.
	invoiceGuard *invoiceBatchGuard
}

// ErrInvoicesUnavailable is returned by the invoice use-cases when the console
// was wired without an InvoiceStore (a misconfiguration in production; some
// wiring-light tests deliberately omit it). The HTTP adapter maps it to 503.
var ErrInvoicesUnavailable = errors.New("invoice store not configured")

// InvoiceStore is the append-only persistence the console needs for Faturas: the
// write path (SaveInvoice) plus the tenant-scoped reads powering the list screen
// and the CSV download. The concrete sqlite/inmemory stores satisfy it. It is a
// narrow app-level port (like LedgerReader) — the invoice save runs outside the
// unit-of-work, paired with its audit entry, mirroring the console's other
// privileged writes (creditor-key, certificate).
type InvoiceStore interface {
	SaveInvoice(ctx context.Context, inv invoice.Invoice) error
	FindInvoiceByID(ctx context.Context, tenantID, id string) (invoice.Invoice, error)
	ListInvoices(ctx context.Context, tenantID string) ([]invoice.Invoice, error)
}

// TenantStore is the tenant capability the console needs: the foundation's
// persistence plus cross-tenant listing for the admin plane.
type TenantStore interface {
	SaveTenant(ctx context.Context, t *tenant.Tenant) error
	FindTenantByID(ctx context.Context, id string) (*tenant.Tenant, error)
	ListTenants(ctx context.Context) ([]*tenant.Tenant, error)
}

// AccountStore is the account (API user / reseller) capability the console needs
// for the two-level tenancy admin plane (SIN-69157, spec SIN-69122): the
// write/lookup pair from the canonical AccountRepository plus a cross-account
// listing for the Contas screen. It is a narrow app-level port (like TenantStore)
// so the console declares exactly the account capabilities it uses. The concrete
// sqlite/inmemory stores satisfy it. An account is attribution-only — it never
// carries a bank credential and never touches money (model (a), ADR-0009).
type AccountStore interface {
	SaveAccount(ctx context.Context, a *account.Account) error
	FindAccountByID(ctx context.Context, id string) (*account.Account, error)
	ListAccounts(ctx context.Context) ([]*account.Account, error)
}

// PricingStore is the pricing capability the console needs.
type PricingStore interface {
	UpsertEndpointPrice(ctx context.Context, p billing.EndpointPricing) error
	ListEndpointPrices(ctx context.Context, tenantID string) ([]billing.EndpointPricing, error)
}

// LedgerReader is the read side of the billing ledger powering the consumption
// audit. Writes stay on the append-only path used by the charge/settlement flow.
// ListLedgerEntriesByAccount serves the account→tenant→endpoint rollup (SIN-69127):
// it returns every entry owned by an account across all of its tenants.
type LedgerReader interface {
	ListLedgerEntries(ctx context.Context, tenantID string) ([]billing.LedgerEntry, error)
	ListLedgerEntriesByAccount(ctx context.Context, accountID string) ([]billing.LedgerEntry, error)
}

// ConsoleDeps bundles the console's dependencies. The fields reuse the same
// concrete adapters wired in Deps, narrowed to the console's ports.
type ConsoleDeps struct {
	Tenants TenantStore
	// Accounts is the two-level tenancy account plane (SIN-69157). Optional: a nil
	// store disables the account use-cases (they return ErrAccountsUnavailable, mapped
	// to 503) so wiring-light tests that don't exercise the Contas screens keep working.
	Accounts   AccountStore
	Pricing    PricingStore
	Ledger     LedgerReader
	CredWriter ports.CredentialWriter
	// CredReader is the read side of the credential store. The console uses it ONLY
	// to answer "does this (tenant, bank) have a credential configured?" and to echo
	// back the non-secret ClientID / CreditorKey on the bank screens — the secret is
	// never projected into a view (threat C1/C4). Optional: nil degrades to "no bank
	// reports a credential" (the screens still render, every bank shows — pendente).
	CredReader ports.CredentialStore
	// CreditorWriter is the fund-routing write path for a tenant's PIX creditor key
	// (chave do recebedor). It is intentionally separate from CredWriter (ISP, least
	// privilege): the console grants the creditor-key capability independently of the
	// secret-rotation capability (SIN-66092 / ADR-0008).
	CreditorWriter ports.CreditorKeyWriter
	// Sharing answers which tenants already hold a PIX key / PSP account. Optional;
	// nil disables the exclusivity check and the removal guard. See ConsoleService.sharing.
	Sharing ports.CreditorKeySharingLookup
	// CertWriter / CertReader are the per-(tenant,bank) mTLS certificate vault
	// (SIN-66087). CertWriter stores the validated cert/key pair (write-only key);
	// CertReader projects only the stored certificate's public metadata into the
	// bank screens (badges, validity window, fingerprint) — never the key. Both are
	// optional: nil CertReader degrades to "no certificate configured" and nil
	// CertWriter disables the upload use-case (the screen still renders read-only).
	CertWriter ports.BankCertificateWriter
	CertReader ports.BankCertificateReader
	// CredDeleter / CertDeleter hard-delete a tenant's per-bank configuration on
	// "Remover banco" (ADR-0012 §5): the credential and certificate for a (tenant,
	// bank) pair, each idempotent and zeroising the secret before delete. Optional:
	// a nil deleter degrades to a no-op for that half.
	CredDeleter ports.CredentialDeleter
	CertDeleter ports.BankCertificateDeleter
	// WebhookDeregistrar stops the PSP calling us when a bank configuration is removed.
	// Nil (stub / not wired) keeps the previous behaviour. Creds resolves the PIX key that
	// deregistration is keyed by, read before the credential is deleted.
	WebhookDeregistrar ports.WebhookDeregistrar
	Creds              ports.CredentialStore
	// Invoices is the append-only Fatura store (SIN-69121). Optional: nil disables
	// the invoice use-cases (the rest of the console still works).
	Invoices InvoiceStore
	// OutboundWebhooks is the durable, encrypted-at-rest outbound-webhook config store
	// per Conta (SIN-69490). Optional: nil disables the outbound-webhook use-cases
	// (ErrOutboundWebhookUnavailable → 503). Dark behind PAYMENT_ACCOUNT_OUTBOUND_WEBHOOK.
	OutboundWebhooks OutboundWebhookStore
	// CredInvalidator evicts cached state keyed on a tenant's credential (the C6
	// OAuth2 token cache) right after a credential write, closing the
	// token-revocation lag (ADR-0003). Optional: nil degrades to a no-op.
	CredInvalidator ports.CredentialInvalidator
	// Audit is the append-only trail every privileged console mutation is recorded
	// to with the acting operator (OWASP A09). Optional: nil degrades to a no-op so
	// wiring-light tests keep working, but production MUST wire a real audit log.
	Audit ports.AuditLog
	Clock ports.Clock
	IDs   ports.IDProvider
}

// NewConsoleService wires a ConsoleService from its dependencies. A nil
// CredInvalidator degrades to a no-op (the credential write still succeeds; only
// the cache-eviction step is skipped).
func NewConsoleService(d ConsoleDeps) *ConsoleService {
	ci := d.CredInvalidator
	if ci == nil {
		ci = noopCredInvalidator{}
	}
	a := d.Audit
	if a == nil {
		a = noopAudit{}
	}
	return &ConsoleService{
		tenants:            d.Tenants,
		accounts:           d.Accounts,
		pricing:            d.Pricing,
		ledger:             d.Ledger,
		credWriter:         d.CredWriter,
		creditorWrite:      d.CreditorWriter,
		credReader:         d.CredReader,
		certWriter:         d.CertWriter,
		certReader:         d.CertReader,
		credDeleter:        d.CredDeleter,
		certDeleter:        d.CertDeleter,
		webhookDeregistrar: d.WebhookDeregistrar,
		creds:              d.Creds,
		sharing:            d.Sharing,
		invoices:           d.Invoices,
		webhooks:           d.OutboundWebhooks,
		credEvictor:        ci,
		audit:              a,
		clock:              d.Clock,
		ids:                d.IDs,
		invoiceGuard:       newInvoiceBatchGuard(invoiceBatchIdempotencyTTL),
	}
}

// Now returns the service's notion of the current time from the injected clock.
// The console's read side uses it to default the consumption date window, so the
// default tracks the same clock the rest of the use-cases stamp events with
// (deterministic under a fixed test clock).
func (s *ConsoleService) Now() time.Time { return s.clock.Now() }

// --- Tenants ---

// StatusFilter narrows a tenant listing by lifecycle status.
type StatusFilter string

const (
	// StatusAny matches active and suspended tenants.
	StatusAny StatusFilter = ""
	// StatusActive matches only active tenants.
	StatusActive StatusFilter = "active"
	// StatusSuspended matches only suspended tenants.
	StatusSuspended StatusFilter = "suspended"
)

// ParseStatusFilter maps a raw query value to a StatusFilter, defaulting to
// StatusAny for unknown/empty input (forgiving input handling at the boundary).
func ParseStatusFilter(raw string) StatusFilter {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "active":
		return StatusActive
	case "suspended":
		return StatusSuspended
	default:
		return StatusAny
	}
}

// ListTenantsQuery describes a filtered tenant listing.
type ListTenantsQuery struct {
	Search string       // case-insensitive substring over the tenant name
	Status StatusFilter // lifecycle filter
}

// ListTenants returns tenants matching the query, newest-first.
func (s *ConsoleService) ListTenants(ctx context.Context, q ListTenantsQuery) ([]*tenant.Tenant, error) {
	all, err := s.tenants.ListTenants(ctx)
	if err != nil {
		return nil, fmt.Errorf("list tenants: %w", err)
	}
	needle := strings.ToLower(strings.TrimSpace(q.Search))
	out := make([]*tenant.Tenant, 0, len(all))
	for _, t := range all {
		if !matchesStatus(t, q.Status) {
			continue
		}
		if needle != "" && !strings.Contains(strings.ToLower(t.Name()), needle) {
			continue
		}
		out = append(out, t)
	}
	// The store already returns newest-first; enforce determinism here too in case
	// an adapter returns an unordered slice.
	sort.SliceStable(out, func(i, j int) bool {
		ci, cj := out[i].CreatedAt(), out[j].CreatedAt()
		if ci.Equal(cj) {
			return out[i].ID() > out[j].ID()
		}
		return ci.After(cj)
	})
	return out, nil
}

func matchesStatus(t *tenant.Tenant, f StatusFilter) bool {
	switch f {
	case StatusActive:
		return t.Active()
	case StatusSuspended:
		return !t.Active()
	default:
		return true
	}
}

// GetTenant returns a tenant by id, or shared.ErrNotFound.
func (s *ConsoleService) GetTenant(ctx context.Context, id string) (*tenant.Tenant, error) {
	t, err := s.tenants.FindTenantByID(ctx, strings.TrimSpace(id))
	if err != nil {
		return nil, fmt.Errorf("find tenant: %w", err)
	}
	return t, nil
}

// CreateTenant provisions a new tenant from the console form (name only). The
// domain enforces the name invariants; a validation error is surfaced inline by
// the boundary.
func (s *ConsoleService) CreateTenant(ctx context.Context, name string) (*tenant.Tenant, error) {
	t, err := tenant.New(s.ids.NewID(), name, s.clock.Now())
	if err != nil {
		return nil, err
	}
	if err := s.tenants.SaveTenant(ctx, t); err != nil {
		return nil, fmt.Errorf("save tenant: %w", err)
	}
	return t, nil
}

// RenameTenant edits a tenant's display name (ADR-0012 §1). The domain enforces the
// name invariants (non-blank, ≤ 200 chars) and leaves the immutable accountID
// binding untouched; a validation error surfaces inline at the boundary. A missing
// tenant yields the same clean 404 (no enumeration oracle, OWASP A01). Audited
// (tenant.rename) with who/which-tenant/when — never the name value.
func (s *ConsoleService) RenameTenant(ctx context.Context, id, name string) (*tenant.Tenant, error) {
	return s.transition(ctx, id, audit.ActionRenameTenant, func(t *tenant.Tenant) error {
		return t.Rename(name)
	})
}

// SuspendTenant deactivates a tenant (soft-delete / reversible, ADR-0012 §4).
// Returns the updated tenant. Audited (tenant.suspend). The auth choke-point already
// rejects a deactivated tenant's token/selector, so the deactivation takes effect at
// the boundary without any change here (ADR-0012 §4).
func (s *ConsoleService) SuspendTenant(ctx context.Context, id string) (*tenant.Tenant, error) {
	return s.transition(ctx, id, audit.ActionSuspendTenant, func(t *tenant.Tenant) error {
		t.Deactivate()
		return nil
	})
}

// DeactivateTenant is the ADR-0012 §4 name for SuspendTenant (soft-delete). Both
// deactivate the tenant and audit as tenant.suspend.
func (s *ConsoleService) DeactivateTenant(ctx context.Context, id string) (*tenant.Tenant, error) {
	return s.SuspendTenant(ctx, id)
}

// ActivateTenant re-enables a suspended tenant (ADR-0012 §4). Returns the updated
// tenant. Audited (tenant.activate).
func (s *ConsoleService) ActivateTenant(ctx context.Context, id string) (*tenant.Tenant, error) {
	return s.transition(ctx, id, audit.ActionActivateTenant, func(t *tenant.Tenant) error {
		t.Activate()
		return nil
	})
}

// transition loads a tenant, applies a mutation (which may reject with a validation
// error, e.g. a rename), persists it and appends the tenant-scoped audit entry for
// the given action. Fail-closed: an audit-append error surfaces rather than dropping
// the forensic trail (mirroring the console's credential/creditor-key writes). The
// audit runs after the save, matching the console's other single-store mutations.
func (s *ConsoleService) transition(ctx context.Context, id string, action audit.Action, apply func(*tenant.Tenant) error) (*tenant.Tenant, error) {
	t, err := s.tenants.FindTenantByID(ctx, strings.TrimSpace(id))
	if err != nil {
		return nil, fmt.Errorf("find tenant: %w", err)
	}
	if err := apply(t); err != nil {
		return nil, err
	}
	if err := s.tenants.SaveTenant(ctx, t); err != nil {
		return nil, fmt.Errorf("save tenant: %w", err)
	}
	e, err := audit.NewEntry(s.ids.NewID(), OperatorIDFromContext(ctx), action, t.ID(), s.clock.Now())
	if err != nil {
		return nil, fmt.Errorf("build audit entry: %w", err)
	}
	if err := s.audit.Append(ctx, e); err != nil {
		return nil, fmt.Errorf("append audit entry: %w", err)
	}
	return t, nil
}

// --- Bank credentials (write-only) ---

// SetBankCredential stores a tenant's bank (PSP) credential via the secret-store
// write port. The target tenant must exist. The secret transits straight to the
// writer: it never enters domain state, logs, errors or any rendered response
// (threat C1/C4). The console never reads a credential back.
func (s *ConsoleService) SetBankCredential(ctx context.Context, tenantID, clientID, secret string) error {
	if _, err := s.tenants.FindTenantByID(ctx, strings.TrimSpace(tenantID)); err != nil {
		return fmt.Errorf("resolve tenant: %w", err)
	}
	// Single-bank write path: persists under the default bank (BankIDC6),
	// preserving current behaviour. A per-bank selector in the console is the
	// routing/UX workstream (SIN-66022 / SIN-66017), not this schema change.
	if err := s.assertClientIDFree(ctx, tenantID, ports.BankIDC6, clientID); err != nil {
		return err
	}
	if err := s.credWriter.SetBankCredential(ctx, tenantID, ports.BankIDC6, clientID, secret); err != nil {
		// Wrap with non-sensitive context only; never include the secret.
		return fmt.Errorf("set bank credential: %w", err)
	}
	// Evict any cached OAuth2 token minted under the prior credential so the
	// rotation/revocation takes effect immediately instead of after the cached
	// bearer expires (token-revocation lag, ADR-0003). Best-effort and local.
	s.credEvictor.InvalidateToken(strings.TrimSpace(tenantID))
	return nil
}

// --- Banks (multi-bank console, SIN-66017 / SIN-66086) ---

// BankInfo is the console projection of one bank within a tenant. It never
// carries the secret: CredentialSet answers "is a credential configured?" and
// ClientID / CreditorKey are non-secret identity fields echoed back for operator
// recognition (the secret is fetched at use time and never rendered, threat C1).
// Cert is the per-bank mTLS certificate's PUBLIC metadata (nil when none is
// configured); it never carries the private key (threat C1/C4).
type BankInfo struct {
	Slug          string
	CredentialSet bool
	ClientID      string
	CreditorKey   string
	Cert          *BankCertInfo
}

// CertStatus is the lifecycle band of a stored mTLS certificate relative to the
// service clock, driving the expiry badge on the bank screens.
type CertStatus string

const (
	// CertStatusValid is in its validity window with more than the warning margin
	// of life left.
	CertStatusValid CertStatus = "valid"
	// CertStatusExpiringSoon is still valid but expires within certExpiryWarningWindow.
	CertStatusExpiringSoon CertStatus = "expiring_soon"
	// CertStatusExpired is past its NotAfter (the live transport would be rejected).
	CertStatusExpired CertStatus = "expired"
	// CertStatusNotYetValid is pre-provisioned: its NotBefore is in the future
	// (an operator staged the next rotation cert; SIN-66087 accepts these).
	CertStatusNotYetValid CertStatus = "not_yet_valid"
)

// certExpiryWarningWindow is how close to NotAfter a certificate flips to the
// "expiring soon" warning band (plan §7: warning ≤ 30 days).
const certExpiryWarningWindow = 30 * 24 * time.Hour

// BankCertInfo is the console projection of one bank's mTLS certificate. It is
// PUBLIC metadata only — the private key never reaches this struct (threat
// C1/C4). Status and DaysToExpiry are computed against the service clock at read
// time so the UI can badge a valid / expiring / expired / pre-provisioned cert
// without re-deriving the policy in the template.
type BankCertInfo struct {
	SubjectCN         string
	Issuer            string
	SerialNumber      string
	FingerprintSHA256 string
	NotBefore         time.Time
	NotAfter          time.Time
	Status            CertStatus
	// DaysToExpiry is the (ceil) number of days until NotAfter; it is negative once
	// the certificate has expired. The UI shows its magnitude in the badge.
	DaysToExpiry int
}

// certStatusFor classifies a certificate's validity window against now and
// returns the days remaining until NotAfter (negative once expired). The bands
// are deny-leaning: a cert exactly at or past NotAfter is Expired, and one whose
// NotBefore is still in the future is NotYetValid (pre-provisioned rotation).
func certStatusFor(notBefore, notAfter, now time.Time) (CertStatus, int) {
	days := ceilDays(notAfter.Sub(now))
	switch {
	case now.Before(notBefore):
		return CertStatusNotYetValid, days
	case !now.Before(notAfter):
		return CertStatusExpired, days
	case notAfter.Sub(now) <= certExpiryWarningWindow:
		return CertStatusExpiringSoon, days
	default:
		return CertStatusValid, days
	}
}

// ceilDays rounds a duration up to whole days (so "12 hours left" reads as
// "1 day"). A non-positive duration (already expired) floors toward zero or
// negative so the badge can show how long ago it lapsed.
func ceilDays(d time.Duration) int {
	const day = 24 * time.Hour
	if d <= 0 {
		return int(d / day)
	}
	return int((d + day - time.Nanosecond) / day)
}

// lookupBank reads the (tenantID, bankID) credential and reports whether one is
// configured. A missing credential (ErrNotFound) is not an error — it is the
// "pendente" state. A nil reader (optional dependency) degrades to "not
// configured". Any other store error propagates so the screen 500s honestly.
func (s *ConsoleService) lookupBank(ctx context.Context, tenantID, bankID string) (BankInfo, error) {
	info := BankInfo{Slug: bankID}
	if s.credReader != nil {
		c, err := s.credReader.GetBankCredential(ctx, tenantID, bankID)
		switch {
		case err == nil:
			// Project only non-secret identity fields. The secret stays in the store.
			info.CredentialSet = true
			info.ClientID = c.ClientID
			info.CreditorKey = c.CreditorKey
		case errors.Is(err, shared.ErrNotFound):
			// Unconfigured bank: the "pendente" state, not an error.
		default:
			return BankInfo{}, fmt.Errorf("read bank credential: %w", err)
		}
	}
	if s.certReader != nil {
		meta, err := s.certReader.GetBankCertificateMeta(ctx, tenantID, bankID)
		switch {
		case err == nil:
			st, days := certStatusFor(meta.NotBefore, meta.NotAfter, s.clock.Now())
			info.Cert = &BankCertInfo{
				SubjectCN:         meta.SubjectCN,
				Issuer:            meta.Issuer,
				SerialNumber:      meta.SerialNumber,
				FingerprintSHA256: meta.FingerprintSHA256,
				NotBefore:         meta.NotBefore,
				NotAfter:          meta.NotAfter,
				Status:            st,
				DaysToExpiry:      days,
			}
		case errors.Is(err, shared.ErrNotFound):
			// No certificate configured for this bank yet — leave Cert nil.
		default:
			return BankInfo{}, fmt.Errorf("read bank certificate: %w", err)
		}
	}
	return info, nil
}

// ListBanks returns the tenant's configured banks (those with a credential),
// ordered deterministically by slug. The set of candidate banks is the platform's
// closed allow-list (ports.KnownBankIDs) — there is no per-tenant bank registry,
// so "the banks this tenant uses" is "the supported banks this tenant has a
// credential for". A brand-new tenant returns an empty slice (the empty state).
// The tenant must exist so the screen 404s cleanly.
func (s *ConsoleService) ListBanks(ctx context.Context, tenantID string) ([]BankInfo, error) {
	tenantID = strings.TrimSpace(tenantID)
	if _, err := s.tenants.FindTenantByID(ctx, tenantID); err != nil {
		return nil, fmt.Errorf("resolve tenant: %w", err)
	}
	out := make([]BankInfo, 0, len(ports.KnownBankIDs()))
	for _, slug := range ports.KnownBankIDs() {
		info, err := s.lookupBank(ctx, tenantID, slug)
		if err != nil {
			return nil, err
		}
		if info.CredentialSet {
			out = append(out, info)
		}
	}
	return out, nil
}

// AddableBankSlugs returns the supported bank slugs the tenant has NOT configured
// yet, ordered by slug — the closed allow-list for the add-bank selector. When it
// is empty every supported bank is already configured (the selector is disabled).
func (s *ConsoleService) AddableBankSlugs(ctx context.Context, tenantID string) ([]string, error) {
	tenantID = strings.TrimSpace(tenantID)
	if _, err := s.tenants.FindTenantByID(ctx, tenantID); err != nil {
		return nil, fmt.Errorf("resolve tenant: %w", err)
	}
	out := make([]string, 0, len(ports.KnownBankIDs()))
	for _, slug := range ports.KnownBankIDs() {
		info, err := s.lookupBank(ctx, tenantID, slug)
		if err != nil {
			return nil, err
		}
		if !info.CredentialSet {
			out = append(out, slug)
		}
	}
	return out, nil
}

// GetBank returns one bank's console projection for the detail screen. The bank
// slug must be a supported bank (deny-by-default allow-list) — an unknown slug is
// shared.ErrNotFound so the screen 404s rather than rendering a bank that can
// never route a charge. The tenant must exist.
func (s *ConsoleService) GetBank(ctx context.Context, tenantID, bankID string) (BankInfo, error) {
	tenantID = strings.TrimSpace(tenantID)
	if _, err := s.tenants.FindTenantByID(ctx, tenantID); err != nil {
		return BankInfo{}, fmt.Errorf("resolve tenant: %w", err)
	}
	slug := ports.NormalizeBankID(bankID)
	if !ports.IsKnownBankID(slug) {
		return BankInfo{}, fmt.Errorf("unknown bank %q: %w", bankID, shared.ErrNotFound)
	}
	return s.lookupBank(ctx, tenantID, slug)
}

// SetBankCredentialFor stores a tenant's credential for an explicit bank (the
// per-bank console write path, mirroring the admin PUT bank-credential contract
// of SIN-66023). The bank slug is validated against the closed allow-list
// (deny-by-default): an unknown slug is a validation error and the input is never
// echoed (threat C1/C4). The secret transits straight to the writer — it never
// enters domain state, logs, errors or any rendered response. The cached OAuth2
// token minted under the prior credential is evicted immediately (ADR-0003).
func (s *ConsoleService) SetBankCredentialFor(ctx context.Context, tenantID, bankID, clientID, secret string) error {
	tenantID = strings.TrimSpace(tenantID)
	if _, err := s.tenants.FindTenantByID(ctx, tenantID); err != nil {
		return fmt.Errorf("resolve tenant: %w", err)
	}
	slug := ports.NormalizeBankID(bankID)
	if !ports.IsKnownBankID(slug) {
		return shared.NewValidationError("bank", "banco não suportado")
	}
	if err := s.assertClientIDFree(ctx, tenantID, slug, clientID); err != nil {
		return err
	}
	if err := s.credWriter.SetBankCredential(ctx, tenantID, slug, clientID, secret); err != nil {
		return fmt.Errorf("set bank credential: %w", err)
	}
	s.credEvictor.InvalidateToken(tenantID)
	return nil
}

// SetCreditorKey records a tenant's PIX creditor key (chave do recebedor) via the
// fund-routing write port, then audits the change with the acting operator. The
// target tenant must exist (defense-in-depth alongside the boundary RBAC). The
// key targets the tenant's default-bank credential (BankIDC6, the single
// allow-listed bank) per the binding port-shape decision (SIN-66017 / ADR-0008):
// no bank dimension on this write path. The key is routing-sensitive, not a
// secret: the adapter validates its PIX shape and preserves the credential's
// secret/client id (read-modify-write), and the error path never echoes the value
// (threat C1/C4). No OAuth token-cache eviction is performed — the creditor key is
// not part of the OAuth identity, so a cached bearer stays valid (ADR-0003).
// SetCreditorKeySelfServe grava a chave PIX do recebedor a partir do plano do
// TENANT, e não do console do operador.
//
// É a mesma escrita de SetCreditorKey — mesmo port, mesma auditoria, mesmo cuidado
// de nunca registrar o valor da chave — com uma diferença que importa: aqui o
// tenantID vem do contexto AUTENTICADO, nunca de entrada do cliente. Não existe
// seletor de tenant no contrato, então um token só consegue escrever a própria
// chave; a classe inteira de quebra de controle de acesso (A01) é eliminada por
// construção, não conferida.
//
// Existe porque a chave PIX faz par com a credencial: sem ela o adaptador não sabe
// para qual conta rotear os fundos, e a empresa-cliente que provisiona a própria
// credencial não tinha como completar o par sem passar por um operador.
func (s *ConsoleService) SetCreditorKeySelfServe(ctx context.Context, tenantID, creditorKey string) error {
	return s.SetCreditorKey(WithOperatorID(ctx, selfServeOperatorID), tenantID, creditorKey)
}

// selfServeOperatorID é o ator sintético gravado na auditoria quando a própria
// empresa-cliente faz a escrita. Nomeia o sistema em vez de inventar um usuário, e
// separa no rastro a rotação feita pelo tenant da feita por um operador.
const selfServeOperatorID = "system:self-serve"

func (s *ConsoleService) SetCreditorKey(ctx context.Context, tenantID, creditorKey string) error {
	tenantID = strings.TrimSpace(tenantID)
	if _, err := s.tenants.FindTenantByID(ctx, tenantID); err != nil {
		return fmt.Errorf("resolve tenant: %w", err)
	}
	key := strings.TrimSpace(creditorKey)
	if err := s.assertCreditorKeyFree(ctx, tenantID, key); err != nil {
		return err
	}
	if err := s.creditorWrite.SetCreditorKey(ctx, tenantID, key); err != nil {
		// Wrap with non-sensitive context only; never include the key value.
		return fmt.Errorf("set creditor key: %w", err)
	}
	// Audit the fund-routing change with who/which-tenant/which-bank (the default
	// bank the creditor key is registered under) — never the key value. Fail-closed:
	// a forensic-record error surfaces rather than silently dropping the trail.
	e, err := audit.NewCreditorKeySetEntry(s.ids.NewID(), OperatorIDFromContext(ctx), tenantID, ports.BankIDC6, s.clock.Now())
	if err != nil {
		return fmt.Errorf("build audit entry: %w", err)
	}
	if err := s.audit.Append(ctx, e); err != nil {
		return fmt.Errorf("append audit entry: %w", err)
	}
	return nil
}

// SetBankCertificate validates and stores a tenant's per-bank mTLS client
// certificate from the console upload (SIN-66088), mirroring the admin-plane
// AdminService.SetBankCertificate contract (SIN-66087). The bank slug is
// validated against the closed allow-list (deny-by-default; empty → default c6)
// and the tenant must exist. The PEM pair is parsed and key-matched BEFORE the
// vault, and a certificate already expired at upload (NotAfter ≤ now) is rejected
// — all as named validation errors (HTTP 400/422), never a 500; a not-yet-valid
// cert is accepted so an operator can pre-provision the next rotation. The private
// key transits straight to the writer: beyond the transient BankCertificate it
// never enters domain state, logs, errors or any rendered response (threat
// C1/C4). On success only the public metadata is returned, the cached OAuth token
// is evicted (a rotation takes effect without the TTL lag, ADR-0003), and the
// write is audited by who/tenant/bank/fingerprint — never the key.
func (s *ConsoleService) SetBankCertificate(ctx context.Context, tenantID, bankID, certPEM, keyPEM string) (ports.BankCertificateMeta, error) {
	tenantID = strings.TrimSpace(tenantID)
	if _, err := s.tenants.FindTenantByID(ctx, tenantID); err != nil {
		return ports.BankCertificateMeta{}, fmt.Errorf("resolve tenant: %w", err)
	}
	slug := ports.NormalizeBankID(bankID)
	if !ports.IsKnownBankID(slug) {
		return ports.BankCertificateMeta{}, shared.NewValidationError("bank", "banco não suportado")
	}
	// Parse + key-pair match BEFORE the vault: bad material never reaches storage
	// and the caller gets a precise validation error, not a 500 (plan §7.1 c/d).
	cert, err := bankcert.Parse(certPEM, keyPEM)
	if err != nil {
		return ports.BankCertificateMeta{}, err
	}
	if cert.NotAfter.Before(s.clock.Now()) {
		return ports.BankCertificateMeta{}, shared.NewValidationError("cert_pem", "certificado já expirado")
	}
	if err := s.certWriter.SetBankCertificate(ctx, ports.BankCertificate{
		TenantID: tenantID,
		BankID:   slug,
		CertPEM:  certPEM,
		KeyPEM:   keyPEM,
	}); err != nil {
		// Wrap with non-sensitive context only; never include key material.
		return ports.BankCertificateMeta{}, fmt.Errorf("set bank certificate: %w", err)
	}
	// Evict the tenant's cached token AND its pooled mTLS connections, so the
	// certificate just written is the one presented on the next handshake (ADR-0003,
	// SIN-69368) instead of only after the next restart.
	s.credEvictor.InvalidateToken(tenantID)
	// Audit the provisioning with who/tenant/bank/fingerprint (never the key).
	// Fail-closed: a forensic-record error surfaces rather than dropping the trail.
	e, err := audit.NewCertificateSetEntry(s.ids.NewID(), OperatorIDFromContext(ctx), tenantID, slug, cert.FingerprintSHA256, s.clock.Now())
	if err != nil {
		return ports.BankCertificateMeta{}, fmt.Errorf("build audit entry: %w", err)
	}
	if err := s.audit.Append(ctx, e); err != nil {
		return ports.BankCertificateMeta{}, fmt.Errorf("append audit entry: %w", err)
	}
	return ports.BankCertificateMeta{
		TenantID:          tenantID,
		BankID:            slug,
		SubjectCN:         cert.SubjectCN,
		Issuer:            cert.Issuer,
		SerialNumber:      cert.SerialNumber,
		FingerprintSHA256: cert.FingerprintSHA256,
		NotBefore:         cert.NotBefore,
		NotAfter:          cert.NotAfter,
	}, nil
}

// RemoveBankConfig hard-deletes a tenant's per-bank configuration — the credential
// AND the mTLS certificate for the (tenantID, bankID) pair (ADR-0012 §5). It is the
// only destructive path that removes real material rather than soft-deleting, and it
// is safe precisely because the (tenant, bank) pair anchors no ledger, invoice,
// pii_access_log nor recurrence mandate — it is pure operational configuration. The
// tenant must exist (clean 404 — no enumeration oracle, OWASP A01) and the bank slug
// must be in the closed allow-list (deny-by-default; empty → default c6). Both
// deletes are IDEMPOTENT (removing an absent half is a no-op that still returns 200),
// so a repeated "Remover banco" click is harmless, and each adapter zeroises the
// secret/key BEFORE dropping the row (threat C1/C4). The cached OAuth token is evicted
// so the removal takes effect without the TTL lag (ADR-0003). Audited
// (bank_config.remove) with who/tenant/bank — NEVER the deleted secret or key.
//
// The two deletes are ordered credential-then-certificate and fail fast: on a
// deleter error the operation aborts and surfaces it. With the in-process stores
// each delete cannot partially fail; a durable backing would wrap the pair in the
// unit-of-work so they commit or roll back together (ADR-0012 §5, "transacional").
func (s *ConsoleService) RemoveBankConfig(ctx context.Context, tenantID, bankID string) error {
	tenantID = strings.TrimSpace(tenantID)
	if _, err := s.tenants.FindTenantByID(ctx, tenantID); err != nil {
		return fmt.Errorf("resolve tenant: %w", err)
	}
	slug := ports.NormalizeBankID(bankID)
	if !ports.IsKnownBankID(slug) {
		return shared.NewValidationError("bank", "banco não suportado")
	}
	// Deregister at the PSP FIRST: the calls below authenticate with the very credential
	// this operation is about to delete, and the PIX callback is keyed by the creditor key
	// stored on it. Doing it after would make deregistration impossible — the PSP would
	// keep POSTing notifications we can no longer authenticate or reconcile.
	s.deregisterWebhooks(ctx, tenantID, slug)

	if s.credDeleter != nil {
		if err := s.credDeleter.DeleteBankCredential(ctx, tenantID, slug); err != nil {
			return fmt.Errorf("delete bank credential: %w", err)
		}
	}
	if s.certDeleter != nil {
		if err := s.certDeleter.DeleteBankCertificate(ctx, tenantID, slug); err != nil {
			return fmt.Errorf("delete bank certificate: %w", err)
		}
	}
	// Evict any cached OAuth token minted under the now-removed credential so new
	// transactions fail closed immediately instead of riding a cached bearer.
	s.credEvictor.InvalidateToken(tenantID)
	// Audit the removal with who/tenant/bank (never the deleted material). Fail-closed:
	// a forensic-record error surfaces rather than dropping the trail.
	e, err := audit.NewBankConfigRemovedEntry(s.ids.NewID(), OperatorIDFromContext(ctx), tenantID, slug, s.clock.Now())
	if err != nil {
		return fmt.Errorf("build audit entry: %w", err)
	}
	if err := s.audit.Append(ctx, e); err != nil {
		return fmt.Errorf("append audit entry: %w", err)
	}
	return nil
}

// --- Pricing ---

// ListPricing returns a tenant's per-endpoint pricing rules (ordered by
// endpoint). The tenant must exist so the screen 404s cleanly for a bad id.
func (s *ConsoleService) ListPricing(ctx context.Context, tenantID string) ([]billing.EndpointPricing, error) {
	if _, err := s.tenants.FindTenantByID(ctx, strings.TrimSpace(tenantID)); err != nil {
		return nil, fmt.Errorf("resolve tenant: %w", err)
	}
	prices, err := s.pricing.ListEndpointPrices(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list prices: %w", err)
	}
	return prices, nil
}

// SetPrice upserts the price (cents) a tenant pays for an endpoint call. The
// tenant must exist; the operation is idempotent (a repeated upsert with the
// same value is a no-op), so the inline editor is safe to retry.
func (s *ConsoleService) SetPrice(ctx context.Context, tenantID, endpoint string, priceCents int64) (billing.EndpointPricing, error) {
	if _, err := s.tenants.FindTenantByID(ctx, strings.TrimSpace(tenantID)); err != nil {
		return billing.EndpointPricing{}, fmt.Errorf("resolve tenant: %w", err)
	}
	p, err := billing.NewEndpointPricing(tenantID, endpoint, priceCents)
	if err != nil {
		return billing.EndpointPricing{}, err
	}
	if err := s.pricing.UpsertEndpointPrice(ctx, p); err != nil {
		return billing.EndpointPricing{}, fmt.Errorf("upsert price: %w", err)
	}
	return p, nil
}

// --- Consumption audit ---

// ConsumptionLine is one endpoint's aggregated usage in a consumption report.
type ConsumptionLine struct {
	Endpoint   string
	Calls      int
	TotalCents int64
}

// ConsumptionReport is the read-only consumption audit for one tenant: the
// per-endpoint aggregation of the append-only ledger plus the grand totals.
type ConsumptionReport struct {
	TenantID   string
	Lines      []ConsumptionLine
	TotalCalls int
	TotalCents int64
}

// ConsumptionRange bounds a consumption report by ledger-entry time. The window
// is half-open [Start, End): an entry is counted when its time is not before
// Start and strictly before End. A zero value on either side is unbounded on
// that side, so the zero ConsumptionRange selects every entry.
type ConsumptionRange struct {
	Start time.Time
	End   time.Time
}

// includes reports whether t falls inside the (possibly unbounded) window.
func (rng ConsumptionRange) includes(t time.Time) bool {
	if !rng.Start.IsZero() && t.Before(rng.Start) {
		return false
	}
	if !rng.End.IsZero() && !t.Before(rng.End) {
		return false
	}
	return true
}

// Consumption builds the per-endpoint consumption report for a tenant over all
// recorded ledger entries. See ConsumptionInRange for the time-bounded variant.
func (s *ConsoleService) Consumption(ctx context.Context, tenantID string) (ConsumptionReport, error) {
	return s.ConsumptionInRange(ctx, tenantID, ConsumptionRange{})
}

// ConsumptionInRange builds the per-endpoint consumption report for a tenant from
// its ledger, counting only entries whose time falls inside rng. The ledger is
// authoritative for billing, so the audit is a pure aggregation of recorded
// events — never a value derived from mutable state. The tenant must exist so
// the screen 404s cleanly.
func (s *ConsoleService) ConsumptionInRange(ctx context.Context, tenantID string, rng ConsumptionRange) (ConsumptionReport, error) {
	tenantID = strings.TrimSpace(tenantID)
	if _, err := s.tenants.FindTenantByID(ctx, tenantID); err != nil {
		return ConsumptionReport{}, fmt.Errorf("resolve tenant: %w", err)
	}
	entries, err := s.ledger.ListLedgerEntries(ctx, tenantID)
	if err != nil {
		return ConsumptionReport{}, fmt.Errorf("list ledger: %w", err)
	}
	byEndpoint := make(map[string]*ConsumptionLine)
	rep := ConsumptionReport{TenantID: tenantID}
	for _, e := range entries {
		if !rng.includes(e.At()) {
			continue
		}
		line, ok := byEndpoint[e.Endpoint()]
		if !ok {
			line = &ConsumptionLine{Endpoint: e.Endpoint()}
			byEndpoint[e.Endpoint()] = line
		}
		line.Calls++
		line.TotalCents += e.PriceCents()
		rep.TotalCalls++
		rep.TotalCents += e.PriceCents()
	}
	rep.Lines = make([]ConsumptionLine, 0, len(byEndpoint))
	for _, line := range byEndpoint {
		rep.Lines = append(rep.Lines, *line)
	}
	sort.SliceStable(rep.Lines, func(i, j int) bool { return rep.Lines[i].Endpoint < rep.Lines[j].Endpoint })
	return rep, nil
}

// --- Invoices (Faturas, SIN-69121) ---

// GenerateInvoice freezes the tenant's metered consumption over the BOUNDED
// window rng into a durable, append-only Fatura and records it on the audit
// trail. The invoice line totals are the sum of the recorded ledger prices in the
// window (via ConsumptionInRange) — never recomputed from the mutable pricing
// table — so the document is authoritative and reproducible.
//
// The window MUST be bounded on both sides: an invoice bills a definite period,
// so an open-ended range is rejected (unlike the read-only consumption screen,
// which allows an unbounded "all time" view). The tenant must exist (404 clean).
// Regenerating the same period is allowed and produces a NEW invoice id — the
// store is append-only, never an overwrite, so the full billing history stands.
func (s *ConsoleService) GenerateInvoice(ctx context.Context, tenantID string, rng ConsumptionRange) (invoice.Invoice, error) {
	if s.invoices == nil {
		return invoice.Invoice{}, ErrInvoicesUnavailable
	}
	tenantID = strings.TrimSpace(tenantID)
	if rng.Start.IsZero() || rng.End.IsZero() {
		return invoice.Invoice{}, shared.NewValidationError("period", "invoice period start and end are required")
	}
	if !rng.Start.Before(rng.End) {
		return invoice.Invoice{}, shared.NewValidationError("period", "invoice period start must be before end")
	}
	t, err := s.tenants.FindTenantByID(ctx, tenantID)
	if err != nil {
		return invoice.Invoice{}, fmt.Errorf("resolve tenant: %w", err)
	}
	rep, err := s.ConsumptionInRange(ctx, tenantID, rng)
	if err != nil {
		return invoice.Invoice{}, err
	}
	lines := make([]invoice.LineItem, 0, len(rep.Lines))
	for _, l := range rep.Lines {
		li, err := invoice.NewLineItem(l.Endpoint, l.Calls, l.TotalCents)
		if err != nil {
			return invoice.Invoice{}, fmt.Errorf("build invoice line: %w", err)
		}
		lines = append(lines, li)
	}
	// account rollup parent: the tenant's owning account, defaulting to the
	// deterministic self-account id (matching migration 0007's ledger backfill)
	// when the tenant has not yet been bound to a real account.
	accountID := t.AccountID()
	if accountID == "" {
		accountID = "acct-" + tenantID
	}
	inv, err := invoice.New(s.ids.NewID(), tenantID, accountID, rng.Start, rng.End, s.clock.Now(), lines)
	if err != nil {
		return invoice.Invoice{}, err
	}
	if err := s.invoices.SaveInvoice(ctx, inv); err != nil {
		return invoice.Invoice{}, fmt.Errorf("save invoice: %w", err)
	}
	e, err := audit.NewEntry(s.ids.NewID(), OperatorIDFromContext(ctx), audit.ActionInvoiceGenerated, tenantID, s.clock.Now())
	if err != nil {
		return invoice.Invoice{}, err
	}
	if err := s.audit.Append(ctx, e); err != nil {
		return invoice.Invoice{}, fmt.Errorf("audit invoice generation: %w", err)
	}
	return inv, nil
}

// GetInvoice returns one invoice for a tenant, or shared.ErrNotFound. Tenant-
// scoped: the id is resolved only within the tenant's own invoices (threat P1).
func (s *ConsoleService) GetInvoice(ctx context.Context, tenantID, id string) (invoice.Invoice, error) {
	if s.invoices == nil {
		return invoice.Invoice{}, ErrInvoicesUnavailable
	}
	return s.invoices.FindInvoiceByID(ctx, strings.TrimSpace(tenantID), strings.TrimSpace(id))
}

// ListInvoices returns a tenant's invoices newest-first. The tenant must exist so
// the screen 404s cleanly on an unknown id.
func (s *ConsoleService) ListInvoices(ctx context.Context, tenantID string) ([]invoice.Invoice, error) {
	if s.invoices == nil {
		return nil, ErrInvoicesUnavailable
	}
	tenantID = strings.TrimSpace(tenantID)
	if _, err := s.tenants.FindTenantByID(ctx, tenantID); err != nil {
		return nil, fmt.Errorf("resolve tenant: %w", err)
	}
	return s.invoices.ListInvoices(ctx, tenantID)
}

// --- Account consumption rollup (account → tenant → endpoint) ---

// TenantConsumption is one tenant's slice of an account-level rollup: the same
// per-endpoint aggregation as ConsumptionReport, scoped to a single tenant
// (empresa-cliente) owned by the account.
type TenantConsumption struct {
	TenantID   string
	Lines      []ConsumptionLine
	TotalCalls int
	TotalCents int64
}

// AccountConsumptionReport is the read-only metering rollup for one API-user/reseller
// account: each tenant (empresa-cliente) it owns, broken down per endpoint, plus the
// account-wide grand totals. It is the account→tenant→endpoint view the invoicing
// track (F4, SIN-69121) groups on. Like ConsumptionReport it is a pure aggregation of
// the append-only ledger — never a value derived from mutable state.
type AccountConsumptionReport struct {
	AccountID  string
	Tenants    []TenantConsumption
	TotalCalls int
	TotalCents int64
}

// AccountConsumption builds the account→tenant→endpoint rollup over all recorded
// ledger entries owned by the account. See AccountConsumptionInRange for the
// time-bounded variant.
func (s *ConsoleService) AccountConsumption(ctx context.Context, accountID string) (AccountConsumptionReport, error) {
	return s.AccountConsumptionInRange(ctx, accountID, ConsumptionRange{})
}

// AccountConsumptionInRange builds the account→tenant→endpoint rollup from every
// ledger entry the account owns (across all its tenants), counting only entries whose
// time falls inside rng. The scan is account-scoped at the adapter (an account only
// sees its own tenants' entries). Tenants are returned in stable tenant-id order and
// each tenant's lines in endpoint order, so the rollup renders and invoices
// deterministically.
func (s *ConsoleService) AccountConsumptionInRange(ctx context.Context, accountID string, rng ConsumptionRange) (AccountConsumptionReport, error) {
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		return AccountConsumptionReport{}, shared.NewValidationError("account_id", "account id is required")
	}
	// The account must exist so the screen 404s cleanly and enumeration stays
	// closed, mirroring ConsumptionInRange (tenant). A valid account with no
	// ledger entries still returns an empty report (TotalCents=0), never 404.
	if s.accounts != nil {
		if _, err := s.accounts.FindAccountByID(ctx, accountID); err != nil {
			return AccountConsumptionReport{}, fmt.Errorf("resolve account: %w", err)
		}
	}
	entries, err := s.ledger.ListLedgerEntriesByAccount(ctx, accountID)
	if err != nil {
		return AccountConsumptionReport{}, fmt.Errorf("list ledger by account: %w", err)
	}
	byTenant := make(map[string]*TenantConsumption)
	byTenantEndpoint := make(map[string]map[string]*ConsumptionLine)
	rep := AccountConsumptionReport{AccountID: accountID}
	for _, e := range entries {
		if !rng.includes(e.At()) {
			continue
		}
		tc, ok := byTenant[e.TenantID()]
		if !ok {
			tc = &TenantConsumption{TenantID: e.TenantID()}
			byTenant[e.TenantID()] = tc
			byTenantEndpoint[e.TenantID()] = make(map[string]*ConsumptionLine)
		}
		line, ok := byTenantEndpoint[e.TenantID()][e.Endpoint()]
		if !ok {
			line = &ConsumptionLine{Endpoint: e.Endpoint()}
			byTenantEndpoint[e.TenantID()][e.Endpoint()] = line
		}
		line.Calls++
		line.TotalCents += e.PriceCents()
		tc.TotalCalls++
		tc.TotalCents += e.PriceCents()
		rep.TotalCalls++
		rep.TotalCents += e.PriceCents()
	}
	rep.Tenants = make([]TenantConsumption, 0, len(byTenant))
	for tenantID, tc := range byTenant {
		lines := make([]ConsumptionLine, 0, len(byTenantEndpoint[tenantID]))
		for _, line := range byTenantEndpoint[tenantID] {
			lines = append(lines, *line)
		}
		sort.SliceStable(lines, func(i, j int) bool { return lines[i].Endpoint < lines[j].Endpoint })
		tc.Lines = lines
		rep.Tenants = append(rep.Tenants, *tc)
	}
	sort.SliceStable(rep.Tenants, func(i, j int) bool { return rep.Tenants[i].TenantID < rep.Tenants[j].TenantID })
	return rep, nil
}

// deregisterWebhooks removes the tenant's PSP callbacks, best-effort. It never fails the
// removal: the operator asked for the configuration to go, and refusing because the bank
// is briefly unavailable would be worse than the residue — which is exactly the state
// every removal left behind before this existed. An already-absent registration is not an
// error. Each outcome is logged with the tenant and bank (never the callback URL, which
// embeds the secret ref).
// assertCreditorKeyFree delegates to the package guard; see bank_identity.go for why
// the invariant exists and why a suspended holder does not block.
func (s *ConsoleService) assertCreditorKeyFree(ctx context.Context, tenantID, creditorKey string) error {
	return assertCreditorKeyUnclaimed(ctx, s.sharing, s.tenants, tenantID, ports.BankIDC6, creditorKey)
}

// assertClientIDFree rejects a PSP account (client_id) already used by another ACTIVE
// empresa. Dividir a conta quebra recorrência e CHECKOUT — o aviso de pagamento com
// cartão —, mesmo que as chaves PIX sejam diferentes.
func (s *ConsoleService) assertClientIDFree(ctx context.Context, tenantID, bankID, clientID string) error {
	return assertClientIDUnclaimed(ctx, s.sharing, s.tenants, tenantID, bankID, clientID)
}

// tenantIsActive resolves a tenant's ACTIVE flag. A tenant that no longer exists counts
// as inactive (an orphan credential row must not block a legitimate write).
func (s *ConsoleService) tenantIsActive(ctx context.Context, tenantID string) (bool, error) {
	t, err := s.tenants.FindTenantByID(ctx, tenantID)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	return t.Active(), nil
}

// sharesBankIdentityWithActiveTenant reports whether ANOTHER ACTIVE tenant is registered
// under the same PIX key or the same PSP account (client_id) as tenantID.
//
// Falha FECHADO para o chamador que a usa: quando não dá para responder, tratamos como
// "compartilha", porque o estrago de desregistrar o webhook de uma empresa ativa é bem
// pior do que o de deixar uma inscrição órfã no PSP.
func (s *ConsoleService) sharesBankIdentityWithActiveTenant(ctx context.Context, tenantID, bankID, chave, clientID string) bool {
	if s.sharing == nil {
		return false
	}
	lookups := []func() ([]string, error){
		func() ([]string, error) { return s.sharing.FindTenantsByCreditorKey(ctx, bankID, chave) },
		func() ([]string, error) { return s.sharing.FindTenantsByClientID(ctx, bankID, clientID) },
	}
	for _, lookup := range lookups {
		holders, err := lookup()
		if err != nil {
			return true
		}
		for _, other := range holders {
			if other == tenantID {
				continue
			}
			active, err := s.tenantIsActive(ctx, other)
			if err != nil || active {
				return true
			}
		}
	}
	return false
}

func (s *ConsoleService) deregisterWebhooks(ctx context.Context, tenantID, bankID string) {
	if s == nil || s.webhookDeregistrar == nil || bankID != ports.BankIDC6 {
		return
	}
	drop := func(name string, fn func() error) {
		if err := fn(); err != nil && !errors.Is(err, shared.ErrNotFound) {
			slog.WarnContext(ctx, "console: could not deregister webhook at the PSP",
				slog.String("channel", name), slog.String("tenant_id", tenantID),
				slog.String("bank_id", bankID), slog.String("error", err.Error()))
		}
	}
	// The PIX callback is keyed by the creditor key, so it is read from the credential
	// while that credential still exists. No key means nothing was ever registered.
	var chave, clientID string
	if s.creds != nil {
		if cred, err := s.creds.GetBankCredential(ctx, tenantID, bankID); err == nil {
			chave = strings.TrimSpace(cred.CreditorKey)
			clientID = strings.TrimSpace(cred.ClientID)
		}
	}

	// Desregistrar é uma operação sobre a IDENTIDADE no PSP, não sobre este tenant. O
	// canal PIX é apagado POR CHAVE e os canais de recorrência pela CONTA do client_id —
	// então remover a config de um tenant que divide chave ou conta com outro derruba a
	// inscrição VIVA do outro, e nada a refaz (a varredura de renovação está desligada).
	//
	// Aconteceu de verdade: a Verz tinha o mesmo cadastro duas vezes, um suspenso e um
	// ativo, com a mesma chave. Limpar o suspenso teria deixado a empresa ativa sem
	// webhook, em silêncio, até alguém regravar a credencial dela.
	//
	// Então: se outro tenant ATIVO divide a identidade, apagamos só o NOSSO lado e
	// deixamos o PSP como está. A inscrição que sobra pertence a quem ainda a usa.
	if s.sharesBankIdentityWithActiveTenant(ctx, tenantID, bankID, chave, clientID) {
		slog.InfoContext(ctx, "console: PSP deregistration skipped, bank identity shared with an active tenant",
			slog.String("tenant_id", tenantID), slog.String("bank_id", bankID))
		return
	}

	if chave != "" {
		drop("pix", func() error { return s.webhookDeregistrar.DeleteWebhook(ctx, tenantID, chave) })
	}
	drop("rec", func() error { return s.webhookDeregistrar.DeleteRecWebhook(ctx, tenantID) })
	drop("cobr", func() error { return s.webhookDeregistrar.DeleteCobRWebhook(ctx, tenantID) })
}

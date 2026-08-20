package app

import (
	"context"
	"fmt"

	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
	"github.com/ia-dev-sindireceita/payment/internal/domain/bankcert"
	"github.com/ia-dev-sindireceita/payment/internal/domain/billing"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// AdminService implements the admin plane: tenant lifecycle, per-endpoint
// pricing and per-tenant bank credential management. These operations are
// privileged (RBAC enforced at the boundary) and every successful mutation is
// recorded to the append-only audit trail with the operator's identity.
type AdminService struct {
	tenants    ports.TenantRepository
	pricing    ports.PricingRepository
	credWriter ports.CredentialWriter
	// sharing keeps a PSP account (client_id) from being claimed by two ACTIVE empresas
	// at once. Optional: nil leaves the historical behaviour. See bank_identity.go.
	sharing     ports.CreditorKeySharingLookup
	certWriter  ports.BankCertificateWriter
	credEvictor ports.CredentialInvalidator
	audit       ports.AuditLog
	clock       ports.Clock
	ids         ports.IDProvider
}

// noopAudit is the fallback AuditLog used when Deps.Audit is nil. It keeps the
// foundation and unit tests wiring-light, but it records nothing: production MUST
// wire a real audit log (see Deps.Audit).
type noopAudit struct{}

func (noopAudit) Append(context.Context, audit.Entry) error { return nil }

// noopCredInvalidator is the fallback CredentialInvalidator used when
// Deps.CredInvalidator is nil — e.g. the in-memory bank stub holds no token cache
// to evict. It drops nothing.
type noopCredInvalidator struct{}

func (noopCredInvalidator) InvalidateToken(string) {}

// NewAdminService wires an AdminService from the provided ports. A nil audit log
// degrades to a no-op so existing callers keep working; production wires a real
// append-only audit log. A nil credential invalidator likewise degrades to a
// no-op (the credential write still succeeds; only the cache-eviction step is
// skipped).
func NewAdminService(d Deps) *AdminService {
	a := d.Audit
	if a == nil {
		a = noopAudit{}
	}
	ci := d.CredInvalidator
	if ci == nil {
		ci = noopCredInvalidator{}
	}
	return &AdminService{tenants: d.Tenants, pricing: d.Pricing, credWriter: d.CredWriter, sharing: d.Sharing, certWriter: d.CertWriter, credEvictor: ci, audit: a, clock: d.Clock, ids: d.IDs}
}

// recordAudit appends an audit entry for a privileged action. who is derived
// server-side from the request context (never client input); the entry carries
// only who/what/tenant/when — never a secret. The audit append is fail-closed:
// if it errors the operation surfaces the error rather than silently dropping the
// forensic record.
func (s *AdminService) recordAudit(ctx context.Context, action audit.Action, tenantID string) error {
	e, err := audit.NewEntry(s.ids.NewID(), OperatorIDFromContext(ctx), action, tenantID, s.clock.Now())
	if err != nil {
		return fmt.Errorf("build audit entry: %w", err)
	}
	if err := s.audit.Append(ctx, e); err != nil {
		return fmt.Errorf("append audit entry: %w", err)
	}
	return nil
}

// recordCredentialAudit appends the audit entry for a bank credential write. It
// is the credential-specific sibling of recordAudit: it carries the non-secret
// bankID so the trail records which bank's credential was set, while still
// deriving the operator server-side and never recording the secret/client id. The
// selfServe flag selects the origin the entry is stamped with (self-serve when the
// tenant rotated its own credential via the tenant-plane intake, SIN-69196; admin
// otherwise) — the sole difference between the two write surfaces at the trail.
// The append is fail-closed (an error surfaces rather than dropping the record).
func (s *AdminService) recordCredentialAudit(ctx context.Context, tenantID, bankID string, selfServe bool) error {
	build := audit.NewCredentialSetEntry
	if selfServe {
		build = audit.NewSelfServeCredentialSetEntry
	}
	e, err := build(s.ids.NewID(), OperatorIDFromContext(ctx), tenantID, bankID, s.clock.Now())
	if err != nil {
		return fmt.Errorf("build audit entry: %w", err)
	}
	if err := s.audit.Append(ctx, e); err != nil {
		return fmt.Errorf("append audit entry: %w", err)
	}
	return nil
}

// CreateTenant provisions a new tenant and returns it.
func (s *AdminService) CreateTenant(ctx context.Context, name string) (*tenant.Tenant, error) {
	t, err := tenant.New(s.ids.NewID(), name, s.clock.Now())
	if err != nil {
		return nil, err
	}
	if err := s.tenants.SaveTenant(ctx, t); err != nil {
		return nil, fmt.Errorf("save tenant: %w", err)
	}
	if err := s.recordAudit(ctx, audit.ActionCreateTenant, t.ID()); err != nil {
		return nil, err
	}
	return t, nil
}

// SetEndpointPrice sets the price (cents) a tenant pays for an endpoint call.
// The tenant must exist. Tenants are read-only over their own pricing (threat B3).
func (s *AdminService) SetEndpointPrice(ctx context.Context, tenantID, endpoint string, priceCents int64) (billing.EndpointPricing, error) {
	if _, err := s.tenants.FindTenantByID(ctx, tenantID); err != nil {
		return billing.EndpointPricing{}, fmt.Errorf("resolve tenant: %w", err)
	}
	p, err := billing.NewEndpointPricing(tenantID, endpoint, priceCents)
	if err != nil {
		return billing.EndpointPricing{}, err
	}
	if err := s.pricing.UpsertEndpointPrice(ctx, p); err != nil {
		return billing.EndpointPricing{}, fmt.Errorf("upsert price: %w", err)
	}
	if err := s.recordAudit(ctx, audit.ActionSetEndpointPrice, tenantID); err != nil {
		return billing.EndpointPricing{}, err
	}
	return p, nil
}

// SetBankCredential stores a tenant's bank (PSP) credential via the secret-store
// write port, keyed by the (tenantID, bank) pair (ADR-0007 / SIN-66015). The
// target tenant must exist (defense-in-depth alongside the boundary RBAC +
// tenant-scope checks) and bank must name a supported bank (deny-by-default): an
// empty bank resolves to the default BankIDC6 (retro-compat) and an unknown slug
// is rejected as a validation error before any write. The secret is passed
// straight through to the writer: it never enters domain state, and on failure
// the returned error wraps only sentinel/validation context — never the secret
// value (threat C1/C4). The caller (admin handler) supplies tenantID explicitly;
// admin crosses tenants by design but every credential write names exactly one
// (tenant, bank).
func (s *AdminService) SetBankCredential(ctx context.Context, tenantID, bank, clientID, secret string) error {
	return s.setBankCredential(ctx, tenantID, bank, clientID, secret, false)
}

// SetBankCredentialSelfServe stores an empresa-cliente's OWN bank credential
// through the self-serve intake (SIN-69196 / trilha E2). It is byte-for-byte the
// same write as SetBankCredential — same (tenant, bank) key, same CredentialWriter
// port, same token-cache eviction, same never-leak-the-secret guarantee — with two
// deliberate distinctions: (1) the HTTP boundary derives tenantID from the
// authenticated tenant context, NEVER from client input (so a token can only ever
// write its own credential — the broken-access-control class A01 is designed out,
// there is no tenant selector to abuse); and (2) the audit entry is stamped
// origin=self-serve so the forensic trail separates a tenant self-rotation from an
// admin-driven write. The bank allow-list is enforced at the HTTP boundary (a
// dedicated self-serve allow-list, currently {c6}); this method re-validates the
// bank against the platform-wide known set as defense-in-depth, identically to the
// admin path.
func (s *AdminService) SetBankCredentialSelfServe(ctx context.Context, tenantID, bank, clientID, secret string) error {
	return s.setBankCredential(ctx, tenantID, bank, clientID, secret, true)
}

// setBankCredential is the shared implementation behind the admin and self-serve
// credential writes. selfServe selects only the audit origin; every port
// interaction (validate → resolve tenant → write → evict → audit) is identical, so
// the two surfaces can never diverge in what they persist or evict.
func (s *AdminService) setBankCredential(ctx context.Context, tenantID, bank, clientID, secret string, selfServe bool) error {
	bank = ports.NormalizeBankID(bank)
	if !ports.IsKnownBankID(bank) {
		// Reject an unknown bank without echoing any input back (deny-by-default).
		return shared.NewValidationError("bank", "unknown bank")
	}
	if _, err := s.tenants.FindTenantByID(ctx, tenantID); err != nil {
		return fmt.Errorf("resolve tenant: %w", err)
	}
	if err := assertClientIDUnclaimed(ctx, s.sharing, s.tenants, tenantID, bank, clientID); err != nil {
		return err
	}
	if err := s.credWriter.SetBankCredential(ctx, tenantID, bank, clientID, secret); err != nil {
		// Wrap with a non-sensitive context only; never include the secret.
		return fmt.Errorf("set bank credential: %w", err)
	}
	// Evict any cached OAuth2 token minted under the prior credential so the
	// rotation/revocation takes effect immediately instead of after the cached
	// bearer expires (token-revocation lag, ADR-0003). Best-effort and local; the
	// write has already committed and a missing cache entry is a no-op.
	s.credEvictor.InvalidateToken(tenantID)
	// Audit records who set a credential for which tenant AND which bank — the
	// bank id is a non-secret routing slug; the secret and client id are NEVER
	// recorded (threat C1/C4). The origin distinguishes the write surface.
	if err := s.recordCredentialAudit(ctx, tenantID, bank, selfServe); err != nil {
		return err
	}
	return nil
}

// recordCertificateAudit appends the audit entry for a per-bank mTLS certificate
// write. It carries the non-secret bankID and the certificate's public SHA-256
// fingerprint so the trail records WHICH certificate was provisioned, while still
// deriving the operator server-side and never recording the private key. The
// selfServe flag selects the origin the entry is stamped with (self-serve when the
// tenant self-provisioned its own certificate via the tenant-plane intake,
// SIN-69346; admin otherwise) — the sole difference between the two write surfaces
// at the trail. The append is fail-closed (an error surfaces rather than dropping
// the record).
func (s *AdminService) recordCertificateAudit(ctx context.Context, tenantID, bankID, fingerprint string, selfServe bool) error {
	build := audit.NewCertificateSetEntry
	if selfServe {
		build = audit.NewSelfServeCertificateSetEntry
	}
	e, err := build(s.ids.NewID(), OperatorIDFromContext(ctx), tenantID, bankID, fingerprint, s.clock.Now())
	if err != nil {
		return fmt.Errorf("build audit entry: %w", err)
	}
	if err := s.audit.Append(ctx, e); err != nil {
		return fmt.Errorf("append audit entry: %w", err)
	}
	return nil
}

// SetBankCertificate validates and stores a tenant's per-bank mTLS client
// certificate (SIN-66087), mirroring SetBankCredential. The bank must be known
// (deny-by-default; empty → default c6) and the tenant must exist. The PEM pair is
// parsed and validated server-side BEFORE it reaches the vault: a malformed
// certificate or key, a certificate already expired at upload (NotAfter < now), or
// a key that does not match the certificate are all rejected as a named
// ValidationError (HTTP 400), never a 500. A not-yet-valid certificate (NotBefore
// in the future) is accepted so an operator can pre-provision the next certificate
// for a rotation; the validity window is returned so the UI can badge it. On
// success ONLY the public metadata is returned (never the private key) and the
// write is audited by who/tenant/bank/fingerprint — the key is never logged,
// echoed or audited (threat C1/C4). The write reaches the LIVE transport: the
// eviction below drops the tenant's pooled TLS connections, so the new certificate
// is presented on the very next call instead of waiting out a restart.
func (s *AdminService) SetBankCertificate(ctx context.Context, tenantID, bank, certPEM, keyPEM string) (ports.BankCertificateMeta, error) {
	return s.setBankCertificate(ctx, tenantID, bank, certPEM, keyPEM, false)
}

// SetBankCertificateSelfServe stores an empresa-cliente's OWN per-bank mTLS client
// certificate through the self-serve intake (SIN-69346), mirroring
// SetBankCredentialSelfServe. It is byte-for-byte the same write as
// SetBankCertificate — same (tenant, bank) key, same parse/expiry/key-pair
// validation, same token-cache eviction, same never-leak-the-private-key guarantee
// — with two deliberate distinctions: (1) the HTTP boundary derives tenantID from
// the authenticated tenant context, NEVER from client input (so a token can only
// ever write its own certificate — the broken-access-control class A01 is designed
// out, there is no tenant selector to abuse); and (2) the audit entry is stamped
// origin=self-serve so the forensic trail separates a tenant self-provisioned
// certificate from an admin-driven write. The bank allow-list is enforced at the
// HTTP boundary (a dedicated self-serve allow-list, currently {c6}); this method
// re-validates the bank against the platform-wide known set as defense-in-depth,
// identically to the admin path.
func (s *AdminService) SetBankCertificateSelfServe(ctx context.Context, tenantID, bank, certPEM, keyPEM string) (ports.BankCertificateMeta, error) {
	return s.setBankCertificate(ctx, tenantID, bank, certPEM, keyPEM, true)
}

// setBankCertificate is the shared implementation behind the admin and self-serve
// certificate writes. selfServe selects only the audit origin; every port
// interaction (validate → parse → expiry-check → write → evict → audit) is
// identical, so the two surfaces can never diverge in what they validate, persist
// or evict.
func (s *AdminService) setBankCertificate(ctx context.Context, tenantID, bank, certPEM, keyPEM string, selfServe bool) (ports.BankCertificateMeta, error) {
	bank = ports.NormalizeBankID(bank)
	if !ports.IsKnownBankID(bank) {
		// Reject an unknown bank without echoing any input back (deny-by-default).
		return ports.BankCertificateMeta{}, shared.NewValidationError("bank", "unknown bank")
	}
	if _, err := s.tenants.FindTenantByID(ctx, tenantID); err != nil {
		return ports.BankCertificateMeta{}, fmt.Errorf("resolve tenant: %w", err)
	}
	// Parse + key-pair match BEFORE the vault: a bad cert/key never reaches storage
	// and the caller gets a precise 400, not a 500 (plan §7.1 c/d).
	cert, err := bankcert.Parse(certPEM, keyPEM)
	if err != nil {
		return ports.BankCertificateMeta{}, err
	}
	// Expiry-at-upload is a policy applied with the service clock; a not-yet-valid
	// cert is allowed (rotation pre-provisioning) and exposed via NotBefore.
	if cert.NotAfter.Before(s.clock.Now()) {
		return ports.BankCertificateMeta{}, shared.NewValidationError("cert_pem", "certificate is expired")
	}
	if err := s.certWriter.SetBankCertificate(ctx, ports.BankCertificate{
		TenantID: tenantID,
		BankID:   bank,
		CertPEM:  certPEM,
		KeyPEM:   keyPEM,
	}); err != nil {
		// Wrap with non-sensitive context only; never include key material.
		return ports.BankCertificateMeta{}, fmt.Errorf("set bank certificate: %w", err)
	}
	// Evict the tenant's cached token AND its pooled mTLS connections, so the
	// certificate just written is the one presented on the next handshake (ADR-0003,
	// SIN-69368). A pooled connection never re-runs GetClientCertificate: without this
	// the rotation would only take effect at the next restart.
	s.credEvictor.InvalidateToken(tenantID)
	if err := s.recordCertificateAudit(ctx, tenantID, bank, cert.FingerprintSHA256, selfServe); err != nil {
		return ports.BankCertificateMeta{}, err
	}
	return ports.BankCertificateMeta{
		TenantID:          tenantID,
		BankID:            bank,
		SubjectCN:         cert.SubjectCN,
		Issuer:            cert.Issuer,
		SerialNumber:      cert.SerialNumber,
		FingerprintSHA256: cert.FingerprintSHA256,
		NotBefore:         cert.NotBefore,
		NotAfter:          cert.NotAfter,
	}, nil
}

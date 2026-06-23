package app

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/ia-dev-sindireceita/payment/internal/domain/billing"
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
	tenants     TenantStore
	pricing     PricingStore
	ledger      LedgerReader
	credWriter  ports.CredentialWriter
	credEvictor ports.CredentialInvalidator
	clock       ports.Clock
	ids         ports.IDProvider
}

// TenantStore is the tenant capability the console needs: the foundation's
// persistence plus cross-tenant listing for the admin plane.
type TenantStore interface {
	SaveTenant(ctx context.Context, t *tenant.Tenant) error
	FindTenantByID(ctx context.Context, id string) (*tenant.Tenant, error)
	ListTenants(ctx context.Context) ([]*tenant.Tenant, error)
}

// PricingStore is the pricing capability the console needs.
type PricingStore interface {
	UpsertEndpointPrice(ctx context.Context, p billing.EndpointPricing) error
	ListEndpointPrices(ctx context.Context, tenantID string) ([]billing.EndpointPricing, error)
}

// LedgerReader is the read side of the billing ledger powering the consumption
// audit. Writes stay on the append-only path used by the charge/settlement flow.
type LedgerReader interface {
	ListLedgerEntries(ctx context.Context, tenantID string) ([]billing.LedgerEntry, error)
}

// ConsoleDeps bundles the console's dependencies. The fields reuse the same
// concrete adapters wired in Deps, narrowed to the console's ports.
type ConsoleDeps struct {
	Tenants    TenantStore
	Pricing    PricingStore
	Ledger     LedgerReader
	CredWriter ports.CredentialWriter
	// CredInvalidator evicts cached state keyed on a tenant's credential (the C6
	// OAuth2 token cache) right after a credential write, closing the
	// token-revocation lag (ADR-0003). Optional: nil degrades to a no-op.
	CredInvalidator ports.CredentialInvalidator
	Clock           ports.Clock
	IDs             ports.IDProvider
}

// NewConsoleService wires a ConsoleService from its dependencies. A nil
// CredInvalidator degrades to a no-op (the credential write still succeeds; only
// the cache-eviction step is skipped).
func NewConsoleService(d ConsoleDeps) *ConsoleService {
	ci := d.CredInvalidator
	if ci == nil {
		ci = noopCredInvalidator{}
	}
	return &ConsoleService{
		tenants:     d.Tenants,
		pricing:     d.Pricing,
		ledger:      d.Ledger,
		credWriter:  d.CredWriter,
		credEvictor: ci,
		clock:       d.Clock,
		ids:         d.IDs,
	}
}

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

// SuspendTenant deactivates a tenant (reversible). Returns the updated tenant.
func (s *ConsoleService) SuspendTenant(ctx context.Context, id string) (*tenant.Tenant, error) {
	return s.transition(ctx, id, (*tenant.Tenant).Deactivate)
}

// ActivateTenant re-enables a suspended tenant. Returns the updated tenant.
func (s *ConsoleService) ActivateTenant(ctx context.Context, id string) (*tenant.Tenant, error) {
	return s.transition(ctx, id, (*tenant.Tenant).Activate)
}

func (s *ConsoleService) transition(ctx context.Context, id string, apply func(*tenant.Tenant)) (*tenant.Tenant, error) {
	t, err := s.tenants.FindTenantByID(ctx, strings.TrimSpace(id))
	if err != nil {
		return nil, fmt.Errorf("find tenant: %w", err)
	}
	apply(t)
	if err := s.tenants.SaveTenant(ctx, t); err != nil {
		return nil, fmt.Errorf("save tenant: %w", err)
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
	if err := s.credWriter.SetBankCredential(ctx, tenantID, clientID, secret); err != nil {
		// Wrap with non-sensitive context only; never include the secret.
		return fmt.Errorf("set bank credential: %w", err)
	}
	// Evict any cached OAuth2 token minted under the prior credential so the
	// rotation/revocation takes effect immediately instead of after the cached
	// bearer expires (token-revocation lag, ADR-0003). Best-effort and local.
	s.credEvictor.InvalidateToken(strings.TrimSpace(tenantID))
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

// Consumption builds the per-endpoint consumption report for a tenant from its
// ledger. The ledger is authoritative for billing, so the audit is a pure
// aggregation of recorded events — never a value derived from mutable state. The
// tenant must exist so the screen 404s cleanly.
func (s *ConsoleService) Consumption(ctx context.Context, tenantID string) (ConsumptionReport, error) {
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

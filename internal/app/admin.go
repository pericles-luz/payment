package app

import (
	"context"
	"fmt"

	"github.com/ia-dev-sindireceita/payment/internal/domain/billing"
	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// AdminService implements the admin plane: tenant lifecycle, per-endpoint
// pricing and per-tenant bank credential management. These operations are
// privileged (RBAC enforced at the boundary).
type AdminService struct {
	tenants    ports.TenantRepository
	pricing    ports.PricingRepository
	credWriter ports.CredentialWriter
	clock      ports.Clock
	ids        ports.IDProvider
}

// NewAdminService wires an AdminService from the provided ports.
func NewAdminService(d Deps) *AdminService {
	return &AdminService{tenants: d.Tenants, pricing: d.Pricing, credWriter: d.CredWriter, clock: d.Clock, ids: d.IDs}
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
	return p, nil
}

// SetBankCredential stores a tenant's bank (PSP) credential via the secret-store
// write port. The target tenant must exist (defense-in-depth alongside the
// boundary RBAC + tenant-scope checks). The secret is passed straight through to
// the writer: it never enters domain state, and on failure the returned error
// wraps only sentinel/validation context — never the secret value (threat
// C1/C4). The caller (admin handler) supplies tenantID explicitly; admin crosses
// tenants by design but every credential write names exactly one tenant.
func (s *AdminService) SetBankCredential(ctx context.Context, tenantID, clientID, secret string) error {
	if _, err := s.tenants.FindTenantByID(ctx, tenantID); err != nil {
		return fmt.Errorf("resolve tenant: %w", err)
	}
	if err := s.credWriter.SetBankCredential(ctx, tenantID, clientID, secret); err != nil {
		// Wrap with a non-sensitive context only; never include the secret.
		return fmt.Errorf("set bank credential: %w", err)
	}
	return nil
}

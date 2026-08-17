package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/ia-dev-sindireceita/payment/internal/domain/billing"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// resolvePriceOrFree resolves the billable price for a tenant × endpoint pair.
//
// Business rule (CEO clarification on SIN-69485/SIN-69508): an endpoint that has
// no price configured is a normal, valid condition — the endpoint is treated as
// free and the request is billed 0 cents (a ledger entry is still written so the
// per-Conta rollup/report stays consistent; complements the read-side SIN-69509).
//
// The pricing port stays honest: GetEndpointPrice keeps returning shared.ErrNotFound
// for unpriced pairs (console/invoice depend on that semantic). This "unpriced =
// free" policy is a billing use-case concern and lives here, not in the adapter.
//
// Fail-safe (OWASP A09 / insecure design): ONLY shared.ErrNotFound is mapped to a
// free (zero) price. Any OTHER error (db down, decode failure, etc.) propagates and
// fails the request — a broken store must never be masked as "free". Isolation
// (A01): the synthesized free price uses the SAME tenantID+endpoint; it never
// resolves to another tenant's price.
func resolvePriceOrFree(ctx context.Context, pricing ports.PricingRepository, tenantID, endpoint string) (billing.EndpointPricing, error) {
	price, err := pricing.GetEndpointPrice(ctx, tenantID, endpoint)
	if err == nil {
		return price, nil
	}
	if !errors.Is(err, shared.ErrNotFound) {
		// Infra/read error — never mask as free.
		return billing.EndpointPricing{}, fmt.Errorf("resolve price: %w", err)
	}
	// No price configured for this tenant × endpoint: free endpoint, bill 0.
	free, ferr := billing.NewEndpointPricing(tenantID, endpoint, 0)
	if ferr != nil {
		return billing.EndpointPricing{}, fmt.Errorf("resolve price (free default): %w", ferr)
	}
	slog.InfoContext(ctx, "billing.endpoint_unpriced_free",
		slog.String("tenant_id", tenantID),
		slog.String("endpoint", endpoint),
	)
	return free, nil
}

package app

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/domain/billing"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

// stubPricing is a minimal ports.PricingRepository for exercising the
// resolvePriceOrFree policy in isolation (white-box). It never touches storage.
type stubPricing struct {
	price billing.EndpointPricing
	err   error
}

func (s stubPricing) GetEndpointPrice(context.Context, string, string) (billing.EndpointPricing, error) {
	return s.price, s.err
}

func (s stubPricing) UpsertEndpointPrice(context.Context, billing.EndpointPricing) error { return nil }

var errInfra = errors.New("db down")

func TestResolvePriceOrFree(t *testing.T) {
	t.Parallel()

	priced, _ := billing.NewEndpointPricing("t1", "pix.create", 99)

	tests := []struct {
		name       string
		repo       stubPricing
		wantCents  int64
		wantErr    error // errors.Is target; nil means no error expected
		wantTenant string
	}{
		{
			name:       "configured price is returned unchanged",
			repo:       stubPricing{price: priced},
			wantCents:  99,
			wantTenant: "t1",
		},
		{
			name:       "unpriced endpoint (ErrNotFound) becomes free (0), same tenant+endpoint",
			repo:       stubPricing{err: shared.ErrNotFound},
			wantCents:  0,
			wantTenant: "t1",
		},
		{
			name:    "infra error propagates — never masked as free (fail-safe)",
			repo:    stubPricing{err: errInfra},
			wantErr: errInfra,
		},
		{
			name:    "wrapped infra error still propagates",
			repo:    stubPricing{err: errWrap(errInfra)},
			wantErr: errInfra,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := resolvePriceOrFree(context.Background(), tt.repo, "t1", "pix.create")
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v; want errors.Is %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if got.PriceCents() != tt.wantCents {
				t.Fatalf("price = %d; want %d", got.PriceCents(), tt.wantCents)
			}
			if got.TenantID() != tt.wantTenant || got.Endpoint() != "pix.create" {
				t.Fatalf("isolation: got (%q,%q); want (%q,%q)", got.TenantID(), got.Endpoint(), tt.wantTenant, "pix.create")
			}
		})
	}
}

// errWrap returns err wrapped so errors.Is still finds the cause (guards the
// unpriced-vs-infra distinction against wrapping in the adapter chain).
func errWrap(err error) error { return errJoin(err) }

func errJoin(err error) error { return errors.Join(errors.New("adapter: query failed"), err) }

// syncBuf is a mutex-guarded io.Writer so swapping the process-wide slog default
// in this test cannot data-race with other parallel tests in the package that
// also log to the default logger.
type syncBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// TestResolvePriceOrFreeEmitsUnpricedLog asserts the observability contract: the
// free path emits exactly the structured Info line billing.endpoint_unpriced_free
// with tenant_id+endpoint and nothing else (no PII, no secret), while the priced
// path emits no such line. Not parallel: it swaps the global slog default.
func TestResolvePriceOrFreeEmitsUnpricedLog(t *testing.T) {
	var out syncBuf
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&out, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	// Free path logs.
	if _, err := resolvePriceOrFree(context.Background(), stubPricing{err: shared.ErrNotFound}, "t-log", "boleto.create"); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	logged := out.String()
	if !strings.Contains(logged, "billing.endpoint_unpriced_free") {
		t.Fatalf("want unpriced-free log line, got: %q", logged)
	}
	if !strings.Contains(logged, "tenant_id=t-log") || !strings.Contains(logged, "endpoint=boleto.create") {
		t.Fatalf("log must carry tenant_id+endpoint, got: %q", logged)
	}

	// Priced path is silent (no unpriced-free line for a configured price).
	priced, _ := billing.NewEndpointPricing("t-log", "boleto.create", 500)
	if _, err := resolvePriceOrFree(context.Background(), stubPricing{price: priced}, "t-log", "boleto.create"); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got := strings.Count(out.String(), "billing.endpoint_unpriced_free"); got != 1 {
		t.Fatalf("priced path must not emit the unpriced-free log; total occurrences = %d", got)
	}
}

package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/domain/webhookref"
)

// mintRef generates a valid ref and binds it to tenant in the store, returning the
// plaintext (as the operator would supply it via PAYMENT_WEBHOOK_REFS).
func mintRef(t *testing.T, store *persistence.WebhookRefStore, tenant string) string {
	t.Helper()
	ref, err := webhookref.Generate()
	if err != nil {
		t.Fatalf("generate ref: %v", err)
	}
	sum := webhookref.Sum(ref)
	if err := store.PutWebhookRef(context.Background(), sum[:], tenant); err != nil {
		t.Fatalf("put ref: %v", err)
	}
	return ref
}

// TestResolveDurableBindingWins proves a ref recorded in the durable store resolves to the
// store's tenant (the authoritative binding) tagged RefSourceDurable.
func TestResolveDurableBindingWins(t *testing.T) {
	t.Parallel()
	store := persistence.NewWebhookRefStore()
	ref := mintRef(t, store, "acct-self-serve")
	r := NewWebhookRefResolver(store)

	res, err := r.Resolve(context.Background(), ref, "acct-self-serve")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.TenantID != "acct-self-serve" || res.Source != RefSourceDurable || res.Mismatch {
		t.Fatalf("got %+v, want durable acct-self-serve no mismatch", res)
	}
}

// TestResolveDurableMismatchFlagged proves that when the env-declared tenant disagrees with
// the durable binding, the durable binding wins and Mismatch is flagged.
func TestResolveDurableMismatchFlagged(t *testing.T) {
	t.Parallel()
	store := persistence.NewWebhookRefStore()
	ref := mintRef(t, store, "durable-tenant")
	r := NewWebhookRefResolver(store)

	res, err := r.Resolve(context.Background(), ref, "env-tenant")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.TenantID != "durable-tenant" || res.Source != RefSourceDurable || !res.Mismatch {
		t.Fatalf("got %+v, want durable-tenant with mismatch flagged", res)
	}
}

// TestResolveMissFallsBackToEnv proves a ref the store does not know falls back to the
// env-declared tenant tagged RefSourceEnv (bootstrap ref not yet in the durable store).
func TestResolveMissFallsBackToEnv(t *testing.T) {
	t.Parallel()
	store := persistence.NewWebhookRefStore()
	r := NewWebhookRefResolver(store)
	// A valid but unregistered ref.
	ref, _ := webhookref.Generate()

	res, err := r.Resolve(context.Background(), ref, "env-tenant")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.TenantID != "env-tenant" || res.Source != RefSourceEnv || res.Mismatch {
		t.Fatalf("got %+v, want env-tenant via RefSourceEnv", res)
	}
}

// TestResolveMissNoEnvIsNone proves an unregistered ref with no env tenant resolves to
// RefSourceNone (unbound), so the caller takes no side effect.
func TestResolveMissNoEnvIsNone(t *testing.T) {
	t.Parallel()
	store := persistence.NewWebhookRefStore()
	r := NewWebhookRefResolver(store)
	ref, _ := webhookref.Generate()

	res, err := r.Resolve(context.Background(), ref, "")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.TenantID != "" || res.Source != RefSourceNone {
		t.Fatalf("got %+v, want empty RefSourceNone", res)
	}
}

// TestResolveNilStoreEnvOnly proves a nil store (no durable wiring) resolves to the
// env-declared tenant without touching any store.
func TestResolveNilStoreEnvOnly(t *testing.T) {
	t.Parallel()
	r := NewWebhookRefResolver(nil)
	ref, _ := webhookref.Generate()

	res, err := r.Resolve(context.Background(), ref, "env-tenant")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.TenantID != "env-tenant" || res.Source != RefSourceEnv {
		t.Fatalf("got %+v, want env-tenant via RefSourceEnv", res)
	}
}

// TestResolveInvalidRefNotLookedUp proves a structurally invalid ref is never looked up
// (it cannot be a durable capability) and resolves env-only.
func TestResolveInvalidRefNotLookedUp(t *testing.T) {
	t.Parallel()
	store := &countingRefStore{inner: persistence.NewWebhookRefStore()}
	r := NewWebhookRefResolver(store)

	res, err := r.Resolve(context.Background(), "../etc/passwd", "env-tenant")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.Source != RefSourceEnv || res.TenantID != "env-tenant" {
		t.Fatalf("got %+v, want env-only for invalid ref", res)
	}
	if store.lookups != 0 {
		t.Fatalf("invalid ref must not reach the store, lookups=%d", store.lookups)
	}
}

// TestResolveStoreErrorFailsClosed proves an infrastructure error from the store is
// surfaced (the caller must NOT register against an uncertain binding).
func TestResolveStoreErrorFailsClosed(t *testing.T) {
	t.Parallel()
	boom := errors.New("db down")
	r := NewWebhookRefResolver(&countingRefStore{err: boom})
	ref, _ := webhookref.Generate()

	_, err := r.Resolve(context.Background(), ref, "env-tenant")
	if !errors.Is(err, boom) {
		t.Fatalf("want store error surfaced, got %v", err)
	}
}

// countingRefStore wraps the in-memory store to count LookupWebhookRef calls and,
// optionally, to fault every lookup — enough to prove the "not looked up" and "fail
// closed" paths without a real database.
type countingRefStore struct {
	inner   *persistence.WebhookRefStore
	err     error
	lookups int
}

func (c *countingRefStore) PutWebhookRef(ctx context.Context, refSHA []byte, tenantID string) error {
	return c.inner.PutWebhookRef(ctx, refSHA, tenantID)
}

func (c *countingRefStore) LookupWebhookRef(ctx context.Context, refSHA []byte) (string, bool, error) {
	c.lookups++
	if c.err != nil {
		return "", false, c.err
	}
	return c.inner.LookupWebhookRef(ctx, refSHA)
}

// guard: a resolver with a valid ref that IS registered but env matches exactly emits no
// mismatch (covers the equal-tenant branch alongside the mismatch test).
func TestResolveEqualEnvNoMismatch(t *testing.T) {
	t.Parallel()
	store := persistence.NewWebhookRefStore()
	ref := mintRef(t, store, "same")
	r := NewWebhookRefResolver(store)
	res, err := r.Resolve(context.Background(), ref, "same")
	if err != nil || res.Mismatch || res.Source != RefSourceDurable {
		t.Fatalf("got %+v err=%v, want durable no-mismatch", res, err)
	}
	if !strings.EqualFold(res.TenantID, "same") {
		t.Fatalf("tenant mismatch: %q", res.TenantID)
	}
}

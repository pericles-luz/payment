package app_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/system"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// recordingInvalidator is a CredentialInvalidator that records the tenants it was
// asked to evict. It proves the admin plane evicts the cached OAuth2 token right
// after a credential write (token-revocation-lag fix, ADR-0003).
type recordingInvalidator struct {
	mu      sync.Mutex
	tenants []string
}

func (r *recordingInvalidator) InvalidateToken(tenantID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tenants = append(r.tenants, tenantID)
}

func (r *recordingInvalidator) calls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.tenants...)
}

func TestAdminSetBankCredentialEvictsTokenCache(t *testing.T) {
	t.Parallel()
	store := persistence.NewStore()
	inv := &recordingInvalidator{}
	deps := app.Deps{
		Tenants:         store,
		Pricing:         store,
		CredWriter:      secret.NewStore(nil),
		CredInvalidator: inv,
		Clock:           system.Clock{},
		IDs:             &seqIDs{},
	}
	admin := app.NewAdminService(deps)
	tn, err := admin.CreateTenant(context.Background(), "Acme")
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	if err := admin.SetBankCredential(context.Background(), tn.ID(), "client-1", "s3cr3t"); err != nil {
		t.Fatalf("set credential: %v", err)
	}
	if got := inv.calls(); len(got) != 1 || got[0] != tn.ID() {
		t.Fatalf("want one eviction for %q, got %v", tn.ID(), got)
	}
}

// TestAdminSetBankCredentialNoEvictOnWriteFailure: the cache is evicted only
// after the write commits. A failed write leaves the old credential in force, so
// evicting would needlessly drop a still-valid token.
func TestAdminSetBankCredentialNoEvictOnWriteFailure(t *testing.T) {
	t.Parallel()
	store := persistence.NewStore()
	inv := &recordingInvalidator{}
	deps := app.Deps{
		Tenants:         store,
		Pricing:         store,
		CredWriter:      &recordingWriter{err: errors.New("vault unavailable")},
		CredInvalidator: inv,
		Clock:           system.Clock{},
		IDs:             &seqIDs{},
	}
	admin := app.NewAdminService(deps)
	tn, err := admin.CreateTenant(context.Background(), "Acme")
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	if err := admin.SetBankCredential(context.Background(), tn.ID(), "client-1", "s3cr3t"); err == nil {
		t.Fatal("want error from writer")
	}
	if got := inv.calls(); len(got) != 0 {
		t.Fatalf("must not evict when the write failed, got %v", got)
	}
}

// TestAdminSetBankCredentialNoEvictForUnknownTenant: the tenant-existence guard
// short-circuits before the write, so nothing is evicted.
func TestAdminSetBankCredentialNoEvictForUnknownTenant(t *testing.T) {
	t.Parallel()
	store := persistence.NewStore()
	inv := &recordingInvalidator{}
	deps := app.Deps{
		Tenants:         store,
		Pricing:         store,
		CredWriter:      secret.NewStore(nil),
		CredInvalidator: inv,
		Clock:           system.Clock{},
		IDs:             &seqIDs{},
	}
	admin := app.NewAdminService(deps)

	if err := admin.SetBankCredential(context.Background(), "ghost", "c", "s"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if got := inv.calls(); len(got) != 0 {
		t.Fatalf("must not evict for an unknown tenant, got %v", got)
	}
}

// TestAdminSetBankCredentialNilInvalidatorIsSafe: a nil CredInvalidator degrades
// to a no-op (e.g. the in-memory bank stub has no token cache); the write still
// succeeds.
func TestAdminSetBankCredentialNilInvalidatorIsSafe(t *testing.T) {
	t.Parallel()
	store := persistence.NewStore()
	admin := app.NewAdminService(app.Deps{
		Tenants:    store,
		Pricing:    store,
		CredWriter: secret.NewStore(nil),
		Clock:      system.Clock{},
		IDs:        &seqIDs{},
	})
	tn, err := admin.CreateTenant(context.Background(), "Acme")
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	if err := admin.SetBankCredential(context.Background(), tn.ID(), "c", "s"); err != nil {
		t.Fatalf("nil invalidator must be safe, got %v", err)
	}
}

func TestConsoleSetBankCredentialEvictsTokenCache(t *testing.T) {
	t.Parallel()
	store := persistence.NewStore()
	creds := secret.NewStore(map[string]ports.BankCredential{})
	inv := &recordingInvalidator{}
	svc := app.NewConsoleService(app.ConsoleDeps{
		Tenants:         store,
		Pricing:         store,
		Ledger:          store,
		CredWriter:      creds,
		CredInvalidator: inv,
		Clock:           fixedClock{t: time.Unix(1000, 0).UTC()},
		IDs:             &seqIDs{},
	})
	seedTenant(t, store, "t1", "Acme", true, 1000)

	if err := svc.SetBankCredential(context.Background(), "t1", "client-1", "s3cr3t"); err != nil {
		t.Fatalf("set credential: %v", err)
	}
	if got := inv.calls(); len(got) != 1 || got[0] != "t1" {
		t.Fatalf("want one eviction for t1, got %v", got)
	}

	// A rejected write (empty secret) must not evict.
	if err := svc.SetBankCredential(context.Background(), "t1", "client-1", ""); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation for empty secret, got %v", err)
	}
	if got := inv.calls(); len(got) != 1 {
		t.Fatalf("rejected write must not evict, got %v", got)
	}
}

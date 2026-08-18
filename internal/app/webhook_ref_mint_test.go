package app

import (
	"context"
	"errors"
	"testing"

	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/domain/webhookref"
)

// TestMintWebhookRefPersistsHashReturnsPlaintext proves the mint returns a well-formed
// plaintext ONCE and persists only its hash — the returned ref resolves through the
// store to the tenant, and the store round-trips on the SAME hash.
func TestMintWebhookRefPersistsHashReturnsPlaintext(t *testing.T) {
	t.Parallel()
	store := persistence.NewWebhookRefStore()
	svc := NewWebhookRefMintService(store)

	ref, err := svc.MintWebhookRef(context.Background(), "tenant-1")
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if !webhookref.Valid(ref) {
		t.Fatalf("minted ref is not well-formed: %q", ref)
	}
	sum := webhookref.Sum(ref)
	got, ok, err := store.LookupWebhookRef(context.Background(), sum[:])
	if err != nil || !ok || got != "tenant-1" {
		t.Fatalf("lookup minted ref = (%q, %v, %v), want (tenant-1, true, nil)", got, ok, err)
	}
}

// TestMintWebhookRefNilStoreFailsClosed proves a service with no store cannot mint —
// it returns an error rather than silently handing back a ref the store never saw.
func TestMintWebhookRefNilStoreFailsClosed(t *testing.T) {
	t.Parallel()
	svc := NewWebhookRefMintService(nil)
	if _, err := svc.MintWebhookRef(context.Background(), "tenant-1"); err == nil {
		t.Fatal("mint with a nil store must fail closed")
	}
	// A nil receiver is also safe (defensive).
	var nilSvc *WebhookRefMintService
	if _, err := nilSvc.MintWebhookRef(context.Background(), "tenant-1"); err == nil {
		t.Fatal("mint on a nil service must fail closed")
	}
}

// TestMintWebhookRefStoreErrorPropagates proves a persistence fault surfaces (and the
// plaintext is NOT returned — a caller must never surface a ref the store rejected).
func TestMintWebhookRefStoreErrorPropagates(t *testing.T) {
	t.Parallel()
	svc := NewWebhookRefMintService(faultyRefStore{})
	ref, err := svc.MintWebhookRef(context.Background(), "tenant-1")
	if err == nil {
		t.Fatal("a store fault must surface as an error")
	}
	if ref != "" {
		t.Fatalf("no ref must be returned on a store fault, got %q", ref)
	}
}

// faultyRefStore fails every Put (models a persistence fault).
type faultyRefStore struct{}

func (faultyRefStore) PutWebhookRef(context.Context, []byte, string) error {
	return errors.New("boom")
}

func (faultyRefStore) LookupWebhookRef(context.Context, []byte) (string, bool, error) {
	return "", false, nil
}

// TestProvisionClientWithWebhookMintsOnCreate proves the webhook variant returns a
// durable ref on a genuine create and that the ref resolves to the new tenant.
func TestProvisionClientWithWebhookMintsOnCreate(t *testing.T) {
	t.Parallel()
	store := persistence.NewStore()
	refStore := persistence.NewWebhookRefStore()
	svc := NewClientProvisioningService(store, &seqIDs{}, &akClock{now: akEpoch()}).
		WithWebhookRefMinter(NewWebhookRefMintService(refStore))

	cli, ref, err := svc.ProvisionClientWithWebhook(context.Background(), "acct-A", "Loja X", "idem-1")
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if ref == "" || !webhookref.Valid(ref) {
		t.Fatalf("expected a well-formed webhook ref, got %q", ref)
	}
	sum := webhookref.Sum(ref)
	got, ok, err := refStore.LookupWebhookRef(context.Background(), sum[:])
	if err != nil || !ok || got != cli.ID() {
		t.Fatalf("minted ref resolves to (%q, %v, %v), want (%s, true, nil)", got, ok, err, cli.ID())
	}
}

// TestProvisionClientWithWebhookReplayOmitsRef proves display-once semantics: an
// idempotent replay returns the SAME empresa-cliente but NO ref (the first response
// carried it, and only the hash is stored).
func TestProvisionClientWithWebhookReplayOmitsRef(t *testing.T) {
	t.Parallel()
	store := persistence.NewStore()
	refStore := persistence.NewWebhookRefStore()
	svc := NewClientProvisioningService(store, &seqIDs{}, &akClock{now: akEpoch()}).
		WithWebhookRefMinter(NewWebhookRefMintService(refStore))
	ctx := context.Background()

	first, ref1, err := svc.ProvisionClientWithWebhook(ctx, "acct-A", "Loja X", "idem-1")
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	replay, ref2, err := svc.ProvisionClientWithWebhook(ctx, "acct-A", "Loja Y", "idem-1")
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if replay.ID() != first.ID() {
		t.Fatalf("replay created a different tenant: %s vs %s", replay.ID(), first.ID())
	}
	if ref1 == "" {
		t.Fatal("first call must return a ref")
	}
	if ref2 != "" {
		t.Fatalf("replay must NOT return a ref (display-once), got %q", ref2)
	}
}

// TestProvisionClientWithWebhookNoMinterOmitsRef proves the variant degrades cleanly
// when no minter is wired: the client is created, the ref is empty.
func TestProvisionClientWithWebhookNoMinterOmitsRef(t *testing.T) {
	t.Parallel()
	store := persistence.NewStore()
	svc := NewClientProvisioningService(store, &seqIDs{}, &akClock{now: akEpoch()})

	cli, ref, err := svc.ProvisionClientWithWebhook(context.Background(), "acct-A", "Loja X", "idem-1")
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if cli == nil || ref != "" {
		t.Fatalf("no minter: want (client, ''), got (%v, %q)", cli, ref)
	}
}

// TestProvisionClientWithWebhookMintFailureDoesNotPoisonIdemKey proves a mint fault
// surfaces AND leaves the idempotency key un-recorded, so a retry re-provisions (a new
// tenant) rather than replaying a ref-less client.
func TestProvisionClientWithWebhookMintFailureDoesNotPoisonIdemKey(t *testing.T) {
	t.Parallel()
	store := persistence.NewStore()
	svc := NewClientProvisioningService(store, &seqIDs{}, &akClock{now: akEpoch()}).
		WithWebhookRefMinter(NewWebhookRefMintService(faultyRefStore{}))
	ctx := context.Background()

	if _, _, err := svc.ProvisionClientWithWebhook(ctx, "acct-A", "x", "idem-1"); err == nil {
		t.Fatal("mint fault must surface")
	}
	// The idem key was NOT recorded: a retry runs the create path again (a fresh tenant),
	// not a replay of a ref-less client. Wire a WORKING minter for the retry.
	refStore := persistence.NewWebhookRefStore()
	svc.WithWebhookRefMinter(NewWebhookRefMintService(refStore))
	cli, ref, err := svc.ProvisionClientWithWebhook(ctx, "acct-A", "x", "idem-1")
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if ref == "" {
		t.Fatal("retry after a mint fault must mint a fresh ref (idem key was not poisoned)")
	}
	sum := webhookref.Sum(ref)
	if got, ok, _ := refStore.LookupWebhookRef(ctx, sum[:]); !ok || got != cli.ID() {
		t.Fatalf("retry ref resolves to %q, want %s", got, cli.ID())
	}
}

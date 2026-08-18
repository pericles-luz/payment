package secret_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// stubStore is a minimal ports.CredentialStore whose GetBankCredential returns a fixed
// credential or a fixed error, so the fallback semantics can be exercised without a real
// vault. It also records the (tenant, bank) pairs it was queried with, to prove the
// composite passes the lookup through unchanged (no widening).
type stubStore struct {
	cred    ports.BankCredential
	err     error
	queried []string
}

func (s *stubStore) GetBankCredential(_ context.Context, tenantID, bankID string) (ports.BankCredential, error) {
	s.queried = append(s.queried, tenantID+"/"+bankID)
	if s.err != nil {
		return ports.BankCredential{}, s.err
	}
	return s.cred, nil
}

// TestFallbackPrimaryHitSkipsSecondary proves a credential present in the primary is
// answered from the primary and the secondary is never consulted (dedup by construction).
func TestFallbackPrimaryHitSkipsSecondary(t *testing.T) {
	t.Parallel()
	primary := &stubStore{cred: ports.BankCredential{TenantID: "t1", CreditorKey: "prim@pix"}}
	secondary := &stubStore{cred: ports.BankCredential{TenantID: "t1", CreditorKey: "sec@pix"}}
	fb := secret.NewFallbackStore(primary, secondary)

	got, err := fb.GetBankCredential(context.Background(), "t1", ports.BankIDC6)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.CreditorKey != "prim@pix" {
		t.Fatalf("want primary key, got %q", got.CreditorKey)
	}
	if len(secondary.queried) != 0 {
		t.Fatalf("secondary must not be consulted on a primary hit, queried=%v", secondary.queried)
	}
	if len(primary.queried) != 1 || primary.queried[0] != "t1/c6" {
		t.Fatalf("primary should be queried once with the exact pair, got %v", primary.queried)
	}
}

// TestFallbackPrimaryMissFallsThrough proves a primary ErrNotFound falls through to the
// secondary (the env-bootstrap tenant resolves via the fallback).
func TestFallbackPrimaryMissFallsThrough(t *testing.T) {
	t.Parallel()
	primary := &stubStore{err: shared.ErrNotFound}
	secondary := &stubStore{cred: ports.BankCredential{TenantID: "t1", CreditorKey: "sec@pix"}}
	fb := secret.NewFallbackStore(primary, secondary)

	got, err := fb.GetBankCredential(context.Background(), "t1", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.CreditorKey != "sec@pix" {
		t.Fatalf("want secondary key on primary miss, got %q", got.CreditorKey)
	}
}

// TestFallbackPrimaryFaultFailsClosed proves a NON-ErrNotFound primary error is surfaced
// unchanged and the secondary is NOT consulted — the command must fail closed on an
// infrastructure fault rather than silently read a stale env value.
func TestFallbackPrimaryFaultFailsClosed(t *testing.T) {
	t.Parallel()
	boom := errors.New("decrypt failure")
	primary := &stubStore{err: boom}
	secondary := &stubStore{cred: ports.BankCredential{CreditorKey: "sec@pix"}}
	fb := secret.NewFallbackStore(primary, secondary)

	_, err := fb.GetBankCredential(context.Background(), "t1", ports.BankIDC6)
	if !errors.Is(err, boom) {
		t.Fatalf("want the primary fault surfaced, got %v", err)
	}
	if len(secondary.queried) != 0 {
		t.Fatalf("secondary must not be consulted after a primary fault, queried=%v", secondary.queried)
	}
}

// TestFallbackNilPrimaryDelegates proves a nil primary delegates straight to the secondary
// (the plain env-only path when no vault is configured).
func TestFallbackNilPrimaryDelegates(t *testing.T) {
	t.Parallel()
	secondary := &stubStore{cred: ports.BankCredential{CreditorKey: "sec@pix"}}
	fb := secret.NewFallbackStore(nil, secondary)

	got, err := fb.GetBankCredential(context.Background(), "t1", ports.BankIDC6)
	if err != nil || got.CreditorKey != "sec@pix" {
		t.Fatalf("nil primary should delegate to secondary, got (%q, %v)", got.CreditorKey, err)
	}
}

// TestFallbackNilSecondaryMiss proves a primary miss with a nil secondary returns
// ErrNotFound (no oracle, no panic).
func TestFallbackNilSecondaryMiss(t *testing.T) {
	t.Parallel()
	primary := &stubStore{err: shared.ErrNotFound}
	fb := secret.NewFallbackStore(primary, nil)

	_, err := fb.GetBankCredential(context.Background(), "t1", ports.BankIDC6)
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

// TestFallbackBothNil proves the degenerate all-nil composite is a safe ErrNotFound.
func TestFallbackBothNil(t *testing.T) {
	t.Parallel()
	fb := secret.NewFallbackStore(nil, nil)
	if _, err := fb.GetBankCredential(context.Background(), "t1", ""); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want ErrNotFound from all-nil composite, got %v", err)
	}
}

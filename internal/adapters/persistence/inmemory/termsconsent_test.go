package inmemory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/domain/termsconsent"
)

func mustConsent(t *testing.T, id, tenant, subject, version, channel, ip, ua string, at time.Time) *termsconsent.Record {
	t.Helper()
	e, err := termsconsent.NewEvidence(channel, ip, ua)
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	r, err := termsconsent.NewRecord(termsconsent.NewRecordParams{
		ID: id, TenantID: tenant, Subject: subject, TermsVersion: version, Evidence: e,
	}, at)
	if err != nil {
		t.Fatalf("NewRecord: %v", err)
	}
	return r
}

func TestInMemoryConsentRoundTripAndLatest(t *testing.T) {
	s := inmemory.NewStore()
	ctx := context.Background()
	t1 := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 7, 10, 8, 0, 0, 0, time.UTC)

	if err := s.RecordConsent(ctx, mustConsent(t, "c1", "tenant-a", "user-42", "v1", "web", "1.1.1.1", "B1", t1)); err != nil {
		t.Fatalf("record c1: %v", err)
	}
	if err := s.RecordConsent(ctx, mustConsent(t, "c2", "tenant-a", "user-42", "v1", "mobile", "2.2.2.2", "B2", t2)); err != nil {
		t.Fatalf("record c2: %v", err)
	}

	got, err := s.FindLatestConsent(ctx, "tenant-a", "user-42", "v1")
	if err != nil {
		t.Fatalf("FindLatestConsent: %v", err)
	}
	if got.ID() != "c2" || got.Evidence().Channel() != "mobile" {
		t.Fatalf("latest wrong: %+v", got)
	}

	list, err := s.ListConsents(ctx, "tenant-a", "user-42")
	if err != nil {
		t.Fatalf("ListConsents: %v", err)
	}
	if len(list) != 2 || list[0].ID() != "c2" || list[1].ID() != "c1" {
		t.Fatalf("history wrong: %+v", list)
	}
	// Original preserved (append-only, no overwrite).
	if list[1].Evidence().Channel() != "web" || !list[1].GrantedAt().Equal(t1) {
		t.Fatalf("original mutated: %+v", list[1])
	}
}

func TestInMemoryConsentNotFoundAndIsolation(t *testing.T) {
	s := inmemory.NewStore()
	ctx := context.Background()
	at := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	if err := s.RecordConsent(ctx, mustConsent(t, "c1", "tenant-a", "user-42", "v1", "api", "", "", at)); err != nil {
		t.Fatalf("record: %v", err)
	}
	if _, err := s.FindLatestConsent(ctx, "tenant-a", "user-42", "missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if _, err := s.FindLatestConsent(ctx, "tenant-b", "user-42", "v1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant: want ErrNotFound, got %v", err)
	}
	list, err := s.ListConsents(ctx, "tenant-b", "user-42")
	if err != nil {
		t.Fatalf("ListConsents: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("cross-tenant list leaked %d", len(list))
	}
}

// TestInMemoryConsentTieBreakByID confirms the newest-first ordering falls back
// to a deterministic id-descending tie-break when two consents share an instant,
// matching the SQLite adapter's "ORDER BY granted_at DESC, id DESC".
func TestInMemoryConsentTieBreakByID(t *testing.T) {
	s := inmemory.NewStore()
	ctx := context.Background()
	at := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	// Same instant → id descending is the deterministic tie-break.
	if err := s.RecordConsent(ctx, mustConsent(t, "aaa", "tenant-a", "user-1", "v1", "api", "", "", at)); err != nil {
		t.Fatalf("record aaa: %v", err)
	}
	if err := s.RecordConsent(ctx, mustConsent(t, "zzz", "tenant-a", "user-1", "v1", "api", "", "", at)); err != nil {
		t.Fatalf("record zzz: %v", err)
	}
	got, err := s.FindLatestConsent(ctx, "tenant-a", "user-1", "v1")
	if err != nil {
		t.Fatalf("FindLatestConsent: %v", err)
	}
	if got.ID() != "zzz" {
		t.Fatalf("tie-break wrong: got %s, want zzz", got.ID())
	}
	list, _ := s.ListConsents(ctx, "tenant-a", "user-1")
	if list[0].ID() != "zzz" || list[1].ID() != "aaa" {
		t.Fatalf("list tie-break wrong: %+v", list)
	}
}

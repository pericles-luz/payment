package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/postgres"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/domain/termsconsent"
	migrations "github.com/ia-dev-sindireceita/payment/migrations/pg"
)

func newConsentStore(t *testing.T) *postgres.Store {
	t.Helper()
	dsn := testDSN(t)
	db, err := postgres.Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := postgres.Migrate(context.Background(), db, migrations.FS); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return postgres.NewStore(db)
}

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

func TestPostgresConsentRoundTrip(t *testing.T) {
	s := newConsentStore(t)
	ctx := context.Background()
	at := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	rec := mustConsent(t, "cns_1", "tenant-a", "user-42", "2026-07-01", "web-console", "203.0.113.7", "Mozilla/5.0", at)

	if err := s.RecordConsent(ctx, rec); err != nil {
		t.Fatalf("RecordConsent: %v", err)
	}

	got, err := s.FindLatestConsent(ctx, "tenant-a", "user-42", "2026-07-01")
	if err != nil {
		t.Fatalf("FindLatestConsent: %v", err)
	}
	if got.ID() != "cns_1" || got.Subject() != "user-42" || got.TermsVersion() != "2026-07-01" {
		t.Fatalf("unexpected record: %+v", got)
	}
	if !got.GrantedAt().Equal(at) {
		t.Fatalf("granted_at = %v, want %v", got.GrantedAt(), at)
	}
	if got.Evidence().Channel() != "web-console" || got.Evidence().IP() != "203.0.113.7" ||
		got.Evidence().UserAgent() != "Mozilla/5.0" {
		t.Fatalf("evidence not persisted: %+v", got.Evidence())
	}
}

func TestPostgresConsentNotFound(t *testing.T) {
	s := newConsentStore(t)
	ctx := context.Background()
	if _, err := s.FindLatestConsent(ctx, "tenant-a", "nobody", "v1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

// TestPostgresConsentTenantIsolation proves one tenant can never read another's
// consent — the same (subject, version) owned by tenant-a is invisible to
// tenant-b (threat P1, no cross-tenant oracle).
func TestPostgresConsentTenantIsolation(t *testing.T) {
	s := newConsentStore(t)
	ctx := context.Background()
	at := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	if err := s.RecordConsent(ctx, mustConsent(t, "cns_1", "tenant-a", "user-42", "v1", "api", "", "", at)); err != nil {
		t.Fatalf("RecordConsent: %v", err)
	}
	if _, err := s.FindLatestConsent(ctx, "tenant-b", "user-42", "v1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant read: want ErrNotFound, got %v", err)
	}
	list, err := s.ListConsents(ctx, "tenant-b", "user-42")
	if err != nil {
		t.Fatalf("ListConsents: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("cross-tenant list leaked %d rows", len(list))
	}
}

// TestPostgresConsentAppendOnlyImmutable is the acceptance proof: re-consent to the
// SAME (tenant, subject, version) with different evidence and a later time does
// NOT overwrite the prior capture — both rows survive, the original's evidence is
// unchanged, and FindLatest returns the newest.
func TestPostgresConsentAppendOnlyImmutable(t *testing.T) {
	s := newConsentStore(t)
	ctx := context.Background()
	t1 := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 7, 10, 8, 30, 0, 0, time.UTC)

	first := mustConsent(t, "cns_1", "tenant-a", "user-42", "v1", "web-console", "203.0.113.7", "FirstBrowser", t1)
	second := mustConsent(t, "cns_2", "tenant-a", "user-42", "v1", "mobile", "198.51.100.9", "SecondApp", t2)
	if err := s.RecordConsent(ctx, first); err != nil {
		t.Fatalf("record first: %v", err)
	}
	if err := s.RecordConsent(ctx, second); err != nil {
		t.Fatalf("record second: %v", err)
	}

	// Latest wins.
	got, err := s.FindLatestConsent(ctx, "tenant-a", "user-42", "v1")
	if err != nil {
		t.Fatalf("FindLatestConsent: %v", err)
	}
	if got.ID() != "cns_2" || !got.GrantedAt().Equal(t2) || got.Evidence().Channel() != "mobile" {
		t.Fatalf("latest not returned: %+v", got)
	}

	// Full history preserved, newest-first, original untouched.
	list, err := s.ListConsents(ctx, "tenant-a", "user-42")
	if err != nil {
		t.Fatalf("ListConsents: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("append-only history len = %d, want 2", len(list))
	}
	if list[0].ID() != "cns_2" || list[1].ID() != "cns_1" {
		t.Fatalf("history order wrong: %s, %s", list[0].ID(), list[1].ID())
	}
	if list[1].Evidence().Channel() != "web-console" || list[1].Evidence().IP() != "203.0.113.7" ||
		list[1].Evidence().UserAgent() != "FirstBrowser" || !list[1].GrantedAt().Equal(t1) {
		t.Fatalf("original consent was mutated: %+v", list[1])
	}
}

// TestPostgresConsentReusedIDRejected proves the primary-key immutability guard: an
// attempt to reuse an existing record id (the only way an INSERT could clobber a
// prior row) is rejected as a conflict, never a silent overwrite.
func TestPostgresConsentReusedIDRejected(t *testing.T) {
	s := newConsentStore(t)
	ctx := context.Background()
	at := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	if err := s.RecordConsent(ctx, mustConsent(t, "dup", "tenant-a", "user-1", "v1", "api", "", "", at)); err != nil {
		t.Fatalf("first record: %v", err)
	}
	dup := mustConsent(t, "dup", "tenant-a", "user-1", "v2", "api", "", "", at.Add(time.Hour))
	if err := s.RecordConsent(ctx, dup); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("reused id: want ErrConflict, got %v", err)
	}
	// The original row is intact (not overwritten by the rejected write).
	got, err := s.FindLatestConsent(ctx, "tenant-a", "user-1", "v1")
	if err != nil {
		t.Fatalf("FindLatestConsent: %v", err)
	}
	if got.TermsVersion() != "v1" {
		t.Fatalf("original overwritten: %+v", got)
	}
}

// TestPostgresConsentFindLatestAcrossVersions confirms FindLatest is scoped to the
// requested version, not merely the newest row for the subject.
func TestPostgresConsentFindLatestAcrossVersions(t *testing.T) {
	s := newConsentStore(t)
	ctx := context.Background()
	old := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	recent := time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC)
	if err := s.RecordConsent(ctx, mustConsent(t, "cns_v1", "tenant-a", "user-42", "v1", "api", "", "", old)); err != nil {
		t.Fatalf("record v1: %v", err)
	}
	if err := s.RecordConsent(ctx, mustConsent(t, "cns_v2", "tenant-a", "user-42", "v2", "api", "", "", recent)); err != nil {
		t.Fatalf("record v2: %v", err)
	}
	got, err := s.FindLatestConsent(ctx, "tenant-a", "user-42", "v1")
	if err != nil {
		t.Fatalf("FindLatestConsent v1: %v", err)
	}
	if got.ID() != "cns_v1" || !got.GrantedAt().Equal(old) {
		t.Fatalf("version scoping wrong: %+v", got)
	}
}

package inmemory

import (
	"context"
	"sort"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/domain/termsconsent"
)

// This file implements ports.TermsConsentStore on the in-memory store, mirroring
// the SQLite adapter's behaviour: append-only capture (a new row per consent,
// never an overwrite), tenant-scoped reads, and clone-in/clone-out so stored
// records are never mutated in place (SIN-68743). It is the durable-faithful test
// double for the LGPD consent-to-terms trail.

// cloneConsent returns a defensive copy. termsconsent.Record's fields are all
// value types (strings, time.Time, the Evidence value struct with string fields),
// so a struct copy is a deep copy — a caller can never mutate stored state.
func cloneConsent(r *termsconsent.Record) *termsconsent.Record {
	if r == nil {
		return nil
	}
	c := *r
	return &c
}

// RecordConsent appends one immutable consent event (append-only, mirrors the
// INSERT-only SQLite adapter). Re-consent adds a new element; nothing is
// overwritten.
func (s *Store) RecordConsent(ctx context.Context, r *termsconsent.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.consents = append(s.consents, cloneConsent(r))
	return nil
}

// FindLatestConsent returns the most recent consent for (tenant, subject,
// version), or shared.ErrNotFound. Tenant-scoped.
func (s *Store) FindLatestConsent(ctx context.Context, tenantID, subject, termsVersion string) (*termsconsent.Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var latest *termsconsent.Record
	for _, r := range s.consents {
		if r.TenantID() != tenantID || r.Subject() != subject || r.TermsVersion() != termsVersion {
			continue
		}
		if latest == nil || consentAfter(r, latest) {
			latest = r
		}
	}
	if latest == nil {
		return nil, shared.ErrNotFound
	}
	return cloneConsent(latest), nil
}

// ListConsents returns a subject's consent history for a tenant, newest first
// (granted_at desc, id desc tie-break). Tenant-scoped.
func (s *Store) ListConsents(ctx context.Context, tenantID, subject string) ([]*termsconsent.Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*termsconsent.Record
	for _, r := range s.consents {
		if r.TenantID() == tenantID && r.Subject() == subject {
			out = append(out, cloneConsent(r))
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return consentAfter(out[i], out[j]) })
	return out, nil
}

// consentAfter reports whether a sorts before b in newest-first order: later
// granted_at wins, with the id as a deterministic descending tie-break (matching
// the SQLite "ORDER BY granted_at DESC, id DESC").
func consentAfter(a, b *termsconsent.Record) bool {
	if a.GrantedAt().Equal(b.GrantedAt()) {
		return a.ID() > b.ID()
	}
	return a.GrantedAt().After(b.GrantedAt())
}

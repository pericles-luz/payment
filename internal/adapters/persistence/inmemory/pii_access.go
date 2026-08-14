package inmemory

import (
	"context"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/access"
)

// This file implements the LGPD / art.13 PII read-access register
// (ports.PIIAccessRecorder + ports.PIIAccessPurger; ADR-0008, SIN-68748) on the
// in-memory store, mirroring the SQLite adapter: append-only records, and a single
// retention-expiry delete (PurgePIIAccessBefore). Entries are value structs
// (access.Entry has only unexported value fields) so appending/copying is a deep
// copy — no aggregate is mutated in place, keeping the WithinTx snapshot rollback
// correct, exactly like the audit trail.

// RecordPIIAccess appends one PII read record (append-only). Mirrors the SQLite
// adapter: the entry is durable and never updated (only retention-expired).
func (s *Store) RecordPIIAccess(ctx context.Context, e access.Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.appendPIIAccess(e)
}

// PurgePIIAccessBefore removes entries strictly older than cutoff (the only delete
// permitted on the append-only register — retention minimisation, ADR-0008 §3) and
// returns how many were removed. Append-safe: entries at or after cutoff are kept.
func (s *Store) PurgePIIAccessBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.piiAccess[:0:0]
	var removed int64
	for _, e := range s.piiAccess {
		if e.At().Before(cutoff) {
			removed++
			continue
		}
		kept = append(kept, e)
	}
	s.piiAccess = kept
	return removed, nil
}

// PIIAccessEntries returns a copy of the recorded PII access entries in append
// order. A copy is returned so callers can never mutate the trail (append-only
// integrity) — the inspection helper mirrors AuditEntries.
func (s *Store) PIIAccessEntries() []access.Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]access.Entry, len(s.piiAccess))
	copy(out, s.piiAccess)
	return out
}

// --- Lock-free core (callers must hold s.mu) ---

func (s *Store) appendPIIAccess(e access.Entry) error {
	s.piiAccess = append(s.piiAccess, e)
	return nil
}

// RecordPIIAccess records a PII read within the unit of work; it is rolled back
// with the rest of the transaction (the piiAccess slice is part of the snapshot),
// which is what makes the access append and the mediated read atomic (Complete
// Mediation, ADR-0008 §5).
func (v txView) RecordPIIAccess(ctx context.Context, e access.Entry) error {
	return v.s.appendPIIAccess(e)
}

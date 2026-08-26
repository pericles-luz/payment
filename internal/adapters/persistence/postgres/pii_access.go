package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/access"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// This file is the persistent implementation of the LGPD / art.13 PII read-access
// register (ports.PIIAccessRecorder + ports.PIIAccessPurger; ADR-0008, SIN-68748).
//
// ATOMICITY (Complete Mediation, ADR-0008 §5/§6): RecordPIIAccess runs on repo's
// current handle, so when a mediated read of local PII (FindRecByID) and this
// append share one WithinTx, the access record commits with the read — a read whose
// append fails is rolled back, leaving no unlogged read of PII at rest. Bundled into
// ports.Repository exactly like AuditLog.
//
// APPEND-ONLY: the only statement issued against pii_access_log outside retention is
// an INSERT. The single DELETE path is PurgePIIAccessBefore — the bounded, minimising
// retention expiry — never an UPDATE, never a targeted delete. It runs on the pool
// (*Store), not inside a business transaction.
//
// MINIMISATION: access.Entry carries no plaintext PII by construction (subject_ref is
// already a pseudonym), so no column here can leak devedor_doc/devedor_nome (§4).

var (
	_ ports.PIIAccessRecorder = (*Store)(nil)
	_ ports.PIIAccessRecorder = repo{}
	_ ports.PIIAccessPurger   = (*Store)(nil)
)

// RecordPIIAccess durably records one PII read (append-only INSERT). It runs on the
// adapter's current handle: the transaction when this repo came from WithinTx, the
// connection pool otherwise. It never persists plaintext PII — Entry exposes only a
// pseudonymous subject_ref plus who/what/object/when/duration (ADR-0008 §2/§4).
func (r repo) RecordPIIAccess(ctx context.Context, e access.Entry) error {
	_, err := r.q.ExecContext(ctx,
		`INSERT INTO pii_access_log (id, at, duration_ms, tenant_id, client_id, operator_id, subject_ref, object, action)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		e.ID(), e.At().Format(tsLayout), e.DurationMs(), e.TenantID(), e.ClientID(),
		e.OperatorID(), e.SubjectRef(), e.Object(), string(e.Action()))
	if err != nil {
		return fmt.Errorf("record pii access: %w", err)
	}
	return nil
}

// PurgePIIAccessBefore removes access entries strictly older than cutoff — the ONLY
// delete permitted on the append-only register (LGPD retention minimisation,
// ADR-0008 §3). It runs on the pool and returns how many rows were removed. It never
// touches entries at or after cutoff (append-safe).
func (s *Store) PurgePIIAccessBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM pii_access_log WHERE at < $1`, cutoff.UTC().Format(tsLayout))
	if err != nil {
		return 0, fmt.Errorf("purge pii access: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("purge rows affected: %w", err)
	}
	return n, nil
}

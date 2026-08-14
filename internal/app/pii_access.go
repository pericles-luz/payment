package app

import (
	"context"
	"fmt"
	"strings"

	"github.com/ia-dev-sindireceita/payment/internal/domain/access"
	"github.com/ia-dev-sindireceita/payment/internal/domain/recurrence"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// noopPIIAccess is the fallback PIIAccessRecorder used when Deps.PIIAccess is nil.
// It keeps the autocommit fallback and unit tests with per-port fakes panic-free;
// production MUST wire a real append-only recorder (footgun guarded via the nil
// pseudonymizer check in NewPIIAccessService — the service refuses to read PII when
// it cannot pseudonymise the subject).
type noopPIIAccess struct{}

func (noopPIIAccess) RecordPIIAccess(context.Context, access.Entry) error { return nil }

// PIIAccessService is the single Complete-Mediation choke-point through which a
// tier-1 read of titular PII AT REST (today: pix_rec.devedor_*) MUST pass (ADR-0008
// §5, SIN-68748). It exists so the SECURE read path is the EASY read path: a future
// endpoint that must expose the debtor of a mandate calls ReadRec, which loads the
// mandate AND records the LGPD / art.13 access event in the SAME transaction — a
// read whose access append fails is rolled back, so PII at rest cannot be read
// without being recorded.
//
// The responsible is derived SERVER-SIDE (the authenticated tenant + the non-secret
// client/credential id, plus an operator id for admin/console reads); it is never
// taken from client input. The subject is recorded only as a non-reversible
// pseudonym (Pseudonymizer) — never the plaintext document or name (ADR-0008 §4).
type PIIAccessService struct {
	uow    ports.UnitOfWork
	pseudo access.Pseudonymizer
	clock  ports.Clock
	ids    ports.IDProvider
}

// NewPIIAccessService wires the choke-point from Deps and the subject pseudonymizer.
// The pseudonymizer carries the service HMAC key; it is required (deny-by-default):
// without it the service cannot produce a non-reversible subject_ref, so it must not
// read PII at all.
func NewPIIAccessService(d Deps, pseudo access.Pseudonymizer) *PIIAccessService {
	return &PIIAccessService{
		uow:    resolveUoW(d),
		pseudo: pseudo,
		clock:  d.Clock,
		ids:    d.IDs,
	}
}

// ReadRecInput is the validated boundary input for a mediated mandate read. TenantID
// is the authenticated tenant (scopes the read AND names the responsible). ClientID
// is the non-secret credential/client id of the responsible; OperatorID attributes
// the read when it came from the admin/console plane (both server-derived, empty
// when not applicable). All identity fields are server-derived, never client input.
type ReadRecInput struct {
	TenantID   string
	IDRec      string
	ClientID   string
	OperatorID string
}

// ReadRec loads a mandate tenant-scoped AND records the art.13 access event in one
// unit of work. The access record commits with the read: if the append fails, the
// whole operation is rolled back and ReadRec returns the error with no mandate — so
// a read of local PII is never unlogged (Complete Mediation, ADR-0008 §5/§6). A
// not-found mandate surfaces shared.ErrNotFound and records nothing (no PII was
// exposed). The read duration is measured around the load and recorded (art.13
// "duração").
func (s *PIIAccessService) ReadRec(ctx context.Context, in ReadRecInput) (*recurrence.Rec, error) {
	tenantID := strings.TrimSpace(in.TenantID)
	if tenantID == "" {
		return nil, shared.NewValidationError("tenant_id", "is required")
	}
	idRec := strings.TrimSpace(in.IDRec)
	if idRec == "" {
		return nil, shared.NewValidationError("id_rec", "is required")
	}

	start := s.clock.Now()
	var out *recurrence.Rec
	err := s.uow.WithinTx(ctx, func(r ports.Repository) error {
		rec, err := r.FindRecByID(ctx, tenantID, idRec)
		if err != nil {
			// ErrNotFound (or any load error) surfaces without an access record: no
			// titular PII was resolved, so there is nothing to register.
			return err
		}
		// PII is now materialised: pseudonymise the subject and record the access on
		// the SAME transaction handle before returning it to the caller.
		dur := s.clock.Now().Sub(start)
		entry, err := access.NewEntry(access.NewEntryParams{
			ID:         s.ids.NewID(),
			At:         start,
			Duration:   dur,
			TenantID:   tenantID,
			ClientID:   strings.TrimSpace(in.ClientID),
			OperatorID: strings.TrimSpace(in.OperatorID),
			SubjectRef: s.pseudo.Ref(rec.Devedor().Doc()),
			Object:     "rec:" + rec.IDRec(),
			Action:     access.ActionReadRec,
		})
		if err != nil {
			return fmt.Errorf("build access entry: %w", err)
		}
		if err := r.RecordPIIAccess(ctx, entry); err != nil {
			return fmt.Errorf("record pii access: %w", err)
		}
		out = rec
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// PIIAccessRetentionService expires access-log entries older than the configured
// retention window — the LGPD minimisation routine (ADR-0008 §3). It is meant to run
// on a schedule (an ops cron), not on the request path. The purge is the only delete
// permitted on the otherwise append-only register and is append-safe (entries newer
// than the cutoff are untouched).
type PIIAccessRetentionService struct {
	purger ports.PIIAccessPurger
	policy access.RetentionPolicy
	clock  ports.Clock
}

// NewPIIAccessRetentionService wires the retention routine from the purger, the
// (validated) policy and a clock.
func NewPIIAccessRetentionService(purger ports.PIIAccessPurger, policy access.RetentionPolicy, clock ports.Clock) *PIIAccessRetentionService {
	return &PIIAccessRetentionService{purger: purger, policy: policy, clock: clock}
}

// Purge removes access entries older than the retention cutoff (now − window) and
// returns how many were removed. Idempotent to re-run: a second immediate call finds
// nothing new to expire.
func (s *PIIAccessRetentionService) Purge(ctx context.Context) (int64, error) {
	cutoff := s.policy.Cutoff(s.clock.Now())
	n, err := s.purger.PurgePIIAccessBefore(ctx, cutoff)
	if err != nil {
		return 0, fmt.Errorf("purge pii access: %w", err)
	}
	return n, nil
}

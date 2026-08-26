package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/domain/termsconsent"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// This file is the persistent, append-only implementation of
// ports.TermsConsentStore (SIN-68743): the durable LGPD consent-to-terms trail.
//
// APPEND-ONLY: the only statement this adapter ever issues against terms_consent
// is an INSERT. There is no UPDATE or DELETE anywhere in application code, so a
// captured consent is immutable and re-consent adds a NEW row (keyed by its own
// opaque id) rather than mutating the prior one — immutability is a property of
// the code surface, not just a convention (OWASP A09).
//
// TENANT SCOPE: every read is filtered by tenant_id (threat P1) so one tenant can
// never observe another's consents; a subject/version owned by another tenant
// reads back as shared.ErrNotFound (no cross-tenant existence oracle).
//
// PII: subject / ip / user-agent are persisted (the durable evidence LGPD
// requires) but this adapter never logs a value — the Record redacts them under
// structured logging (termsconsent.Record.LogValue).

var _ ports.TermsConsentStore = (*Store)(nil)

// RecordConsent durably appends one consent event (append-only INSERT). Because
// this method lives on repo, it runs on the adapter's current handle — the
// transaction when this repo came from WithinTx, the connection pool otherwise —
// so a caller that wants the consent captured atomically with another write can.
func (r repo) RecordConsent(ctx context.Context, rec *termsconsent.Record) error {
	e := rec.Evidence()
	_, err := r.q.ExecContext(ctx,
		`INSERT INTO terms_consent (id, tenant_id, subject, terms_version, granted_at,
		    method_channel, method_ip, method_user_agent)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		rec.ID(), rec.TenantID(), rec.Subject(), rec.TermsVersion(),
		rec.GrantedAt().Format(tsLayout), e.Channel(), e.IP(), e.UserAgent())
	if err != nil {
		if isUniqueViolation(err) {
			return shared.ErrConflict
		}
		return fmt.Errorf("record consent: %w", err)
	}
	return nil
}

// FindLatestConsent returns the most recent consent for (tenant, subject,
// version), or shared.ErrNotFound. Tenant-scoped.
func (r repo) FindLatestConsent(ctx context.Context, tenantID, subject, termsVersion string) (*termsconsent.Record, error) {
	row := r.q.QueryRowContext(ctx,
		`SELECT id, tenant_id, subject, terms_version, granted_at, method_channel, method_ip, method_user_agent
		 FROM terms_consent
		 WHERE tenant_id = $1 AND subject = $2 AND terms_version = $3
		 ORDER BY granted_at DESC, id DESC LIMIT 1`, tenantID, subject, termsVersion)
	rec, err := scanConsent(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, fmt.Errorf("scan consent: %w", err)
	}
	return rec, nil
}

// ListConsents returns a subject's full consent history for a tenant, newest
// first (granted_at desc, id desc tie-break). Tenant-scoped (threat P1).
func (s *Store) ListConsents(ctx context.Context, tenantID, subject string) ([]*termsconsent.Record, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, tenant_id, subject, terms_version, granted_at, method_channel, method_ip, method_user_agent
		 FROM terms_consent
		 WHERE tenant_id = $1 AND subject = $2 ORDER BY granted_at DESC, id DESC`, tenantID, subject)
	if err != nil {
		return nil, fmt.Errorf("query consents: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*termsconsent.Record
	for rows.Next() {
		rec, err := scanConsent(rows)
		if err != nil {
			return nil, fmt.Errorf("scan consent: %w", err)
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate consents: %w", err)
	}
	return out, nil
}

func scanConsent(s scanner) (*termsconsent.Record, error) {
	var id, tenantID, subject, termsVersion, grantedAt, channel, ip, userAgent string
	if err := s.Scan(&id, &tenantID, &subject, &termsVersion, &grantedAt, &channel, &ip, &userAgent); err != nil {
		return nil, err
	}
	evidence, err := termsconsent.NewEvidence(channel, ip, userAgent)
	if err != nil {
		return nil, fmt.Errorf("rehydrate evidence: %w", err)
	}
	return termsconsent.Rehydrate(id, tenantID, subject, termsVersion, parseTime(grantedAt), evidence), nil
}

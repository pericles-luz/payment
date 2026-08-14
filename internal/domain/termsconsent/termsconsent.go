// Package termsconsent holds the LGPD "consentimento informado aos termos de uso
// da Solução" domain: the durable, append-only proof that a given user accepted a
// specific version of the Solution's terms of use, at a moment, through a
// recorded channel. It exists because the C6 "Termo de Uso de APIs" (cláusula 3.5
// / B9, SIN-68740) makes collecting AND STORING that consent an obligation of the
// Desenvolvedor.
//
// This is a DISTINCT concern from the internal/domain/consent package, which
// models the PIX Automático recurring-debit MANDATE (an authorization to debit
// money). This package models legal consent to the terms of use — no money, no
// bank, just an auditable record of "who agreed to what version, when and how".
//
// A Record is IMMUTABLE by construction: fields are unexported and there is no
// mutator, so once captured a consent event never changes. The storage adapters
// only ever INSERT (append-only) — re-consent produces a NEW timestamped Record,
// it never overwrites an existing one, so the full history is preserved (the
// forensic property LGPD/OWASP A09 rely on).
//
// PII: a Record carries the subject (user identity) and the collection evidence
// (IP / user-agent), which ARE personal data. They are persisted (that is the
// point — the durable proof) but MUST NOT leak into logs; LogValue below redacts
// them so structured logging emits only non-PII descriptors (segredo/PII-zero em
// log, mirroring ports.BankCredential/BankCertificate).
//
// Pure domain: this package MUST NOT import database/sql, net/http, vendor SDKs or
// the ports package. Persistence lives behind ports.TermsConsentStore, implemented
// by the sqlite and inmemory adapters.
package termsconsent

import (
	"log/slog"
	"strings"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

// Evidence describes HOW a consent was collected: the channel it came through
// (required — e.g. "web-console", "api", "mobile") and, when available, the
// requester IP and user-agent. IP and user-agent are optional because a
// non-browser channel may not carry them; the channel is always required so every
// stored consent records at least the surface it was granted on.
//
// IP and UserAgent are personal data and are redacted by Record.LogValue.
type Evidence struct {
	channel   string
	ip        string
	userAgent string
}

// Channel returns the collection channel (never empty for a valid Evidence).
func (e Evidence) Channel() string { return e.channel }

// IP returns the requester IP as recorded (may be empty).
func (e Evidence) IP() string { return e.ip }

// UserAgent returns the requester user-agent as recorded (may be empty).
func (e Evidence) UserAgent() string { return e.userAgent }

// NewEvidence validates and builds the collection evidence. channel is required;
// ip and userAgent are trimmed and stored as-is (optional context). Over-strict
// validation of PII form is deliberately avoided — the value is evidence, not a
// key we route on.
func NewEvidence(channel, ip, userAgent string) (Evidence, error) {
	channel = strings.TrimSpace(channel)
	if channel == "" {
		return Evidence{}, shared.NewValidationError("channel", "is required")
	}
	return Evidence{
		channel:   channel,
		ip:        strings.TrimSpace(ip),
		userAgent: strings.TrimSpace(userAgent),
	}, nil
}

// Record is the immutable, append-only proof of one consent event: subject S
// accepted terms version V, for tenant T, at time G, through Evidence E. It is
// constructed once (NewRecord) or rehydrated from storage (Rehydrate) and never
// mutated — there is no setter, so the captured fact cannot drift.
type Record struct {
	id           string
	tenantID     string
	subject      string // the consenting user's identity ref (PII — redacted in logs)
	termsVersion string
	grantedAt    time.Time
	evidence     Evidence
}

// NewRecordParams is the validated input to capture a consent event.
type NewRecordParams struct {
	ID           string
	TenantID     string
	Subject      string
	TermsVersion string
	Evidence     Evidence
}

// NewRecord builds a consent Record, enforcing invariants: a non-empty
// server-generated id, tenant, subject and terms version, a valid Evidence
// (non-zero channel) and a non-zero grantedAt timestamp. grantedAt is supplied by
// the caller's clock so the domain stays deterministic/testable.
func NewRecord(p NewRecordParams, grantedAt time.Time) (*Record, error) {
	id := strings.TrimSpace(p.ID)
	if id == "" {
		return nil, shared.NewValidationError("id", "is required")
	}
	tenantID := strings.TrimSpace(p.TenantID)
	if tenantID == "" {
		return nil, shared.NewValidationError("tenant_id", "is required")
	}
	subject := strings.TrimSpace(p.Subject)
	if subject == "" {
		return nil, shared.NewValidationError("subject", "is required")
	}
	termsVersion := strings.TrimSpace(p.TermsVersion)
	if termsVersion == "" {
		return nil, shared.NewValidationError("terms_version", "is required")
	}
	if p.Evidence == (Evidence{}) {
		return nil, shared.NewValidationError("evidence", "is required")
	}
	if grantedAt.IsZero() {
		return nil, shared.NewValidationError("granted_at", "is required")
	}
	return &Record{
		id:           id,
		tenantID:     tenantID,
		subject:      subject,
		termsVersion: termsVersion,
		grantedAt:    grantedAt.UTC(),
		evidence:     p.Evidence,
	}, nil
}

// Rehydrate reconstructs a Record from persisted columns without re-running
// construction validation (the row was valid when written). It is the storage
// adapter's inverse of the accessors.
func Rehydrate(id, tenantID, subject, termsVersion string, grantedAt time.Time, evidence Evidence) *Record {
	return &Record{
		id:           id,
		tenantID:     tenantID,
		subject:      subject,
		termsVersion: termsVersion,
		grantedAt:    grantedAt.UTC(),
		evidence:     evidence,
	}
}

// ID returns the opaque record identifier.
func (r *Record) ID() string { return r.id }

// TenantID returns the owning tenant (isolation boundary).
func (r *Record) TenantID() string { return r.tenantID }

// Subject returns the consenting user's identity ref (PII).
func (r *Record) Subject() string { return r.subject }

// TermsVersion returns the accepted terms-of-use version.
func (r *Record) TermsVersion() string { return r.termsVersion }

// GrantedAt returns the instant the consent was captured (UTC).
func (r *Record) GrantedAt() time.Time { return r.grantedAt }

// Evidence returns the collection evidence (channel/IP/user-agent).
func (r *Record) Evidence() Evidence { return r.evidence }

// LogValue implements slog.LogValuer so structured logging of a Record emits only
// non-PII descriptors. The subject, IP and user-agent are personal data and are
// redacted, so a stray log call can never leak them (segredo/PII-zero em log).
func (r *Record) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", r.id),
		slog.String("tenant_id", r.tenantID),
		slog.String("subject", "[REDACTED]"),
		slog.String("terms_version", r.termsVersion),
		slog.Time("granted_at", r.grantedAt),
		slog.String("channel", r.evidence.channel),
		slog.String("ip", "[REDACTED]"),
		slog.String("user_agent", "[REDACTED]"),
	)
}

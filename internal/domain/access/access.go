// Package access holds the immutable, append-only inventory of READ access to a
// natural person's personal data in the data plane — the LGPD / Decreto
// 8.771/2016 art.13 register (Termo C6 B10-v; see ADR-0008). An Entry captures
// WHO read (a server-derived responsible: the tenant + the credential/client id,
// plus an operator id when the read came from the admin/console plane), WHICH
// SUBJECT (a NON-reversible pseudonymous reference, never the plaintext document
// or name), WHICH OBJECT (type + opaque id), WHEN and for HOW LONG.
//
// It is a distinct trail from the privileged-mutation audit_log (audit.Entry):
// reads are far more frequent than privileged mutations and carry their own
// retention/erasure policy (minimisation), so mixing them would blur both trails
// and change the audit_log's cost/tamper-evidence profile (ADR-0008 §3).
//
// MINIMISATION (non-negotiable, ADR-0008 §4): an Entry NEVER carries devedor_doc,
// devedor_nome, a name, or an address in clear. It records only a subject_ref — an
// HMAC-SHA256 pseudonym of the normalised document (Pseudonymizer) or an already
// opaque business id — so this A09 mitigation does not itself become a new LGPD
// leak surface or a second copy of PII to erase. Pure domain: this package MUST
// NOT import database/sql, net/http or vendor SDKs.
package access

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"strings"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

// Action is the kind of PII read an Entry records. Actions are a closed
// vocabulary (deny-by-default) so the trail stays queryable and a typo can never
// produce an unclassifiable access record — mirroring audit.Action.
type Action string

const (
	// ActionReadRec records a read that resolved and exposed the debtor
	// (devedor_doc/devedor_nome) of a PIX Automático mandate — the only structured
	// titular PII at rest today (pix_rec, SIN-66037). This is the concrete,
	// immediate trigger (ADR-0008 §1, tier 1).
	ActionReadRec Action = "pii.read.rec"
	// ActionReadDDA records a read of a DDA boleto whose BeneficiaryName may be a
	// natural person (tier 2 — logged as access to the object, not to the titular).
	ActionReadDDA Action = "pii.read.dda"
	// ActionReadStatement records a read of an account statement window whose free
	// text may name a counterparty (tier 2 — logged as access to the window).
	ActionReadStatement Action = "pii.read.statement"
)

// valid reports whether a is a known action (deny-by-default).
func (a Action) valid() bool {
	switch a {
	case ActionReadRec, ActionReadDDA, ActionReadStatement:
		return true
	default:
		return false
	}
}

// Entry is an immutable record of one PII read. Fields are unexported and exposed
// via accessors so an entry cannot be mutated after construction (append-only at
// the type level, mirroring audit.Entry / billing.LedgerEntry). No field ever
// carries plaintext PII by construction — subjectRef is already a pseudonym.
type Entry struct {
	id         string
	at         time.Time
	durationMs int64
	tenantID   string
	clientID   string
	operatorID string
	subjectRef string
	object     string
	action     Action
}

// NewEntryParams is the validated input to build an access Entry. The caller
// derives every responsible field SERVER-SIDE (the authenticated tenant, the
// credential/client id, and — for admin/console reads — the operator id); none is
// ever taken from client input (least privilege / no client-asserted identity).
// SubjectRef MUST already be a pseudonym (Pseudonymizer.Ref) or an opaque business
// id — passing a plaintext document/name is a programming error the caller must
// avoid; the constructor has no plaintext-PII parameter to make that the easy path.
type NewEntryParams struct {
	ID         string
	At         time.Time
	Duration   time.Duration
	TenantID   string
	ClientID   string
	OperatorID string
	SubjectRef string
	Object     string
	Action     Action
}

// NewEntry builds an access entry, enforcing invariants: a non-empty id, a known
// action, a target tenant, a non-empty subject_ref (the pseudonym) and a non-empty
// object. The duration is recorded in whole milliseconds (a negative duration is
// rejected — a read cannot take negative time). It has no plaintext-PII parameter,
// so an entry cannot smuggle devedor_doc/devedor_nome by construction (ADR-0008 §4).
func NewEntry(p NewEntryParams) (Entry, error) {
	id := strings.TrimSpace(p.ID)
	if id == "" {
		return Entry{}, shared.NewValidationError("id", "access entry id is required")
	}
	if !p.Action.valid() {
		return Entry{}, shared.NewValidationError("action", "unknown access action")
	}
	tenantID := strings.TrimSpace(p.TenantID)
	if tenantID == "" {
		return Entry{}, shared.NewValidationError("tenant_id", "tenant id is required")
	}
	subjectRef := strings.TrimSpace(p.SubjectRef)
	if subjectRef == "" {
		return Entry{}, shared.NewValidationError("subject_ref", "subject_ref is required")
	}
	object := strings.TrimSpace(p.Object)
	if object == "" {
		return Entry{}, shared.NewValidationError("object", "object is required")
	}
	if p.Duration < 0 {
		return Entry{}, shared.NewValidationError("duration", "duration must not be negative")
	}
	return Entry{
		id:         id,
		at:         p.At,
		durationMs: p.Duration.Milliseconds(),
		tenantID:   tenantID,
		clientID:   strings.TrimSpace(p.ClientID),
		operatorID: strings.TrimSpace(p.OperatorID),
		subjectRef: subjectRef,
		object:     object,
		action:     p.Action,
	}, nil
}

// ID returns the access entry identifier.
func (e Entry) ID() string { return e.id }

// At returns the instant the read began (RFC3339-UTC when persisted).
func (e Entry) At() time.Time { return e.at }

// DurationMs returns the read duration in whole milliseconds (art.13 "duração").
func (e Entry) DurationMs() int64 { return e.durationMs }

// TenantID returns the tenant responsible for (and scoping) the read.
func (e Entry) TenantID() string { return e.tenantID }

// ClientID returns the non-secret credential / client id of the responsible, or
// "" when not applicable. Never the credential secret (threat C1/C4).
func (e Entry) ClientID() string { return e.clientID }

// OperatorID returns the server-derived operator id when the read was triggered
// from the admin/console plane, or "" for a data-plane (tenant-credential) read.
func (e Entry) OperatorID() string { return e.operatorID }

// SubjectRef returns the non-reversible pseudonymous reference to the titular.
// It is NEVER the plaintext document or name (ADR-0008 §4).
func (e Entry) SubjectRef() string { return e.subjectRef }

// Object returns the accessed object as type:id (e.g. "rec:{idRec}").
func (e Entry) Object() string { return e.object }

// Action returns the recorded read action (closed vocabulary).
func (e Entry) Action() Action { return e.action }

// Pseudonymizer turns a natural person's document into a stable, non-reversible
// subject_ref via HMAC-SHA256 under a per-service key. The same document always
// maps to the same ref (so art.13 / an LGPD data-subject request can list every
// access to one titular) while the ref is not reversible to the document without
// the key. The key is secret material and MUST NOT be logged — LogValue redacts it.
type Pseudonymizer struct {
	key []byte
}

// NewPseudonymizer builds a Pseudonymizer from the service key. A short/empty key
// is rejected: without a secret key the "pseudonym" would be a plain hash any party
// could brute-force over the small CPF/CNPJ space, defeating non-reversibility.
func NewPseudonymizer(key []byte) (Pseudonymizer, error) {
	if len(key) < 16 {
		return Pseudonymizer{}, shared.NewValidationError("key", "subject pseudonymizer key must be at least 16 bytes")
	}
	k := make([]byte, len(key))
	copy(k, key)
	return Pseudonymizer{key: k}, nil
}

// Ref returns the pseudonymous subject reference for a document. The document is
// normalised (digits only) before hashing so formatting differences map to the
// same ref. The result is prefixed with the algorithm for forward-compatibility.
func (p Pseudonymizer) Ref(doc string) string {
	mac := hmac.New(sha256.New, p.key)
	mac.Write([]byte(normalizeDoc(doc)))
	return "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil))
}

// LogValue makes Pseudonymizer write-only for its secret key: it never renders the
// key, only a redacted marker (same discipline used for credential secrets).
func (p Pseudonymizer) LogValue() slog.Value {
	return slog.StringValue("access.Pseudonymizer{key:REDACTED}")
}

var _ slog.LogValuer = Pseudonymizer{}

// normalizeDoc keeps only the digits of a document so "123.456.789-09" and
// "12345678909" pseudonymise identically.
func normalizeDoc(doc string) string {
	var b strings.Builder
	b.Grow(len(doc))
	for _, r := range doc {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// DefaultRetention is the default bounded retention window for the access log
// (6 months). LGPD minimisation: the register is kept only as long as needed to
// evidence art.13 compliance, then expired by the purge routine (ADR-0008 §3).
const DefaultRetention = 180 * 24 * time.Hour

// RetentionPolicy is a validated, configurable retention window. Cutoff computes
// the boundary before which entries are expired, given the current time.
type RetentionPolicy struct {
	window time.Duration
}

// NewRetentionPolicy validates a retention window (must be positive) — an
// unbounded or non-positive window would defeat minimisation.
func NewRetentionPolicy(window time.Duration) (RetentionPolicy, error) {
	if window <= 0 {
		return RetentionPolicy{}, shared.NewValidationError("window", "retention window must be positive")
	}
	return RetentionPolicy{window: window}, nil
}

// Window returns the configured retention duration.
func (r RetentionPolicy) Window() time.Duration { return r.window }

// Cutoff returns the instant before which entries are expired: entries with
// at < Cutoff(now) may be purged (append-safe — newer entries are untouched).
func (r RetentionPolicy) Cutoff(now time.Time) time.Time { return now.Add(-r.window) }

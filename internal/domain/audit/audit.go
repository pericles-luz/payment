// Package audit holds the immutable, append-only audit trail of privileged
// admin-plane actions. An Entry captures who (the server-derived operator id),
// what (the action), the target tenant and when — it is the forensic/compliance
// record for cross-tenant privileged operations (credential writes, tenant
// provisioning, pricing changes, and future activation/suspension).
//
// An Entry NEVER carries a secret value or any credential material: it records
// only the fact that an action occurred and by whom (threat C1/C4). Pure domain:
// this package MUST NOT import database/sql, net/http or vendor SDKs.
package audit

import (
	"strings"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

// Action is the privileged operation an audit Entry records. Actions are a
// closed vocabulary so the trail stays queryable and tamper-evident.
type Action string

const (
	// ActionCreateTenant records provisioning of a new tenant.
	ActionCreateTenant Action = "tenant.create"
	// ActionSetEndpointPrice records an upsert of a tenant's endpoint pricing.
	ActionSetEndpointPrice Action = "pricing.set"
	// ActionSetBankCredential records a write of a tenant's bank (PSP) credential.
	// The audit entry names the tenant and operator only — never the secret.
	ActionSetBankCredential Action = "credential.set"
	// ActionSuspendTenant records suspension of a tenant (reserved for when the
	// lifecycle operation exists).
	ActionSuspendTenant Action = "tenant.suspend"
	// ActionActivateTenant records (re)activation of a tenant (reserved).
	ActionActivateTenant Action = "tenant.activate"
	// ActionSettlementAmountMismatch records a money-movement divergence: a charge
	// the PSP marked paid whose received amount did not match the expected
	// (original) amount, so settlement was refused (reconcile-before-settle, threat
	// W3). Unlike the other actions this is a system-actor event (no human
	// operator) and carries the expected/received cents and the txid.
	ActionSettlementAmountMismatch Action = "settlement.amount_mismatch"
)

// valid reports whether a is a known action (deny-by-default: unknown actions
// are rejected so a typo can never produce an unclassifiable audit record).
func (a Action) valid() bool {
	switch a {
	case ActionCreateTenant, ActionSetEndpointPrice, ActionSetBankCredential,
		ActionSuspendTenant, ActionActivateTenant, ActionSettlementAmountMismatch:
		return true
	default:
		return false
	}
}

// Entry is an immutable record of one privileged admin-plane or system action.
// Fields are unexported and exposed via accessors so an entry cannot be mutated
// after construction (append-only at the type level, mirroring
// billing.LedgerEntry).
//
// txID/expectedCents/receivedCents are populated only for money-movement events
// (ActionSettlementAmountMismatch). They are zero-valued for admin-plane actions,
// which have no charge or amounts. No field ever carries a secret.
type Entry struct {
	id            string
	operatorID    string
	action        Action
	tenantID      string
	at            time.Time
	txID          string
	expectedCents int64
	receivedCents int64
}

// NewEntry builds an audit entry, enforcing invariants: a non-empty id, a known
// action and a target tenant. The operator id is intentionally allowed to be
// empty: it denotes a non-attributed internal caller (the HTTP admin middleware
// always populates it server-side for real requests). NewEntry rejects any
// attempt to smuggle a secret by construction — it has no secret parameter.
func NewEntry(id, operatorID string, action Action, tenantID string, at time.Time) (Entry, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return Entry{}, shared.NewValidationError("id", "audit entry id is required")
	}
	if !action.valid() {
		return Entry{}, shared.NewValidationError("action", "unknown audit action")
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return Entry{}, shared.NewValidationError("tenant_id", "tenant id is required")
	}
	return Entry{
		id:         id,
		operatorID: strings.TrimSpace(operatorID),
		action:     action,
		tenantID:   tenantID,
		at:         at,
	}, nil
}

// NewSettlementMismatchEntry builds the audit record for a refused settlement: a
// charge the PSP marked paid whose received amount did not match the expected
// amount (reconcile-before-settle, threat W3). It is a system-actor event — the
// operatorID is a reserved synthetic id (e.g. "system:c6-webhook"), since a PSP
// webhook has no human operator. It records who/what/tenant/when plus the txid
// and the expected/received cents so the divergence is durably queryable; it
// carries no secret by construction (it has no secret parameter).
//
// Invariants: a non-empty id, tenant and txid. The amounts are recorded verbatim
// (including a zero received) — the whole point is to capture what diverged.
func NewSettlementMismatchEntry(id, operatorID, tenantID, txID string, expectedCents, receivedCents int64, at time.Time) (Entry, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return Entry{}, shared.NewValidationError("id", "audit entry id is required")
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return Entry{}, shared.NewValidationError("tenant_id", "tenant id is required")
	}
	txID = strings.TrimSpace(txID)
	if txID == "" {
		return Entry{}, shared.NewValidationError("tx_id", "tx id is required")
	}
	return Entry{
		id:            id,
		operatorID:    strings.TrimSpace(operatorID),
		action:        ActionSettlementAmountMismatch,
		tenantID:      tenantID,
		at:            at,
		txID:          txID,
		expectedCents: expectedCents,
		receivedCents: receivedCents,
	}, nil
}

// ID returns the audit entry identifier.
func (e Entry) ID() string { return e.id }

// OperatorID returns the server-derived id of the operator who performed the
// action, or "" for a non-attributed internal caller.
func (e Entry) OperatorID() string { return e.operatorID }

// Action returns the recorded privileged action.
func (e Entry) Action() Action { return e.action }

// TenantID returns the tenant the action targeted.
func (e Entry) TenantID() string { return e.tenantID }

// At returns the time the action occurred.
func (e Entry) At() time.Time { return e.at }

// TxID returns the charge txid for a money-movement event, or "" for an
// admin-plane action.
func (e Entry) TxID() string { return e.txID }

// ExpectedCents returns the expected (original) charge amount in cents for a
// money-movement event, or 0 for an admin-plane action.
func (e Entry) ExpectedCents() int64 { return e.expectedCents }

// ReceivedCents returns the received amount in cents for a money-movement event,
// or 0 for an admin-plane action.
func (e Entry) ReceivedCents() int64 { return e.receivedCents }

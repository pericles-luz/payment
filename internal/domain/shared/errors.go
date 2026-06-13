// Package shared holds value objects and error values used across the pure
// domain aggregates. It MUST NOT import database/sql, net/http or vendor SDKs.
package shared

import (
	"errors"
	"fmt"
)

// Sentinel domain errors. Adapters translate these into transport-specific
// responses (HTTP status, etc.) using errors.Is / errors.As.
var (
	// ErrValidation indicates an input that violates a domain invariant.
	ErrValidation = errors.New("validation error")
	// ErrNotFound indicates a requested aggregate does not exist (within tenant).
	ErrNotFound = errors.New("not found")
	// ErrConflict indicates a uniqueness / idempotency conflict.
	ErrConflict = errors.New("conflict")
	// ErrTenantScope indicates an attempt to act across tenant boundaries.
	ErrTenantScope = errors.New("tenant scope violation")
	// ErrInvalidTransition indicates an illegal aggregate state transition.
	ErrInvalidTransition = errors.New("invalid state transition")
	// ErrUnauthorized indicates an upstream dependency (the bank/PSP) rejected our
	// authentication — e.g. invalid OAuth2 client credentials, an expired or wrong
	// scope, or a refused token. It is NOT a client-facing authz decision (that is
	// enforced at the inbound HTTP boundary); it means our own credential material
	// for an external system is wrong, so a blind retry will not help.
	ErrUnauthorized = errors.New("unauthorized")
	// ErrUnavailable indicates an upstream dependency (the bank/PSP) is temporarily
	// unavailable: a transport/TLS failure, a timeout, a 429, or a 5xx. It is
	// generally retryable with backoff, unlike ErrUnauthorized or ErrValidation.
	ErrUnavailable = errors.New("unavailable")
	// ErrAmountMismatch indicates a reconciled charge whose received amount does
	// not equal the expected (original) amount — a partial payment, an adjustable
	// charge paid to a different value, or manipulation. Settlement MUST refuse to
	// liquidate on this signal and emit an audit event (reconcile-before-settle,
	// threat W3). It is distinct from ErrValidation: the input was well-formed, the
	// reconciled money simply does not add up.
	ErrAmountMismatch = errors.New("amount mismatch")
)

// ValidationError wraps ErrValidation with the offending field and a message so
// callers can surface a precise, non-sensitive error at the boundary.
type ValidationError struct {
	Field string
	Msg   string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s (%s)", ErrValidation.Error(), e.Msg, e.Field)
}

// Is allows errors.Is(err, ErrValidation) to match a *ValidationError.
func (e *ValidationError) Is(target error) bool { return target == ErrValidation }

// NewValidationError builds a *ValidationError for the given field.
func NewValidationError(field, msg string) error {
	return &ValidationError{Field: field, Msg: msg}
}

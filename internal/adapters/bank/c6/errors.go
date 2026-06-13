package c6

import (
	"encoding/json"
	"fmt"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

// Error is the adapter-level error returned by the C6 provider. It carries just
// enough non-sensitive metadata to be actionable (the operation, the upstream
// HTTP status and, when present, the PSP's short machine error code) and wraps a
// shared.Err* sentinel so callers can branch with errors.Is, while errors.As can
// recover this concrete type for the status/code.
//
// It deliberately never carries the raw PSP response body, the request URL or any
// credential material — leaking the upstream body in an error or log is exactly
// the threat this adapter must avoid (no secret/PII in errors or logs).
type Error struct {
	// Op is the logical operation that failed: "token", "create_charge" or
	// "get_charge".
	Op string
	// StatusCode is the upstream HTTP status, or 0 for a transport/TLS failure.
	StatusCode int
	// Code is the PSP's short machine error code (e.g. "invalid_client"), parsed
	// from a well-known JSON field. It is a stable token, not the human-readable
	// message/body, so it is safe to surface.
	Code string

	// detail is an optional, non-sensitive clarification for adapter-originated
	// failures that are not a plain HTTP status mapping — e.g. a 2xx response the
	// adapter refused to trust. It is a fixed, code-authored string and never
	// carries the raw upstream body, URL or any credential material.
	detail string

	sentinel error
}

// Error renders a stable, non-sensitive message. It never includes the raw
// upstream body.
func (e *Error) Error() string {
	switch {
	case e.detail != "":
		return fmt.Sprintf("c6 %s: %s: %v", e.Op, e.detail, e.sentinel)
	case e.StatusCode == 0:
		return fmt.Sprintf("c6 %s: upstream transport failure: %v", e.Op, e.sentinel)
	case e.Code != "":
		return fmt.Sprintf("c6 %s: upstream status %d (code %q): %v", e.Op, e.StatusCode, e.Code, e.sentinel)
	default:
		return fmt.Sprintf("c6 %s: upstream status %d: %v", e.Op, e.StatusCode, e.sentinel)
	}
}

// Unwrap exposes the shared.Err* sentinel so errors.Is(err, shared.ErrX) matches.
func (e *Error) Unwrap() error { return e.sentinel }

// transportError builds an Error for a transport/TLS/timeout failure (no HTTP
// status). It maps to shared.ErrUnavailable (retryable) and never embeds the raw
// transport error, which could contain the request URL.
func transportError(op string) *Error {
	return &Error{Op: op, StatusCode: 0, sentinel: shared.ErrUnavailable}
}

// mapError translates a non-2xx upstream response into an *Error wrapping the
// appropriate shared sentinel. body is parsed only for the safe machine code; its
// raw contents are never surfaced.
func mapError(op string, status int, body []byte) *Error {
	return &Error{
		Op:         op,
		StatusCode: status,
		Code:       parseErrorCode(body),
		sentinel:   sentinelForStatus(status),
	}
}

// sentinelForStatus maps an HTTP status to a domain sentinel. The mapping is by
// status class because the C6 per-code error catalogue (SIN-64704) is not yet
// finalized; when it lands, a code→sentinel refinement slots in here and in
// parseErrorCode without changing the adapter's surface.
func sentinelForStatus(status int) error {
	switch {
	case status == 400, status == 422:
		return shared.ErrValidation
	case status == 401, status == 403:
		return shared.ErrUnauthorized
	case status == 404:
		return shared.ErrNotFound
	case status == 409:
		return shared.ErrConflict
	case status == 429:
		return shared.ErrUnavailable
	case status >= 500:
		return shared.ErrUnavailable
	default:
		// Any other unexpected status (incl. 3xx we did not follow) is treated as
		// an upstream problem rather than silently swallowed.
		return shared.ErrUnavailable
	}
}

// errorEnvelope is the minimal, safe slice of a C6/OAuth2 error response. Only the
// short machine code fields are read; the human message/description is ignored on
// purpose so it cannot leak into an error or log.
type errorEnvelope struct {
	Error string `json:"error"` // OAuth2 style: "invalid_client", "invalid_scope"
	Code  string `json:"code"`  // C6 REST style machine code
}

// parseErrorCode extracts the PSP's short machine error code, preferring the C6
// "code" field and falling back to the OAuth2 "error" field. It returns "" when
// the body is absent or not the expected shape — never an error, never the body.
func parseErrorCode(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	var env errorEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return ""
	}
	if env.Code != "" {
		return env.Code
	}
	return env.Error
}

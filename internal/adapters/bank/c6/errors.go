package c6

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

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
	// Fields are the NAMES of the properties the PSP rejected, parsed from the
	// RFC7807 BACEN "violacoes" array (SIN-69582). Only the property name of each
	// violation is captured — never the free-text "razao"/"detail"/"title" nor any
	// rejected "valor", which can carry PII/secret. Each name is sanitized
	// (length-capped, identifier-shaped) and the slice is count-capped, so an
	// upstream that returns free text where a name is expected cannot leak it here.
	// This is the minimum needed to debug a 400 without reopening the no-leak hole.
	Fields []string

	// detail is an optional, non-sensitive clarification for adapter-originated
	// failures that are not a plain HTTP status mapping — e.g. a 2xx response the
	// adapter refused to trust. It is a fixed, code-authored string and never
	// carries the raw upstream body, URL or any credential material.
	detail string

	sentinel error
}

// Error renders a stable, non-sensitive message. It never includes the raw
// upstream body. When the PSP named the rejected fields (RFC7807 "violacoes"),
// their sanitized NAMES — and only their names — are appended so a 400 is
// debuggable, e.g. `... (code "RequisicaoInvalida") [violacoes: url, chave]: ...`.
func (e *Error) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "c6 %s: ", e.Op)
	switch {
	case e.detail != "":
		b.WriteString(e.detail)
	case e.StatusCode == 0:
		b.WriteString("upstream transport failure")
	case e.Code != "":
		fmt.Fprintf(&b, "upstream status %d (code %q)", e.StatusCode, e.Code)
	default:
		fmt.Fprintf(&b, "upstream status %d", e.StatusCode)
	}
	if len(e.Fields) > 0 {
		fmt.Fprintf(&b, " [violacoes: %s]", strings.Join(e.Fields, ", "))
	}
	fmt.Fprintf(&b, ": %v", e.sentinel)
	return b.String()
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
	e := &Error{
		Op:         op,
		StatusCode: status,
		Code:       parseErrorCode(body),
		Fields:     parseViolatedFields(body),
		sentinel:   sentinelForStatus(status),
	}
	logPSPRejection(op, status, e.Code, e.Fields, parseCorrelationID(body))
	return e
}

// parseCorrelationID extracts the PSP's opaque request id, or "" when absent.
func parseCorrelationID(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	var env errorEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return ""
	}
	id := strings.TrimSpace(env.CorrelationID)
	if len(id) > maxFieldNameLength {
		return ""
	}
	return id
}

// logPSPRejection records that the PSP refused a call, with every field that is safe to
// keep: the operation, the status, the machine code, the rejected field NAMES, and the
// PSP's correlation id.
//
// It exists because a refusal used to leave no trace at all. The adapter maps the PSP
// error to a sentinel and the boundary answers a generic message, so
// `400 {"error":"invalid request"}` was the whole story — measured 15/09/2026, an invalid
// payer CPF took an hour to diagnose and only the probe could show the reason.
//
// What is NOT logged, and will not be: the problem+json `title`/`detail`. They are free
// text the PSP composes, and on the boleto surface the request is MADE of payer personal
// data — name, CPF/CNPJ, address — so a detail that echoes a rejected value would put PII
// in the logs of the one surface where that is least acceptable (threat C1/C4). The
// correlation id is the safe equivalent: it carries no data and still lets C6 support find
// the exact request. For the free text itself, cmd/c6-webhook-probe remains the sanctioned
// one-shot escape hatch.
func logPSPRejection(op string, status int, code string, fields []string, correlationID string) {
	attrs := []any{
		slog.String("op", op),
		slog.Int("status", status),
	}
	if code != "" {
		attrs = append(attrs, slog.String("psp_code", code))
	}
	if correlationID != "" {
		attrs = append(attrs, slog.String("psp_correlation_id", correlationID))
	}
	if len(fields) > 0 {
		attrs = append(attrs, slog.Any("psp_rejected_fields", fields))
	}
	slog.Warn("c6.psp_rejected", attrs...)
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
// short machine code fields are read; the human message/description (title/detail)
// is ignored on purpose so it cannot leak into an error or log.
//
// Type is the RFC7807 problem+json "type" URN both real C6 surfaces return
// (SIN-65856): BACEN PIX echoes ".../api/v2/error/RequisicaoInvalida" and the
// C6-proprietary surfaces echo ".../v1/error/invalid_request". Only its final path
// segment (a stable token) is surfaced as the code.
type errorEnvelope struct {
	Error string `json:"error"` // OAuth2 style: "invalid_client", "invalid_scope"
	Code  string `json:"code"`  // legacy C6 REST style machine code
	Type  string `json:"type"`  // RFC7807 problem+json type URN
	// CorrelationID is the PSP's own opaque request identifier (problem+json
	// "correlation_id", e.g. "a3ba9b636de21acb-GRU"). It is read and LOGGED because it is
	// the one field that makes a rejection diagnosable without carrying any request data:
	// an operator hands it to C6 support and they locate the exact call.
	//
	// It is deliberately the ONLY human-useful field added. `title`/`detail` stay unread —
	// see parseErrorDiagnostics.
	CorrelationID string     `json:"correlation_id"`
	Violacoes     []violacao `json:"violacoes"`
}

// violacao is a single entry of the RFC7807 BACEN "violacoes" array. Only the
// field-NAME keys are decoded ("propriedade", with "campo" as a plausible alias);
// the free-text "razao" and the rejected "valor" are deliberately NOT declared so
// json.Unmarshal never even reads them — they can carry PII/secret and must not be
// surfaced. See parseViolatedFields for the sanitizing choke-point.
type violacao struct {
	Propriedade string `json:"propriedade"`
	Campo       string `json:"campo"`
}

const (
	// maxViolatedFields caps how many rejected-field names are surfaced, so a
	// hostile/oversized response cannot bloat an error string or log line.
	maxViolatedFields = 20
	// maxFieldNameLength caps the length of a single surfaced name. A real field
	// name is short; anything longer is treated as free text and dropped.
	maxFieldNameLength = 64
)

// parseErrorCode extracts the PSP's short machine error code, preferring an
// explicit "code", then the OAuth2 "error", then the final path segment of the
// RFC7807 "type" URN. A problem+json's title/detail are never read, so they cannot
// leak into an error or log. Returns "" when the body is absent or not the expected
// shape — never an error, never the body.
func parseErrorCode(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	var env errorEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return ""
	}
	switch {
	case env.Code != "":
		return env.Code
	case env.Error != "":
		return env.Error
	default:
		return problemTypeCode(env.Type)
	}
}

// parseViolatedFields extracts ONLY the names of the properties the PSP rejected
// from an RFC7807 BACEN problem+json "violacoes" array (SIN-69582). It surfaces
// field names exclusively — never the free-text "razao"/"detail"/"title" nor any
// "valor" (the rejected value), which can carry PII or a reflected secret. This is
// a deliberate, minimal reopening of the adapter's no-leak policy so a C6 400 is
// debuggable at all: without it we only see the bare code and cannot tell WHICH
// field C6 refused.
//
// The C6 response is untrusted even here: each candidate name is sanitized
// (length-capped, identifier-shaped) and the result is count-capped, so a server
// that returns free text where a name is expected cannot leak it through this
// choke-point. Returns nil when the body is absent, malformed or carries no usable
// names — never an error, never the raw body.
func parseViolatedFields(body []byte) []string {
	if len(body) == 0 {
		return nil
	}
	var env errorEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil
	}
	if len(env.Violacoes) == 0 {
		return nil
	}
	fields := make([]string, 0, len(env.Violacoes))
	for _, v := range env.Violacoes {
		// Prefer "propriedade"; fall back to the "campo" alias. Both name the
		// violated field. razao/valor are never read (not declared on violacao).
		name := v.Propriedade
		if name == "" {
			name = v.Campo
		}
		if name = sanitizeFieldName(name); name != "" {
			fields = append(fields, name)
		}
		if len(fields) >= maxViolatedFields {
			break
		}
	}
	if len(fields) == 0 {
		return nil
	}
	return fields
}

// sanitizeFieldName guards the log/error choke-point: the C6 body is untrusted, so
// a "field name" is surfaced only when it is short and identifier-shaped — letters,
// digits and the small separator set BACEN uses in dotted / JSON-pointer property
// paths. Anything containing a space or an out-of-set rune is assumed to be free
// text (which could carry a value/PII) and dropped by returning "". Over-long names
// are dropped rather than truncated, so no partial free-text can slip through.
func sanitizeFieldName(name string) string {
	if name == "" || len(name) > maxFieldNameLength {
		return ""
	}
	for _, r := range name {
		if !isFieldNameRune(r) {
			return ""
		}
	}
	return name
}

// isFieldNameRune reports whether r may appear in a surfaced field name. The set is
// intentionally narrow: [A-Za-z0-9] plus the separators seen in BACEN property
// paths ('_', '.', '-', '[', ']', '/'). Notably it excludes whitespace, so any
// free-text reason (which has spaces) is rejected wholesale.
func isFieldNameRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return true
	}
	switch r {
	case '_', '.', '-', '[', ']', '/':
		return true
	}
	return false
}

// problemTypeCode returns the final path segment of an RFC7807 "type" URN — a
// stable, non-sensitive machine token (e.g. "RequisicaoInvalida", "invalid_request")
// — or "" when the URN is empty or ends in a slash. Any query/fragment is trimmed
// so only the bare token is surfaced.
func problemTypeCode(typ string) string {
	if typ == "" {
		return ""
	}
	if i := strings.IndexAny(typ, "?#"); i >= 0 {
		typ = typ[:i]
	}
	return typ[strings.LastIndexByte(typ, '/')+1:]
}

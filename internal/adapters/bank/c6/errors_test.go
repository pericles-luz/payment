package c6

import (
	"errors"
	"strings"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

func TestSentinelForStatus(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		status int
		want   error
	}{
		{"bad request", 400, shared.ErrValidation},
		{"unprocessable", 422, shared.ErrValidation},
		{"unauthorized", 401, shared.ErrUnauthorized},
		{"forbidden", 403, shared.ErrUnauthorized},
		{"not found", 404, shared.ErrNotFound},
		{"conflict", 409, shared.ErrConflict},
		{"too many requests", 429, shared.ErrUnavailable},
		{"internal", 500, shared.ErrUnavailable},
		{"bad gateway", 502, shared.ErrUnavailable},
		{"service unavailable", 503, shared.ErrUnavailable},
		{"teapot (unexpected)", 418, shared.ErrUnavailable},
		{"redirect (unexpected)", 302, shared.ErrUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := mapError("op", tc.status, nil)
			if !errors.Is(err, tc.want) {
				t.Fatalf("status %d: errors.Is mismatch: want %v, got %v", tc.status, tc.want, err)
			}
		})
	}
}

func TestMapErrorAsConcrete(t *testing.T) {
	t.Parallel()
	err := mapError("create_charge", 409, []byte(`{"code":"DUPLICATE_CHARGE","message":"already exists"}`))

	var ce *Error
	if !errors.As(err, &ce) {
		t.Fatalf("errors.As(*Error) failed for %v", err)
	}
	if ce.Op != "create_charge" {
		t.Fatalf("Op: want create_charge, got %q", ce.Op)
	}
	if ce.StatusCode != 409 {
		t.Fatalf("StatusCode: want 409, got %d", ce.StatusCode)
	}
	if ce.Code != "DUPLICATE_CHARGE" {
		t.Fatalf("Code: want DUPLICATE_CHARGE, got %q", ce.Code)
	}
	if !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("want errors.Is ErrConflict")
	}
}

func TestParseErrorCode(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body string
		want string
	}{
		{"c6 code field", `{"code":"EAUTH001"}`, "EAUTH001"},
		{"oauth2 error field", `{"error":"invalid_client"}`, "invalid_client"},
		{"code preferred over error", `{"code":"C1","error":"e1"}`, "C1"},
		{"empty body", ``, ""},
		{"not json", `<html>boom</html>`, ""},
		{"json without code", `{"message":"nope"}`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := parseErrorCode([]byte(tc.body)); got != tc.want {
				t.Fatalf("parseErrorCode(%q): want %q, got %q", tc.body, tc.want, got)
			}
		})
	}
}

// TestErrorMessageDoesNotLeakBody is the security regression: a raw PSP body
// (which could carry PII or a reflected secret) must never appear in the error
// string. Only the safe machine code and status are allowed.
func TestErrorMessageDoesNotLeakBody(t *testing.T) {
	t.Parallel()
	secretish := "super-secret-token-and-pii-cpf-12345678900"
	body := `{"code":"ERR","message":"` + secretish + `","description":"` + secretish + `"}`
	err := mapError("get_charge", 400, []byte(body))

	msg := err.Error()
	if strings.Contains(msg, secretish) {
		t.Fatalf("error message leaked raw body: %q", msg)
	}
	if !strings.Contains(msg, "ERR") {
		t.Fatalf("error message should include the safe machine code, got %q", msg)
	}
}

func TestTransportErrorMessage(t *testing.T) {
	t.Parallel()
	err := transportError("token")
	if !errors.Is(err, shared.ErrUnavailable) {
		t.Fatalf("transport error must map to ErrUnavailable, got %v", err)
	}
	if err.StatusCode != 0 {
		t.Fatalf("transport error StatusCode: want 0, got %d", err.StatusCode)
	}
	if !strings.Contains(err.Error(), "transport") {
		t.Fatalf("transport error message should mention transport, got %q", err.Error())
	}
}

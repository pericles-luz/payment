package c6

import (
	"errors"
	"strconv"
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

// TestParseViolatedFields proves the choke-point surfaces ONLY sanitized field
// names from the RFC7807 BACEN "violacoes" array and never the free-text
// razao/valor/detail. See SIN-69582.
func TestParseViolatedFields(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body string
		want []string
	}{
		{
			name: "bacen violacoes propriedade",
			body: `{"type":"https://pix.bcb.gov.br/api/v2/error/RequisicaoInvalida",` +
				`"title":"Requisição inválida","detail":"corpo mal formado",` +
				`"violacoes":[` +
				`{"razao":"campo obrigatório ausente","propriedade":"webhookUrl"},` +
				`{"razao":"formato inválido","propriedade":"chave","valor":"cpf-12345678900"}` +
				`]}`,
			want: []string{"webhookUrl", "chave"},
		},
		{
			name: "campo alias when propriedade absent",
			body: `{"violacoes":[{"razao":"ausente","campo":"url"}]}`,
			want: []string{"url"},
		},
		{
			name: "propriedade preferred over campo",
			body: `{"violacoes":[{"propriedade":"webhookUrl","campo":"ignored"}]}`,
			want: []string{"webhookUrl"},
		},
		{
			name: "json-pointer / dotted paths kept",
			body: `{"violacoes":[{"propriedade":"body.webhookUrl"},{"propriedade":"/items[0]/chave"}]}`,
			want: []string{"body.webhookUrl", "/items[0]/chave"},
		},
		{"no violacoes array", `{"type":"x/RequisicaoInvalida"}`, nil},
		{"empty violacoes array", `{"violacoes":[]}`, nil},
		{"empty body", ``, nil},
		{"malformed json no panic", `{"violacoes":[{`, nil},
		{"violacoes wrong shape", `{"violacoes":"boom"}`, nil},
		{
			name: "free-text in name field is dropped",
			body: `{"violacoes":[{"propriedade":"o campo cpf 123.456.789-00 é inválido"},{"propriedade":"chave"}]}`,
			want: []string{"chave"},
		},
		{
			name: "over-long name dropped not truncated",
			body: `{"violacoes":[{"propriedade":"` + strings.Repeat("a", maxFieldNameLength+1) + `"},{"propriedade":"chave"}]}`,
			want: []string{"chave"},
		},
		{
			name: "empty name entry skipped",
			body: `{"violacoes":[{"razao":"algo"},{"propriedade":"chave"}]}`,
			want: []string{"chave"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := parseViolatedFields([]byte(tc.body))
			if len(got) != len(tc.want) {
				t.Fatalf("parseViolatedFields(%q): want %v, got %v", tc.body, tc.want, got)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("parseViolatedFields(%q)[%d]: want %q, got %q", tc.body, i, tc.want[i], got[i])
				}
			}
		})
	}
}

// TestParseViolatedFieldsCountCap proves the count cap holds: no more than
// maxViolatedFields names are surfaced even if C6 returns a huge array.
func TestParseViolatedFieldsCountCap(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	b.WriteString(`{"violacoes":[`)
	for i := 0; i < maxViolatedFields+10; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"propriedade":"campo` + strconv.Itoa(i) + `"}`)
	}
	b.WriteString(`]}`)

	got := parseViolatedFields([]byte(b.String()))
	if len(got) != maxViolatedFields {
		t.Fatalf("count cap: want %d names, got %d", maxViolatedFields, len(got))
	}
}

// TestErrorMessageSurfacesFieldNamesNotValues is the security regression for
// SIN-69582: a 400 with a violacoes array must surface the rejected field NAMES in
// the error string, while the razao/detail/valor (which can carry PII) must NOT
// appear.
func TestErrorMessageSurfacesFieldNamesNotValues(t *testing.T) {
	t.Parallel()
	secretish := "cpf-12345678900-super-secret"
	body := `{"type":"https://pix.bcb.gov.br/api/v2/error/RequisicaoInvalida",` +
		`"title":"` + secretish + `","detail":"` + secretish + `",` +
		`"violacoes":[{"razao":"` + secretish + `","propriedade":"webhookUrl","valor":"` + secretish + `"}]}`

	err := mapError("register_webhook", 400, []byte(body))
	msg := err.Error()

	if strings.Contains(msg, secretish) {
		t.Fatalf("error message leaked a value/razao/detail: %q", msg)
	}
	if !strings.Contains(msg, "webhookUrl") {
		t.Fatalf("error message should surface the rejected field name, got %q", msg)
	}
	if !strings.Contains(msg, "violacoes:") {
		t.Fatalf("error message should tag the violated fields, got %q", msg)
	}
	if !strings.Contains(msg, "RequisicaoInvalida") {
		t.Fatalf("error message should keep the safe machine code, got %q", msg)
	}

	var ce *Error
	if !errors.As(err, &ce) {
		t.Fatalf("errors.As(*Error) failed for %v", err)
	}
	if len(ce.Fields) != 1 || ce.Fields[0] != "webhookUrl" {
		t.Fatalf("Fields: want [webhookUrl], got %v", ce.Fields)
	}
}

// TestErrorMessageNoViolacoesTagWhenAbsent proves the existing message shape is
// untouched when there is no violacoes array (no stray "[violacoes: ]").
func TestErrorMessageNoViolacoesTagWhenAbsent(t *testing.T) {
	t.Parallel()
	err := mapError("get_charge", 400, []byte(`{"code":"ERR"}`))
	msg := err.Error()
	if strings.Contains(msg, "violacoes") {
		t.Fatalf("no violacoes present but message tagged it: %q", msg)
	}
	if msg != `c6 get_charge: upstream status 400 (code "ERR"): `+shared.ErrValidation.Error() {
		t.Fatalf("unexpected message shape: %q", msg)
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

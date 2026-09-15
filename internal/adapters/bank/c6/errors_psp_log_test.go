package c6

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

// captureLogs swaps the default logger for the duration of a test.
//
// NOT parallel-safe, and the tests below therefore do not call t.Parallel(): slog's default
// logger is process-global, so a parallel test that triggers mapError writes into this
// buffer too. Rather than pretend otherwise, each test uses a UNIQUE op name and asserts on
// the record carrying it — which is robust even if another test interleaves.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// findRecord returns the logged record whose "op" matches, or nil.
func findRecord(t *testing.T, buf *bytes.Buffer, op string) map[string]any {
	t.Helper()
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		if rec["op"] == op {
			return rec
		}
	}
	return nil
}

// The real 422 the C6 sandbox returned on 15/09/2026. Before this logging existed a
// rejection left NO trace: the adapter mapped it to a sentinel and the boundary answered a
// generic message, so the reason was unobtainable without the probe.
const realC6Rejection = `{"type":"https://developers.c6bank.com.br/v1/error/unprocessable_entity",` +
	`"title":"Entidade não pode ser processada.",` +
	`"status":422,` +
	`"detail":"Error generating boleto: {\"type\":\"MATERA_CLIENT_ERROR_400\",\"message\":\"Valor informado no campo <cnpjCpf do grupo pagador> não pertence ao Domínio.\"} Unprocessable Entity",` +
	`"correlation_id":"a3ba9b636de21acb-GRU","timestamp":"2026-09-15T21:08:33.786Z"}`

func TestPSPRejectionIsLoggedWithCorrelationID(t *testing.T) {
	buf := captureLogs(t)
	mapError("psplog_correlation", 422, []byte(realC6Rejection))

	rec := findRecord(t, buf, "psplog_correlation")
	if rec == nil {
		t.Fatalf("a PSP refusal must leave a log line, got %q", buf.String())
	}
	if rec["msg"] != "c6.psp_rejected" {
		t.Fatalf("unexpected msg: %v", rec["msg"])
	}
	// The correlation id is the whole point: it is what an operator hands to C6 support.
	if rec["psp_correlation_id"] != "a3ba9b636de21acb-GRU" {
		t.Fatalf("correlation id must be logged, got %v", rec["psp_correlation_id"])
	}
	if rec["status"] != float64(422) {
		t.Fatalf("status must be logged, got %v", rec["status"])
	}
	if rec["psp_code"] != "unprocessable_entity" {
		t.Fatalf("machine code must be logged, got %v", rec["psp_code"])
	}
}

// The free text stays OUT of the logs, and this is the test that keeps it out.
//
// On the boleto surface the request is MADE of payer personal data, so a `detail` echoing a
// rejected value would put PII in the logs of the one surface where that is least
// acceptable. The probe remains the sanctioned one-shot way to read it.
func TestPSPRejectionNeverLogsTitleOrDetail(t *testing.T) {
	buf := captureLogs(t)
	mapError("psplog_nodetail", 422, []byte(realC6Rejection))

	// Checked over the WHOLE buffer, not just our record: the free text must not appear
	// anywhere, by any path.
	out := buf.String()
	for _, leaked := range []string{
		"cnpjCpf",
		"Entidade",
		"MATERA_CLIENT_ERROR_400",
		"Dom\\u00ednio",
		"Error generating boleto",
	} {
		if strings.Contains(out, leaked) {
			t.Fatalf("free text %q must never reach the logs: %s", leaked, out)
		}
	}
	if findRecord(t, buf, "psplog_nodetail") == nil {
		t.Fatal("the record itself must still be there")
	}
}

// A body that is not the expected shape, or empty, must not panic and must not invent a
// correlation id.
func TestPSPRejectionToleratesOddBodies(t *testing.T) {
	for _, body := range []string{"", "not json at all", "{}", `{"correlation_id":123}`, "[]"} {
		buf := captureLogs(t)
		if e := mapError("psplog_odd", 500, []byte(body)); e == nil {
			t.Fatalf("mapError must always return an error (body %q)", body)
		}
		rec := findRecord(t, buf, "psplog_odd")
		if rec == nil {
			t.Fatalf("record missing for body %q", body)
		}
		if _, present := rec["psp_correlation_id"]; present {
			t.Fatalf("no correlation id should be logged for body %q: %v", body, rec)
		}
	}
}

// An absurdly long correlation id is dropped rather than bloating every log line.
func TestPSPCorrelationIDLengthIsCapped(t *testing.T) {
	t.Parallel() // pure function, no global state
	body, err := json.Marshal(map[string]string{"correlation_id": strings.Repeat("x", 500)})
	if err != nil {
		t.Fatal(err)
	}
	if got := parseCorrelationID(body); got != "" {
		t.Fatalf("oversized correlation id must be dropped, got %d chars", len(got))
	}
}

// The rejected FIELD NAMES are still surfaced — they were safe before and remain so.
func TestPSPRejectionLogsRejectedFieldNames(t *testing.T) {
	buf := captureLogs(t)
	mapError("psplog_fields", 400, []byte(`{"type":"x/error/RequisicaoInvalida","violacoes":[{"propriedade":"valor.original"}]}`))

	rec := findRecord(t, buf, "psplog_fields")
	if rec == nil {
		t.Fatalf("record missing: %s", buf.String())
	}
	fields, _ := rec["psp_rejected_fields"].([]any)
	if len(fields) != 1 || fields[0] != "valor.original" {
		t.Fatalf("rejected field names must be logged, got %v", rec["psp_rejected_fields"])
	}
}

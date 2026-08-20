package http_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A rejected inbound webhook used to produce NO log line at all. In production that
// turned a live settlement outage — C6 delivering notifications every 30s while this
// receiver answered 400, then 500 — into something indistinguishable from the PSP never
// calling, and the investigation went the wrong way for exactly that reason.
//
// These tests pin the contract that makes that failure mode impossible to repeat: a
// rejection MUST record the raw body it rejected. They also pin the privacy boundary on
// the other side — the accepted path, which is high-volume, must NOT log payloads unless
// the operator deliberately turns it on.
//
// They do not use t.Parallel(): they swap the process-wide default slog logger.

// captureLogs redirects the default slog logger for the duration of fn and returns
// everything written.
func captureLogs(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	fn()
	return buf.String()
}

// postRaw sends bytes verbatim, so a test can submit a body that is not valid JSON.
func postRaw(t *testing.T, h http.Handler, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// A body that parses as JSON but matches no known shape is the single most likely
// failure when the PSP extends a contract — and the one that is unfixable without the
// bytes. The distinctive marker must reach the log.
func TestWebhookRejectionLogsRawPayload(t *testing.T) {
	f := newFixture(t)

	const marker = "a-shape-this-receiver-does-not-know"
	body := map[string]any{"client_id": tenantClientID, "status": "PAID", "unknown_shape": marker}

	var code int
	logs := captureLogs(t, func() {
		code = do(t, f.handler, http.MethodPost, "/webhooks/c6/"+webhookRef, "", nil, body).Code
	})

	if code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", code)
	}
	if !strings.Contains(logs, "c6 webhook rejected") {
		t.Fatalf("rejection was not logged at all; logs: %s", logs)
	}
	if !strings.Contains(logs, marker) {
		t.Fatalf("raw payload absent from the rejection log — the failure it exists to \ndiagnose would still be invisible; logs: %s", logs)
	}
	if !strings.Contains(logs, "unresolved_shape") {
		t.Fatalf("rejection reason absent; logs: %s", logs)
	}
}

// A body that is not JSON at all must also surface its bytes: "invalid request body"
// alone cannot distinguish a truncated delivery from a contract change.
func TestWebhookMalformedBodyLogsRawPayload(t *testing.T) {
	f := newFixture(t)

	raw := []byte(`{"external_id": "tx-1", TRUNCATED`)

	var code int
	logs := captureLogs(t, func() {
		code = postRaw(t, f.handler, "/webhooks/c6/"+webhookRef, raw).Code
	})

	if code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", code)
	}
	if !strings.Contains(logs, "TRUNCATED") {
		t.Fatalf("raw bytes absent from the malformed-body log; logs: %s", logs)
	}
	if !strings.Contains(logs, "decode_failed") {
		t.Fatalf("decode reason absent; logs: %s", logs)
	}
}

// The privacy half of the contract: with the flag off (the default), a SUCCESSFUL
// notification must not put its payload in the log. The accepted path is high-volume and
// already leaves a durable trace in processed_events, so logging it would spend real
// exposure — payer name and tax id — for nothing.
func TestWebhookAcceptedPayloadNotLoggedByDefault(t *testing.T) {
	f := newFixture(t)
	_, txID := seedCharge(t, f)
	// O banco confirma o pagamento: é a única situação em que o C6 avisa.
	f.bank.MarkSettled(f.tenantID, txID)

	const marker = "SENSITIVE-PAYER-MARKER"
	body := map[string]any{
		"external_id": txID,
		"client_id":   tenantClientID,
		"service":     "BANK_SLIP",
		"status":      "PAID",
		"payer_name":  marker,
	}

	var code int
	logs := captureLogs(t, func() {
		code = do(t, f.handler, http.MethodPost, "/webhooks/c6/"+webhookRef, "", nil, body).Code
	})

	if code != http.StatusAccepted {
		t.Fatalf("want 202, got %d", code)
	}
	if strings.Contains(logs, marker) {
		t.Fatalf("accepted payload leaked into the log with the flag off; logs: %s", logs)
	}
}

// Guard the buffering rewrite itself: reading the body into memory before decoding must
// not change what the receiver accepts. A well-formed notification still settles.
func TestWebhookStillAcceptsAfterBuffering(t *testing.T) {
	f := newFixture(t)
	_, txID := seedCharge(t, f)
	// O banco confirma o pagamento: é a única situação em que o C6 avisa.
	f.bank.MarkSettled(f.tenantID, txID)

	body, err := json.Marshal(map[string]any{
		"external_id": txID,
		"client_id":   tenantClientID,
		"service":     "BANK_SLIP",
		"status":      "PAID",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if rec := postRaw(t, f.handler, "/webhooks/c6/"+webhookRef, body); rec.Code != http.StatusAccepted {
		t.Fatalf("want 202, got %d (%s)", rec.Code, rec.Body.String())
	}
}

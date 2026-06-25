package c6

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// stmtTestServer is a C6 + OAuth2 double exposing the extrato endpoint
// (GET /v1/statement with start_date/end_date) so the statement read path can be exercised.
type stmtTestServer struct {
	*httptest.Server
	lastQuery      url.Values
	lastAuthHeader string
	statusCode     int
	body           string
}

func newStmtTestServer(t *testing.T) *stmtTestServer {
	t.Helper()
	ts := &stmtTestServer{statusCode: http.StatusOK}
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		user, _, _ := r.BasicAuth()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok-` + user + `","token_type":"Bearer","expires_in":3600}`))
	})
	mux.HandleFunc("/v1/statement", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		ts.lastQuery = r.URL.Query()
		ts.lastAuthHeader = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(ts.statusCode)
		_, _ = w.Write([]byte(ts.body))
	})
	ts.Server = httptest.NewTLSServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

func (ts *stmtTestServer) provider(t *testing.T, creds ports.CredentialStore) *Provider {
	t.Helper()
	p, err := New(Config{
		BaseURL:    ts.URL,
		TokenURL:   ts.URL + "/oauth/token",
		HTTPClient: ts.Client(),
	}, creds)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func TestGetStatementSuccess(t *testing.T) {
	t.Parallel()
	ts := newStmtTestServer(t)
	ts.body = `{"entries":[
		{"id":"e1","date":"2026-06-05T00:00:00Z","amount_cents":1000,"kind":"credit","description":"in"},
		{"id":"e2","date":"2026-06-10T00:00:00Z","amount_cents":500,"kind":"debit","description":"out"}
	]}`
	p := ts.provider(t, oneTenant("t1", "client-1", "s"))

	start := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC)
	st, err := p.GetStatement(context.Background(), "t1", ports.StatementFilter{Start: start, End: end})
	if err != nil {
		t.Fatalf("GetStatement: %v", err)
	}
	if ts.lastQuery.Get("start_date") != "2026-06-01" || ts.lastQuery.Get("end_date") != "2026-06-30" {
		t.Fatalf("date window not forwarded as start_date/end_date YYYY-MM-DD: %v", ts.lastQuery)
	}
	if ts.lastAuthHeader != "Bearer tok-client-1" {
		t.Fatalf("per-tenant bearer not attached: %q", ts.lastAuthHeader)
	}
	if len(st.Entries) != 2 || st.Entries[0].ID != "e1" || st.Entries[1].Kind != "debit" {
		t.Fatalf("unexpected entries: %+v", st.Entries)
	}
	if st.Entries[0].AmountCents != 1000 {
		t.Fatalf("amount: %+v", st.Entries[0])
	}
}

func TestGetStatementMissingWindow(t *testing.T) {
	t.Parallel()
	ts := newStmtTestServer(t)
	p := ts.provider(t, oneTenant("t1", "c", "s"))

	if _, err := p.GetStatement(context.Background(), "t1", ports.StatementFilter{End: time.Now()}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation for missing inicio, got %v", err)
	}
	if _, err := p.GetStatement(context.Background(), "t1", ports.StatementFilter{Start: time.Now()}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation for missing fim, got %v", err)
	}
}

func TestGetStatementUpstreamError(t *testing.T) {
	t.Parallel()
	ts := newStmtTestServer(t)
	ts.statusCode = http.StatusInternalServerError
	ts.body = `{}`
	p := ts.provider(t, oneTenant("t1", "c", "s"))

	_, err := p.GetStatement(context.Background(), "t1", ports.StatementFilter{
		Start: time.Now().Add(-time.Hour), End: time.Now(),
	})
	if !errors.Is(err, shared.ErrUnavailable) {
		t.Fatalf("want ErrUnavailable on 5xx, got %v", err)
	}
}

func TestGetStatementMalformedBody(t *testing.T) {
	t.Parallel()
	ts := newStmtTestServer(t)
	ts.body = `not-json`
	p := ts.provider(t, oneTenant("t1", "c", "s"))

	_, err := p.GetStatement(context.Background(), "t1", ports.StatementFilter{
		Start: time.Now().Add(-time.Hour), End: time.Now(),
	})
	if !errors.Is(err, shared.ErrUnavailable) {
		t.Fatalf("want ErrUnavailable on malformed body, got %v", err)
	}
}

func TestGetStatementUnknownTenantCredential(t *testing.T) {
	t.Parallel()
	ts := newStmtTestServer(t)
	ts.body = `{"entries":[]}`
	p := ts.provider(t, oneTenant("t1", "c", "s"))

	// A tenant with no credential cannot obtain a token → not-found from the store.
	if _, err := p.GetStatement(context.Background(), "other", ports.StatementFilter{
		Start: time.Now().Add(-time.Hour), End: time.Now(),
	}); err == nil {
		t.Fatal("missing credential must error (isolation)")
	}
}

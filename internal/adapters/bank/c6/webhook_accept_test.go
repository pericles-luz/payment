package c6

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// Regression guard for SIN-69580: C6 rejects the three webhook REGISTRATION PUTs with
// 400 RequisicaoInvalida unless Accept is application/problem+json —
//
//	Request Accept header '[application/json]' does not match any defined response
//	types. Must be one of: [application/problem+json].
//
// Live-verified against the real C6: the identical request differing only in this
// header returns 400 with application/json and 200 with application/problem+json. The
// quirk is invisible in unit tests unless asserted, and the shared request builder
// (authedJSONRequest) still defaults every other surface to application/json — so a
// future refactor that "tidies up" these header overrides would silently reintroduce a
// failure that only appears against the real bank, as settlements that never arrive.
//
// The GET readbacks are deliberately NOT covered: they were verified to work with the
// default application/json, so pinning them would over-specify.

// acceptRecorder is a C6 double that records the Accept header of the last request per
// path, for the OAuth2 token endpoint plus the three registration PUTs.
type acceptRecorder struct {
	*httptest.Server

	mu     sync.Mutex
	accept map[string]string
}

func newAcceptRecorder(t *testing.T) *acceptRecorder {
	t.Helper()
	ar := &acceptRecorder{accept: map[string]string{}}

	record := func(w http.ResponseWriter, r *http.Request) {
		ar.mu.Lock()
		ar.accept[r.URL.Path] = r.Header.Get("Accept")
		ar.mu.Unlock()
		w.Header().Set("Content-Type", "application/problem+json")
		_, _ = w.Write([]byte(`{"webhookUrl":"https://payment.lmhost.com.br/webhooks/c6/ref"}`))
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /oauth/token", func(w http.ResponseWriter, r *http.Request) {
		user, _, _ := r.BasicAuth()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok-` + user + `","token_type":"Bearer","expires_in":3600}`))
	})
	mux.HandleFunc("PUT /v2/pix/webhook/{chave}", record)
	mux.HandleFunc("PUT /v2/pix/webhookrec", record)
	mux.HandleFunc("PUT /v2/pix/webhookcobr", record)

	ar.Server = httptest.NewTLSServer(mux)
	t.Cleanup(ar.Close)
	return ar
}

func (ar *acceptRecorder) acceptFor(path string) string {
	ar.mu.Lock()
	defer ar.mu.Unlock()
	return ar.accept[path]
}

func TestWebhookRegistrationSendsProblemJSONAccept(t *testing.T) {
	t.Parallel()
	ar := newAcceptRecorder(t)
	p, err := New(Config{
		BaseURL:    ar.URL,
		TokenURL:   ar.URL + "/oauth/token",
		HTTPClient: ar.Client(),
	}, oneTenant("t1", "client-1", "secret-1"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	const callback = "https://payment.lmhost.com.br/webhooks/c6/super-secret-ref"

	cases := []struct {
		name string
		path string
		call func() error
	}{
		{
			name: "immediate PIX settlement webhook",
			path: "/v2/pix/webhook/acme@pix.example",
			call: func() error { return p.RegisterWebhook(ctx, "t1", "acme@pix.example", callback) },
		},
		{
			name: "recurrence mandate webhook",
			path: "/v2/pix/webhookrec",
			call: func() error { return p.RegisterRecWebhook(ctx, "t1", callback) },
		},
		{
			name: "recurring charge webhook",
			path: "/v2/pix/webhookcobr",
			call: func() error { return p.RegisterCobRWebhook(ctx, "t1", callback) },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(); err != nil {
				t.Fatalf("register: %v", err)
			}
			if got := ar.acceptFor(tc.path); got != "application/problem+json" {
				t.Fatalf("Accept = %q, want %q — C6 answers 400 RequisicaoInvalida otherwise",
					got, "application/problem+json")
			}
		})
	}
}

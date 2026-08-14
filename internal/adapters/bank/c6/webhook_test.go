package c6

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// webhookServer is a configurable C6 PIX webhook + OAuth2 double backed by httptest
// TLS. It serves PUT/GET /v2/pix/webhook/{chave} with overridable handlers and
// records the last Authorization / Idempotency-Key / body / path so tests can
// assert the plumbing without races. It is kept separate from the shared
// productServer so this slice adds coverage without touching existing test files.
type webhookServer struct {
	*httptest.Server

	mu             sync.Mutex
	tokenHits      int
	lastAuthHeader string
	lastIdemKey    string
	lastBody       []byte
	lastPath       string

	put http.HandlerFunc
	get http.HandlerFunc
}

func newWebhookServer(t *testing.T) *webhookServer {
	t.Helper()
	ws := &webhookServer{}

	record := func(r *http.Request) {
		ws.mu.Lock()
		defer ws.mu.Unlock()
		ws.lastAuthHeader = r.Header.Get("Authorization")
		ws.lastIdemKey = r.Header.Get("Idempotency-Key")
		ws.lastBody, _ = io.ReadAll(io.LimitReader(r.Body, 1<<20))
		ws.lastPath = r.URL.Path
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /oauth/token", func(w http.ResponseWriter, r *http.Request) {
		ws.mu.Lock()
		ws.tokenHits++
		ws.mu.Unlock()
		user, _, _ := r.BasicAuth()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok-` + user + `","token_type":"Bearer","expires_in":3600}`))
	})
	mux.HandleFunc("PUT /v2/pix/webhook/{chave}", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		if ws.put != nil {
			ws.put(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"webhookUrl":"https://payment.lmhost.com.br/webhooks/c6/ref"}`))
	})
	mux.HandleFunc("GET /v2/pix/webhook/{chave}", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		if ws.get != nil {
			ws.get(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"webhookUrl":"https://payment.lmhost.com.br/webhooks/c6/ref","criacao":"2026-06-25T12:00:00Z"}`))
	})

	ws.Server = httptest.NewTLSServer(mux)
	t.Cleanup(ws.Close)
	return ws
}

func (ws *webhookServer) provider(t *testing.T, creds ports.CredentialStore) *Provider {
	t.Helper()
	p, err := New(Config{
		BaseURL:    ws.URL,
		TokenURL:   ws.URL + "/oauth/token",
		HTTPClient: ws.Client(),
	}, creds)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func (ws *webhookServer) snapshot() (auth, idem, path string, body []byte, tokenHits int) {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	return ws.lastAuthHeader, ws.lastIdemKey, ws.lastPath, ws.lastBody, ws.tokenHits
}

const testWebhookURL = "https://payment.lmhost.com.br/webhooks/c6/super-secret-ref"

// RegisterWebhook PUTs the callback URL keyed by the PIX key: the bearer is
// attached per tenant, the key is path-escaped and forwarded as the
// Idempotency-Key, and only the webhookUrl rides in the body.
func TestRegisterWebhookSuccess(t *testing.T) {
	t.Parallel()
	ws := newWebhookServer(t)
	p := ws.provider(t, oneTenant("t1", "client-1", "secret-1"))

	if err := p.RegisterWebhook(context.Background(), "t1", "acme@pix.example", testWebhookURL); err != nil {
		t.Fatalf("RegisterWebhook: %v", err)
	}
	auth, idem, path, body, _ := ws.snapshot()
	if auth != "Bearer tok-client-1" {
		t.Fatalf("bearer not attached: %q", auth)
	}
	if idem != "acme@pix.example" {
		t.Fatalf("pix key not forwarded as Idempotency-Key: %q", idem)
	}
	if path != "/v2/pix/webhook/acme@pix.example" {
		t.Fatalf("unexpected path: %q", path)
	}
	var sent struct {
		WebhookURL string `json:"webhookUrl"`
	}
	if err := json.Unmarshal(body, &sent); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if sent.WebhookURL != testWebhookURL {
		t.Fatalf("webhookUrl not transported: %s", body)
	}
}

// A PIX key with reserved URL characters (EVP keys are UUIDs, but a phone/CPF key
// is safe; here we prove path-escaping for a key with a '+') is escaped, not split.
func TestRegisterWebhookEscapesKey(t *testing.T) {
	t.Parallel()
	ws := newWebhookServer(t)
	p := ws.provider(t, oneTenant("t1", "c", "s"))

	if err := p.RegisterWebhook(context.Background(), "t1", "+5511999998888", testWebhookURL); err != nil {
		t.Fatalf("RegisterWebhook: %v", err)
	}
	_, _, path, _, _ := ws.snapshot()
	if path != "/v2/pix/webhook/+5511999998888" {
		t.Fatalf("key not handled in path: %q", path)
	}
}

// Re-running the registration with the same URL is safe: the PSP keys the webhook
// by PIX key (PUT replaces, never duplicates), so two identical PUTs both succeed
// and a follow-up GET confirms the single registered URL.
func TestRegisterWebhookIdempotent(t *testing.T) {
	t.Parallel()
	ws := newWebhookServer(t)
	p := ws.provider(t, oneTenant("t1", "client-1", "secret-1"))

	for i := 0; i < 2; i++ {
		if err := p.RegisterWebhook(context.Background(), "t1", "acme@pix.example", testWebhookURL); err != nil {
			t.Fatalf("RegisterWebhook run %d: %v", i, err)
		}
	}
	got, err := p.GetWebhook(context.Background(), "t1", "acme@pix.example")
	if err != nil {
		t.Fatalf("GetWebhook: %v", err)
	}
	if got.WebhookURL == "" {
		t.Fatalf("confirmation read returned no URL: %+v", got)
	}
}

// GetWebhook reads back the registered URL and parses the creation instant.
func TestGetWebhookSuccess(t *testing.T) {
	t.Parallel()
	ws := newWebhookServer(t)
	p := ws.provider(t, oneTenant("t1", "client-1", "secret-1"))

	got, err := p.GetWebhook(context.Background(), "t1", "acme@pix.example")
	if err != nil {
		t.Fatalf("GetWebhook: %v", err)
	}
	if got.WebhookURL != "https://payment.lmhost.com.br/webhooks/c6/ref" {
		t.Fatalf("unexpected webhook url: %q", got.WebhookURL)
	}
	want := time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)
	if !got.CreatedAt.Equal(want) {
		t.Fatalf("criacao not parsed: got %v want %v", got.CreatedAt, want)
	}
	auth, _, _, _, _ := ws.snapshot()
	if auth != "Bearer tok-client-1" {
		t.Fatalf("bearer not attached: %q", auth)
	}
}

// A GET for an unregistered key surfaces as ErrNotFound; a malformed criacao on an
// otherwise-OK read does not fail the read (cosmetic echo, zero time).
func TestGetWebhookEdgeCases(t *testing.T) {
	t.Parallel()
	t.Run("not found", func(t *testing.T) {
		t.Parallel()
		ws := newWebhookServer(t)
		ws.get = func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"code":"NOT_FOUND"}`))
		}
		p := ws.provider(t, oneTenant("t1", "c", "s"))
		if _, err := p.GetWebhook(context.Background(), "t1", "nope@pix.example"); !errors.Is(err, shared.ErrNotFound) {
			t.Fatalf("404 should map to ErrNotFound, got %v", err)
		}
	})
	t.Run("malformed criacao is best-effort zero", func(t *testing.T) {
		t.Parallel()
		ws := newWebhookServer(t)
		ws.get = func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"webhookUrl":"https://payment.lmhost.com.br/webhooks/c6/ref","criacao":"not-a-date"}`))
		}
		p := ws.provider(t, oneTenant("t1", "c", "s"))
		got, err := p.GetWebhook(context.Background(), "t1", "acme@pix.example")
		if err != nil {
			t.Fatalf("GetWebhook: %v", err)
		}
		if !got.CreatedAt.IsZero() {
			t.Fatalf("malformed criacao should yield zero time, got %v", got.CreatedAt)
		}
	})
	t.Run("undecodable body maps to ErrUnavailable", func(t *testing.T) {
		t.Parallel()
		ws := newWebhookServer(t)
		ws.get = func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`not json`))
		}
		p := ws.provider(t, oneTenant("t1", "c", "s"))
		if _, err := p.GetWebhook(context.Background(), "t1", "acme@pix.example"); !errors.Is(err, shared.ErrUnavailable) {
			t.Fatalf("undecodable 2xx should map to ErrUnavailable, got %v", err)
		}
	})
}

// Complete mediation at the boundary: a blank tenant/key or a non-HTTPS callback
// URL is refused as ErrValidation WITHOUT hitting the PSP (no token, no PUT).
func TestRegisterWebhookRejectsBadInput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		tenant string
		key    string
		url    string
	}{
		{"empty tenant", "", "acme@pix.example", testWebhookURL},
		{"empty key", "t1", "  ", testWebhookURL},
		{"empty url", "t1", "acme@pix.example", ""},
		{"http url", "t1", "acme@pix.example", "http://payment.lmhost.com.br/webhooks/c6/ref"},
		{"garbage url", "t1", "acme@pix.example", "://nope"},
		{"no host", "t1", "acme@pix.example", "https:///webhooks"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ws := newWebhookServer(t)
			p := ws.provider(t, oneTenant("t1", "c", "s"))
			if err := p.RegisterWebhook(context.Background(), tc.tenant, tc.key, tc.url); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want ErrValidation, got %v", err)
			}
			if _, _, _, _, hits := ws.snapshot(); hits != 0 {
				t.Fatalf("PSP must not be hit on a rejected input, token hits=%d", hits)
			}
		})
	}
}

func TestGetWebhookRejectsBadInput(t *testing.T) {
	t.Parallel()
	ws := newWebhookServer(t)
	p := ws.provider(t, oneTenant("t1", "c", "s"))
	if _, err := p.GetWebhook(context.Background(), "", "acme@pix.example"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty tenant should be ErrValidation, got %v", err)
	}
	if _, err := p.GetWebhook(context.Background(), "t1", ""); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty key should be ErrValidation, got %v", err)
	}
	if _, _, _, _, hits := ws.snapshot(); hits != 0 {
		t.Fatalf("PSP must not be hit on a rejected input, token hits=%d", hits)
	}
}

// Upstream status classes map to the shared sentinels (errors-as-values via
// errors.go), for both the PUT and GET surfaces.
func TestWebhookErrorMapping(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		status int
		want   error
	}{
		{"bad request", http.StatusBadRequest, shared.ErrValidation},
		{"unauthorized", http.StatusUnauthorized, shared.ErrUnauthorized},
		{"forbidden", http.StatusForbidden, shared.ErrUnauthorized},
		{"conflict", http.StatusConflict, shared.ErrConflict},
		{"server error", http.StatusInternalServerError, shared.ErrUnavailable},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ws := newWebhookServer(t)
			ws.put = func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(`{"code":"X"}`))
			}
			p := ws.provider(t, oneTenant("t1", "c", "s"))
			if err := p.RegisterWebhook(context.Background(), "t1", "acme@pix.example", testWebhookURL); !errors.Is(err, tc.want) {
				t.Fatalf("status %d: want %v, got %v", tc.status, tc.want, err)
			}
		})
	}
}

// A missing credential propagates the store's typed error and never reaches the
// PSP (no token can be minted).
func TestRegisterWebhookMissingCredential(t *testing.T) {
	t.Parallel()
	ws := newWebhookServer(t)
	p := ws.provider(t, &fakeCreds{creds: map[string]ports.BankCredential{}})
	if err := p.RegisterWebhook(context.Background(), "unknown", "acme@pix.example", testWebhookURL); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("missing credential should propagate ErrNotFound, got %v", err)
	}
	if _, _, _, _, hits := ws.snapshot(); hits != 0 {
		t.Fatalf("token must not be hit without a credential, hits=%d", hits)
	}
}

// The webhook URL embeds a SECRET per-tenant ref and the bearer is a SECRET; an
// upstream error that echoes a secret-bearing body must never surface the bearer,
// the client secret, the raw body, or the webhook URL in the returned error.
func TestWebhookSecretsNeverLeak(t *testing.T) {
	t.Parallel()
	const leak = "super-secret-ref"
	ws := newWebhookServer(t)
	ws.put = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		// A hostile/verbose PSP echoes the bearer and a secret in the body.
		_, _ = w.Write([]byte(`{"detail":"token tok-client-1 rejected; secret-1 leaked ` + leak + `"}`))
	}
	p := ws.provider(t, oneTenant("t1", "client-1", "secret-1"))

	err := p.RegisterWebhook(context.Background(), "t1", "acme@pix.example", testWebhookURL)
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	for _, secret := range []string{"tok-client-1", "secret-1", leak, testWebhookURL, "super-secret"} {
		if strings.Contains(msg, secret) {
			t.Fatalf("error leaked secret %q: %s", secret, msg)
		}
	}
	// The same guarantee holds for the GET surface.
	ws.get = ws.put
	if _, gerr := p.GetWebhook(context.Background(), "t1", "acme@pix.example"); gerr == nil || strings.Contains(gerr.Error(), leak) {
		t.Fatalf("get error must be non-nil and leak-free: %v", gerr)
	}
}

// isHTTPSURL / parseWebhookCreatedAt unit edges (pure helpers).
func TestWebhookHelpers(t *testing.T) {
	t.Parallel()
	urls := []struct {
		in   string
		want bool
	}{
		{"https://x.example/p", true},
		{"  https://x.example  ", true},
		{"http://x.example", false},
		{"ftp://x.example", false},
		{"https:///nohost", false},
		{"", false},
		{"://bad", false},
	}
	for _, u := range urls {
		if got := isHTTPSURL(u.in); got != u.want {
			t.Fatalf("isHTTPSURL(%q) = %v, want %v", u.in, got, u.want)
		}
	}
	if !parseWebhookCreatedAt("").IsZero() {
		t.Fatal("empty criacao should be zero time")
	}
	if !parseWebhookCreatedAt("garbage").IsZero() {
		t.Fatal("malformed criacao should be zero time")
	}
	if parseWebhookCreatedAt("2026-06-25T12:00:00Z").IsZero() {
		t.Fatal("valid criacao should parse")
	}
}

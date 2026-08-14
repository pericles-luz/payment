package c6

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// recWebhookServer is a configurable C6 recurrence-webhook + OAuth2 double backed by
// httptest TLS. It serves PUT/GET on the two singleton recurrence collections
// (/v2/pix/webhookrec, /v2/pix/webhookcobr) and records the last request so tests
// can assert the plumbing (no path key, bearer attached, only webhookUrl in body).
type recWebhookServer struct {
	*httptest.Server

	mu       sync.Mutex
	lastAuth string
	lastPath string
	lastBody []byte
	// status, when non-zero, overrides the response code on the next PUT/GET.
	putStatus int
	getStatus int
}

func newRecWebhookServer(t *testing.T) *recWebhookServer {
	t.Helper()
	ws := &recWebhookServer{}
	record := func(r *http.Request) {
		ws.mu.Lock()
		defer ws.mu.Unlock()
		ws.lastAuth = r.Header.Get("Authorization")
		ws.lastPath = r.URL.Path
		ws.lastBody, _ = io.ReadAll(io.LimitReader(r.Body, 1<<20))
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /oauth/token", func(w http.ResponseWriter, r *http.Request) {
		user, _, _ := r.BasicAuth()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok-` + user + `","token_type":"Bearer","expires_in":3600}`))
	})
	put := func(w http.ResponseWriter, r *http.Request) {
		record(r)
		ws.mu.Lock()
		code := ws.putStatus
		ws.mu.Unlock()
		if code != 0 {
			w.WriteHeader(code)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
	get := func(w http.ResponseWriter, r *http.Request) {
		record(r)
		ws.mu.Lock()
		code := ws.getStatus
		ws.mu.Unlock()
		if code != 0 {
			w.WriteHeader(code)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"webhookUrl":"https://payment.lmhost.com.br/webhooks/c6/ref","criacao":"2026-06-25T12:00:00Z"}`))
	}
	mux.HandleFunc("PUT /v2/pix/webhookrec", put)
	mux.HandleFunc("GET /v2/pix/webhookrec", get)
	mux.HandleFunc("PUT /v2/pix/webhookcobr", put)
	mux.HandleFunc("GET /v2/pix/webhookcobr", get)
	ws.Server = httptest.NewTLSServer(mux)
	t.Cleanup(ws.Close)
	return ws
}

func (ws *recWebhookServer) provider(t *testing.T, creds ports.CredentialStore) *Provider {
	t.Helper()
	p, err := New(Config{BaseURL: ws.URL, TokenURL: ws.URL + "/oauth/token", HTTPClient: ws.Client()}, creds)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func (ws *recWebhookServer) snap() (auth, path string, body []byte) {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	return ws.lastAuth, ws.lastPath, ws.lastBody
}

const testRecWebhookURL = "https://payment.lmhost.com.br/webhooks/c6/super-secret-ref"

// Register/Get for both recurrence streams hit the no-key singleton path, attach the
// per-tenant bearer, and carry only the webhookUrl in the body.
func TestRegisterRecurrenceWebhookSuccess(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		register func(p *Provider) error
		confirm  func(p *Provider) (ports.WebhookRegistration, error)
		wantPath string
	}{
		{"rec",
			func(p *Provider) error { return p.RegisterRecWebhook(context.Background(), "t1", testRecWebhookURL) },
			func(p *Provider) (ports.WebhookRegistration, error) {
				return p.GetRecWebhook(context.Background(), "t1")
			},
			"/v2/pix/webhookrec"},
		{"cobr",
			func(p *Provider) error { return p.RegisterCobRWebhook(context.Background(), "t1", testRecWebhookURL) },
			func(p *Provider) (ports.WebhookRegistration, error) {
				return p.GetCobRWebhook(context.Background(), "t1")
			},
			"/v2/pix/webhookcobr"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ws := newRecWebhookServer(t)
			p := ws.provider(t, oneTenant("t1", "client-1", "secret-1"))
			if err := tc.register(p); err != nil {
				t.Fatalf("register: %v", err)
			}
			auth, path, body := ws.snap()
			if auth != "Bearer tok-client-1" {
				t.Fatalf("bearer not attached: %q", auth)
			}
			if path != tc.wantPath {
				t.Fatalf("path: want %s got %s", tc.wantPath, path)
			}
			var sent struct {
				WebhookURL string `json:"webhookUrl"`
			}
			if err := json.Unmarshal(body, &sent); err != nil || sent.WebhookURL != testRecWebhookURL {
				t.Fatalf("webhookUrl not transported: %s (err %v)", body, err)
			}
			reg, err := tc.confirm(p)
			if err != nil {
				t.Fatalf("confirm: %v", err)
			}
			if reg.WebhookURL == "" || reg.CreatedAt.IsZero() {
				t.Fatalf("readback incomplete: %+v", reg)
			}
		})
	}
}

// A non-HTTPS callback is refused at the boundary before any call is made.
func TestRegisterRecurrenceWebhookRejectsNonHTTPS(t *testing.T) {
	t.Parallel()
	ws := newRecWebhookServer(t)
	p := ws.provider(t, oneTenant("t1", "c", "s"))
	if err := p.RegisterRecWebhook(context.Background(), "t1", "http://insecure.example/cb"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("rec want validation, got %v", err)
	}
	if err := p.RegisterCobRWebhook(context.Background(), "t1", "ftp://nope"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("cobr want validation, got %v", err)
	}
	if _, _, body := ws.snap(); body != nil {
		t.Fatal("a refused non-HTTPS url must not reach the PSP")
	}
}

// An empty tenant is refused on both register and read.
func TestRecurrenceWebhookEmptyTenant(t *testing.T) {
	t.Parallel()
	ws := newRecWebhookServer(t)
	p := ws.provider(t, oneTenant("t1", "c", "s"))
	if err := p.RegisterRecWebhook(context.Background(), "", testRecWebhookURL); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("register want validation, got %v", err)
	}
	if _, err := p.GetCobRWebhook(context.Background(), ""); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("get want validation, got %v", err)
	}
}

// A PSP non-2xx is mapped to a domain error (a 404 on the singleton GET → NotFound).
func TestRecurrenceWebhookReadNotFound(t *testing.T) {
	t.Parallel()
	ws := newRecWebhookServer(t)
	ws.getStatus = http.StatusNotFound
	p := ws.provider(t, oneTenant("t1", "c", "s"))
	if _, err := p.GetRecWebhook(context.Background(), "t1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want not found, got %v", err)
	}
}

// A PSP error status on register surfaces as a domain error (does not silently pass).
func TestRecurrenceWebhookRegisterServerError(t *testing.T) {
	t.Parallel()
	ws := newRecWebhookServer(t)
	ws.putStatus = http.StatusInternalServerError
	p := ws.provider(t, oneTenant("t1", "c", "s"))
	if err := p.RegisterCobRWebhook(context.Background(), "t1", testRecWebhookURL); err == nil {
		t.Fatal("want error on 500, got nil")
	}
}

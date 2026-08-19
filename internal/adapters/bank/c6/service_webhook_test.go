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
)

// The C6-proprietary webhook surface (/v1/webhooks) was live-discovered, and three of its
// properties are the OPPOSITE of the BACEN surface next door. Each of them cost a
// round-trip against the real bank to learn, and none is visible from the type system, so
// they are pinned here: POST (not PUT), body field `url` (not `webhookUrl`), and
// Accept: application/json (not application/problem+json). A refactor that unifies the two
// families would break settlement notifications for checkout/boleto in a way that only
// shows up against the real PSP.

type serviceWebhookDouble struct {
	*httptest.Server

	mu          sync.Mutex
	lastMethod  string
	lastAccept  string
	lastBody    []byte
	lastQuery   string
	getStatus   int
	getResponse string
}

func newServiceWebhookDouble(t *testing.T) *serviceWebhookDouble {
	t.Helper()
	d := &serviceWebhookDouble{getStatus: http.StatusNotFound, getResponse: `{}`}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /oauth/token", func(w http.ResponseWriter, r *http.Request) {
		user, _, _ := r.BasicAuth()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok-` + user + `","token_type":"Bearer","expires_in":3600}`))
	})
	mux.HandleFunc("/v1/webhooks", func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		d.lastMethod = r.Method
		d.lastAccept = r.Header.Get("Accept")
		d.lastQuery = r.URL.Query().Get("service")
		d.lastBody, _ = io.ReadAll(io.LimitReader(r.Body, 1<<20))
		status, resp := d.getStatus, d.getResponse
		d.mu.Unlock()

		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write([]byte(resp))
			return
		}
		w.WriteHeader(http.StatusCreated)
	})

	d.Server = httptest.NewTLSServer(mux)
	t.Cleanup(d.Close)
	return d
}

func (d *serviceWebhookDouble) provider(t *testing.T) *Provider {
	t.Helper()
	p, err := New(Config{
		BaseURL:    d.URL,
		TokenURL:   d.URL + "/oauth/token",
		HTTPClient: d.Client(),
	}, oneTenant("t1", "client-1", "secret-1"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func (d *serviceWebhookDouble) snapshot() (method, accept, query string, body []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.lastMethod, d.lastAccept, d.lastQuery, d.lastBody
}

const serviceCallbackURL = "https://payment.lmhost.com.br/webhooks/c6/super-secret-ref"

func TestRegisterServiceWebhookWireContract(t *testing.T) {
	t.Parallel()
	d := newServiceWebhookDouble(t)
	p := d.provider(t)

	if err := p.RegisterServiceWebhook(context.Background(), "t1", ServiceCheckout, serviceCallbackURL); err != nil {
		t.Fatalf("RegisterServiceWebhook: %v", err)
	}
	method, accept, _, body := d.snapshot()

	if method != http.MethodPost {
		t.Fatalf("method = %s, want POST — C6 answers PUT with 400 %q", method, "PUT operation not allowed")
	}
	if accept != "application/json" {
		t.Fatalf("Accept = %q, want application/json — this family REJECTS application/problem+json", accept)
	}
	var sent map[string]string
	if err := json.Unmarshal(body, &sent); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if sent["url"] != serviceCallbackURL {
		t.Fatalf("body must carry the callback under %q (not webhookUrl): %s", "url", body)
	}
	if sent["service"] != ServiceCheckout {
		t.Fatalf("service = %q, want %q", sent["service"], ServiceCheckout)
	}
}

// The service discriminator rides as a QUERY parameter on the read, not in the path.
func TestGetServiceWebhookSendsServiceQueryParam(t *testing.T) {
	t.Parallel()
	d := newServiceWebhookDouble(t)
	d.getStatus = http.StatusOK
	d.getResponse = `{"url":"` + serviceCallbackURL + `"}`
	p := d.provider(t)

	got, err := p.GetServiceWebhook(context.Background(), "t1", ServiceCheckout)
	if err != nil {
		t.Fatalf("GetServiceWebhook: %v", err)
	}
	if got.WebhookURL != serviceCallbackURL {
		t.Fatalf("WebhookURL = %q, want %q", got.WebhookURL, serviceCallbackURL)
	}
	method, accept, query, _ := d.snapshot()
	if method != http.MethodGet || query != ServiceCheckout || accept != "application/json" {
		t.Fatalf("read contract broken: method=%s service=%q accept=%q", method, query, accept)
	}
}

// An unregistered service is ErrNotFound, so a caller can treat it as "not set up yet"
// rather than a fault.
func TestGetServiceWebhookUnregisteredIsNotFound(t *testing.T) {
	t.Parallel()
	d := newServiceWebhookDouble(t)
	p := d.provider(t)

	_, err := p.GetServiceWebhook(context.Background(), "t1", ServiceCheckout)
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

// Complete mediation at the boundary: a typo'd service or a non-HTTPS callback is refused
// locally, so it surfaces as a validation error instead of an opaque PSP 400.
func TestServiceWebhookValidatesAtBoundary(t *testing.T) {
	t.Parallel()
	d := newServiceWebhookDouble(t)
	p := d.provider(t)
	ctx := context.Background()

	cases := []struct {
		name, tenant, service, url string
	}{
		{"unknown service", "t1", "PIX_MAGIC", serviceCallbackURL},
		{"non-https callback", "t1", ServiceCheckout, "http://payment.lmhost.com.br/webhooks/c6/ref"},
		{"empty tenant", "", ServiceCheckout, serviceCallbackURL},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := p.RegisterServiceWebhook(ctx, tc.tenant, tc.service, tc.url)
			if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("err = %v, want ErrValidation", err)
			}
		})
	}
}

// Service names are normalised, so an operator passing "checkout" is not silently rejected
// by the PSP for a case mismatch.
func TestRegisterServiceWebhookNormalisesService(t *testing.T) {
	t.Parallel()
	d := newServiceWebhookDouble(t)
	p := d.provider(t)

	if err := p.RegisterServiceWebhook(context.Background(), "t1", "checkout", serviceCallbackURL); err != nil {
		t.Fatalf("RegisterServiceWebhook: %v", err)
	}
	_, _, _, body := d.snapshot()
	var sent map[string]string
	_ = json.Unmarshal(body, &sent)
	if sent["service"] != ServiceCheckout {
		t.Fatalf("service = %q, want normalised %q", sent["service"], ServiceCheckout)
	}
}

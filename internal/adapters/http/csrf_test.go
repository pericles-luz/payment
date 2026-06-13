package http_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	httpadapter "github.com/ia-dev-sindireceita/payment/internal/adapters/http"
)

// echoCSRFHandler renders the CSRF token from the context so tests can read what
// a template would embed into the page.
var echoCSRFHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte(httpadapter.CSRFToken(r.Context())))
})

func csrfCookieValue(rec *httptest.ResponseRecorder) string {
	if c := csrfCookie(rec); c != nil {
		return c.Value
	}
	return ""
}

func csrfCookie(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == "csrf_token" {
			return c
		}
	}
	return nil
}

func TestCSRFSafeMethodMintsToken(t *testing.T) {
	t.Parallel()
	h := httpadapter.CSRFProtect(echoCSRFHandler)

	req := httptest.NewRequest(http.MethodGet, "/admin/form", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	cookie := csrfCookieValue(rec)
	if cookie == "" {
		t.Fatal("expected a csrf_token cookie to be set")
	}
	if body := rec.Body.String(); body == "" || body != cookie {
		t.Fatalf("rendered token %q must equal cookie %q", body, cookie)
	}
}

func TestCSRFRejectsMutationWithoutToken(t *testing.T) {
	t.Parallel()
	h := httpadapter.CSRFProtect(echoCSRFHandler)

	req := httptest.NewRequest(http.MethodPost, "/admin/save", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403 for POST without token, got %d", rec.Code)
	}
}

func TestCSRFAcceptsMatchingHeader(t *testing.T) {
	t.Parallel()
	h := httpadapter.CSRFProtect(echoCSRFHandler)

	// Mint a token via a safe request.
	get := httptest.NewRequest(http.MethodGet, "/admin/form", nil)
	getRec := httptest.NewRecorder()
	h.ServeHTTP(getRec, get)
	token := csrfCookieValue(getRec)
	if token == "" {
		t.Fatal("no token minted")
	}

	// Replay it as header + cookie on a mutation.
	post := httptest.NewRequest(http.MethodPost, "/admin/save", nil)
	post.AddCookie(&http.Cookie{Name: "csrf_token", Value: token})
	post.Header.Set(httpadapter.CSRFHeaderName, token)
	postRec := httptest.NewRecorder()
	h.ServeHTTP(postRec, post)
	if postRec.Code != http.StatusOK {
		t.Fatalf("want 200 with matching token, got %d", postRec.Code)
	}
}

func TestCSRFRejectsMismatchedHeader(t *testing.T) {
	t.Parallel()
	h := httpadapter.CSRFProtect(echoCSRFHandler)

	post := httptest.NewRequest(http.MethodPost, "/admin/save", nil)
	post.AddCookie(&http.Cookie{Name: "csrf_token", Value: "the-real-token"})
	post.Header.Set(httpadapter.CSRFHeaderName, "an-attacker-guess")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, post)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403 for mismatched token, got %d", rec.Code)
	}
}

func TestCSRFAcceptsMatchingFormField(t *testing.T) {
	t.Parallel()
	h := httpadapter.CSRFProtect(echoCSRFHandler)

	form := url.Values{httpadapter.CSRFFieldName: {"form-token"}}
	post := httptest.NewRequest(http.MethodPost, "/admin/save", strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.AddCookie(&http.Cookie{Name: "csrf_token", Value: "form-token"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, post)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200 with matching form field, got %d", rec.Code)
	}
}

// TestCSRFCookieSecureFlag asserts the Secure attribute follows the configured
// policy and NOT per-request TLS (SIN-64731 L2). The request is plaintext
// (r.TLS == nil), exactly the production case behind a TLS-terminating proxy, so
// sniffing r.TLS would wrongly drop Secure; config must drive it instead.
func TestCSRFCookieSecureFlag(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		secure bool
	}{
		{"secure cookies enabled", true},
		{"secure cookies disabled (local dev)", false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := httpadapter.NewCSRFGuard(tc.secure).Protect(echoCSRFHandler)

			req := httptest.NewRequest(http.MethodGet, "http://admin.local/admin/form", nil)
			if req.TLS != nil {
				t.Fatal("precondition: request must be non-TLS to model the proxy case")
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			c := csrfCookie(rec)
			if c == nil {
				t.Fatal("expected a csrf_token cookie to be set")
			}
			if c.Secure != tc.secure {
				t.Fatalf("cookie Secure=%v, want %v regardless of r.TLS", c.Secure, tc.secure)
			}
			if !c.HttpOnly {
				t.Fatal("csrf cookie must remain HttpOnly")
			}
		})
	}
}

// TestCSRFProtectSecureByDefault pins that the package-level CSRFProtect (callers
// that do not thread config) mints Secure cookies — secure-by-default.
func TestCSRFProtectSecureByDefault(t *testing.T) {
	t.Parallel()
	h := httpadapter.CSRFProtect(echoCSRFHandler)
	req := httptest.NewRequest(http.MethodGet, "/admin/form", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	c := csrfCookie(rec)
	if c == nil || !c.Secure {
		t.Fatalf("package-level CSRFProtect must default to Secure cookies; got %+v", c)
	}
}

func TestCSRFReusesExistingCookie(t *testing.T) {
	t.Parallel()
	h := httpadapter.CSRFProtect(echoCSRFHandler)

	req := httptest.NewRequest(http.MethodGet, "/admin/form", nil)
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "preexisting"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if body := rec.Body.String(); body != "preexisting" {
		t.Fatalf("want existing token reused, got %q", body)
	}
}

package http

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
)

// CSRF protection for the browser-served HTMX admin console (/console).
//
// Auth transport (ADR-0001, docs/security): the console today authenticates only
// via the Authorization: Bearer header — injected at the reverse proxy from an
// edge-authenticated session — with no first-party session cookie. Because the
// bearer header is not an ambient credential, a cross-origin attacker cannot
// forge it, so this double-submit guard is currently belt-and-suspenders
// (defense-in-depth) rather than load-bearing. It is kept wired so that if the
// service later adopts a session cookie (ADR-0001 Option B), the model is already
// in place and becomes load-bearing without a redesign. The JSON tenant/admin API
// likewise authenticates by Bearer token and is not CSRF-exposed.
//
// Strategy: double-submit token. On a safe request the middleware mints a random
// token, sets it in a cookie and exposes the same value via CSRFToken(ctx) so a
// template can echo it into the page. On a mutating request (POST/PUT/PATCH/
// DELETE) the submitted token (header or form field) must equal the cookie,
// compared in constant time. The cookie is HttpOnly, so the only way to learn
// the token is to render it server-side into a same-origin page — a cross-origin
// attacker can do neither.
const (
	// csrfCookieName is the cookie carrying the per-session CSRF token.
	csrfCookieName = "csrf_token"
	// CSRFHeaderName is the request header HTMX should send the token in (wire it
	// once with hx-headers='{"X-CSRF-Token": "<token>"}' on the admin <body>).
	CSRFHeaderName = "X-CSRF-Token"
	// CSRFFieldName is the hidden form-field name for non-HTMX/plain-form fallback.
	CSRFFieldName = "csrf_token"
	// csrfTokenBytes is the entropy of a freshly minted token (256 bits).
	csrfTokenBytes = 32
)

// newCSRFToken returns a URL-safe random token.
func newCSRFToken() (string, error) {
	b := make([]byte, csrfTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// CSRFGuard issues and verifies double-submit CSRF tokens. It carries the
// deployment's Secure-cookie policy so the token cookie's Secure attribute is
// driven by config (unspoofable) rather than per-request TLS state — the service
// terminates TLS at a proxy and serves plaintext, so r.TLS is always nil in
// production. The admin-UI child constructs its own guard (or reuses the server's
// via Server.CSRF) so its session cookie inherits the same policy.
type CSRFGuard struct {
	secureCookies bool
}

// NewCSRFGuard builds a guard whose minted cookies carry Secure=secureCookies.
func NewCSRFGuard(secureCookies bool) CSRFGuard { return CSRFGuard{secureCookies: secureCookies} }

// defaultCSRFGuard backs the package-level CSRFProtect. It is secure-by-default:
// callers that do not thread config still get Secure cookies.
var defaultCSRFGuard = CSRFGuard{secureCookies: true}

// middleware enforces double-submit CSRF protection on mutating requests and
// ensures a token cookie exists on safe ones.
func (g CSRFGuard) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(csrfCookieName)
		token := ""
		if err == nil {
			token = cookie.Value
		}

		if isSafeMethod(r.Method) {
			// Ensure a token exists so the rendered page can carry it.
			if token == "" {
				minted, mErr := newCSRFToken()
				if mErr != nil {
					writeError(w, http.StatusInternalServerError, "internal error")
					return
				}
				token = minted
				setCSRFCookie(w, g.secureCookies, token)
			}
			ctx := context.WithValue(r.Context(), ctxCSRFToken, token)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// Mutating method: the cookie token must exist and match the submitted one.
		submitted := r.Header.Get(CSRFHeaderName)
		if submitted == "" {
			submitted = r.PostFormValue(CSRFFieldName)
		}
		if token == "" || submitted == "" ||
			subtle.ConstantTimeCompare([]byte(token), []byte(submitted)) != 1 {
			writeError(w, http.StatusForbidden, "forbidden")
			return
		}
		ctx := context.WithValue(r.Context(), ctxCSRFToken, token)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Protect is the reusable middleware the admin-UI child wraps its browser/HTML
// routes with. Compose it after the auth middleware so only authenticated
// sessions mint tokens.
func (g CSRFGuard) Protect(next http.Handler) http.Handler { return g.middleware(next) }

// CSRFProtect wraps a handler with the secure-by-default guard. It is retained
// for callers that do not thread the Secure-cookie config; production wiring
// should prefer Server.CSRF().Protect so the configured policy applies.
func CSRFProtect(next http.Handler) http.Handler { return defaultCSRFGuard.Protect(next) }

// CSRFToken returns the CSRF token for the current request so a template can
// render it into the form / hx-headers. Empty if the request did not pass
// through csrfMiddleware.
func CSRFToken(ctx context.Context) string {
	if v, ok := ctx.Value(ctxCSRFToken).(string); ok {
		return v
	}
	return ""
}

// setCSRFCookie writes the token cookie. HttpOnly so JS cannot read it; SameSite
// Lax and Secure as defense-in-depth alongside the double-submit check. Secure is
// driven by the deployment's config (secure), not per-request TLS: the service
// runs plaintext behind a TLS-terminating proxy, so sniffing r.TLS would never
// set Secure in production and the cookie could leak over a plaintext hop.
func setCSRFCookie(w http.ResponseWriter, secure bool, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// isSafeMethod reports whether the method is read-only per RFC 7231 (no CSRF
// token required).
func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	default:
		return false
	}
}

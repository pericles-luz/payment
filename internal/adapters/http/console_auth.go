package http

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/adminweb"
	"github.com/ia-dev-sindireceita/payment/internal/app"
)

// console_auth.go implements the self-contained console login (ADR-0001 Opção B,
// SIN-69265): the session-or-Bearer auth middleware for /console, the login /
// logout handlers, and the gated first-access bootstrap. The domain (password +
// TOTP + session) and the use-cases (app.ConsoleAuthService) do the security work;
// this file owns only the HTTP concerns — the session cookie, form parsing, and
// rendering — layered on the existing CSRF double-submit and per-IP rate limiting.

const (
	// sessionCookieName carries ONLY the opaque server-side session id. Scoped to
	// /console so it is never sent to the JSON /admin or /v1 planes.
	sessionCookieName = "console_session"
	// sessionCookiePath scopes the session cookie to the console surface.
	sessionCookiePath = "/console"
)

// consoleRateKey keys the authenticated console limiter by the caller's identity:
// the admin Bearer (hashed) when present, else the session cookie (hashed) so a
// cookie-authenticated operator gets a stable bucket, else the client IP. Secrets
// are hashed so the limiter never holds a raw token/session id as a map key.
func consoleRateKey(r *http.Request) string {
	if tok := bearerToken(r); tok != "" {
		sum := sha256.Sum256([]byte(tok))
		return "admin:" + base64.RawURLEncoding.EncodeToString(sum[:])
	}
	if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" {
		sum := sha256.Sum256([]byte(c.Value))
		return "sess:" + base64.RawURLEncoding.EncodeToString(sum[:])
	}
	return "ip:" + clientIP(r)
}

// consoleAuthMiddleware admits a /console request authenticated by EITHER the
// existing admin Bearer token (retrocompat with ADR-0001 Opção A) OR a valid
// first-party session cookie (Opção B). Deny-by-default: a present-but-invalid
// Bearer is rejected outright (no silent fallthrough); with no Bearer, a valid
// session cookie authorizes the single operator as a full admin. Anything else is
// denied — a browser navigation is redirected to the login page, everything else
// gets a 401.
func (s *Server) consoleAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1) Admin Bearer (keeps the JSON-plane transport and existing tests working).
		if tok := bearerToken(r); tok != "" {
			if p, ok := s.adminAuth.AuthenticateAdminPrincipal(tok); ok {
				ctx := context.WithValue(r.Context(), ctxRole, p.Role)
				ctx = app.WithOperatorID(ctx, p.OperatorID)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
			// A bad Bearer must not silently fall through to the cookie path.
			s.consoleAuthDeny(w, r)
			return
		}

		// 2) First-party session cookie. The single operator is a full admin
		// (board direction): read + write access to the whole console.
		if s.consoleAuth != nil {
			if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" {
				if subject, ok := s.consoleAuth.Authenticate(r.Context(), c.Value); ok {
					ctx := context.WithValue(r.Context(), ctxRole, RoleAdmin)
					ctx = app.WithOperatorID(ctx, "console:"+subject)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}
		}

		s.consoleAuthDeny(w, r)
	})
}

// consoleAuthDeny denies an unauthenticated console request. A top-level browser
// navigation (GET, not an htmx swap, that accepts HTML) is redirected to the login
// page for a usable flow; every other shape (htmx fragment, non-GET, API client)
// gets a uniform 401 so the deny-by-default contract — and the existing
// HX-Request-based tests — are preserved.
func (s *Server) consoleAuthDeny(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet &&
		r.Header.Get("HX-Request") != "true" &&
		strings.Contains(r.Header.Get("Accept"), "text/html") {
		http.Redirect(w, r, "/console/login", http.StatusSeeOther)
		return
	}
	writeError(w, http.StatusUnauthorized, "unauthorized")
}

// --- Login ---

// consoleLoginForm renders the public login page. An already-authenticated
// operator (valid session cookie) is bounced straight to the console. The
// double-submit CSRF token seeded by the guard is echoed into the form.
func (s *Server) consoleLoginForm(w http.ResponseWriter, r *http.Request) {
	if s.consoleAuthenticated(r) {
		http.Redirect(w, r, "/console", http.StatusSeeOther)
		return
	}
	s.renderLogin(w, r, http.StatusOK, "")
}

// consoleLogin verifies username + password + TOTP and, on success, sets the
// session cookie and redirects to the console. Every failure re-renders the login
// page with the single generic message (no enumeration) and a 401. The CSRF
// double-submit and per-IP limiter are applied by the router group.
func (s *Server) consoleLogin(w http.ResponseWriter, r *http.Request) {
	if s.consoleAuth == nil {
		s.renderLogin(w, r, http.StatusServiceUnavailable, "login indisponível")
		return
	}
	username := strings.TrimSpace(r.PostFormValue("username"))
	password := r.PostFormValue("password")
	code := strings.TrimSpace(r.PostFormValue("totp"))

	id, err := s.consoleAuth.Login(r.Context(), username, password, code)
	if err != nil {
		// One generic message for every failure (bad user/password/TOTP or lockout).
		s.renderLogin(w, r, http.StatusUnauthorized, loginErrorMessage(err))
		return
	}
	setSessionCookie(w, s.csrf.secureCookies, id)
	http.Redirect(w, r, "/console", http.StatusSeeOther)
}

// consoleLogout revokes the current session and clears the cookie, then redirects
// to the login page. Idempotent: no session is still a clean redirect.
func (s *Server) consoleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" && s.consoleAuth != nil {
		_ = s.consoleAuth.Logout(r.Context(), c.Value)
	}
	clearSessionCookie(w, s.csrf.secureCookies)
	http.Redirect(w, r, "/console/login", http.StatusSeeOther)
}

// consoleAuthenticated reports whether the request already carries a valid
// session cookie (used to skip the login form for a logged-in operator).
func (s *Server) consoleAuthenticated(r *http.Request) bool {
	if s.consoleAuth == nil {
		return false
	}
	c, err := r.Cookie(sessionCookieName)
	if err != nil || c.Value == "" {
		return false
	}
	_, ok := s.consoleAuth.Authenticate(r.Context(), c.Value)
	return ok
}

// renderLogin renders the login page with an optional generic error. It exposes
// whether first-access bootstrap is still available (enabled AND not yet
// provisioned) so the page can surface the one-time provisioning link.
func (s *Server) renderLogin(w http.ResponseWriter, r *http.Request, status int, errMsg string) {
	view := adminweb.LoginView{
		CSRF:             CSRFToken(r.Context()),
		Username:         s.consoleUsername(),
		Error:            errMsg,
		BootstrapVisible: s.bootstrapAvailable(r),
	}
	s.ui.LoginPage(w, status, view)
}

// --- Bootstrap (first access) ---

// consoleBootstrapForm renders the first-access provisioning form. It is
// failure-closed: when bootstrap is disabled (no deploy token configured) the
// route 404s so its existence is not even advertised. Once a credential is
// provisioned it renders a "locked" notice instead of a form.
func (s *Server) consoleBootstrapForm(w http.ResponseWriter, r *http.Request) {
	if !s.bootstrapEnabled() {
		http.NotFound(w, r)
		return
	}
	view := adminweb.BootstrapView{
		CSRF:        CSRFToken(r.Context()),
		Provisioned: s.consoleAuth.Provisioned(r.Context()),
	}
	s.ui.BootstrapPage(w, http.StatusOK, view)
}

// consoleBootstrap provisions the operator credential once, gated by the deploy
// bootstrap token. Disabled ⇒ 404. On success it renders the generated password +
// otpauth URI EXACTLY once (never persisted in plaintext, never logged). A wrong
// token or an already-provisioned box re-renders the form with a generic notice
// and the appropriate status. CSRF + per-IP limiter applied by the router group.
func (s *Server) consoleBootstrap(w http.ResponseWriter, r *http.Request) {
	if !s.bootstrapEnabled() {
		http.NotFound(w, r)
		return
	}
	token := r.PostFormValue("token")
	res, err := s.consoleAuth.Bootstrap(r.Context(), token)
	if err != nil {
		status, msg := bootstrapError(err)
		s.ui.BootstrapPage(w, status, adminweb.BootstrapView{
			CSRF:        CSRFToken(r.Context()),
			Provisioned: errors.Is(err, app.ErrBootstrapLocked),
			Error:       msg,
		})
		return
	}
	s.ui.BootstrapPage(w, http.StatusOK, adminweb.BootstrapView{
		CSRF: CSRFToken(r.Context()),
		Result: &adminweb.BootstrapResultView{
			Username:   res.Username,
			Password:   res.Password,
			TOTPSecret: res.TOTPSecret,
			OTPAuthURI: res.OTPAuthURI,
		},
	})
}

// --- helpers ---

func (s *Server) consoleUsername() string {
	if s.consoleAuth == nil {
		return ""
	}
	return s.consoleAuth.Username()
}

func (s *Server) bootstrapEnabled() bool {
	return s.consoleAuth != nil && s.consoleAuth.BootstrapEnabled()
}

// bootstrapAvailable reports whether the login page should offer the first-access
// link: bootstrap enabled AND no credential provisioned yet.
func (s *Server) bootstrapAvailable(r *http.Request) bool {
	return s.bootstrapEnabled() && !s.consoleAuth.Provisioned(r.Context())
}

// loginErrorMessage returns the single generic login failure message. It is a
// function (not a constant echo of err) so a future need to special-case, say, a
// service-unavailable error has one place to change; today every login failure is
// identical (no enumeration oracle).
func loginErrorMessage(err error) string {
	if errors.Is(err, app.ErrConsoleAuthUnavailable) {
		return "login indisponível"
	}
	return "credenciais inválidas"
}

// bootstrapError maps a bootstrap failure to an HTTP status + operator-facing
// message. The operator provisioning the box is trusted with WHY it was refused
// (unlike the login path), but the messages still never leak the token.
func bootstrapError(err error) (int, string) {
	switch {
	case errors.Is(err, app.ErrBootstrapLocked):
		return http.StatusConflict, "Credencial já provisionada. O bootstrap é de uso único."
	case errors.Is(err, app.ErrBootstrapForbidden), errors.Is(err, app.ErrBootstrapDisabled):
		return http.StatusForbidden, "Token de bootstrap inválido."
	default:
		return http.StatusInternalServerError, "Não foi possível provisionar a credencial."
	}
}

// setSessionCookie writes the session cookie carrying the opaque id. HttpOnly (JS
// cannot read it), Secure driven by the deployment config (TLS terminates at the
// proxy, so r.TLS is unreliable), SameSite=Lax so a top-level navigation to the
// console still carries it while cross-site POSTs do not. Scoped to /console.
func setSessionCookie(w http.ResponseWriter, secure bool, id string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    id,
		Path:     sessionCookiePath,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// clearSessionCookie expires the session cookie (logout / stale id).
func clearSessionCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     sessionCookiePath,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

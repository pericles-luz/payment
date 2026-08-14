package adminweb

import (
	"bytes"
	"net/http"
)

// auth.go renders the standalone console login and first-access bootstrap pages
// (self-contained login, ADR-0001 Opção B / SIN-69265). These pages render for
// UNauthenticated callers, so they use their own minimal layout — no sidebar, no
// operator label — and reuse only the public static stylesheet. Output is
// auto-escaped by html/template (the generated bootstrap password and otpauth URI
// are shown verbatim but safely encoded). No secret is ever logged here.

// LoginView is the view-model for the login page.
type LoginView struct {
	// CSRF is the double-submit token echoed into the form's hidden field.
	CSRF string
	// Username pre-fills the (fixed) operator login for convenience.
	Username string
	// Error is a single generic message shown on a failed attempt (empty on the
	// first render) — never distinguishes which factor failed.
	Error string
	// BootstrapVisible offers the first-access provisioning link (bootstrap enabled
	// AND not yet provisioned).
	BootstrapVisible bool
}

// BootstrapView is the view-model for the first-access provisioning page. Exactly
// one of Result (success — show credentials once) or the form is meaningful;
// Provisioned/Error drive the form-side notices.
type BootstrapView struct {
	CSRF string
	// Provisioned is true once a credential exists: the form is replaced by a
	// "locked / single-use" notice.
	Provisioned bool
	// Error is an operator-facing message for a refused attempt (bad token, etc.).
	Error string
	// Result is non-nil only immediately after a successful bootstrap; it carries
	// the one-time credentials to display.
	Result *BootstrapResultView
}

// BootstrapResultView carries the one-time generated credentials shown after a
// successful bootstrap. It is rendered once and never persisted in plaintext.
type BootstrapResultView struct {
	Username   string
	Password   string
	TOTPSecret string
	OTPAuthURI string
}

// LoginPage renders the login page.
func (rd *Renderer) LoginPage(w http.ResponseWriter, status int, data LoginView) {
	rd.renderAuth(w, status, "auth_login", data)
}

// BootstrapPage renders the first-access bootstrap page.
func (rd *Renderer) BootstrapPage(w http.ResponseWriter, status int, data BootstrapView) {
	rd.renderAuth(w, status, "auth_bootstrap", data)
}

// renderAuth executes a standalone auth template into a buffer (clean 500 on a
// template error) and writes it as HTML.
func (rd *Renderer) renderAuth(w http.ResponseWriter, status int, name string, data any) {
	var buf bytes.Buffer
	if err := rd.auth.ExecuteTemplate(&buf, name, data); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeHTML(w, status, buf.Bytes())
}

// Package adminweb is the presentation layer for the server-rendered HTMX admin
// console (wireframes SIN-64707). It owns the html/template set, the view-model
// projections and the embedded static assets, exposing a small Renderer the HTTP
// driving adapter calls. Security/transport concerns (authentication, RBAC, CSRF,
// routing) live in the HTTP adapter on top of the merged security spine
// (SIN-64726) — this package renders, it does not authorize.
//
// Output is auto-escaped by html/template (XSS defense). No secret value is ever
// projected into a view model or rendered: credential management is write-only.
package adminweb

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"net/http"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

// screenFiles are the per-screen template files. Each defines a "body" template
// and is cloned onto the shared base (layout + partials) so it can render both
// the full page ("layout") and the htmx fragment ("body").
var screenFiles = map[string]string{
	"tenants_list":  "templates/tenants_list.html",
	"tenant_new":    "templates/tenant_new.html",
	"tenant_detail": "templates/tenant_detail.html",
	"credentials":   "templates/credentials.html",
	"banks":         "templates/banks.html",
	"bank_detail":   "templates/bank_detail.html",
	"pricing":       "templates/pricing.html",
	"consumption":   "templates/consumption.html",
	"invoices":      "templates/invoices.html",
	// Accounts (two-level tenancy admin, SIN-69157 / spec SIN-69122).
	"accounts_list":       "templates/accounts_list.html",
	"account_new":         "templates/account_new.html",
	"account_detail":      "templates/account_detail.html",
	"account_tenant_new":  "templates/account_tenant_new.html",
	"account_consumption": "templates/account_consumption.html",
	"account_invoices":    "templates/account_invoices.html",
}

// Renderer holds the parsed template sets. base carries the layout and all
// shared partials; pages maps a screen name to its cloned, body-bearing set; auth
// carries the standalone, layout-free login/bootstrap pages (SIN-69265) — they
// render for UNauthenticated callers, so they deliberately do not use the admin
// shell (no nav, no operator label).
type Renderer struct {
	base  *template.Template
	pages map[string]*template.Template
	auth  *template.Template
}

// New parses the embedded templates, returning an error if any fails to parse so
// wiring fails fast at startup (never at first request).
func New() (*Renderer, error) {
	base, err := template.New("base").ParseFS(templateFS, "templates/layout.html", "templates/partials.html")
	if err != nil {
		return nil, fmt.Errorf("parse base templates: %w", err)
	}
	pages := make(map[string]*template.Template, len(screenFiles))
	for name, file := range screenFiles {
		clone, err := base.Clone()
		if err != nil {
			return nil, fmt.Errorf("clone base for %s: %w", name, err)
		}
		if _, err := clone.ParseFS(templateFS, file); err != nil {
			return nil, fmt.Errorf("parse screen %s: %w", name, err)
		}
		pages[name] = clone
	}
	// Standalone auth pages (login + bootstrap): parsed as their own set so they can
	// render a full page without the authenticated admin shell.
	auth, err := template.New("auth").ParseFS(templateFS, "templates/auth_login.html", "templates/auth_bootstrap.html")
	if err != nil {
		return nil, fmt.Errorf("parse auth templates: %w", err)
	}
	return &Renderer{base: base, pages: pages, auth: auth}, nil
}

// isHX reports whether the request came from htmx (a partial swap is expected).
func isHX(r *http.Request) bool { return r.Header.Get("HX-Request") == "true" }

// Page renders a screen: the full layout for normal navigations, or just the
// "body" fragment for htmx swaps. Output is buffered so a template error yields a
// clean 500 instead of a half-written response.
func (rd *Renderer) Page(w http.ResponseWriter, r *http.Request, screen string, status int, data any) {
	tmpl, ok := rd.pages[screen]
	if !ok {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	def := "layout"
	if isHX(r) {
		def = "body"
	}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, def, data); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeHTML(w, status, buf.Bytes())
}

// Partial renders a named shared partial (e.g. "tenant_rows") to the response.
func (rd *Renderer) Partial(w http.ResponseWriter, status int, name string, data any) {
	var buf bytes.Buffer
	if err := rd.base.ExecuteTemplate(&buf, name, data); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeHTML(w, status, buf.Bytes())
}

// OOBPart is one named partial to render in an out-of-band htmx swap.
type OOBPart struct {
	Name string
	Data any
}

// Partials renders one or more shared partials concatenated into a single
// response — used for pure out-of-band swaps (e.g. status header + toast in one
// reply with hx-swap="none"). Output is buffered for clean error handling.
func (rd *Renderer) Partials(w http.ResponseWriter, status int, parts ...OOBPart) {
	var buf bytes.Buffer
	for _, p := range parts {
		if err := rd.base.ExecuteTemplate(&buf, p.Name, p.Data); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}
	writeHTML(w, status, buf.Bytes())
}

// BodyWithOOB renders a screen's "body" fragment followed by one or more
// out-of-band partials in a single htmx response (e.g. swap #main to the new
// view and inject a toast). Output is buffered for clean error handling.
func (rd *Renderer) BodyWithOOB(w http.ResponseWriter, status int, screen string, data any, parts ...OOBPart) {
	tmpl, ok := rd.pages[screen]
	if !ok {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "body", data); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	for _, p := range parts {
		if err := tmpl.ExecuteTemplate(&buf, p.Name, p.Data); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}
	writeHTML(w, status, buf.Bytes())
}

// allowedStatic restricts the embedded asset names the console will serve, with
// their content types (no directory traversal, no arbitrary file exposure).
var allowedStatic = map[string]string{
	"tokens.css":  "text/css; charset=utf-8",
	"app.css":     "text/css; charset=utf-8",
	"htmx.min.js": "application/javascript; charset=utf-8",
}

// ServeStatic serves a whitelisted embedded asset by base name. Unknown names
// 404 — the path is reduced to its base so traversal cannot escape the set.
func (rd *Renderer) ServeStatic(w http.ResponseWriter, name string) {
	ctype, ok := allowedStatic[name]
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	b, err := staticFS.ReadFile("static/" + name)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(b)
}

func writeHTML(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

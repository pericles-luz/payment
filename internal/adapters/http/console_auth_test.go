package http_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/adminweb"
	consoleauthstore "github.com/ia-dev-sindireceita/payment/internal/adapters/consoleauth"
	httpadapter "github.com/ia-dev-sindireceita/payment/internal/adapters/http"
	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// authClock is a fixed clock shared by the service and the TOTP computation so a
// generated code always lands in the current step.
type authClock struct{ t time.Time }

func (c authClock) Now() time.Time { return c.t }

// authFixture wires a console server with a real ConsoleAuthService over an
// in-memory store, so the login/session/bootstrap HTTP paths run end-to-end.
type authFixture struct {
	handler http.Handler
	svc     *app.ConsoleAuthService
	clock   authClock
}

func newAuthFixture(t *testing.T, cfg app.ConsoleAuthConfig) *authFixture {
	t.Helper()
	clk := authClock{t: time.Unix(1_700_000_000, 0).UTC()}
	mem := consoleauthstore.NewMemStore()
	svc := app.NewConsoleAuthService(mem, mem, mem, clk, cfg)

	store := persistence.NewStore()
	creds := secret.NewStore(map[string]ports.BankCredential{})
	if err := store.SaveTenant(context.Background(), tenant.Rehydrate("t1", "Acme", true, time.Unix(100, 0).UTC())); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	console := app.NewConsoleService(app.ConsoleDeps{
		Tenants: store, Pricing: store, Ledger: store, CredWriter: creds, CredReader: creds,
		Clock: fixedClock{}, IDs: &seqIDs{},
	})
	ui, err := adminweb.New()
	if err != nil {
		t.Fatalf("renderer: %v", err)
	}
	auth := httpadapter.NewStaticTokenAuthWithRoles(nil, map[string]httpadapter.Role{
		adminToken: httpadapter.RoleAdmin,
	}, nil)
	srv := httpadapter.NewServer(httpadapter.Config{
		Console: console, ConsoleAuth: svc, UI: ui,
		AdminAuth: auth, TenantAuth: auth, WebhookAuth: auth,
	})
	return &authFixture{handler: srv.Router(), svc: svc, clock: clk}
}

func totpCode(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(at.Unix()/30))
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[off]&0x7f) << 24) | (uint32(sum[off+1]) << 16) | (uint32(sum[off+2]) << 8) | uint32(sum[off+3])
	return fmt.Sprintf("%06d", bin%1_000_000)
}

// loginCSRF GETs the public login page and returns the minted csrf cookie.
func loginCSRF(t *testing.T, h http.Handler) *http.Cookie {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/console/login", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /console/login = %d, want 200", rec.Code)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "csrf_token" {
			return c
		}
	}
	t.Fatal("no csrf cookie on login page")
	return nil
}

func TestConsoleLoginPageRenders(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, app.ConsoleAuthConfig{BootstrapToken: "tok", Username: "pericles.luz"})
	req := httptest.NewRequest(http.MethodGet, "/console/login", nil)
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"Entrar", `name="username"`, `name="password"`, `name="totp"`, `name="csrf_token"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("login page missing %q", want)
		}
	}
	// Bootstrap enabled and not provisioned → first-access link shown.
	if !strings.Contains(body, "/console/bootstrap") {
		t.Fatal("first-access link should be present before provisioning")
	}
}

func TestConsoleLoginFullFlow(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, app.ConsoleAuthConfig{BootstrapToken: "tok", Username: "pericles.luz"})
	// Provision directly via the service to obtain the TOTP secret.
	res, err := f.svc.Bootstrap(context.Background(), "tok")
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}

	csrf := loginCSRF(t, f.handler)
	form := url.Values{
		"username": {"pericles.luz"},
		"password": {res.Password},
		"totp":     {totpCode(t, res.TOTPSecret, f.clock.Now())},
	}
	req := httptest.NewRequest(http.MethodPost, "/console/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(csrf)
	req.Header.Set("X-CSRF-Token", csrf.Value)
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("login status = %d, want 303 (body=%s)", rec.Code, rec.Body.String())
	}
	var sess *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "console_session" {
			sess = c
		}
	}
	if sess == nil || sess.Value == "" {
		t.Fatal("no session cookie set on successful login")
	}
	if !sess.HttpOnly {
		t.Fatal("session cookie must be HttpOnly")
	}
	if sess.SameSite != http.SameSiteLaxMode {
		t.Fatalf("session cookie SameSite = %v, want Lax", sess.SameSite)
	}

	// The session cookie (no bearer) now opens the console.
	req2 := httptest.NewRequest(http.MethodGet, "/console/tenants", nil)
	req2.AddCookie(sess)
	req2.Header.Set("HX-Request", "true")
	rec2 := httptest.NewRecorder()
	f.handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("session-authed console read = %d, want 200", rec2.Code)
	}

	// Logout revokes the session (CSRF-guarded).
	csrf2 := loginCSRF(t, f.handler)
	lo := httptest.NewRequest(http.MethodPost, "/console/logout", nil)
	lo.AddCookie(sess)
	lo.AddCookie(csrf2)
	lo.Header.Set("X-CSRF-Token", csrf2.Value)
	loRec := httptest.NewRecorder()
	f.handler.ServeHTTP(loRec, lo)
	if loRec.Code != http.StatusSeeOther {
		t.Fatalf("logout = %d, want 303", loRec.Code)
	}
	// After logout the same session id no longer authenticates.
	req3 := httptest.NewRequest(http.MethodGet, "/console/tenants", nil)
	req3.AddCookie(sess)
	req3.Header.Set("HX-Request", "true")
	rec3 := httptest.NewRecorder()
	f.handler.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusUnauthorized {
		t.Fatalf("post-logout read = %d, want 401", rec3.Code)
	}
}

func TestConsoleLoginWrongCredentials(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, app.ConsoleAuthConfig{BootstrapToken: "tok", Username: "pericles.luz"})
	if _, err := f.svc.Bootstrap(context.Background(), "tok"); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	csrf := loginCSRF(t, f.handler)
	form := url.Values{"username": {"pericles.luz"}, "password": {"wrong"}, "totp": {"000000"}}
	req := httptest.NewRequest(http.MethodPost, "/console/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(csrf)
	req.Header.Set("X-CSRF-Token", csrf.Value)
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong login = %d, want 401", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "credenciais inválidas") {
		t.Fatal("generic error message expected")
	}
	// No session cookie on failure.
	for _, c := range rec.Result().Cookies() {
		if c.Name == "console_session" && c.Value != "" {
			t.Fatal("no session cookie should be set on failed login")
		}
	}
}

func TestConsoleLoginRequiresCSRF(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, app.ConsoleAuthConfig{BootstrapToken: "tok", Username: "pericles.luz"})
	form := url.Values{"username": {"pericles.luz"}, "password": {"x"}, "totp": {"000000"}}
	// No csrf cookie/header → double-submit fails.
	req := httptest.NewRequest(http.MethodPost, "/console/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("login without CSRF = %d, want 403", rec.Code)
	}
}

func TestConsoleUnauthedBrowserRedirects(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, app.ConsoleAuthConfig{BootstrapToken: "tok"})
	// A top-level browser navigation (Accept text/html, not htmx) is redirected.
	req := httptest.NewRequest(http.MethodGet, "/console/tenants", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("browser nav = %d, want 303", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/console/login" {
		t.Fatalf("redirect location = %q, want /console/login", loc)
	}
	// An htmx request (no text/html accept) still gets a hard 401.
	req2 := httptest.NewRequest(http.MethodGet, "/console/tenants", nil)
	req2.Header.Set("HX-Request", "true")
	rec2 := httptest.NewRecorder()
	f.handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("htmx unauthed = %d, want 401", rec2.Code)
	}
}

func TestConsoleBearerStillWorks(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, app.ConsoleAuthConfig{BootstrapToken: "tok"})
	// The existing admin Bearer transport (ADR-0001 Opção A) is preserved.
	req := httptest.NewRequest(http.MethodGet, "/console/tenants", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("bearer console read = %d, want 200", rec.Code)
	}
	// An invalid bearer is denied outright (no silent fallthrough).
	req2 := httptest.NewRequest(http.MethodGet, "/console/tenants", nil)
	req2.Header.Set("Authorization", "Bearer nope")
	req2.Header.Set("HX-Request", "true")
	rec2 := httptest.NewRecorder()
	f.handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("bad bearer = %d, want 401", rec2.Code)
	}
}

func TestConsoleInvalidSessionCookieDenied(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, app.ConsoleAuthConfig{BootstrapToken: "tok"})
	req := httptest.NewRequest(http.MethodGet, "/console/tenants", nil)
	req.AddCookie(&http.Cookie{Name: "console_session", Value: "bogus"})
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bogus session = %d, want 401", rec.Code)
	}
}

func TestConsoleBootstrapDisabled404(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, app.ConsoleAuthConfig{}) // no bootstrap token
	for _, m := range []string{http.MethodGet, http.MethodPost} {
		req := httptest.NewRequest(m, "/console/bootstrap", nil)
		if m == http.MethodPost {
			csrf := loginCSRF(t, f.handler)
			req = httptest.NewRequest(m, "/console/bootstrap", strings.NewReader(url.Values{"token": {"x"}}.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.AddCookie(csrf)
			req.Header.Set("X-CSRF-Token", csrf.Value)
		}
		rec := httptest.NewRecorder()
		f.handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s bootstrap disabled = %d, want 404", m, rec.Code)
		}
	}
}

func TestConsoleBootstrapFlow(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, app.ConsoleAuthConfig{BootstrapToken: "deploy-secret", Username: "pericles.luz"})

	// GET form renders.
	greq := httptest.NewRequest(http.MethodGet, "/console/bootstrap", nil)
	grec := httptest.NewRecorder()
	f.handler.ServeHTTP(grec, greq)
	if grec.Code != http.StatusOK || !strings.Contains(grec.Body.String(), `name="token"`) {
		t.Fatalf("bootstrap form = %d", grec.Code)
	}

	post := func(token string) *httptest.ResponseRecorder {
		csrf := loginCSRF(t, f.handler)
		req := httptest.NewRequest(http.MethodPost, "/console/bootstrap", strings.NewReader(url.Values{"token": {token}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(csrf)
		req.Header.Set("X-CSRF-Token", csrf.Value)
		rec := httptest.NewRecorder()
		f.handler.ServeHTTP(rec, req)
		return rec
	}

	// Wrong token → 403.
	if rec := post("guess"); rec.Code != http.StatusForbidden {
		t.Fatalf("wrong token = %d, want 403", rec.Code)
	}
	// Right token → 200 with one-time credentials shown.
	rec := post("deploy-secret")
	if rec.Code != http.StatusOK {
		t.Fatalf("bootstrap = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"pericles.luz", "otpauth://totp/", "Segredo TOTP"} {
		if !strings.Contains(body, want) {
			t.Fatalf("bootstrap result missing %q", want)
		}
	}
	// Already provisioned → 409 locked.
	if rec := post("deploy-secret"); rec.Code != http.StatusConflict {
		t.Fatalf("second bootstrap = %d, want 409", rec.Code)
	}
}

// newBearerOnlyFixture builds a console server WITHOUT a ConsoleAuthService
// (ADR-0001 Opção A / retrocompat): login must fail closed and only a Bearer opens
// the console.
func newBearerOnlyFixture(t *testing.T) http.Handler {
	t.Helper()
	store := persistence.NewStore()
	creds := secret.NewStore(map[string]ports.BankCredential{})
	console := app.NewConsoleService(app.ConsoleDeps{
		Tenants: store, Pricing: store, Ledger: store, CredWriter: creds, CredReader: creds,
		Clock: fixedClock{}, IDs: &seqIDs{},
	})
	ui, err := adminweb.New()
	if err != nil {
		t.Fatalf("renderer: %v", err)
	}
	auth := httpadapter.NewStaticTokenAuthWithRoles(nil, map[string]httpadapter.Role{adminToken: httpadapter.RoleAdmin}, nil)
	srv := httpadapter.NewServer(httpadapter.Config{
		Console: console, UI: ui, AdminAuth: auth, TenantAuth: auth, WebhookAuth: auth,
	})
	return srv.Router()
}

func TestConsoleNilAuthServiceLoginUnavailable(t *testing.T) {
	t.Parallel()
	h := newBearerOnlyFixture(t)
	// The login page still renders (no bootstrap link, empty username).
	greq := httptest.NewRequest(http.MethodGet, "/console/login", nil)
	grec := httptest.NewRecorder()
	h.ServeHTTP(grec, greq)
	if grec.Code != http.StatusOK {
		t.Fatalf("login page = %d, want 200", grec.Code)
	}
	if strings.Contains(grec.Body.String(), "/console/bootstrap") {
		t.Fatal("no bootstrap link should show without a ConsoleAuthService")
	}
	// A login POST fails closed with 503 (service unavailable).
	var csrf *http.Cookie
	for _, c := range grec.Result().Cookies() {
		if c.Name == "csrf_token" {
			csrf = c
		}
	}
	form := url.Values{"username": {"x"}, "password": {"y"}, "totp": {"000000"}}
	req := httptest.NewRequest(http.MethodPost, "/console/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(csrf)
	req.Header.Set("X-CSRF-Token", csrf.Value)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("nil-service login = %d, want 503", rec.Code)
	}
	// Bearer still opens the console.
	breq := httptest.NewRequest(http.MethodGet, "/console/tenants", nil)
	breq.Header.Set("Authorization", "Bearer "+adminToken)
	breq.Header.Set("HX-Request", "true")
	brec := httptest.NewRecorder()
	h.ServeHTTP(brec, breq)
	if brec.Code != http.StatusOK {
		t.Fatalf("bearer read (nil service) = %d, want 200", brec.Code)
	}
}

func TestConsoleLoginRedirectsWhenAlreadyAuthed(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, app.ConsoleAuthConfig{BootstrapToken: "tok", Username: "pericles.luz"})
	res, err := f.svc.Bootstrap(context.Background(), "tok")
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	id, err := f.svc.Login(context.Background(), "pericles.luz", res.Password, totpCode(t, res.TOTPSecret, f.clock.Now()))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/console/login", nil)
	req.AddCookie(&http.Cookie{Name: "console_session", Value: id})
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("already-authed login page = %d, want 303", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/console" {
		t.Fatalf("redirect = %q, want /console", loc)
	}
}

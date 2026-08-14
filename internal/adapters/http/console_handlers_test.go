package http_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/adminweb"
	httpadapter "github.com/ia-dev-sindireceita/payment/internal/adapters/http"
	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/billing"
	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

const operatorToken = "optok"

type consoleFixture struct {
	handler http.Handler
	store   *persistence.Store
	creds   *secret.Store
	certs   *secret.CertStore
}

// newConsoleFixture builds a server wired with the HTML console over a real
// in-memory store, plus an admin and an operator token so the RBAC split is
// testable. A tenant "t1" is seeded.
func newConsoleFixture(t *testing.T) *consoleFixture {
	t.Helper()
	store := persistence.NewStore()
	creds := secret.NewStore(map[string]ports.BankCredential{})
	certs := secret.NewCertStore()
	if err := store.SaveTenant(context.Background(), tenant.Rehydrate("t1", "Acme", true, time.Unix(100, 0).UTC())); err != nil {
		t.Fatalf("seed: %v", err)
	}
	console := app.NewConsoleService(app.ConsoleDeps{
		Tenants: store, Pricing: store, Ledger: store, CredWriter: creds, CredReader: creds,
		CertWriter: certs, CertReader: certs,
		Clock: fixedClock{}, IDs: &seqIDs{},
	})
	ui, err := adminweb.New()
	if err != nil {
		t.Fatalf("renderer: %v", err)
	}
	auth := httpadapter.NewStaticTokenAuthWithRoles(nil, map[string]httpadapter.Role{
		adminToken:       httpadapter.RoleAdmin,
		secondAdminToken: httpadapter.RoleAdmin,
		operatorToken:    httpadapter.RoleOperator,
	}, nil)
	srv := httpadapter.NewServer(httpadapter.Config{
		Console: console, UI: ui, AdminAuth: auth, TenantAuth: auth, WebhookAuth: auth,
	})
	return &consoleFixture{handler: srv.Router(), store: store, creds: creds, certs: certs}
}

type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Unix(1000, 0).UTC() }

type seqIDs struct{ n int }

func (s *seqIDs) NewID() string { s.n++; return "gen-id" }

func consoleGet(t *testing.T, h http.Handler, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// csrfToken performs a safe GET to mint the double-submit cookie and returns it.
func csrfToken(t *testing.T, h http.Handler, token string) *http.Cookie {
	t.Helper()
	rec := consoleGet(t, h, "/console/tenants", token)
	for _, c := range rec.Result().Cookies() {
		if c.Name == "csrf_token" {
			return c
		}
	}
	t.Fatalf("no csrf cookie minted")
	return nil
}

// consolePost submits a form-encoded POST. When csrf is non-nil the cookie and a
// matching X-CSRF-Token header are attached (double-submit satisfied).
func consolePost(t *testing.T, h http.Handler, path, token string, form url.Values, csrf *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if csrf != nil {
		req.AddCookie(csrf)
		req.Header.Set("X-CSRF-Token", csrf.Value)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestConsoleAuthDenyByDefault(t *testing.T) {
	t.Parallel()
	f := newConsoleFixture(t)
	// No token → 401.
	if rec := consoleGet(t, f.handler, "/console/tenants", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token = %d, want 401", rec.Code)
	}
	// Operator (read role) → 200 on a read.
	if rec := consoleGet(t, f.handler, "/console/tenants", operatorToken); rec.Code != http.StatusOK {
		t.Fatalf("operator read = %d, want 200", rec.Code)
	}
}

func TestConsoleStaticAndRedirect(t *testing.T) {
	t.Parallel()
	f := newConsoleFixture(t)
	// Static asset is public (no token).
	req := httptest.NewRequest(http.MethodGet, "/console/static/app.css", nil)
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.Len() == 0 {
		t.Fatalf("static = %d len=%d", rec.Code, rec.Body.Len())
	}
	// Root redirects to /console/tenants.
	r := httptest.NewRequest(http.MethodGet, "/console/", nil)
	r.Header.Set("Authorization", "Bearer "+adminToken)
	rr := httptest.NewRecorder()
	f.handler.ServeHTTP(rr, r)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("redirect = %d, want 303", rr.Code)
	}
}

func TestConsoleReadScreens(t *testing.T) {
	t.Parallel()
	f := newConsoleFixture(t)
	cases := []struct{ path, want string }{
		{"/console/tenants", "Acme"},
		{"/console/tenants/rows", "Acme"},
		{"/console/tenants/new", "Novo tenant"},
		{"/console/tenants/t1", "Visão geral"},
		{"/console/tenants/t1/credentials", "Client ID"},
		{"/console/tenants/t1/pricing", "Tarifação"},
		{"/console/tenants/t1/consumption", "Consumo"},
	}
	for _, c := range cases {
		rec := consoleGet(t, f.handler, c.path, adminToken)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), c.want) {
			t.Fatalf("GET %s = %d, want 200 containing %q", c.path, rec.Code, c.want)
		}
	}
	// Unknown tenant → 404.
	if rec := consoleGet(t, f.handler, "/console/tenants/missing", adminToken); rec.Code != http.StatusNotFound {
		t.Fatalf("missing tenant = %d, want 404", rec.Code)
	}
}

func TestConsoleCSRFRequiredOnMutation(t *testing.T) {
	t.Parallel()
	f := newConsoleFixture(t)
	// Admin token but no CSRF token → 403 (forbidden).
	rec := consolePost(t, f.handler, "/console/tenants", adminToken, url.Values{"name": {"Beta"}}, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("no csrf = %d, want 403", rec.Code)
	}
}

func TestConsoleRBACMutationDeniesOperator(t *testing.T) {
	t.Parallel()
	f := newConsoleFixture(t)
	csrf := csrfToken(t, f.handler, operatorToken)
	// Operator with valid CSRF still cannot mutate → 403 (least privilege).
	rec := consolePost(t, f.handler, "/console/tenants", operatorToken, url.Values{"name": {"Beta"}}, csrf)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("operator mutate = %d, want 403", rec.Code)
	}
}

func TestConsoleCreateTenant(t *testing.T) {
	t.Parallel()
	f := newConsoleFixture(t)
	csrf := csrfToken(t, f.handler, adminToken)

	rec := consolePost(t, f.handler, "/console/tenants", adminToken, url.Values{"name": {"Beta SA"}}, csrf)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Beta SA") {
		t.Fatalf("create = %d: %s", rec.Code, rec.Body.String())
	}
	// Blank name → 422 with inline error re-render.
	bad := consolePost(t, f.handler, "/console/tenants", adminToken, url.Values{"name": {"  "}}, csrf)
	if bad.Code != http.StatusUnprocessableEntity {
		t.Fatalf("blank name = %d, want 422", bad.Code)
	}
}

func TestConsoleLifecycleToggle(t *testing.T) {
	t.Parallel()
	f := newConsoleFixture(t)
	csrf := csrfToken(t, f.handler, adminToken)

	susp := consolePost(t, f.handler, "/console/tenants/t1/suspend", adminToken, url.Values{}, csrf)
	if susp.Code != http.StatusOK || !strings.Contains(susp.Body.String(), "Suspenso") {
		t.Fatalf("suspend = %d: %s", susp.Code, susp.Body.String())
	}
	got, _ := f.store.FindTenantByID(context.Background(), "t1")
	if got.Active() {
		t.Fatalf("suspend not persisted")
	}
	act := consolePost(t, f.handler, "/console/tenants/t1/activate", adminToken, url.Values{}, csrf)
	if act.Code != http.StatusOK || !strings.Contains(act.Body.String(), "Ativo") {
		t.Fatalf("activate = %d: %s", act.Code, act.Body.String())
	}
	// Lifecycle on unknown tenant → 404.
	miss := consolePost(t, f.handler, "/console/tenants/missing/suspend", adminToken, url.Values{}, csrf)
	if miss.Code != http.StatusNotFound {
		t.Fatalf("suspend missing = %d, want 404", miss.Code)
	}
}

func TestConsoleSetCredential(t *testing.T) {
	t.Parallel()
	f := newConsoleFixture(t)
	csrf := csrfToken(t, f.handler, adminToken)

	ok := consolePost(t, f.handler, "/console/tenants/t1/credentials", adminToken,
		url.Values{"client_id": {"cid-1"}, "secret": {"s3cr3t"}}, csrf)
	if ok.Code != http.StatusOK || !strings.Contains(ok.Body.String(), "Credencial salva") {
		t.Fatalf("set credential = %d: %s", ok.Code, ok.Body.String())
	}
	// Secret must never be echoed back into the response.
	if strings.Contains(ok.Body.String(), "s3cr3t") {
		t.Fatalf("secret leaked into response")
	}
	got, err := f.creds.GetBankCredential(context.Background(), "t1", ports.BankIDC6)
	if err != nil || got.ClientID != "cid-1" || got.Secret != "s3cr3t" {
		t.Fatalf("stored credential = %+v, %v", got, err)
	}
	// Missing secret → 422.
	bad := consolePost(t, f.handler, "/console/tenants/t1/credentials", adminToken,
		url.Values{"client_id": {"cid"}, "secret": {""}}, csrf)
	if bad.Code != http.StatusUnprocessableEntity {
		t.Fatalf("empty secret = %d, want 422", bad.Code)
	}
}

func TestConsoleSetPrice(t *testing.T) {
	t.Parallel()
	f := newConsoleFixture(t)
	csrf := csrfToken(t, f.handler, adminToken)

	ok := consolePost(t, f.handler, "/console/tenants/t1/pricing", adminToken,
		url.Values{"endpoint": {"POST /v1/charges"}, "price_cents": {"250"}}, csrf)
	if ok.Code != http.StatusOK || !strings.Contains(ok.Body.String(), "POST /v1/charges") {
		t.Fatalf("set price = %d: %s", ok.Code, ok.Body.String())
	}
	prices, _ := f.store.ListEndpointPrices(context.Background(), "t1")
	if len(prices) != 1 || prices[0].PriceCents() != 250 {
		t.Fatalf("price not persisted: %+v", prices)
	}
	// Non-numeric price → 422.
	bad := consolePost(t, f.handler, "/console/tenants/t1/pricing", adminToken,
		url.Values{"endpoint": {"x"}, "price_cents": {"abc"}}, csrf)
	if bad.Code != http.StatusUnprocessableEntity {
		t.Fatalf("bad price = %d, want 422", bad.Code)
	}
	// Empty endpoint (domain validation) → 422.
	bad2 := consolePost(t, f.handler, "/console/tenants/t1/pricing", adminToken,
		url.Values{"endpoint": {""}, "price_cents": {"10"}}, csrf)
	if bad2.Code != http.StatusUnprocessableEntity {
		t.Fatalf("empty endpoint = %d, want 422", bad2.Code)
	}
}

func TestConsoleConsumptionScreen(t *testing.T) {
	t.Parallel()
	f := newConsoleFixture(t)
	e, _ := billing.NewLedgerEntry("e1", "t1", "POST /v1/charges", "ref", 250, time.Unix(1, 0).UTC())
	_ = f.store.AppendLedgerEntry(context.Background(), e)

	rec := consoleGet(t, f.handler, "/console/tenants/t1/consumption", adminToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("consumption = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "POST /v1/charges") || !strings.Contains(body, "R$ 2,50") {
		t.Fatalf("consumption body unexpected: %s", body)
	}
}

// seedLedger appends one ledger entry stamped at the given Unix second.
func seedLedger(t *testing.T, f *consoleFixture, id, endpoint string, cents, atUnix int64) {
	t.Helper()
	e, err := billing.NewLedgerEntry("e-"+endpoint+"-"+strconv.FormatInt(atUnix, 10), "t1", endpoint, "ref", cents, time.Unix(atUnix, 0).UTC())
	if err != nil {
		t.Fatalf("new ledger: %v", err)
	}
	if err := f.store.AppendLedgerEntry(context.Background(), e); err != nil {
		t.Fatalf("append ledger: %v", err)
	}
}

// TestConsoleConsumptionDefaultWindow asserts the screen defaults to the last 30
// days relative to the service clock (fixedClock → Unix(1000)): an entry inside
// the window renders, one well outside it does not.
func TestConsoleConsumptionDefaultWindow(t *testing.T) {
	t.Parallel()
	f := newConsoleFixture(t)
	seedLedger(t, f, "t1", "POST /v1/inside", 250, 500)        // within default 30d window
	seedLedger(t, f, "t1", "POST /v1/outside", 999, 5_000_000) // ~58 days after epoch, outside

	rec := consoleGet(t, f.handler, "/console/tenants/t1/consumption", adminToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("consumption = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "POST /v1/inside") {
		t.Fatalf("default window dropped in-window entry: %s", body)
	}
	if strings.Contains(body, "POST /v1/outside") {
		t.Fatalf("default window leaked out-of-window entry: %s", body)
	}
	// The CSV link and date inputs are present (polish controls).
	if !strings.Contains(body, "/consumption.csv?") || !strings.Contains(body, `name="start_date"`) {
		t.Fatalf("missing range controls / csv link: %s", body)
	}
}

// TestConsoleConsumptionRowsFilter drives the partial-swap endpoint with an
// explicit range and asserts only in-range entries come back.
func TestConsoleConsumptionRowsFilter(t *testing.T) {
	t.Parallel()
	f := newConsoleFixture(t)
	seedLedger(t, f, "t1", "POST /v1/early", 100, 50)
	seedLedger(t, f, "t1", "POST /v1/late", 200, 900)

	rec := consoleGet(t, f.handler, "/console/tenants/t1/consumption/rows?start_date=1969-12-31&end_date=1970-01-01", adminToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("rows = %d", rec.Code)
	}
	body := rec.Body.String()
	// Both entries fall on 1970-01-01 (Unix 50 and 900), so both are in range.
	if !strings.Contains(body, "POST /v1/early") || !strings.Contains(body, "POST /v1/late") {
		t.Fatalf("rows missing entries: %s", body)
	}
	// A window before the epoch day excludes everything → empty-state copy.
	empty := consoleGet(t, f.handler, "/console/tenants/t1/consumption/rows?start_date=1969-01-01&end_date=1969-01-02", adminToken)
	if empty.Code != http.StatusOK || !strings.Contains(empty.Body.String(), "Sem consumo registrado") {
		t.Fatalf("expected empty window, got %d: %s", empty.Code, empty.Body.String())
	}
	// Unknown tenant 404s.
	if miss := consoleGet(t, f.handler, "/console/tenants/missing/consumption/rows", adminToken); miss.Code != http.StatusNotFound {
		t.Fatalf("rows missing tenant = %d", miss.Code)
	}
}

// TestConsoleConsumptionCSV asserts the export is a same-origin CSV download with
// a header row, one line per endpoint and a totals row.
func TestConsoleConsumptionCSV(t *testing.T) {
	t.Parallel()
	f := newConsoleFixture(t)
	seedLedger(t, f, "t1", "POST /v1/charges", 250, 500)
	seedLedger(t, f, "t1", "POST /v1/charges", 250, 600)

	rec := consoleGet(t, f.handler, "/console/tenants/t1/consumption.csv", adminToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("csv = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Fatalf("csv content-type = %q", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") || !strings.Contains(cd, ".csv") {
		t.Fatalf("csv content-disposition = %q", cd)
	}
	body := rec.Body.String()
	for _, want := range []string{"endpoint,chamadas,total_centavos,total_reais", "POST /v1/charges,2,500,5.00", "TOTAL,2,500,5.00"} {
		if !strings.Contains(body, want) {
			t.Fatalf("csv missing %q in:\n%s", want, body)
		}
	}
}

// TestConsoleConsumptionCSVFormulaInjectionNeutralized is the defence-in-depth
// regression for SIN-69183 (CWE-1236) on the per-endpoint consumption export: an
// endpoint label beginning with a formula-trigger character must be neutralized
// (single-quote prefix) so a spreadsheet does not evaluate it. Fails on pre-fix
// code (bare "@evil"), passes after.
func TestConsoleConsumptionCSVFormulaInjectionNeutralized(t *testing.T) {
	t.Parallel()
	f := newConsoleFixture(t)
	seedLedger(t, f, "t1", "@evil", 250, 500)

	rec := consoleGet(t, f.handler, "/console/tenants/t1/consumption.csv", adminToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("csv = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `'@evil`) {
		t.Fatalf("formula not neutralized in consumption CSV:\n%s", body)
	}
}

// TestConsoleConsumptionBadDate asserts a malformed date is rejected at the
// boundary (400) rather than silently falling back to a default window.
func TestConsoleConsumptionBadDate(t *testing.T) {
	t.Parallel()
	f := newConsoleFixture(t)
	for _, path := range []string{
		"/console/tenants/t1/consumption?start_date=nope",
		"/console/tenants/t1/consumption/rows?end_date=2026-13-40",
		"/console/tenants/t1/consumption.csv?start_date=99-99-99",
	} {
		if rec := consoleGet(t, f.handler, path, adminToken); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s = %d, want 400", path, rec.Code)
		}
	}
}

// TestConsoleRateLimit asserts the HTML console plane is rate-limited at parity
// with the JSON admin plane (SIN-64741 L1): a rapid burst on a mutating console
// route trips a 429 after roughly the bucket capacity, and the first request is
// admitted. The CSRF token is supplied so the limiter — not CSRF — is what stops
// the flood; the limiter sits before CSRF so even token-less floods are bounded,
// but exercising the success path proves the 429 comes from the limiter itself.
func TestConsoleRateLimit(t *testing.T) {
	t.Parallel()
	f := newConsoleFixture(t)
	csrf := csrfToken(t, f.handler, adminToken)

	// Matches the console limiter capacity wired in server.go (newRateLimiter(20,10)).
	const capacity = 20
	limitedAt := -1
	for i := 0; i < 60; i++ {
		rec := consolePost(t, f.handler, "/console/tenants", adminToken,
			url.Values{"name": {"Burst SA"}}, csrf)
		if i == 0 && rec.Code == http.StatusTooManyRequests {
			t.Fatalf("first request must not be rate-limited, got 429")
		}
		if rec.Code == http.StatusTooManyRequests {
			limitedAt = i
			break
		}
	}
	if limitedAt < 1 || limitedAt > 3*capacity {
		t.Fatalf("429 tripped at request %d, want it after the first and within burst", limitedAt)
	}
}

// TestConsoleRateLimitPerToken proves the console limiter keys by admin identity,
// not just IP: two admin tokens sharing one client IP get independent buckets, so
// exhausting one must not throttle the other.
func TestConsoleRateLimitPerToken(t *testing.T) {
	t.Parallel()
	f := newConsoleFixture(t)
	csrfA := csrfToken(t, f.handler, adminToken)
	csrfB := csrfToken(t, f.handler, secondAdminToken)

	// Exhaust token A's bucket on a mutating console route.
	var aLimited bool
	for i := 0; i < 60; i++ {
		rec := consolePost(t, f.handler, "/console/tenants", adminToken,
			url.Values{"name": {"A SA"}}, csrfA)
		if rec.Code == http.StatusTooManyRequests {
			aLimited = true
			break
		}
	}
	if !aLimited {
		t.Fatal("token A was never rate-limited")
	}

	// Same process/IP, different admin token → fresh bucket, must not be limited.
	rec := consolePost(t, f.handler, "/console/tenants", secondAdminToken,
		url.Values{"name": {"B SA"}}, csrfB)
	if rec.Code == http.StatusTooManyRequests {
		t.Fatal("token B limited by token A's bucket — console limiter is keyed per-IP, not per-token")
	}
}

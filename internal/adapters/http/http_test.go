package http_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/bank"
	httpadapter "github.com/ia-dev-sindireceita/payment/internal/adapters/http"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/messaging/inmemory"
	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/system"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

const (
	tenantToken = "ttok"
	adminToken  = "atok"
	// secondAdminToken is a distinct admin identity sharing the test client IP, used
	// to prove per-token (not per-IP) rate-limit bucketing on the console plane.
	secondAdminToken = "atok2admin"
	// tenantClientID is the seeded tenant's C6 client_id (in its bank credential).
	// It is what a legitimate webhook body's client_id must match.
	tenantClientID = "c6-acme"
)

// Opaque per-tenant webhook callback refs (tenantRef): a valid one is exactly 43
// base64url chars (httpadapter.GenerateTenantRef). webhookRef is registered to the
// seeded tenant; webhookRefUnknown is well-formed but unregistered (no-oracle
// test). Built with Repeat so the length is exactly right.
var (
	webhookRef        = strings.Repeat("A", 43)
	webhookRefUnknown = strings.Repeat("Z", 43)
)

type fixture struct {
	handler    http.Handler
	tenantID   string
	bank       *bank.StubProvider
	bus        *inmemory.Bus
	webhookRef string
	clientID   string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	return newFixtureAuth(t, []string{adminToken})
}

// newFixtureAuth builds a fixture whose admin authenticator accepts the given
// admin tokens (all RoleAdmin). Used by the rate-limit tests to exercise
// per-token keying with more than one admin identity.
func newFixtureAuth(t *testing.T, adminTokens []string) *fixture {
	t.Helper()
	store := persistence.NewStore()
	creds := secret.NewStore(nil)
	stub := bank.NewStubProvider(creds)
	bus := inmemory.NewBus()
	deps := app.Deps{
		Payments:    store,
		Tenants:     store,
		Pricing:     store,
		Ledger:      store,
		Processed:   store,
		Bus:         bus,
		Bank:        stub,
		Credentials: creds,
		Clock:       system.Clock{},
		IDs:         system.IDProvider{},
	}
	admin := app.NewAdminService(deps)
	tn, err := admin.CreateTenant(context.Background(), "Acme")
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	creds.Set(tn.ID(), ports.BankCredential{ClientID: tenantClientID, Secret: "s"})
	if _, err := admin.SetEndpointPrice(context.Background(), tn.ID(), "pix.create", 50); err != nil {
		t.Fatalf("seed price: %v", err)
	}

	// Bind the seeded tenant's opaque callback ref to its tenant id + C6 client_id
	// (the C6 webhook is unsigned; the ref IS the credential, ADR-0002/F4).
	webhookRefs := map[string]httpadapter.WebhookIdentity{
		webhookRef: {TenantID: tn.ID(), ClientID: tenantClientID},
	}
	auth := httpadapter.NewStaticTokenAuth(map[string]string{tenantToken: tn.ID()}, adminTokens, webhookRefs)
	srv := httpadapter.NewServer(httpadapter.Config{
		Charges:     app.NewChargeService(deps),
		Admin:       admin,
		Webhooks:    app.NewWebhookService(deps),
		TenantAuth:  auth,
		AdminAuth:   auth,
		WebhookAuth: auth,
	})
	return &fixture{handler: srv.Router(), tenantID: tn.ID(), bank: stub, bus: bus, webhookRef: webhookRef, clientID: tenantClientID}
}

func do(t *testing.T, h http.Handler, method, path, token string, headers map[string]string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHealthz(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	rec := do(t, f.handler, http.MethodGet, "/healthz", "", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz: %d", rec.Code)
	}
}

// TestHealthzReportsBuildProvenance verifies the health check surfaces the build
// provenance (status + version/commit/built_at keys) so the CD smoke gate can
// assert the deployed SHA. Under `go test` no ldflags are injected, so version
// resolves to a non-empty fallback ("dev" or the VCS revision) and commit/built_at
// may be empty — only the keys' presence and a non-empty version are asserted here
// (the resolver's value precedence is covered in internal/version).
func TestHealthzReportsBuildProvenance(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	rec := do(t, f.handler, http.MethodGet, "/healthz", "", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz: %d", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode healthz body: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("status = %q; want ok", body["status"])
	}
	if body["version"] == "" {
		t.Errorf("version is empty; want a non-empty build provenance value")
	}
	for _, k := range []string{"version", "commit", "built_at"} {
		if _, ok := body[k]; !ok {
			t.Errorf("healthz body missing key %q (smoke gate asserts the deployed SHA)", k)
		}
	}
}

func TestAuthDenyByDefault(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	// Tenant route without token.
	if rec := do(t, f.handler, http.MethodPost, "/v1/charges", "", map[string]string{"Idempotency-Key": "k"}, map[string]any{"endpoint": "pix.create", "amount_cents": 10, "currency": "BRL"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
	// Tenant route with admin token (wrong audience).
	if rec := do(t, f.handler, http.MethodPost, "/v1/charges", adminToken, map[string]string{"Idempotency-Key": "k"}, map[string]any{"endpoint": "pix.create", "amount_cents": 10, "currency": "BRL"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 for wrong token, got %d", rec.Code)
	}
	// Admin route without admin token.
	if rec := do(t, f.handler, http.MethodPost, "/admin/tenants", tenantToken, nil, map[string]any{"name": "X"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 admin, got %d", rec.Code)
	}
}

func TestCreateAndGetCharge(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	rec := do(t, f.handler, http.MethodPost, "/v1/charges", tenantToken, map[string]string{"Idempotency-Key": "k1"}, map[string]any{"endpoint": "pix.create", "amount_cents": 2500, "currency": "BRL"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d body=%s", rec.Code, rec.Body.String())
	}
	var pv struct {
		ID       string `json:"id"`
		Status   string `json:"status"`
		TenantID string `json:"tenant_id"`
		TxID     string `json:"tx_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &pv); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if pv.ID == "" || pv.Status != "pending" || pv.TenantID != f.tenantID || pv.TxID == "" {
		t.Fatalf("unexpected payment view: %+v", pv)
	}

	// Read it back.
	rec = do(t, f.handler, http.MethodGet, "/v1/charges/"+pv.ID, tenantToken, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get: %d", rec.Code)
	}
	// Unknown id → 404.
	rec = do(t, f.handler, http.MethodGet, "/v1/charges/missing", tenantToken, nil, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404 for missing, got %d", rec.Code)
	}
}

func TestCreateChargeValidation(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	// Missing Idempotency-Key.
	if rec := do(t, f.handler, http.MethodPost, "/v1/charges", tenantToken, nil, map[string]any{"endpoint": "pix.create", "amount_cents": 10, "currency": "BRL"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 missing idem, got %d", rec.Code)
	}
	// Unknown field (mass-assignment guard).
	if rec := do(t, f.handler, http.MethodPost, "/v1/charges", tenantToken, map[string]string{"Idempotency-Key": "k"}, map[string]any{"endpoint": "pix.create", "amount_cents": 10, "currency": "BRL", "tenant_id": "evil"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 unknown field, got %d", rec.Code)
	}
	// Unpriced endpoint → served for free (SIN-69512): 201, billed 0 cents, not 404.
	// Rule-3 disclosure: this assertion previously required 404; the mandated
	// charge-time contract changed it to success. CTO ratifies at the review gate.
	if rec := do(t, f.handler, http.MethodPost, "/v1/charges", tenantToken, map[string]string{"Idempotency-Key": "k2"}, map[string]any{"endpoint": "unpriced", "amount_cents": 10, "currency": "BRL"}); rec.Code != http.StatusCreated {
		t.Fatalf("want 201 for unpriced (free) endpoint, got %d", rec.Code)
	}
	// Bad amount → 400.
	if rec := do(t, f.handler, http.MethodPost, "/v1/charges", tenantToken, map[string]string{"Idempotency-Key": "k3"}, map[string]any{"endpoint": "pix.create", "amount_cents": 0, "currency": "BRL"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 amount, got %d", rec.Code)
	}
}

func TestAdminEndpoints(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	// Create tenant.
	rec := do(t, f.handler, http.MethodPost, "/admin/tenants", adminToken, nil, map[string]any{"name": "New Co"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create tenant: %d", rec.Code)
	}
	var tv struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &tv)
	if tv.ID == "" {
		t.Fatal("no tenant id")
	}
	// Set price for it.
	rec = do(t, f.handler, http.MethodPost, "/admin/tenants/"+tv.ID+"/pricing", adminToken, nil, map[string]any{"endpoint": "pix.create", "price_cents": 99})
	if rec.Code != http.StatusOK {
		t.Fatalf("set price: %d body=%s", rec.Code, rec.Body.String())
	}
	// Invalid name → 400.
	rec = do(t, f.handler, http.MethodPost, "/admin/tenants", adminToken, nil, map[string]any{"name": " "})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 invalid name, got %d", rec.Code)
	}
}

// c6Body builds a C6 WebhookNotification body for the given charge/status. The
// client_id matches the seeded tenant unless overridden by the caller.
func c6Body(extID, clientID, status string) map[string]any {
	return map[string]any{"external_id": extID, "client_id": clientID, "service": "pix", "status": status}
}

// seedCharge creates a charge via the tenant API and returns its id + tx id.
func seedCharge(t *testing.T, f *fixture) (id, txID string) {
	t.Helper()
	rec := do(t, f.handler, http.MethodPost, "/v1/charges", tenantToken, map[string]string{"Idempotency-Key": "k1"}, map[string]any{"endpoint": "pix.create", "amount_cents": 2500, "currency": "BRL"})
	var pv struct {
		ID   string `json:"id"`
		TxID string `json:"tx_id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &pv)
	if pv.ID == "" || pv.TxID == "" {
		t.Fatalf("seed charge: empty ids (code %d body %s)", rec.Code, rec.Body.String())
	}
	return pv.ID, pv.TxID
}

func TestWebhookFlow(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	id, txID := seedCharge(t, f)
	whURL := "/webhooks/c6/" + f.webhookRef

	// A well-formed but UNREGISTERED ref → 401, identical to a forged URL: the
	// capability URL is the only authenticator and reveals nothing (no oracle).
	if rec := do(t, f.handler, http.MethodPost, "/webhooks/c6/"+webhookRefUnknown, "", nil, c6Body(txID, f.clientID, "pending")); rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 unknown ref, got %d", rec.Code)
	}
	// Valid ref, bank not yet settled → 202 (accepted) but charge stays pending:
	// the raw webhook is never trusted; settlement requires reconciliation.
	if rec := do(t, f.handler, http.MethodPost, whURL, "", nil, c6Body(txID, f.clientID, "pending")); rec.Code != http.StatusAccepted {
		t.Fatalf("want 202 pending, got %d", rec.Code)
	}
	// Settle at the bank, then deliver a paid notification (distinct status →
	// distinct event_key) → 202 and the charge reconciles to paid.
	f.bank.MarkSettled(f.tenantID, txID)
	if rec := do(t, f.handler, http.MethodPost, whURL, "", nil, c6Body(txID, f.clientID, "paid")); rec.Code != http.StatusAccepted {
		t.Fatalf("want 202 settle, got %d", rec.Code)
	}
	rec := do(t, f.handler, http.MethodGet, "/v1/charges/"+id, tenantToken, nil, nil)
	var got struct {
		Status string `json:"status"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got.Status != "paid" {
		t.Fatalf("expected paid, got %s", got.Status)
	}
}

// TestWebhookMalformedRefSame401 asserts a malformed ref (wrong length / illegal
// chars) is rejected with the SAME 401 as an unknown ref — uniform deny, no
// existence oracle, and path-traversal-shaped input never reaches the lookup.
func TestWebhookMalformedRefSame401(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	_, txID := seedCharge(t, f)
	for _, ref := range []string{"short", strings.Repeat("A", 42), strings.Repeat("A", 44), strings.Repeat("*", 43)} {
		if rec := do(t, f.handler, http.MethodPost, "/webhooks/c6/"+ref, "", nil, c6Body(txID, f.clientID, "paid")); rec.Code != http.StatusUnauthorized {
			t.Fatalf("ref %q: want 401, got %d", ref, rec.Code)
		}
	}
}

// TestWebhookBodyTenantMismatchRejected asserts the body cannot override the
// channel: a valid ref but a body whose client_id belongs to a different tenant is
// rejected (401), never silently accepted under the channel tenant.
func TestWebhookBodyTenantMismatchRejected(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	_, txID := seedCharge(t, f)
	f.bank.MarkSettled(f.tenantID, txID)
	if rec := do(t, f.handler, http.MethodPost, "/webhooks/c6/"+f.webhookRef, "", nil, c6Body(txID, "someone-elses-client", "paid")); rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 on client_id mismatch, got %d", rec.Code)
	}
}

// TestWebhookOversizeBody asserts the pre-auth body cap: a body over the limit is
// rejected with 413 (distinct from a malformed body's 400).
func TestWebhookOversizeBody(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	_, txID := seedCharge(t, f)
	big := strings.Repeat("x", (64<<10)+1)
	body := map[string]any{"external_id": txID, "client_id": f.clientID, "service": "pix", "status": "paid", "information": big}
	if rec := do(t, f.handler, http.MethodPost, "/webhooks/c6/"+f.webhookRef, "", nil, body); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("want 413 oversize, got %d", rec.Code)
	}
}

// TestWebhookReplayDedup asserts double-delivery of the SAME notification produces
// a single dispatch effect: the second delivery is acked (202) but deduped, so
// exactly one payment.paid message is published.
func TestWebhookReplayDedup(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	id, txID := seedCharge(t, f)
	var published int
	_ = f.bus.Subscribe(context.Background(), app.TopicPaymentPaid, func(_ context.Context, _ ports.Message) error {
		published++
		return nil
	})
	f.bank.MarkSettled(f.tenantID, txID)
	for i := 0; i < 2; i++ {
		if rec := do(t, f.handler, http.MethodPost, "/webhooks/c6/"+f.webhookRef, "", nil, c6Body(txID, f.clientID, "paid")); rec.Code != http.StatusAccepted {
			t.Fatalf("delivery %d: want 202, got %d", i, rec.Code)
		}
	}
	if published != 1 {
		t.Fatalf("want exactly 1 dispatch after double-delivery, got %d", published)
	}
	rec := do(t, f.handler, http.MethodGet, "/v1/charges/"+id, tenantToken, nil, nil)
	var got struct {
		Status string `json:"status"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got.Status != "paid" {
		t.Fatalf("expected paid, got %s", got.Status)
	}
}

// TestWebhookTenantIsolation asserts a ref minted for tenant A only ever acts as A:
// a webhook on B's ref settles B's charge and leaves A's untouched, and vice versa.
// There is no path by which A's credential authenticates as B.
func TestWebhookTenantIsolation(t *testing.T) {
	t.Parallel()
	store := persistence.NewStore()
	creds := secret.NewStore(nil)
	stub := bank.NewStubProvider(creds)
	deps := app.Deps{
		Payments: store, Tenants: store, Pricing: store, Ledger: store, Processed: store,
		Bus: inmemory.NewBus(), Bank: stub, Credentials: creds,
		Clock: system.Clock{}, IDs: system.IDProvider{},
	}
	admin := app.NewAdminService(deps)
	mk := func(name, token, clientID string) (tenantID string) {
		tn, err := admin.CreateTenant(context.Background(), name)
		if err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
		creds.Set(tn.ID(), ports.BankCredential{ClientID: clientID, Secret: "s"})
		if _, err := admin.SetEndpointPrice(context.Background(), tn.ID(), "pix.create", 50); err != nil {
			t.Fatalf("price %s: %v", name, err)
		}
		return tn.ID()
	}
	tenantA := mk("A", "tokA", "client-a")
	tenantB := mk("B", "tokB", "client-b")
	refA, refB := strings.Repeat("A", 43), strings.Repeat("B", 43)
	auth := httpadapter.NewStaticTokenAuth(
		map[string]string{"tokA": tenantA, "tokB": tenantB},
		[]string{adminToken},
		map[string]httpadapter.WebhookIdentity{
			refA: {TenantID: tenantA, ClientID: "client-a"},
			refB: {TenantID: tenantB, ClientID: "client-b"},
		},
	)
	h := httpadapter.NewServer(httpadapter.Config{
		Charges: app.NewChargeService(deps), Admin: admin, Webhooks: app.NewWebhookService(deps),
		TenantAuth: auth, AdminAuth: auth, WebhookAuth: auth,
	}).Router()

	charge := func(token string) (id, txID string) {
		rec := do(t, h, http.MethodPost, "/v1/charges", token, map[string]string{"Idempotency-Key": "k"}, map[string]any{"endpoint": "pix.create", "amount_cents": 100, "currency": "BRL"})
		var pv struct {
			ID   string `json:"id"`
			TxID string `json:"tx_id"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &pv)
		return pv.ID, pv.TxID
	}
	idA, txA := charge("tokA")

	// Settle A's charge at the bank. Deliver A's settled notification on B's ref:
	// it reconciles under tenant B (B has no such charge → not-found, no effect),
	// and must NOT settle A's charge.
	stub.MarkSettled(tenantA, txA)
	if rec := do(t, h, http.MethodPost, "/webhooks/c6/"+refB, "", nil, c6Body(txA, "client-b", "paid")); rec.Code == http.StatusAccepted {
		// Accepted is fine (reconcile found nothing for B); the invariant is A stays pending.
	} else if rec.Code != http.StatusNotFound {
		t.Fatalf("B-ref on A tx: unexpected %d", rec.Code)
	}
	rec := do(t, h, http.MethodGet, "/v1/charges/"+idA, "tokA", nil, nil)
	var got struct {
		Status string `json:"status"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got.Status == "paid" {
		t.Fatal("tenant isolation breach: A settled via B's ref")
	}
	// Sanity: A's own ref settles A.
	if rec := do(t, h, http.MethodPost, "/webhooks/c6/"+refA, "", nil, c6Body(txA, "client-a", "paid")); rec.Code != http.StatusAccepted {
		t.Fatalf("A-ref on A tx: want 202, got %d", rec.Code)
	}
	rec = do(t, h, http.MethodGet, "/v1/charges/"+idA, "tokA", nil, nil)
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got.Status != "paid" {
		t.Fatalf("A's own ref failed to settle A: %s", got.Status)
	}
}

// TestWebhookMalformedAndEmptyBody covers the body-validation branches: a body
// that is not valid JSON → 400, and a body missing the external_id (the reconcile
// key) → 400. Both are distinct from the auth (401) and oversize (413) paths.
func TestWebhookMalformedAndEmptyBody(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	url := "/webhooks/c6/" + f.webhookRef
	// Raw non-JSON body → 400.
	req := httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString("{not-json"))
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed body: want 400, got %d", rec.Code)
	}
	// Well-formed body but no external_id → 400 (cannot reconcile).
	if rec := do(t, f.handler, http.MethodPost, url, "", nil, c6Body("", f.clientID, "paid")); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty external_id: want 400, got %d", rec.Code)
	}
}

// TestGenerateTenantRef asserts a minted ref is well-formed (passes the handler's
// format gate) and unique, and that it can be registered and resolved end-to-end.
func TestGenerateTenantRef(t *testing.T) {
	t.Parallel()
	a, err := httpadapter.GenerateTenantRef()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	b, _ := httpadapter.GenerateTenantRef()
	if a == b {
		t.Fatal("minted refs are not unique")
	}
	if len(a) != 43 {
		t.Fatalf("ref length = %d, want 43", len(a))
	}
	// A minted ref registers and authenticates; a different minted ref does not.
	auth := httpadapter.NewStaticTokenAuth(nil, nil, map[string]httpadapter.WebhookIdentity{
		a: {TenantID: "tenant-x", ClientID: "cx"},
	})
	if id, ok := auth.AuthenticateWebhook(a); !ok || id.TenantID != "tenant-x" {
		t.Fatalf("minted ref did not authenticate: ok=%v id=%+v", ok, id)
	}
	if _, ok := auth.AuthenticateWebhook(b); ok {
		t.Fatal("unregistered minted ref authenticated (oracle)")
	}
}

func TestRateLimit(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	var limited bool
	for i := 0; i < 60; i++ {
		rec := do(t, f.handler, http.MethodGet, "/v1/charges/none", tenantToken, nil, nil)
		if rec.Code == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("expected a 429 within 60 rapid requests")
	}
}

// TestAdminRateLimit asserts the admin plane is rate-limited (SIN-64731 L1): a
// rapid burst on any admin route trips a 429 after roughly the bucket capacity,
// and the very first request is admitted (the limiter does not block legitimate
// traffic outright). Table-driven across every admin route, each on its own
// fixture so the buckets are independent.
func TestAdminRateLimit(t *testing.T) {
	t.Parallel()
	// Matches the admin limiter capacity wired in server.go (newRateLimiter(20,10)).
	// Generous upper bound tolerates negligible refill over a microsecond-scale burst.
	const capacity = 20
	routes := []struct {
		name   string
		method string
		path   string
		body   any
	}{
		{"create tenant", http.MethodPost, "/admin/tenants", map[string]any{"name": " "}},
		{"set pricing", http.MethodPost, "/admin/tenants/x/pricing", map[string]any{"endpoint": "pix.create", "price_cents": 1}},
		{"set bank credential", http.MethodPut, "/admin/tenants/x/bank-credential", map[string]any{"client_id": "c", "secret": "s"}},
	}
	for _, rt := range routes {
		rt := rt
		t.Run(rt.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			limitedAt := -1
			for i := 0; i < 60; i++ {
				rec := do(t, f.handler, rt.method, rt.path, adminToken, nil, rt.body)
				if i == 0 && rec.Code == http.StatusTooManyRequests {
					t.Fatalf("first request must not be rate-limited, got 429")
				}
				if rec.Code == http.StatusTooManyRequests {
					limitedAt = i
					break
				}
			}
			if limitedAt < 0 {
				t.Fatalf("expected a 429 within 60 rapid admin requests")
			}
			if limitedAt < 1 || limitedAt > 3*capacity {
				t.Fatalf("429 tripped at request %d, want it after the first and within burst", limitedAt)
			}
		})
	}
}

// TestAdminRateLimitPerToken proves the admin limiter keys by token identity, not
// just IP: two admin tokens sharing one client IP get independent buckets, so
// exhausting one must not throttle the other.
func TestAdminRateLimitPerToken(t *testing.T) {
	t.Parallel()
	const adminB = "atok2"
	f := newFixtureAuth(t, []string{adminToken, adminB})

	// Exhaust token A's bucket.
	var aLimited bool
	for i := 0; i < 60; i++ {
		rec := do(t, f.handler, http.MethodPost, "/admin/tenants", adminToken, nil, map[string]any{"name": " "})
		if rec.Code == http.StatusTooManyRequests {
			aLimited = true
			break
		}
	}
	if !aLimited {
		t.Fatal("token A was never rate-limited")
	}

	// Same process/IP, different token → fresh bucket, must not be limited. A 429
	// here would mean the limiter keys by IP, defeating the per-token requirement.
	rec := do(t, f.handler, http.MethodPost, "/admin/tenants", adminB, nil, map[string]any{"name": " "})
	if rec.Code == http.StatusTooManyRequests {
		t.Fatal("token B limited by token A's bucket — admin limiter is keyed per-IP, not per-token")
	}
}

package http_test

import (
	"context"
	"encoding/json"
	"net/http"
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

// cobvFixture wires a Server with the PIX cobv service + the C6 webhook handler,
// backed by the in-memory stub, plus two seeded/priced/credentialed tenants and a
// per-tenant webhook callback ref bound to tenant A.
type cobvFixture struct {
	handler    http.Handler
	tenantID   string
	tenantIDB  string
	bank       *bank.StubProvider
	bus        *inmemory.Bus
	webhookRef string
	clientID   string
}

func newCobvFixture(t *testing.T) *cobvFixture {
	t.Helper()
	ctx := context.Background()
	store := persistence.NewStore()
	creds := secret.NewStore(nil)
	stub := bank.NewStubProvider(creds)
	bus := inmemory.NewBus()
	deps := app.Deps{
		Payments:     store,
		Tenants:      store,
		Pricing:      store,
		Ledger:       store,
		Processed:    store,
		Bus:          bus,
		Bank:         stub,
		Pix:          stub,
		PixDueCharge: stub,
		Credentials:  creds,
		Clock:        system.Clock{},
		IDs:          system.IDProvider{},
	}
	admin := app.NewAdminService(deps)
	tnA, err := admin.CreateTenant(ctx, "Acme")
	if err != nil {
		t.Fatalf("seed tenant A: %v", err)
	}
	tnB, err := admin.CreateTenant(ctx, "Beta")
	if err != nil {
		t.Fatalf("seed tenant B: %v", err)
	}
	creds.Set(tnA.ID(), ports.BankCredential{ClientID: tenantClientID, Secret: "s"})
	creds.Set(tnB.ID(), ports.BankCredential{ClientID: "c6-beta", Secret: "s"})
	for _, id := range []string{tnA.ID(), tnB.ID()} {
		if _, err := admin.SetEndpointPrice(ctx, id, app.PixCobVCreateEndpoint, 50); err != nil {
			t.Fatalf("seed price: %v", err)
		}
	}
	webhookRefs := map[string]httpadapter.WebhookIdentity{
		webhookRef: {TenantID: tnA.ID(), ClientID: tenantClientID},
	}
	auth := httpadapter.NewStaticTokenAuth(
		map[string]string{tenantToken: tnA.ID(), tenantTokenB: tnB.ID()},
		[]string{adminToken}, webhookRefs)
	srv := httpadapter.NewServer(httpadapter.Config{
		PixCobV:     app.NewPixDueChargeService(deps),
		Admin:       admin,
		Webhooks:    app.NewWebhookService(deps),
		TenantAuth:  auth,
		AdminAuth:   auth,
		WebhookAuth: auth,
	})
	return &cobvFixture{
		handler: srv.Router(), tenantID: tnA.ID(), tenantIDB: tnB.ID(),
		bank: stub, bus: bus, webhookRef: webhookRef, clientID: tenantClientID,
	}
}

// cobvBody is a valid cobv create/amend body with a far-future due date (the app
// clock is real time).
func cobvBody() map[string]any {
	return map[string]any{
		"amount_cents":         1000,
		"currency":             "BRL",
		"due_date":             "2030-01-01T00:00:00Z",
		"validity_days":        5,
		"fine_bps":             200,
		"monthly_interest_bps": 100,
		"discount_bps":         500,
		"devedor":              map[string]any{"tax_id": "12345678901", "name": "Maria"},
		"creditor_key":         "acme@pix.example",
	}
}

// roteiro 7.5 + 7.6 + 7.7: create, read back, amend.
func TestCobvCreateGetUpdateHTTP(t *testing.T) {
	t.Parallel()
	f := newCobvFixture(t)

	rec := do(t, f.handler, http.MethodPost, "/v1/pix/cobv", tenantToken,
		map[string]string{"Idempotency-Key": "k1"}, cobvBody())
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: status %d body %s", rec.Code, rec.Body.String())
	}
	var created map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	txid, _ := created["txid"].(string)
	if txid == "" || created["status"] != "ATIVA" {
		t.Fatalf("unexpected create body: %v", created)
	}
	if created["qr_code"] == "" || created["amount_cents"].(float64) != 1000 {
		t.Fatalf("missing QR / amount: %v", created)
	}

	// 7.6: GET by txid.
	rec = do(t, f.handler, http.MethodGet, "/v1/pix/cobv/"+txid, tenantToken, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get: status %d body %s", rec.Code, rec.Body.String())
	}
	var got map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got["txid"] != txid {
		t.Fatalf("get txid mismatch: %v", got["txid"])
	}

	// 7.7: PUT amend (new amount).
	body := cobvBody()
	body["amount_cents"] = 2500
	rec = do(t, f.handler, http.MethodPut, "/v1/pix/cobv/"+txid, tenantToken,
		map[string]string{"Idempotency-Key": "upd-1"}, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("update: status %d body %s", rec.Code, rec.Body.String())
	}
	var amended map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &amended)
	if amended["amount_cents"].(float64) != 2500 {
		t.Fatalf("amended amount not reconciled: %v", amended)
	}
}

func TestCobvHTTPErrors(t *testing.T) {
	t.Parallel()
	f := newCobvFixture(t)

	cases := []struct {
		name    string
		token   string
		headers map[string]string
		body    map[string]any
		want    int
	}{
		{"requires_auth", "", map[string]string{"Idempotency-Key": "k"}, cobvBody(), http.StatusUnauthorized},
		{"missing_idempotency", tenantToken, nil, cobvBody(), http.StatusBadRequest},
		{"bad_due_date", tenantToken, map[string]string{"Idempotency-Key": "k"}, withField(cobvBody(), "due_date", "not-a-time"), http.StatusBadRequest},
		{"past_due_date", tenantToken, map[string]string{"Idempotency-Key": "k"}, withField(cobvBody(), "due_date", "2000-01-01T00:00:00Z"), http.StatusBadRequest},
		{"zero_amount", tenantToken, map[string]string{"Idempotency-Key": "k"}, withField(cobvBody(), "amount_cents", 0), http.StatusBadRequest},
		{"bad_devedor", tenantToken, map[string]string{"Idempotency-Key": "k"}, withField(cobvBody(), "devedor", map[string]any{"tax_id": "123", "name": "X"}), http.StatusBadRequest},
		{"missing_creditor_key", tenantToken, map[string]string{"Idempotency-Key": "k"}, withField(cobvBody(), "creditor_key", ""), http.StatusBadRequest},
		{"unknown_field", tenantToken, map[string]string{"Idempotency-Key": "k"}, withField(cobvBody(), "evil", "x"), http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec := do(t, f.handler, http.MethodPost, "/v1/pix/cobv", tc.token, tc.headers, tc.body)
			if rec.Code != tc.want {
				t.Fatalf("%s: want %d, got %d (body %s)", tc.name, tc.want, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestCobvGetUnknownTxid(t *testing.T) {
	t.Parallel()
	f := newCobvFixture(t)
	rec := do(t, f.handler, http.MethodGet, "/v1/pix/cobv/missing", tenantToken, nil, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404 for unknown txid, got %d", rec.Code)
	}
}

// OWASP A01: tenant B can neither read nor amend tenant A's cobv charge (404, no
// existence oracle), while A's own read still works.
func TestCobvCrossTenantIsolationHTTP(t *testing.T) {
	t.Parallel()
	f := newCobvFixture(t)
	rec := do(t, f.handler, http.MethodPost, "/v1/pix/cobv", tenantToken,
		map[string]string{"Idempotency-Key": "k1"}, cobvBody())
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d", rec.Code)
	}
	var created map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	txid := created["txid"].(string)

	if rec := do(t, f.handler, http.MethodGet, "/v1/pix/cobv/"+txid, tenantTokenB, nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant GET: want 404, got %d", rec.Code)
	}
	body := cobvBody()
	body["amount_cents"] = 2000
	if rec := do(t, f.handler, http.MethodPut, "/v1/pix/cobv/"+txid, tenantTokenB,
		map[string]string{"Idempotency-Key": "x"}, body); rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant PUT: want 404, got %d", rec.Code)
	}
	// Owner read still works after the blocked cross-tenant attempts.
	if rec := do(t, f.handler, http.MethodGet, "/v1/pix/cobv/"+txid, tenantToken, nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("owner GET after cross-tenant attempts: want 200, got %d", rec.Code)
	}
}

// roteiro 7.8: a cobv settlement notification flows through the EXISTING
// /webhooks/c6/{tenantRef} endpoint (no second endpoint). The event_key
// (external_id|service|status) distinguishes the cobv service and dedups exact
// redeliveries: a duplicate is acked but produces a single settlement dispatch.
func TestCobvWebhookSettlesAndDedups(t *testing.T) {
	t.Parallel()
	f := newCobvFixture(t)

	rec := do(t, f.handler, http.MethodPost, "/v1/pix/cobv", tenantToken,
		map[string]string{"Idempotency-Key": "k1"}, cobvBody())
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d", rec.Code)
	}
	var created map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	txid := created["txid"].(string)

	var paid int
	_ = f.bus.Subscribe(context.Background(), app.TopicPaymentPaid, func(_ context.Context, _ ports.Message) error {
		paid++
		return nil
	})

	whURL := "/webhooks/c6/" + f.webhookRef
	cobvNote := func(status string) map[string]any {
		return map[string]any{"external_id": txid, "client_id": f.clientID, "service": "pix_cobv", "status": status}
	}

	// Not yet settled at the bank → 202 accepted, but reconcile-before-settle keeps
	// it unpaid (the raw webhook is never trusted). Distinct status from the settle
	// delivery so the two carry distinct event_keys.
	if rec := do(t, f.handler, http.MethodPost, whURL, "", nil, cobvNote("ATIVA")); rec.Code != http.StatusAccepted {
		t.Fatalf("pending cobv webhook: want 202, got %d", rec.Code)
	}
	if paid != 0 {
		t.Fatalf("must not settle before the bank reconciles paid, got %d", paid)
	}

	// Settle at the bank, then deliver the CONCLUIDA event twice: it settles once and
	// the exact duplicate is deduped by event_key.
	f.bank.MarkSettled(f.tenantID, txid)
	for i := 0; i < 2; i++ {
		if rec := do(t, f.handler, http.MethodPost, whURL, "", nil, cobvNote("CONCLUIDA")); rec.Code != http.StatusAccepted {
			t.Fatalf("settle delivery %d: want 202, got %d", i, rec.Code)
		}
	}
	if paid != 1 {
		t.Fatalf("cobv webhook must settle exactly once (event_key dedup), got %d", paid)
	}
}

// withField returns a shallow copy of m with key set to v (keeps table cases from
// mutating the shared base body).
func withField(m map[string]any, key string, v any) map[string]any {
	out := make(map[string]any, len(m)+1)
	for k, val := range m {
		out[k] = val
	}
	out[key] = v
	return out
}

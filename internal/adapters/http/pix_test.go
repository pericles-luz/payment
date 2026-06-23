package http_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/bank"
	httpadapter "github.com/ia-dev-sindireceita/payment/internal/adapters/http"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/messaging/inmemory"
	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/system"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// pixFixture wires a Server with the PIX service backed by the in-memory stub, plus
// a seeded, priced, credentialed tenant. The stub clock is pinned so the date
// window in list tests is deterministic.
type pixFixture struct {
	handler  http.Handler
	tenantID string
	bank     *bank.StubProvider
	now      time.Time
}

func newPixFixture(t *testing.T) *pixFixture {
	t.Helper()
	store := persistence.NewStore()
	creds := secret.NewStore(nil)
	stub := bank.NewStubProvider(creds)
	now := time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)
	stub.SetClock(func() time.Time { return now })
	bus := inmemory.NewBus()
	deps := app.Deps{
		Payments:    store,
		Tenants:     store,
		Pricing:     store,
		Ledger:      store,
		Processed:   store,
		Bus:         bus,
		Bank:        stub,
		Pix:         stub,
		Credentials: creds,
		Clock:       system.Clock{},
		IDs:         system.IDProvider{},
	}
	admin := app.NewAdminService(deps)
	tn, err := admin.CreateTenant(context.Background(), "Acme")
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	creds.Set(tn.ID(), ports.BankCredential{ClientID: "c6-acme", Secret: "s"})
	if _, err := admin.SetEndpointPrice(context.Background(), tn.ID(), app.PixCreateEndpoint, 50); err != nil {
		t.Fatalf("seed price: %v", err)
	}
	auth := httpadapter.NewStaticTokenAuth(map[string]string{tenantToken: tn.ID()}, []string{adminToken}, nil)
	srv := httpadapter.NewServer(httpadapter.Config{
		Charges:    app.NewChargeService(deps),
		Pix:        app.NewPixService(deps),
		Admin:      admin,
		Webhooks:   app.NewWebhookService(deps),
		TenantAuth: auth,
		AdminAuth:  auth,
	})
	return &pixFixture{handler: srv.Router(), tenantID: tn.ID(), bank: stub, now: now}
}

func decodePix(t *testing.T, rec interface{ Result() *http.Response }) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.NewDecoder(rec.Result().Body).Decode(&m); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	return m
}

// roteiro 7.1 + 7.3: create immediate charge, then read it back by txid.
func TestPixCreateAndGet(t *testing.T) {
	t.Parallel()
	f := newPixFixture(t)

	rec := do(t, f.handler, http.MethodPost, "/v1/pix", tenantToken,
		map[string]string{"Idempotency-Key": "k1"},
		map[string]any{"amount_cents": 1050, "currency": "BRL", "expires_in_seconds": 1800})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: status %d body %s", rec.Code, rec.Body.String())
	}
	body := decodePix(t, rec)
	txid, _ := body["txid"].(string)
	if txid == "" {
		t.Fatalf("missing txid: %v", body)
	}
	if body["status"] != "ATIVA" {
		t.Fatalf("status: %v", body["status"])
	}
	if body["qr_code"] == "" || body["qr_code_location"] == "" {
		t.Fatalf("missing QR material: %v", body)
	}
	if body["amount_cents"].(float64) != 1050 {
		t.Fatalf("amount: %v", body["amount_cents"])
	}

	// 7.3: GET by txid.
	rec = do(t, f.handler, http.MethodGet, "/v1/pix/"+txid, tenantToken, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get: status %d body %s", rec.Code, rec.Body.String())
	}
	got := decodePix(t, rec)
	if got["txid"] != txid {
		t.Fatalf("get txid mismatch: %v", got["txid"])
	}
}

// roteiro 7.2: create with devedor (CPF).
func TestPixCreateWithDevedorHTTP(t *testing.T) {
	t.Parallel()
	f := newPixFixture(t)
	rec := do(t, f.handler, http.MethodPost, "/v1/pix", tenantToken,
		map[string]string{"Idempotency-Key": "k1"},
		map[string]any{
			"amount_cents": 500, "currency": "BRL",
			"devedor": map[string]any{"tax_id": "12345678901", "name": "Maria"},
		})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create with devedor: status %d body %s", rec.Code, rec.Body.String())
	}
}

func TestPixCreateBadDevedorTaxID(t *testing.T) {
	t.Parallel()
	f := newPixFixture(t)
	rec := do(t, f.handler, http.MethodPost, "/v1/pix", tenantToken,
		map[string]string{"Idempotency-Key": "k1"},
		map[string]any{
			"amount_cents": 500, "currency": "BRL",
			"devedor": map[string]any{"tax_id": "123", "name": "Maria"},
		})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for bad devedor taxid, got %d", rec.Code)
	}
}

func TestPixCreateMissingIdempotencyKey(t *testing.T) {
	t.Parallel()
	f := newPixFixture(t)
	rec := do(t, f.handler, http.MethodPost, "/v1/pix", tenantToken, nil,
		map[string]any{"amount_cents": 500, "currency": "BRL"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for missing idempotency key, got %d", rec.Code)
	}
}

func TestPixCreateZeroAmount(t *testing.T) {
	t.Parallel()
	f := newPixFixture(t)
	rec := do(t, f.handler, http.MethodPost, "/v1/pix", tenantToken,
		map[string]string{"Idempotency-Key": "k1"},
		map[string]any{"amount_cents": 0, "currency": "BRL"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for zero amount, got %d", rec.Code)
	}
}

func TestPixCreateUnknownField(t *testing.T) {
	t.Parallel()
	f := newPixFixture(t)
	rec := do(t, f.handler, http.MethodPost, "/v1/pix", tenantToken,
		map[string]string{"Idempotency-Key": "k1"},
		map[string]any{"amount_cents": 500, "currency": "BRL", "evil": "x"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for unknown field, got %d", rec.Code)
	}
}

func TestPixCreateRequiresAuth(t *testing.T) {
	t.Parallel()
	f := newPixFixture(t)
	rec := do(t, f.handler, http.MethodPost, "/v1/pix", "",
		map[string]string{"Idempotency-Key": "k1"},
		map[string]any{"amount_cents": 500, "currency": "BRL"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 without auth, got %d", rec.Code)
	}
}

func TestPixGetUnknownTxid(t *testing.T) {
	t.Parallel()
	f := newPixFixture(t)
	rec := do(t, f.handler, http.MethodGet, "/v1/pix/missing", tenantToken, nil, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404 for unknown txid, got %d", rec.Code)
	}
}

// roteiro 7.4: list immediate charges by date window.
func TestPixListByDate(t *testing.T) {
	t.Parallel()
	f := newPixFixture(t)

	for _, k := range []string{"k1", "k2"} {
		rec := do(t, f.handler, http.MethodPost, "/v1/pix", tenantToken,
			map[string]string{"Idempotency-Key": k},
			map[string]any{"amount_cents": 100, "currency": "BRL"})
		if rec.Code != http.StatusCreated {
			t.Fatalf("seed create %s: %d", k, rec.Code)
		}
	}

	start := f.now.Add(-time.Hour).UTC().Format(time.RFC3339)
	end := f.now.Add(time.Hour).UTC().Format(time.RFC3339)
	rec := do(t, f.handler, http.MethodGet, "/v1/pix?start="+start+"&end="+end, tenantToken, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: status %d body %s", rec.Code, rec.Body.String())
	}
	body := decodePix(t, rec)
	if body["total_items"].(float64) != 2 {
		t.Fatalf("want 2 charges, got %v", body["total_items"])
	}
	charges, ok := body["charges"].([]any)
	if !ok || len(charges) != 2 {
		t.Fatalf("charges array: %v", body["charges"])
	}
}

func TestPixListBadDates(t *testing.T) {
	t.Parallel()
	f := newPixFixture(t)
	cases := []string{
		"/v1/pix", // missing both
		"/v1/pix?start=notatime&end=2026-06-13T12:00:00Z",                     // bad start
		"/v1/pix?start=2026-06-13T12:00:00Z&end=bad",                          // bad end
		"/v1/pix?start=2026-06-13T12:00:00Z&end=2026-06-13T10:00:00Z",         // end before start
		"/v1/pix?start=2026-06-13T12:00:00Z&end=2026-06-13T13:00:00Z&page=-1", // bad page
	}
	for _, path := range cases {
		rec := do(t, f.handler, http.MethodGet, path, tenantToken, nil, nil)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: want 400, got %d", path, rec.Code)
		}
	}
}

func TestPixListRequiresAuth(t *testing.T) {
	t.Parallel()
	f := newPixFixture(t)
	rec := do(t, f.handler, http.MethodGet, "/v1/pix?start=2026-06-13T11:00:00Z&end=2026-06-13T13:00:00Z", "", nil, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 without auth, got %d", rec.Code)
	}
}

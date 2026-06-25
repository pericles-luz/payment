package http_test

import (
	"context"
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

// checkoutLifecycle wires a Server with the checkout service AND the webhook plane
// (both backed by the same in-memory stub), the opaque callback ref, and a seeded,
// priced, credentialed tenant — everything needed to exercise roteiro 10–12 over HTTP.
type checkoutLifecycle struct {
	handler  http.Handler
	tenantID string
	bank     *bank.StubProvider
	bus      *inmemory.Bus
	ref      string
}

func newCheckoutLifecycle(t *testing.T) *checkoutLifecycle {
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
		Checkout:    stub,
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
	if _, err := admin.SetEndpointPrice(context.Background(), tn.ID(), app.CheckoutCreateEndpoint, 30); err != nil {
		t.Fatalf("seed price: %v", err)
	}
	webhookRefs := map[string]httpadapter.WebhookIdentity{
		webhookRef: {TenantID: tn.ID(), ClientID: tenantClientID},
	}
	auth := httpadapter.NewStaticTokenAuth(map[string]string{tenantToken: tn.ID()}, []string{adminToken}, webhookRefs)
	srv := httpadapter.NewServer(httpadapter.Config{
		Charges:     app.NewChargeService(deps),
		Checkout:    app.NewCheckoutService(deps),
		Admin:       admin,
		Webhooks:    app.NewWebhookService(deps),
		TenantAuth:  auth,
		AdminAuth:   auth,
		WebhookAuth: auth,
	})
	return &checkoutLifecycle{handler: srv.Router(), tenantID: tn.ID(), bank: stub, bus: bus, ref: webhookRef}
}

// openSession opens a checkout session via HTTP and returns its session id.
func (f *checkoutLifecycle) openSession(t *testing.T, idemKey string) string {
	t.Helper()
	rec := do(t, f.handler, http.MethodPost, "/v1/checkout", tenantToken,
		map[string]string{"Idempotency-Key": idemKey}, checkoutBody("credit", false))
	if rec.Code != http.StatusCreated {
		t.Fatalf("open: status %d body %s", rec.Code, rec.Body.String())
	}
	id, _ := decodePix(t, rec)["session_id"].(string)
	if id == "" {
		t.Fatalf("open: empty session id, body %s", rec.Body.String())
	}
	return id
}

func checkoutC6Body(sessionID, clientID, status string) map[string]any {
	return map[string]any{"external_id": sessionID, "client_id": clientID, "service": "checkout", "status": status}
}

// TestCheckoutGetHTTP covers roteiro 10 over HTTP: reconcile a session, 404 on unknown
// / cross-tenant ids (no oracle), and deny-by-default without auth.
func TestCheckoutGetHTTP(t *testing.T) {
	t.Parallel()
	f := newCheckoutLifecycle(t)
	id := f.openSession(t, "k-get")

	rec := do(t, f.handler, http.MethodGet, "/v1/checkout/"+id, tenantToken, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get: status %d body %s", rec.Code, rec.Body.String())
	}
	body := decodePix(t, rec)
	if body["status"] != "OPEN" || body["amount_cents"].(float64) != 1250 {
		t.Fatalf("unexpected get body: %v", body)
	}

	if rec := do(t, f.handler, http.MethodGet, "/v1/checkout/missing", tenantToken, nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown id: want 404, got %d", rec.Code)
	}
	if rec := do(t, f.handler, http.MethodGet, "/v1/checkout/"+id, "", nil, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no auth: want 401, got %d", rec.Code)
	}
}

// TestCheckoutCancelHTTP covers roteiro 11 over HTTP: cancel flips the status, is
// idempotent, and 404s on unknown ids.
func TestCheckoutCancelHTTP(t *testing.T) {
	t.Parallel()
	f := newCheckoutLifecycle(t)
	id := f.openSession(t, "k-cancel")

	rec := do(t, f.handler, http.MethodDelete, "/v1/checkout/"+id, tenantToken, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("cancel: status %d body %s", rec.Code, rec.Body.String())
	}
	if decodePix(t, rec)["status"] != "CANCELLED" {
		t.Fatalf("cancel: want CANCELLED, body %s", rec.Body.String())
	}
	// Idempotent second cancel.
	if rec := do(t, f.handler, http.MethodDelete, "/v1/checkout/"+id, tenantToken, nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("repeat cancel: want 200, got %d", rec.Code)
	}
	if rec := do(t, f.handler, http.MethodDelete, "/v1/checkout/missing", tenantToken, nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("cancel unknown: want 404, got %d", rec.Code)
	}
}

// TestCheckoutWebhookHTTP covers roteiro 12 over HTTP: a checkout notification routes
// to the checkout reconcile path on the shared /webhooks/c6/{ref} handler, settles
// only after the session is captured, and dedups replays — proving the dispatch
// distinguishes the checkout service without a second endpoint.
func TestCheckoutWebhookHTTP(t *testing.T) {
	t.Parallel()
	f := newCheckoutLifecycle(t)
	id := f.openSession(t, "k-wh")
	whURL := "/webhooks/c6/" + f.ref

	var paid int
	_ = f.bus.Subscribe(context.Background(), app.TopicPaymentPaid, func(_ context.Context, _ ports.Message) error {
		paid++
		return nil
	})

	// Session OPEN at the bank → accepted (202) but not settled.
	if rec := do(t, f.handler, http.MethodPost, whURL, "", nil, checkoutC6Body(id, tenantClientID, "open")); rec.Code != http.StatusAccepted {
		t.Fatalf("open notification: want 202, got %d body %s", rec.Code, rec.Body.String())
	}
	if paid != 0 {
		t.Fatalf("must not settle an open session, paid=%d", paid)
	}

	// Capture at the bank, then deliver a paid notification twice → settles exactly
	// once (dedup).
	f.bank.MarkCheckoutPaid(f.tenantID, id)
	for i := 0; i < 2; i++ {
		if rec := do(t, f.handler, http.MethodPost, whURL, "", nil, checkoutC6Body(id, tenantClientID, "paid")); rec.Code != http.StatusAccepted {
			t.Fatalf("paid delivery %d: want 202, got %d", i, rec.Code)
		}
	}
	if paid != 1 {
		t.Fatalf("want exactly one settlement after double delivery, got %d", paid)
	}
}

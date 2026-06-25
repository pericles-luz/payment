package http_test

import (
	"context"
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

const tenantTokenB = "ttok-b"

// newBoletoFixture wires a Server with the boleto service backed by the in-memory
// stub plus TWO seeded, priced, credentialed tenants so cross-tenant access control
// (OWASP A01) can be exercised. Returns the handler and the two tenant ids.
func newBoletoFixture(t *testing.T) (http.Handler, string, string) {
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
		Boleto:      stub,
		Credentials: creds,
		Clock:       system.Clock{},
		IDs:         system.IDProvider{},
	}
	admin := app.NewAdminService(deps)
	seed := func(name, clientID string) string {
		tn, err := admin.CreateTenant(context.Background(), name)
		if err != nil {
			t.Fatalf("seed tenant %s: %v", name, err)
		}
		creds.Set(tn.ID(), ports.BankCredential{ClientID: clientID, Secret: "s"})
		if _, err := admin.SetEndpointPrice(context.Background(), tn.ID(), app.BoletoCreateEndpoint, 40); err != nil {
			t.Fatalf("seed price %s: %v", name, err)
		}
		return tn.ID()
	}
	idA := seed("Acme", "c6-acme")
	idB := seed("Beta", "c6-beta")
	auth := httpadapter.NewStaticTokenAuth(map[string]string{tenantToken: idA, tenantTokenB: idB}, []string{adminToken}, nil)
	srv := httpadapter.NewServer(httpadapter.Config{
		Charges:    app.NewChargeService(deps),
		Boleto:     app.NewBoletoService(deps),
		Admin:      admin,
		Webhooks:   app.NewWebhookService(deps),
		TenantAuth: auth,
		AdminAuth:  auth,
	})
	return srv.Router(), idA, idB
}

func boletoBody() map[string]any {
	return map[string]any{
		"amount_cents":         100000,
		"currency":             "BRL",
		"due_date":             time.Now().Add(240 * time.Hour).UTC().Format(time.RFC3339),
		"fine_bps":             200,
		"monthly_interest_bps": 100,
		"discounts": []map[string]any{
			{"days_before_due": 10, "bps": 1000},
			{"days_before_due": 0, "bps": 200},
		},
	}
}

// roteiro grupos 1–3 + 6: register over HTTP, then read it back by id.
func TestBoletoCreateAndGetHTTP(t *testing.T) {
	t.Parallel()
	handler, _, _ := newBoletoFixture(t)

	rec := do(t, handler, http.MethodPost, "/v1/boletos", tenantToken,
		map[string]string{"Idempotency-Key": "kb1"}, boletoBody())
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: status %d body %s", rec.Code, rec.Body.String())
	}
	body := decodePix(t, rec)
	id, _ := body["boleto_id"].(string)
	if id == "" || body["status"] != "REGISTERED" {
		t.Fatalf("missing id/status: %v", body)
	}
	if body["amount_cents"].(float64) != 100000 {
		t.Fatalf("amount: %v", body["amount_cents"])
	}
	if discounts, ok := body["discounts"].([]any); !ok || len(discounts) != 2 {
		t.Fatalf("discounts not echoed: %v", body["discounts"])
	}

	rec = do(t, handler, http.MethodGet, "/v1/boletos/"+id, tenantToken, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get: status %d body %s", rec.Code, rec.Body.String())
	}
	got := decodePix(t, rec)
	if got["boleto_id"] != id || got["fine_bps"].(float64) != 200 {
		t.Fatalf("get mismatch: %v", got)
	}
}

// OWASP A01: a GET for another tenant's boleto must 404 (no existence oracle).
func TestBoletoCrossTenantGetIsolation(t *testing.T) {
	t.Parallel()
	handler, _, _ := newBoletoFixture(t)

	rec := do(t, handler, http.MethodPost, "/v1/boletos", tenantToken,
		map[string]string{"Idempotency-Key": "kb1"}, boletoBody())
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: status %d body %s", rec.Code, rec.Body.String())
	}
	id := decodePix(t, rec)["boleto_id"].(string)

	// Tenant B asks for tenant A's boleto -> not found, no disclosure.
	rec = do(t, handler, http.MethodGet, "/v1/boletos/"+id, tenantTokenB, nil, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant get: want 404, got %d body %s", rec.Code, rec.Body.String())
	}
}

func TestBoletoHTTPErrors(t *testing.T) {
	t.Parallel()
	handler, _, _ := newBoletoFixture(t)

	t.Run("requires_auth", func(t *testing.T) {
		rec := do(t, handler, http.MethodPost, "/v1/boletos", "",
			map[string]string{"Idempotency-Key": "k"}, boletoBody())
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("want 401 without auth, got %d", rec.Code)
		}
	})

	t.Run("get_requires_auth", func(t *testing.T) {
		rec := do(t, handler, http.MethodGet, "/v1/boletos/anything", "", nil, nil)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("want 401 without auth, got %d", rec.Code)
		}
	})

	t.Run("missing_idempotency_key", func(t *testing.T) {
		rec := do(t, handler, http.MethodPost, "/v1/boletos", tenantToken, nil, boletoBody())
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("want 400, got %d", rec.Code)
		}
	})

	t.Run("missing_due_date", func(t *testing.T) {
		body := boletoBody()
		delete(body, "due_date")
		rec := do(t, handler, http.MethodPost, "/v1/boletos", tenantToken,
			map[string]string{"Idempotency-Key": "k"}, body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("want 400, got %d", rec.Code)
		}
	})

	t.Run("bad_due_date", func(t *testing.T) {
		body := boletoBody()
		body["due_date"] = "not-a-time"
		rec := do(t, handler, http.MethodPost, "/v1/boletos", tenantToken,
			map[string]string{"Idempotency-Key": "k"}, body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("want 400, got %d", rec.Code)
		}
	})

	t.Run("fine_over_cap", func(t *testing.T) {
		body := boletoBody()
		body["fine_bps"] = 201
		rec := do(t, handler, http.MethodPost, "/v1/boletos", tenantToken,
			map[string]string{"Idempotency-Key": "k"}, body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("want 400, got %d", rec.Code)
		}
	})

	t.Run("unknown_field", func(t *testing.T) {
		body := boletoBody()
		body["evil"] = "x"
		rec := do(t, handler, http.MethodPost, "/v1/boletos", tenantToken,
			map[string]string{"Idempotency-Key": "k"}, body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("want 400 for unknown field, got %d", rec.Code)
		}
	})

	t.Run("get_unknown_id", func(t *testing.T) {
		rec := do(t, handler, http.MethodGet, "/v1/boletos/nope", tenantToken, nil, nil)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("want 404, got %d", rec.Code)
		}
	})
}

// registerBoletoHTTP registers a boleto over HTTP and returns its id.
func registerBoletoHTTP(t *testing.T, handler http.Handler, token, idemKey string) string {
	t.Helper()
	rec := do(t, handler, http.MethodPost, "/v1/boletos", token,
		map[string]string{"Idempotency-Key": idemKey}, boletoBody())
	if rec.Code != http.StatusCreated {
		t.Fatalf("register: status %d body %s", rec.Code, rec.Body.String())
	}
	return decodePix(t, rec)["boleto_id"].(string)
}

func updateBoletoBody() map[string]any {
	return map[string]any{
		"amount_cents":         70000,
		"currency":             "BRL",
		"due_date":             time.Now().Add(360 * time.Hour).UTC().Format(time.RFC3339),
		"valid_until":          time.Now().Add(600 * time.Hour).UTC().Format(time.RFC3339),
		"fine_bps":             150,
		"monthly_interest_bps": 80,
	}
}

// roteiro grupo 4: baixa via DELETE → 204; GET depois reflete CANCELLED.
func TestBoletoDeleteHTTP(t *testing.T) {
	t.Parallel()
	handler, _, _ := newBoletoFixture(t)
	id := registerBoletoHTTP(t, handler, tenantToken, "kdel")

	rec := do(t, handler, http.MethodDelete, "/v1/boletos/"+id, tenantToken, nil, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: want 204, got %d body %s", rec.Code, rec.Body.String())
	}
	rec = do(t, handler, http.MethodGet, "/v1/boletos/"+id, tenantToken, nil, nil)
	if rec.Code != http.StatusOK || decodePix(t, rec)["status"] != "CANCELLED" {
		t.Fatalf("get after delete: code=%d body=%s", rec.Code, rec.Body.String())
	}
}

// roteiro grupo 5: alteração via PUT → 200 com os novos parâmetros.
func TestBoletoUpdateHTTP(t *testing.T) {
	t.Parallel()
	handler, _, _ := newBoletoFixture(t)
	id := registerBoletoHTTP(t, handler, tenantToken, "kupd")

	rec := do(t, handler, http.MethodPut, "/v1/boletos/"+id, tenantToken,
		map[string]string{"Idempotency-Key": "kupd-put"}, updateBoletoBody())
	if rec.Code != http.StatusOK {
		t.Fatalf("update: want 200, got %d body %s", rec.Code, rec.Body.String())
	}
	body := decodePix(t, rec)
	if body["boleto_id"] != id || body["amount_cents"].(float64) != 70000 || body["valid_until"] == "" {
		t.Fatalf("update echo mismatch: %v", body)
	}
}

// OWASP A01: DELETE/PUT for another tenant's boleto must 404 (no oracle).
func TestBoletoCrossTenantWriteIsolation(t *testing.T) {
	t.Parallel()
	handler, _, _ := newBoletoFixture(t)
	id := registerBoletoHTTP(t, handler, tenantToken, "kiso")

	rec := do(t, handler, http.MethodDelete, "/v1/boletos/"+id, tenantTokenB, nil, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant delete: want 404, got %d", rec.Code)
	}
	rec = do(t, handler, http.MethodPut, "/v1/boletos/"+id, tenantTokenB,
		map[string]string{"Idempotency-Key": "x"}, updateBoletoBody())
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant put: want 404, got %d", rec.Code)
	}
	// The boleto is untouched for its real owner.
	rec = do(t, handler, http.MethodGet, "/v1/boletos/"+id, tenantToken, nil, nil)
	if rec.Code != http.StatusOK || decodePix(t, rec)["status"] != "REGISTERED" {
		t.Fatalf("owner read after blocked cross-tenant writes: %d %s", rec.Code, rec.Body.String())
	}
}

func TestBoletoWriteAuthAndValidation(t *testing.T) {
	t.Parallel()
	handler, _, _ := newBoletoFixture(t)
	id := registerBoletoHTTP(t, handler, tenantToken, "kwav")

	t.Run("delete_requires_auth", func(t *testing.T) {
		rec := do(t, handler, http.MethodDelete, "/v1/boletos/"+id, "", nil, nil)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("want 401, got %d", rec.Code)
		}
	})
	t.Run("put_requires_auth", func(t *testing.T) {
		rec := do(t, handler, http.MethodPut, "/v1/boletos/"+id, "",
			map[string]string{"Idempotency-Key": "k"}, updateBoletoBody())
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("want 401, got %d", rec.Code)
		}
	})
	t.Run("put_missing_idempotency_key", func(t *testing.T) {
		rec := do(t, handler, http.MethodPut, "/v1/boletos/"+id, tenantToken, nil, updateBoletoBody())
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("want 400, got %d", rec.Code)
		}
	})
	t.Run("put_unknown_field", func(t *testing.T) {
		body := updateBoletoBody()
		body["evil"] = "x"
		rec := do(t, handler, http.MethodPut, "/v1/boletos/"+id, tenantToken,
			map[string]string{"Idempotency-Key": "k"}, body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("want 400, got %d", rec.Code)
		}
	})
	t.Run("put_bad_due_date", func(t *testing.T) {
		body := updateBoletoBody()
		body["due_date"] = "nope"
		rec := do(t, handler, http.MethodPut, "/v1/boletos/"+id, tenantToken,
			map[string]string{"Idempotency-Key": "k"}, body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("want 400, got %d", rec.Code)
		}
	})
	t.Run("delete_unknown_id", func(t *testing.T) {
		rec := do(t, handler, http.MethodDelete, "/v1/boletos/nope", tenantToken, nil, nil)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("want 404, got %d", rec.Code)
		}
	})
}

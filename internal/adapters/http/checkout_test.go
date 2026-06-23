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

// newCheckoutFixture wires a Server with the checkout service backed by the in-memory
// stub, plus a seeded, priced, credentialed tenant.
func newCheckoutFixture(t *testing.T) (http.Handler, string) {
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
	creds.Set(tn.ID(), ports.BankCredential{ClientID: "c6-acme", Secret: "s"})
	if _, err := admin.SetEndpointPrice(context.Background(), tn.ID(), app.CheckoutCreateEndpoint, 30); err != nil {
		t.Fatalf("seed price: %v", err)
	}
	auth := httpadapter.NewStaticTokenAuth(map[string]string{tenantToken: tn.ID()}, []string{adminToken}, nil)
	srv := httpadapter.NewServer(httpadapter.Config{
		Charges:    app.NewChargeService(deps),
		Checkout:   app.NewCheckoutService(deps),
		Admin:      admin,
		Webhooks:   app.NewWebhookService(deps),
		TenantAuth: auth,
		AdminAuth:  auth,
	})
	return srv.Router(), tn.ID()
}

func checkoutBody(cardType string, requireAuth bool) map[string]any {
	return map[string]any{
		"currency":               "BRL",
		"expires_in_seconds":     1800,
		"card_type":              cardType,
		"require_authentication": requireAuth,
		"items": []map[string]any{
			{"description": "Anuidade", "amount_cents": 1000},
			{"description": "Taxa", "amount_cents": 250},
		},
	}
}

// roteiro 9.a/9.b/9.c: open via HTTP for each card-type / auth combination.
func TestCheckoutCreateHTTPMatrix(t *testing.T) {
	t.Parallel()
	handler, _ := newCheckoutFixture(t)
	cases := []struct {
		name        string
		key         string
		cardType    string
		requireAuth bool
	}{
		{"9a_credit_no_auth", "k9a", "credit", false},
		{"9b_debit", "k9b", "debit", false},
		{"9c_credit_with_auth", "k9c", "credit", true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			rec := do(t, handler, http.MethodPost, "/v1/checkout", tenantToken,
				map[string]string{"Idempotency-Key": tc.key}, checkoutBody(tc.cardType, tc.requireAuth))
			if rec.Code != http.StatusCreated {
				t.Fatalf("%s: status %d body %s", tc.name, rec.Code, rec.Body.String())
			}
			body := decodePix(t, rec)
			if body["session_id"] == "" || body["redirect_url"] == "" {
				t.Fatalf("%s: missing session/redirect: %v", tc.name, body)
			}
			if body["status"] != "OPEN" {
				t.Fatalf("%s: status %v", tc.name, body["status"])
			}
			if body["amount_cents"].(float64) != 1250 {
				t.Fatalf("%s: amount %v", tc.name, body["amount_cents"])
			}
			if body["card_type"] != tc.cardType {
				t.Fatalf("%s: card_type %v", tc.name, body["card_type"])
			}
			if body["require_authentication"].(bool) != tc.requireAuth {
				t.Fatalf("%s: require_authentication %v", tc.name, body["require_authentication"])
			}
		})
	}
}

func TestCheckoutCreateHTTPAbsoluteExpiry(t *testing.T) {
	t.Parallel()
	handler, _ := newCheckoutFixture(t)
	body := checkoutBody("credit", false)
	delete(body, "expires_in_seconds")
	body["expires_at"] = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	rec := do(t, handler, http.MethodPost, "/v1/checkout", tenantToken,
		map[string]string{"Idempotency-Key": "kexp"}, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("absolute expiry: status %d body %s", rec.Code, rec.Body.String())
	}
}

func TestCheckoutCreateHTTPErrors(t *testing.T) {
	t.Parallel()
	handler, _ := newCheckoutFixture(t)

	t.Run("missing_idempotency_key", func(t *testing.T) {
		rec := do(t, handler, http.MethodPost, "/v1/checkout", tenantToken, nil, checkoutBody("credit", false))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("want 400, got %d", rec.Code)
		}
	})

	t.Run("empty_items", func(t *testing.T) {
		body := checkoutBody("credit", false)
		body["items"] = []map[string]any{}
		rec := do(t, handler, http.MethodPost, "/v1/checkout", tenantToken,
			map[string]string{"Idempotency-Key": "k"}, body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("want 400, got %d", rec.Code)
		}
	})

	t.Run("unknown_card_type", func(t *testing.T) {
		rec := do(t, handler, http.MethodPost, "/v1/checkout", tenantToken,
			map[string]string{"Idempotency-Key": "k"}, checkoutBody("crypto", false))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("want 400, got %d", rec.Code)
		}
	})

	t.Run("bad_currency", func(t *testing.T) {
		body := checkoutBody("credit", false)
		body["currency"] = "XX"
		rec := do(t, handler, http.MethodPost, "/v1/checkout", tenantToken,
			map[string]string{"Idempotency-Key": "k"}, body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("want 400, got %d", rec.Code)
		}
	})

	t.Run("bad_expires_at", func(t *testing.T) {
		body := checkoutBody("credit", false)
		delete(body, "expires_in_seconds")
		body["expires_at"] = "not-a-time"
		rec := do(t, handler, http.MethodPost, "/v1/checkout", tenantToken,
			map[string]string{"Idempotency-Key": "k"}, body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("want 400, got %d", rec.Code)
		}
	})

	t.Run("no_expiry", func(t *testing.T) {
		body := checkoutBody("credit", false)
		delete(body, "expires_in_seconds")
		rec := do(t, handler, http.MethodPost, "/v1/checkout", tenantToken,
			map[string]string{"Idempotency-Key": "k"}, body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("want 400, got %d", rec.Code)
		}
	})

	t.Run("unknown_field", func(t *testing.T) {
		body := checkoutBody("credit", false)
		body["evil"] = "x"
		rec := do(t, handler, http.MethodPost, "/v1/checkout", tenantToken,
			map[string]string{"Idempotency-Key": "k"}, body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("want 400 for unknown field, got %d", rec.Code)
		}
	})

	t.Run("requires_auth", func(t *testing.T) {
		rec := do(t, handler, http.MethodPost, "/v1/checkout", "",
			map[string]string{"Idempotency-Key": "k"}, checkoutBody("credit", false))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("want 401 without auth, got %d", rec.Code)
		}
	})
}

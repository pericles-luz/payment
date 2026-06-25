package http_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

// ddaFixture wires a Server with the DDA service backed by the in-memory stub, plus two
// seeded/credentialed tenants (A and B) so cross-tenant isolation can be exercised.
type ddaFixture struct {
	handler  http.Handler
	tenantID string
	bank     *bank.StubProvider
}

func ddaBarcode(seed byte) string { return strings.Repeat(string('0'+seed%10), 44) }

func newDDAFixture(t *testing.T) *ddaFixture {
	t.Helper()
	ctx := context.Background()
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
		DDA:         stub,
		Credentials: creds,
		Clock:       system.Clock{},
		IDs:         system.IDProvider{},
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
	// Seed boletos open in tenant A's DDA (roteiro 8.1).
	stub.SeedDDABoletos(tnA.ID(), []ports.DDABoleto{
		{ID: "b1", Barcode: ddaBarcode(1), AmountCents: 1000, DueDate: time.Now().Add(48 * time.Hour), BeneficiaryName: "Acme"},
	})
	auth := httpadapter.NewStaticTokenAuth(
		map[string]string{tenantToken: tnA.ID(), tenantTokenB: tnB.ID()},
		[]string{adminToken}, nil)
	srv := httpadapter.NewServer(httpadapter.Config{
		DDA:        app.NewDDAService(deps),
		Admin:      admin,
		TenantAuth: auth,
		AdminAuth:  auth,
	})
	return &ddaFixture{handler: srv.Router(), tenantID: tnA.ID(), bank: stub}
}

// createGroup is a helper: POST a consult group and return its txid.
func createGroup(t *testing.T, f *ddaFixture, key string, barcodes ...string) (string, *httptest.ResponseRecorder) {
	t.Helper()
	rec := do(t, f.handler, http.MethodPost, "/v1/dda/payment-groups", tenantToken,
		map[string]string{"Idempotency-Key": key}, map[string]any{"barcodes": barcodes})
	if rec.Code != http.StatusCreated {
		return "", rec
	}
	var v struct {
		TxID  string `json:"txid"`
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode group: %v", err)
	}
	return v.TxID, rec
}

// roteiro 8.1: GET /v1/dda/boletos → 200.
func TestDDAListBoletos(t *testing.T) {
	t.Parallel()
	f := newDDAFixture(t)
	rec := do(t, f.handler, http.MethodGet, "/v1/dda/boletos", tenantToken, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var v struct {
		Boletos []struct {
			ID      string `json:"id"`
			Barcode string `json:"barcode"`
		} `json:"boletos"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(v.Boletos) != 1 || v.Boletos[0].ID != "b1" {
		t.Fatalf("unexpected boletos: %+v", v.Boletos)
	}
	// Deny-by-default: no token → 401.
	if rec := do(t, f.handler, http.MethodGet, "/v1/dda/boletos", "", nil, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 without auth, got %d", rec.Code)
	}
}

// roteiro 8.2: POST /v1/dda/payment-groups → 201 + txid.
func TestDDACreateGroup(t *testing.T) {
	t.Parallel()
	f := newDDAFixture(t)
	txid, rec := createGroup(t, f, "k1", ddaBarcode(1), ddaBarcode(2))
	if rec.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d body=%s", rec.Code, rec.Body.String())
	}
	if txid == "" {
		t.Fatal("response must carry a txid")
	}

	t.Run("missing_idempotency_key", func(t *testing.T) {
		rec := do(t, f.handler, http.MethodPost, "/v1/dda/payment-groups", tenantToken, nil,
			map[string]any{"barcodes": []string{ddaBarcode(1)}})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("want 400, got %d", rec.Code)
		}
	})

	t.Run("empty_barcodes", func(t *testing.T) {
		rec := do(t, f.handler, http.MethodPost, "/v1/dda/payment-groups", tenantToken,
			map[string]string{"Idempotency-Key": "k"}, map[string]any{"barcodes": []string{}})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("want 400, got %d", rec.Code)
		}
	})

	t.Run("invalid_barcode", func(t *testing.T) {
		rec := do(t, f.handler, http.MethodPost, "/v1/dda/payment-groups", tenantToken,
			map[string]string{"Idempotency-Key": "k"}, map[string]any{"barcodes": []string{"not-a-barcode"}})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("want 400, got %d", rec.Code)
		}
	})

	t.Run("unknown_field", func(t *testing.T) {
		rec := do(t, f.handler, http.MethodPost, "/v1/dda/payment-groups", tenantToken,
			map[string]string{"Idempotency-Key": "k"}, map[string]any{"barcodes": []string{ddaBarcode(1)}, "evil": "x"})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("want 400 for unknown field, got %d", rec.Code)
		}
	})
}

// roteiro 8.3: GET /v1/dda/payment-groups/{id}/items → 200.
func TestDDAGetGroupItems(t *testing.T) {
	t.Parallel()
	f := newDDAFixture(t)
	txid, _ := createGroup(t, f, "k1", ddaBarcode(1), ddaBarcode(2))

	rec := do(t, f.handler, http.MethodGet, "/v1/dda/payment-groups/"+txid+"/items", tenantToken, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var v struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(v.Items) != 2 {
		t.Fatalf("want 2 items, got %d", len(v.Items))
	}
	// Unknown group → 404.
	if rec := do(t, f.handler, http.MethodGet, "/v1/dda/payment-groups/missing/items", tenantToken, nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("want 404 unknown group, got %d", rec.Code)
	}
	// Cross-tenant → 404 (no existence oracle).
	if rec := do(t, f.handler, http.MethodGet, "/v1/dda/payment-groups/"+txid+"/items", tenantTokenB, nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("want 404 cross-tenant, got %d", rec.Code)
	}
}

// roteiro 8.4: DELETE /v1/dda/payment-groups/{id}/items (list) → 204.
func TestDDARemoveItemsList(t *testing.T) {
	t.Parallel()
	f := newDDAFixture(t)
	txid, rec := createGroup(t, f, "k1", ddaBarcode(1), ddaBarcode(2), ddaBarcode(3))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d", rec.Code)
	}
	var created struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	ids := []string{created.Items[0].ID, created.Items[1].ID}

	del := do(t, f.handler, http.MethodDelete, "/v1/dda/payment-groups/"+txid+"/items", tenantToken,
		nil, map[string]any{"item_ids": ids})
	if del.Code != http.StatusNoContent {
		t.Fatalf("want 204, got %d body=%s", del.Code, del.Body.String())
	}
	// One item should remain.
	get := do(t, f.handler, http.MethodGet, "/v1/dda/payment-groups/"+txid+"/items", tenantToken, nil, nil)
	var after struct {
		Items []json.RawMessage `json:"items"`
	}
	_ = json.Unmarshal(get.Body.Bytes(), &after)
	if len(after.Items) != 1 {
		t.Fatalf("want 1 item left, got %d", len(after.Items))
	}

	t.Run("unknown_field", func(t *testing.T) {
		rec := do(t, f.handler, http.MethodDelete, "/v1/dda/payment-groups/"+txid+"/items", tenantToken,
			nil, map[string]any{"item_ids": ids, "evil": 1})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("want 400 unknown field, got %d", rec.Code)
		}
	})

	t.Run("empty_list", func(t *testing.T) {
		rec := do(t, f.handler, http.MethodDelete, "/v1/dda/payment-groups/"+txid+"/items", tenantToken,
			nil, map[string]any{"item_ids": []string{}})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("want 400 empty list, got %d", rec.Code)
		}
	})
}

// roteiro 8.5: DELETE /v1/dda/payment-groups/{id}/items/{itemID} → 204.
func TestDDARemoveSingleItem(t *testing.T) {
	t.Parallel()
	f := newDDAFixture(t)
	txid, rec := createGroup(t, f, "k1", ddaBarcode(1), ddaBarcode(2))
	var created struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)

	del := do(t, f.handler, http.MethodDelete, "/v1/dda/payment-groups/"+txid+"/items/"+created.Items[0].ID, tenantToken, nil, nil)
	if del.Code != http.StatusNoContent {
		t.Fatalf("want 204, got %d body=%s", del.Code, del.Body.String())
	}
	// Removing from an unknown group → 404.
	if rec := do(t, f.handler, http.MethodDelete, "/v1/dda/payment-groups/missing/items/x", tenantToken, nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("want 404 unknown group, got %d", rec.Code)
	}
}

// roteiro 8.6: POST /v1/dda/payment-groups/{id}/submit → 204.
func TestDDASubmitGroup(t *testing.T) {
	t.Parallel()
	f := newDDAFixture(t)
	txid, _ := createGroup(t, f, "k1", ddaBarcode(1))

	sub := do(t, f.handler, http.MethodPost, "/v1/dda/payment-groups/"+txid+"/submit", tenantToken,
		map[string]string{"Idempotency-Key": "s1"}, nil)
	if sub.Code != http.StatusNoContent {
		t.Fatalf("want 204, got %d body=%s", sub.Code, sub.Body.String())
	}
	// Idempotent re-submit (already approved) → 204.
	if rec := do(t, f.handler, http.MethodPost, "/v1/dda/payment-groups/"+txid+"/submit", tenantToken,
		map[string]string{"Idempotency-Key": "s1"}, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("re-submit want 204, got %d", rec.Code)
	}
	// After approval the group is frozen: trimming it → 409 Conflict.
	if rec := do(t, f.handler, http.MethodDelete, "/v1/dda/payment-groups/"+txid+"/items/anything", tenantToken, nil, nil); rec.Code != http.StatusConflict {
		t.Fatalf("trim after approval want 409, got %d", rec.Code)
	}

	t.Run("missing_idempotency_key", func(t *testing.T) {
		rec := do(t, f.handler, http.MethodPost, "/v1/dda/payment-groups/"+txid+"/submit", tenantToken, nil, nil)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("want 400, got %d", rec.Code)
		}
	})

	t.Run("unknown_group", func(t *testing.T) {
		rec := do(t, f.handler, http.MethodPost, "/v1/dda/payment-groups/missing/submit", tenantToken,
			map[string]string{"Idempotency-Key": "s2"}, nil)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("want 404, got %d", rec.Code)
		}
	})
}

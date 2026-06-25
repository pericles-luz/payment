package c6

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// ddaServer is a configurable C6 double for the DDA / agendamento de pagamentos
// endpoints (roteiro grupo 8) plus the OAuth2 token endpoint, backed by httptest TLS.
// Each operation defaults to a happy path that a test can override, and the last
// Authorization / Idempotency-Key / body are recorded for plumbing assertions.
type ddaServer struct {
	*httptest.Server

	mu             sync.Mutex
	lastAuthHeader string
	lastIdemKey    string
	lastBody       []byte

	listBoletos http.HandlerFunc
	createGroup http.HandlerFunc
	getGroup    http.HandlerFunc
	removeItems http.HandlerFunc
	removeItem  http.HandlerFunc
	submit      http.HandlerFunc
}

func newDDAServer(t *testing.T) *ddaServer {
	t.Helper()
	ds := &ddaServer{}
	record := func(r *http.Request) {
		ds.mu.Lock()
		defer ds.mu.Unlock()
		ds.lastAuthHeader = r.Header.Get("Authorization")
		ds.lastIdemKey = r.Header.Get("Idempotency-Key")
		ds.lastBody, _ = io.ReadAll(io.LimitReader(r.Body, 1<<20))
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /oauth/token", func(w http.ResponseWriter, r *http.Request) {
		user, _, _ := r.BasicAuth()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok-` + user + `","token_type":"Bearer","expires_in":3600}`))
	})
	mux.HandleFunc("GET /v1/dda/boletos", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		if ds.listBoletos != nil {
			ds.listBoletos(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"boletos":[{"id":"b1","barcode":"123","amount_cents":1000,"due_date":"2030-01-01T00:00:00Z","beneficiary_name":"Acme"}]}`))
	})
	mux.HandleFunc("POST /v1/dda/payment-groups", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		if ds.createGroup != nil {
			ds.createGroup(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"ddag_1","status":"consultando","items":[{"id":"i1","barcode":"123","amount_cents":1000,"due_date":"2030-01-01T00:00:00Z"}]}`))
	})
	mux.HandleFunc("GET /v1/dda/payment-groups/{id}/items", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		if ds.getGroup != nil {
			ds.getGroup(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"` + r.PathValue("id") + `","status":"consultando","items":[{"id":"i1","barcode":"123","amount_cents":1000,"due_date":"2030-01-01T00:00:00Z"}]}`))
	})
	mux.HandleFunc("DELETE /v1/dda/payment-groups/{id}/items", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		if ds.removeItems != nil {
			ds.removeItems(w, r)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("DELETE /v1/dda/payment-groups/{id}/items/{itemID}", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		if ds.removeItem != nil {
			ds.removeItem(w, r)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /v1/dda/payment-groups/{id}/submit", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		if ds.submit != nil {
			ds.submit(w, r)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	ds.Server = httptest.NewTLSServer(mux)
	t.Cleanup(ds.Close)
	return ds
}

func (ds *ddaServer) provider(t *testing.T, creds ports.CredentialStore) *Provider {
	t.Helper()
	p, err := New(Config{BaseURL: ds.URL, TokenURL: ds.URL + "/oauth/token", HTTPClient: ds.Client()}, creds)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func (ds *ddaServer) idemKey() string {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	return ds.lastIdemKey
}

func (ds *ddaServer) body() []byte {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	return ds.lastBody
}

func ddaGroupReq() ports.DDAGroupRequest {
	return ports.DDAGroupRequest{TenantID: "t1", Barcodes: []string{"123", "456"}, IdempotencyKey: "k1"}
}

// roteiro 8.1: list open boletos; bearer attached, wire mapped.
func TestC6ListOpenBoletos(t *testing.T) {
	t.Parallel()
	ds := newDDAServer(t)
	p := ds.provider(t, oneTenant("t1", "client-1", "secret-1"))

	got, err := p.ListOpenBoletos(context.Background(), "t1")
	if err != nil {
		t.Fatalf("ListOpenBoletos: %v", err)
	}
	if len(got) != 1 || got[0].ID != "b1" || got[0].AmountCents != 1000 || got[0].BeneficiaryName != "Acme" {
		t.Fatalf("unexpected boletos: %+v", got)
	}
	if ds.lastAuthHeader != "Bearer tok-client-1" {
		t.Fatalf("bearer not attached: %q", ds.lastAuthHeader)
	}
}

func TestC6ListOpenBoletosErrorMapping(t *testing.T) {
	t.Parallel()
	ds := newDDAServer(t)
	ds.listBoletos = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"code":"X"}`))
	}
	p := ds.provider(t, oneTenant("t1", "c", "s"))
	if _, err := p.ListOpenBoletos(context.Background(), "t1"); err == nil {
		t.Fatal("5xx must surface an error")
	}
}

// roteiro 8.2: create consult group; bearer + idempotency forwarded; barcodes transported.
func TestC6CreatePaymentGroup(t *testing.T) {
	t.Parallel()
	ds := newDDAServer(t)
	p := ds.provider(t, oneTenant("t1", "client-1", "secret-1"))

	g, err := p.CreatePaymentGroup(context.Background(), "t1", ddaGroupReq())
	if err != nil {
		t.Fatalf("CreatePaymentGroup: %v", err)
	}
	if g.ID != "ddag_1" || g.Status != "consultando" || len(g.Items) != 1 {
		t.Fatalf("unexpected group: %+v", g)
	}
	if ds.idemKey() != "k1" {
		t.Fatalf("idempotency key not forwarded: %q", ds.idemKey())
	}
	var sent struct {
		Barcodes []string `json:"barcodes"`
	}
	if err := json.Unmarshal(ds.body(), &sent); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if len(sent.Barcodes) != 2 {
		t.Fatalf("barcodes not transported: %s", ds.body())
	}
}

func TestC6CreatePaymentGroupRejectsBadInput(t *testing.T) {
	t.Parallel()
	ds := newDDAServer(t)
	p := ds.provider(t, oneTenant("t1", "c", "s"))

	bad := ddaGroupReq()
	bad.IdempotencyKey = ""
	if _, err := p.CreatePaymentGroup(context.Background(), "t1", bad); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty anchor must map to ErrValidation, got %v", err)
	}
	bad = ddaGroupReq()
	bad.Barcodes = nil
	if _, err := p.CreatePaymentGroup(context.Background(), "t1", bad); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty barcodes must map to ErrValidation, got %v", err)
	}
}

func TestC6CreatePaymentGroupErrorMapping(t *testing.T) {
	t.Parallel()
	ds := newDDAServer(t)
	ds.createGroup = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"code":"BAD"}`))
	}
	p := ds.provider(t, oneTenant("t1", "c", "s"))
	if _, err := p.CreatePaymentGroup(context.Background(), "t1", ddaGroupReq()); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("400 should map to ErrValidation, got %v", err)
	}
}

// roteiro 8.3: reconcile group items.
func TestC6GetPaymentGroup(t *testing.T) {
	t.Parallel()
	ds := newDDAServer(t)
	p := ds.provider(t, oneTenant("t1", "client-1", "secret-1"))

	g, err := p.GetPaymentGroup(context.Background(), "t1", "ddag_1")
	if err != nil {
		t.Fatalf("GetPaymentGroup: %v", err)
	}
	if g.ID != "ddag_1" || len(g.Items) != 1 {
		t.Fatalf("unexpected group: %+v", g)
	}
}

func TestC6GetPaymentGroupNotFound(t *testing.T) {
	t.Parallel()
	ds := newDDAServer(t)
	ds.getGroup = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":"NOT_FOUND"}`))
	}
	p := ds.provider(t, oneTenant("t1", "c", "s"))
	if _, err := p.GetPaymentGroup(context.Background(), "t1", "nope"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("404 should map to ErrNotFound, got %v", err)
	}
}

// roteiro 8.4: remove a list of items; the id list is transported in the body.
func TestC6RemovePaymentGroupItems(t *testing.T) {
	t.Parallel()
	ds := newDDAServer(t)
	p := ds.provider(t, oneTenant("t1", "client-1", "secret-1"))

	if err := p.RemovePaymentGroupItems(context.Background(), "t1", "ddag_1", []string{"i1", "i2"}); err != nil {
		t.Fatalf("RemovePaymentGroupItems: %v", err)
	}
	var sent struct {
		ItemIDs []string `json:"item_ids"`
	}
	if err := json.Unmarshal(ds.body(), &sent); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if len(sent.ItemIDs) != 2 {
		t.Fatalf("item_ids not transported: %s", ds.body())
	}
}

func TestC6RemovePaymentGroupItemsRejectsEmpty(t *testing.T) {
	t.Parallel()
	ds := newDDAServer(t)
	p := ds.provider(t, oneTenant("t1", "c", "s"))
	if err := p.RemovePaymentGroupItems(context.Background(), "t1", "ddag_1", nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty list must map to ErrValidation, got %v", err)
	}
}

func TestC6RemovePaymentGroupItemsNotFound(t *testing.T) {
	t.Parallel()
	ds := newDDAServer(t)
	ds.removeItems = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":"NOT_FOUND"}`))
	}
	p := ds.provider(t, oneTenant("t1", "c", "s"))
	if err := p.RemovePaymentGroupItems(context.Background(), "t1", "nope", []string{"i1"}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("404 should map to ErrNotFound, got %v", err)
	}
}

// roteiro 8.5: remove a single item.
func TestC6RemovePaymentGroupItem(t *testing.T) {
	t.Parallel()
	ds := newDDAServer(t)
	p := ds.provider(t, oneTenant("t1", "c", "s"))
	if err := p.RemovePaymentGroupItem(context.Background(), "t1", "ddag_1", "i1"); err != nil {
		t.Fatalf("RemovePaymentGroupItem: %v", err)
	}
}

func TestC6RemovePaymentGroupItemRejectsEmpty(t *testing.T) {
	t.Parallel()
	ds := newDDAServer(t)
	p := ds.provider(t, oneTenant("t1", "c", "s"))
	if err := p.RemovePaymentGroupItem(context.Background(), "t1", "ddag_1", "  "); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty item id must map to ErrValidation, got %v", err)
	}
}

func TestC6RemovePaymentGroupItemNotFound(t *testing.T) {
	t.Parallel()
	ds := newDDAServer(t)
	ds.removeItem = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":"NOT_FOUND"}`))
	}
	p := ds.provider(t, oneTenant("t1", "c", "s"))
	if err := p.RemovePaymentGroupItem(context.Background(), "t1", "nope", "i1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("404 should map to ErrNotFound, got %v", err)
	}
}

// roteiro 8.6: submit for approval; idempotency key forwarded.
func TestC6SubmitPaymentGroup(t *testing.T) {
	t.Parallel()
	ds := newDDAServer(t)
	p := ds.provider(t, oneTenant("t1", "c", "s"))
	if err := p.SubmitPaymentGroup(context.Background(), "t1", "ddag_1", "idem-9"); err != nil {
		t.Fatalf("SubmitPaymentGroup: %v", err)
	}
	if ds.idemKey() != "idem-9" {
		t.Fatalf("idempotency key not forwarded: %q", ds.idemKey())
	}
}

func TestC6SubmitPaymentGroupNotFound(t *testing.T) {
	t.Parallel()
	ds := newDDAServer(t)
	ds.submit = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":"NOT_FOUND"}`))
	}
	p := ds.provider(t, oneTenant("t1", "c", "s"))
	if err := p.SubmitPaymentGroup(context.Background(), "t1", "nope", "idem"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("404 should map to ErrNotFound, got %v", err)
	}
}

func TestC6DDAMissingCredential(t *testing.T) {
	t.Parallel()
	ds := newDDAServer(t)
	p := ds.provider(t, &fakeCreds{creds: map[string]ports.BankCredential{}})
	if _, err := p.ListOpenBoletos(context.Background(), "unknown"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("missing credential should propagate ErrNotFound, got %v", err)
	}
}

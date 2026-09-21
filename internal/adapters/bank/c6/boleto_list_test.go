package c6

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// listServer is a double for GET /v2/bank_slips/list (roteiro BP_06).
type listServer struct {
	*httptest.Server

	mu    sync.Mutex
	query url.Values

	list http.HandlerFunc
}

func newListServer(t *testing.T) *listServer {
	t.Helper()
	ls := &listServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /oauth/token", func(w http.ResponseWriter, r *http.Request) {
		user, _, _ := r.BasicAuth()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok-` + user + `","token_type":"Bearer","expires_in":3600}`))
	})
	mux.HandleFunc("GET /v2/bank_slips/list", func(w http.ResponseWriter, r *http.Request) {
		ls.mu.Lock()
		ls.query = r.URL.Query()
		ls.mu.Unlock()
		if ls.list != nil {
			ls.list(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"total_elements":1,"total_pages":1,"page":0,"size":20,"content":[` +
			`{"id":"01M2KEFNXH680SBM714RX13CJT","external_reference_id":"552S2QFD8D61V3BZGWXK27SDQT",` +
			`"amount":12.34,"status":"PAID","due_date":"2026-10-01"}]}`))
	})
	ls.Server = httptest.NewTLSServer(mux)
	t.Cleanup(ls.Close)
	return ls
}

func (ls *listServer) provider(t *testing.T) *Provider {
	t.Helper()
	p, err := New(Config{BaseURL: ls.URL, TokenURL: ls.URL + "/oauth/token", HTTPClient: ls.Client()}, oneTenant("t1", "c", "s"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func (ls *listServer) lastQuery() url.Values {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	return ls.query
}

func TestC6ListBoletos(t *testing.T) {
	t.Parallel()
	ls := newListServer(t)
	p := ls.provider(t)
	from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

	got, err := p.ListBoletos(context.Background(), "t1", ports.BoletoListFilter{
		DueDateFrom: from, DueDateTo: from.AddDate(0, 0, 30),
		Status: "PAID", PageSize: 20,
	})
	if err != nil {
		t.Fatalf("ListBoletos: %v", err)
	}
	if len(got.Boletos) != 1 || got.TotalItems != 1 || got.PageSize != 20 {
		t.Fatalf("unexpected list: %+v", got)
	}
	if got.Boletos[0].AmountCents != 1234 || got.Boletos[0].Status != "PAID" {
		t.Fatalf("unexpected row: %+v", got.Boletos[0])
	}

	q := ls.lastQuery()
	if q.Get("due_date_from") != "2026-09-01" || q.Get("due_date_to") != "2026-10-01" {
		t.Fatalf("unexpected window: %v", q)
	}
	// Page is zero-based on this endpoint, so a zero must be SENT rather than treated
	// as unset — omitting it would silently read a different page than asked for.
	if q.Get("page") != "0" || q.Get("status") != "PAID" {
		t.Fatalf("unexpected query: %v", q)
	}
	// Ranges the caller did not set must not appear.
	if q.Has("payment_date_from") || q.Has("credit_date_from") {
		t.Fatalf("unset ranges must be omitted: %v", q)
	}
}

func TestC6ListBoletosValidation(t *testing.T) {
	t.Parallel()
	ls := newListServer(t)
	p := ls.provider(t)
	ctx := context.Background()
	from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

	// The contract requires at least one date range.
	if _, err := p.ListBoletos(ctx, "t1", ports.BoletoListFilter{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("no window: want validation, got %v", err)
	}
	bad := map[string]ports.BoletoListFilter{
		// A half-open range would make the bank answer a window the caller did not mean.
		"half_open":    {DueDateFrom: from},
		"half_open_to": {PaymentDateTo: from},
		"inverted":     {CreditDateFrom: from, CreditDateTo: from.AddDate(0, 0, -1)},
		"too_wide":     {DueDateFrom: from, DueDateTo: from.AddDate(0, 0, 61)},
		"bad_reference": {
			DueDateFrom: from, DueDateTo: from.AddDate(0, 0, 1),
			ExternalReferenceID: "curto",
		},
	}
	for name, f := range bad {
		if _, err := p.ListBoletos(ctx, "t1", f); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("%s: want validation, got %v", name, err)
		}
	}

	// A well-formed 26-char reference is accepted and forwarded.
	ok := ports.BoletoListFilter{
		DueDateFrom: from, DueDateTo: from.AddDate(0, 0, 1),
		ExternalReferenceID: strings.Repeat("A", 26),
	}
	if _, err := p.ListBoletos(ctx, "t1", ok); err != nil {
		t.Fatalf("valid reference: %v", err)
	}
	if ls.lastQuery().Get("external_reference_id") != strings.Repeat("A", 26) {
		t.Fatalf("reference not forwarded: %v", ls.lastQuery())
	}
}

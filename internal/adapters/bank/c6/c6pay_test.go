package c6

import (
	"context"
	"encoding/json"
	"errors"
	"io"
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

// c6PayServer is a C6 Pay extract double. Its default bodies use the key the WIRE
// really sends (`content`), not the one the published spec declares.
type c6PayServer struct {
	*httptest.Server

	mu          sync.Mutex
	lastPath    string
	lastQuery   url.Values
	lastPartner string

	receivables  http.HandlerFunc
	transactions http.HandlerFunc
}

const c6PayReceivablesWire = `{"page":1,"last_page":1,"items":1,"content":[{` +
	`"local_reference":"ref-1","authorization_code":"123456","authorizer_reference":"auth-1",` +
	`"brand_name":"MASTERCARD","expected_date":"2026-10-17","receivable_id":"rcv-1",` +
	`"installment_number":1,"installments":3,"interest_type":"BY_SELLER",` +
	`"gross_amount":202.45,"fee":-0.22,"mdr":2,"discount":-2.35,"net_amount":200,` +
	`"payment_date":"2026-10-18","payment_type":"CREDIT",` +
	`"transaction_date_time":"2026-09-17T10:00:00Z","transaction_id":"tx-1",` +
	`"type":"SALE","status":"PAYMENT_APPROVED","origin":"PAYMENT_TERMINAL"}]}`

const c6PayTransactionsWire = `{"page":1,"last-page":1,"items":1,"content":[{` +
	`"amount":123.45,"authorization_code":"123456","authorizer_reference":"auth-1",` +
	`"brand_name":"MASTERCARD","card_bin":"000000","card_entry_mode":"CHIP",` +
	`"card_holder_name":"Jose da Silva","card_number":"000000******0000",` +
	`"currency_code":"986","date_time":"2026-09-17T10:00:00Z",` +
	`"fraud_analysis_recommendation":"ACCEPT","id":"tx-1","installments":3,` +
	`"interest_type":"BY_SELLER","local_reference":"ref-1","origin":"ECOMMERCE",` +
	`"payment_type":"CREDIT","status":"AUTHORIZED","terminal_id":"term-1"}]}`

func newC6PayServer(t *testing.T) *c6PayServer {
	t.Helper()
	cs := &c6PayServer{}
	record := func(r *http.Request) {
		cs.mu.Lock()
		defer cs.mu.Unlock()
		cs.lastPath = r.URL.Path
		cs.lastQuery = r.URL.Query()
		cs.lastPartner = r.Header.Get("partner-software-version")
		_, _ = io.Copy(io.Discard, r.Body)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /oauth/token", func(w http.ResponseWriter, r *http.Request) {
		user := tokenClientID(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok-` + user + `","token_type":"Bearer","expires_in":3600}`))
	})
	mux.HandleFunc("GET /v1/c6pay/statement/receivables", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		if cs.receivables != nil {
			cs.receivables(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(c6PayReceivablesWire))
	})
	mux.HandleFunc("GET /v1/c6pay/statement/transactions", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		if cs.transactions != nil {
			cs.transactions(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(c6PayTransactionsWire))
	})
	cs.Server = httptest.NewTLSServer(mux)
	t.Cleanup(cs.Close)
	return cs
}

func (cs *c6PayServer) provider(t *testing.T) *Provider {
	t.Helper()
	p, err := New(Config{BaseURL: cs.URL, TokenURL: cs.URL + "/oauth/token", HTTPClient: cs.Client()}, oneTenant("t1", "c", "s"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func (cs *c6PayServer) query() url.Values {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.lastQuery
}

func c6PayWindow() ports.AcquirerStatementFilter {
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	return ports.AcquirerStatementFilter{Start: start, End: start.AddDate(0, 0, 20), PageSize: 200}
}

func TestC6PayListReceivables(t *testing.T) {
	t.Parallel()
	cs := newC6PayServer(t)
	p := cs.provider(t)

	got, err := p.ListReceivables(context.Background(), "t1", c6PayWindow())
	if err != nil {
		t.Fatalf("ListReceivables: %v", err)
	}
	if len(got.Receivables) != 1 || got.Page != 1 || got.LastPage != 1 || got.Items != 1 {
		t.Fatalf("unexpected page: %+v", got)
	}
	r := got.Receivables[0]
	if r.GrossAmountCents != 20245 || r.NetAmountCents != 20000 {
		t.Fatalf("money mismatch: %+v", r)
	}
	// Deductions keep their sign: flipping them here would hide the direction.
	if r.FeeCents != -22 || r.DiscountCents != -235 {
		t.Fatalf("deductions must stay negative: fee=%d discount=%d", r.FeeCents, r.DiscountCents)
	}
	if r.MDR != 200 {
		t.Fatalf("mdr is transported scaled by 100, got %d", r.MDR)
	}
	if r.Installment != 1 || r.Installments != 3 || r.Status != "PAYMENT_APPROVED" {
		t.Fatalf("unexpected receivable: %+v", r)
	}
	if r.ExpectedDate.IsZero() || r.PaymentDate.IsZero() || r.TransactionTime.IsZero() {
		t.Fatalf("dates not parsed: %+v", r)
	}

	q := cs.query()
	if q.Get("start_date") != "2026-09-01" || q.Get("end_date") != "2026-09-21" ||
		q.Get("page") != "1" || q.Get("size") != "200" {
		t.Fatalf("unexpected query: %v", q)
	}
	if cs.lastPartner != partnerSoftwareVersion {
		t.Fatalf("partner headers required by this contract: %q", cs.lastPartner)
	}
}

// The published OpenAPI declares the array as `receivables`; the wire sends `content`.
// Reading only the spec's name returns an empty list forever, with no error — exactly
// the shape of the SIN-65856 defect. Both must work.
func TestC6PayReadsBothArrayKeys(t *testing.T) {
	t.Parallel()
	cs := newC6PayServer(t)
	p := cs.provider(t)
	cs.receivables = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"page":1,"last_page":1,"items":1,"receivables":[{"receivable_id":"rcv-spec","gross_amount":1}]}`))
	}
	got, err := p.ListReceivables(context.Background(), "t1", c6PayWindow())
	if err != nil {
		t.Fatalf("ListReceivables: %v", err)
	}
	if len(got.Receivables) != 1 || got.Receivables[0].ReceivableID != "rcv-spec" {
		t.Fatalf("the spec's key must still parse: %+v", got)
	}
}

// An empty extract is a legitimate answer — the sandbox returns exactly this — and
// must not look like a failure.
func TestC6PayEmptyExtract(t *testing.T) {
	t.Parallel()
	cs := newC6PayServer(t)
	p := cs.provider(t)
	cs.receivables = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"content":[],"page":1,"last_page":0,"items":0}`))
	}
	got, err := p.ListReceivables(context.Background(), "t1", c6PayWindow())
	if err != nil {
		t.Fatalf("ListReceivables: %v", err)
	}
	if len(got.Receivables) != 0 || got.Items != 0 {
		t.Fatalf("unexpected: %+v", got)
	}
}

func TestC6PayListCardTransactions(t *testing.T) {
	t.Parallel()
	cs := newC6PayServer(t)
	p := cs.provider(t)

	got, err := p.ListCardTransactions(context.Background(), "t1", c6PayWindow())
	if err != nil {
		t.Fatalf("ListCardTransactions: %v", err)
	}
	if len(got.Transactions) != 1 {
		t.Fatalf("want 1 transaction, got %d", len(got.Transactions))
	}
	// The transactions envelope spells the field `last-page`, with a hyphen, while
	// receivables uses `last_page`. Both are read.
	if got.LastPage != 1 {
		t.Fatalf("hyphenated last-page not read: %+v", got.AcquirerPage)
	}
	tx := got.Transactions[0]
	if tx.AmountCents != 12345 || tx.ID != "tx-1" || tx.Status != "AUTHORIZED" ||
		tx.TerminalID != "term-1" || tx.OccurredAt.IsZero() {
		t.Fatalf("unexpected transaction: %+v", tx)
	}
}

// The cardholder's name and the masked PAN are in the response and must not reach the
// port: not modelling them is how they never get logged or stored (ADR-0008).
func TestC6PayTransactionDoesNotCarryCardData(t *testing.T) {
	t.Parallel()
	cs := newC6PayServer(t)
	p := cs.provider(t)
	got, err := p.ListCardTransactions(context.Background(), "t1", c6PayWindow())
	if err != nil {
		t.Fatalf("ListCardTransactions: %v", err)
	}
	rendered, err := json.Marshal(got.Transactions[0])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, leak := range []string{"Jose da Silva", "000000******0000"} {
		if strings.Contains(string(rendered), leak) {
			t.Fatalf("card data leaked into the port type: %s", rendered)
		}
	}
}

func TestC6PayWindowValidation(t *testing.T) {
	t.Parallel()
	cs := newC6PayServer(t)
	p := cs.provider(t)
	ctx := context.Background()
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

	bad := map[string]ports.AcquirerStatementFilter{
		"no_start":        {End: start},
		"end_before":      {Start: start, End: start.AddDate(0, 0, -1)},
		"window_too_wide": {Start: start, End: start.AddDate(0, 0, 61)},
	}
	for name, f := range bad {
		if _, err := p.ListReceivables(ctx, "t1", f); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("receivables %s: want validation, got %v", name, err)
		}
		if _, err := p.ListCardTransactions(ctx, "t1", f); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("transactions %s: want validation, got %v", name, err)
		}
	}

	// An absent end date is legitimate: the acquirer then uses start_date for both
	// ends, so the parameter must be OMITTED rather than sent empty.
	if _, err := p.ListReceivables(ctx, "t1", ports.AcquirerStatementFilter{Start: start}); err != nil {
		t.Fatalf("open-ended window: %v", err)
	}
	if q := cs.query(); q.Has("end_date") {
		t.Fatalf("absent end must be omitted, got %v", q)
	}
}

// Production answers 403 for an account without the acquiring product enabled, even
// with a token that carries statement.read. That is an entitlement answer, and it must
// surface as such rather than as a generic failure.
func TestC6PayForbiddenSurfaces(t *testing.T) {
	t.Parallel()
	cs := newC6PayServer(t)
	p := cs.provider(t)
	cs.receivables = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"code":"acess_denied"}`))
	}
	if _, err := p.ListReceivables(context.Background(), "t1", c6PayWindow()); err == nil {
		t.Fatal("403 must surface an error")
	}
}

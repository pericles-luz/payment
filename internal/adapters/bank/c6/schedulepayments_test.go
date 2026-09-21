package c6

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// scheduleServer is a configurable C6 double for the Agendamento de Pagamentos
// endpoints (roteiro grupo AP) plus the OAuth2 token endpoint, backed by httptest TLS.
//
// The routes it registers are the CONTRACT's routes
// (docs/compliance/c6-schedule-payments-oas.yaml). That is the point of the double
// here: the previous one served /v1/dda/*, so the adapter's tests passed against a
// surface the bank does not have, and the 404 the bank really sent was read as a
// missing product instead of a wrong path.
type scheduleServer struct {
	*httptest.Server

	mu             sync.Mutex
	lastAuthHeader string
	lastIdemKey    string
	lastPartner    string
	lastBody       []byte
	lastPath       string

	query       http.HandlerFunc
	decode      http.HandlerFunc
	getItems    http.HandlerFunc
	removeItems http.HandlerFunc
	removeItem  http.HandlerFunc
	submit      http.HandlerFunc
}

func newScheduleServer(t *testing.T) *scheduleServer {
	t.Helper()
	ss := &scheduleServer{}
	record := func(r *http.Request) {
		ss.mu.Lock()
		defer ss.mu.Unlock()
		ss.lastAuthHeader = r.Header.Get("Authorization")
		ss.lastIdemKey = r.Header.Get("Idempotency-Key")
		ss.lastPartner = r.Header.Get("partner-software-name")
		ss.lastPath = r.URL.Path
		ss.lastBody, _ = io.ReadAll(io.LimitReader(r.Body, 1<<20))
	}
	handle := func(mux *http.ServeMux, pattern string, override *http.HandlerFunc, fallback http.HandlerFunc) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			record(r)
			if *override != nil {
				(*override)(w, r)
				return
			}
			fallback(w, r)
		})
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /oauth/token", func(w http.ResponseWriter, r *http.Request) {
		user, _, _ := r.BasicAuth()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok-` + user + `","token_type":"Bearer","expires_in":3600}`))
	})
	handle(mux, "GET /v1/schedule_payments/query", &ss.query, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[{"amount":123.45,"bank_code":"336","bank_name":"Banco C6",` +
			`"beneficiary_name":"Empresa XYZ Ltda","content":"` + strings.Repeat("1", 44) + `",` +
			`"due_date":"2030-01-01","overdue":true,"payer_name":"Empresa ABC Ltda"}]}`))
	})
	handle(mux, "POST /v1/schedule_payments/decode", &ss.decode, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"group_id":"01J3NCKY6Q99QC4D7T733D35QD"}`))
	})
	handle(mux, "GET /v1/schedule_payments/{group_id}/items", &ss.getItems, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[{"amount":10.00,"content":"` + strings.Repeat("1", 44) + `",` +
			`"due_date":"2030-01-01","group_id":"` + r.PathValue("group_id") + `","id":"i1",` +
			`"overdue":false,"product_type":"BOLETO","status":"READ_DATA"},` +
			`{"amount":2.50,"content":"pericles@example.com","group_id":"` + r.PathValue("group_id") + `",` +
			`"id":"i2","product_type":"PIX","status":"DECODE_ERROR",` +
			`"error_message":"It was not possible to find key: aerror@email.com"}]}`))
	})
	handle(mux, "DELETE /v1/schedule_payments/{group_id}/items", &ss.removeItems, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	handle(mux, "DELETE /v1/schedule_payments/{group_id}/items/{item_id}", &ss.removeItem, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	handle(mux, "POST /v1/schedule_payments/submit", &ss.submit, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	ss.Server = httptest.NewTLSServer(mux)
	t.Cleanup(ss.Close)
	return ss
}

func (ss *scheduleServer) provider(t *testing.T, creds ports.CredentialStore) *Provider {
	t.Helper()
	p, err := New(Config{BaseURL: ss.URL, TokenURL: ss.URL + "/oauth/token", HTTPClient: ss.Client()}, creds)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func (ss *scheduleServer) idemKey() string {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return ss.lastIdemKey
}

func (ss *scheduleServer) body() []byte {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return ss.lastBody
}

func (ss *scheduleServer) path() string {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return ss.lastPath
}

func schedulePayments() []ports.DDAPayment {
	return []ports.DDAPayment{
		{
			Content: strings.Repeat("1", 44), AmountCents: 12345,
			Description: "Boleto do aluguel", BeneficiaryName: "Empresa XYZ Ltda",
			PayerName: "Empresa ABC Ltda", BankCode: "336", BankName: "Banco C6",
			TransactionDate: time.Date(2024, 10, 2, 0, 0, 0, 0, time.UTC),
		},
		{Content: "pericles@example.com", AmountCents: 250},
	}
}

func scheduleGroupReq() ports.DDAGroupRequest {
	return ports.DDAGroupRequest{TenantID: "t1", Payments: schedulePayments(), IdempotencyKey: "k1"}
}

// TestC6ScheduleUsesContractPaths is the regression lock on the whole reason this file
// replaced dda_test.go: every operation must land on /v1/schedule_payments/*. A double
// that serves the old /v1/dda/* simply never gets called, so a silent revert shows up
// as a 404 here instead of in production.
func TestC6ScheduleUsesContractPaths(t *testing.T) {
	t.Parallel()
	ss := newScheduleServer(t)
	p := ss.provider(t, oneTenant("t1", "c", "s"))
	ctx := context.Background()

	if _, err := p.ListOpenBoletos(ctx, "t1"); err != nil {
		t.Fatalf("ListOpenBoletos: %v", err)
	}
	if got := ss.path(); got != "/v1/schedule_payments/query" {
		t.Fatalf("query path: %q", got)
	}
	if _, err := p.CreatePaymentGroup(ctx, "t1", scheduleGroupReq()); err != nil {
		t.Fatalf("CreatePaymentGroup: %v", err)
	}
	if got := ss.path(); got != "/v1/schedule_payments/decode" {
		t.Fatalf("decode path: %q", got)
	}
	if err := p.SubmitPaymentGroup(ctx, "t1", "g1", "Zé da Silva", "idem"); err != nil {
		t.Fatalf("SubmitPaymentGroup: %v", err)
	}
	// Submit is collection-level: the group travels in the BODY, not the path.
	if got := ss.path(); got != "/v1/schedule_payments/submit" {
		t.Fatalf("submit path: %q", got)
	}
}

// roteiro AP_02: consult the DDA; bearer + partner headers attached, wire mapped.
func TestC6ListOpenBoletos(t *testing.T) {
	t.Parallel()
	ss := newScheduleServer(t)
	p := ss.provider(t, oneTenant("t1", "client-1", "secret-1"))

	got, err := p.ListOpenBoletos(context.Background(), "t1")
	if err != nil {
		t.Fatalf("ListOpenBoletos: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 bond, got %d", len(got))
	}
	b := got[0]
	// amount is a JSON decimal in reais on the wire and cents in the port: 123.45 ⇒ 12345.
	if b.AmountCents != 12345 || b.BeneficiaryName != "Empresa XYZ Ltda" ||
		b.PayerName != "Empresa ABC Ltda" || b.BankCode != "336" || !b.Overdue {
		t.Fatalf("unexpected bond: %+v", b)
	}
	if want := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC); !b.DueDate.Equal(want) {
		t.Fatalf("due date: got %v want %v", b.DueDate, want)
	}
	if ss.lastAuthHeader != "Bearer tok-client-1" {
		t.Fatalf("bearer not attached: %q", ss.lastAuthHeader)
	}
	if ss.lastPartner != partnerSoftwareName {
		t.Fatalf("partner header not attached: %q", ss.lastPartner)
	}
}

func TestC6ListOpenBoletosErrorMapping(t *testing.T) {
	t.Parallel()
	ss := newScheduleServer(t)
	ss.query = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"code":"X"}`))
	}
	p := ss.provider(t, oneTenant("t1", "c", "s"))
	if _, err := p.ListOpenBoletos(context.Background(), "t1"); err == nil {
		t.Fatal("5xx must surface an error")
	}
}

// roteiro AP_01: submit the consult; the body is the contract's {items:[payment]},
// amounts render as decimals in reais and dates as YYYY-MM-DD.
func TestC6CreatePaymentGroup(t *testing.T) {
	t.Parallel()
	ss := newScheduleServer(t)
	p := ss.provider(t, oneTenant("t1", "client-1", "secret-1"))

	g, err := p.CreatePaymentGroup(context.Background(), "t1", scheduleGroupReq())
	if err != nil {
		t.Fatalf("CreatePaymentGroup: %v", err)
	}
	if g.ID != "01J3NCKY6Q99QC4D7T733D35QD" {
		t.Fatalf("group id: %q", g.ID)
	}
	// The 201 carries the id alone, so the returned group must carry NO items rather
	// than items we invented from the request.
	if len(g.Items) != 0 {
		t.Fatalf("create must not synthesise items, got %+v", g.Items)
	}
	if ss.idemKey() != "k1" {
		t.Fatalf("idempotency key not forwarded: %q", ss.idemKey())
	}

	var sent struct {
		Items []struct {
			Amount          json.Number `json:"amount"`
			Content         string      `json:"content"`
			Description     string      `json:"description"`
			TransactionDate string      `json:"transaction_date"`
		} `json:"items"`
	}
	if err := json.Unmarshal(ss.body(), &sent); err != nil {
		t.Fatalf("decode sent body: %v (%s)", err, ss.body())
	}
	if len(sent.Items) != 2 {
		t.Fatalf("want 2 items sent, got %d", len(sent.Items))
	}
	if sent.Items[0].Amount.String() != "123.45" {
		t.Fatalf("amount must be a decimal in reais, got %q", sent.Items[0].Amount)
	}
	if sent.Items[0].TransactionDate != "2024-10-02" {
		t.Fatalf("transaction_date must be YYYY-MM-DD, got %q", sent.Items[0].TransactionDate)
	}
	// A payment with no execution date must OMIT the field so the bank applies its
	// documented default (today) — not send a zero date.
	if sent.Items[1].TransactionDate != "" {
		t.Fatalf("absent date must be omitted, got %q", sent.Items[1].TransactionDate)
	}
}

// A 201 without a group id is not a success: without it nothing can address the group.
func TestC6CreatePaymentGroupRejectsMissingGroupID(t *testing.T) {
	t.Parallel()
	ss := newScheduleServer(t)
	ss.decode = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{}`))
	}
	p := ss.provider(t, oneTenant("t1", "c", "s"))
	if _, err := p.CreatePaymentGroup(context.Background(), "t1", scheduleGroupReq()); !errors.Is(err, shared.ErrUnavailable) {
		t.Fatalf("want ErrUnavailable, got %v", err)
	}
}

func TestC6CreatePaymentGroupRejectsBadInput(t *testing.T) {
	t.Parallel()
	ss := newScheduleServer(t)
	p := ss.provider(t, oneTenant("t1", "c", "s"))
	ctx := context.Background()

	bad := map[string]ports.DDAGroupRequest{
		"no_anchor":     {TenantID: "t1", Payments: schedulePayments()},
		"no_payments":   {TenantID: "t1", IdempotencyKey: "k1"},
		"empty_content": {TenantID: "t1", IdempotencyKey: "k1", Payments: []ports.DDAPayment{{AmountCents: 100}}},
		"zero_amount":   {TenantID: "t1", IdempotencyKey: "k1", Payments: []ports.DDAPayment{{Content: strings.Repeat("1", 44)}}},
	}
	for name, req := range bad {
		if _, err := p.CreatePaymentGroup(ctx, "t1", req); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("%s: want validation error, got %v", name, err)
		}
	}
}

func TestC6CreatePaymentGroupErrorMapping(t *testing.T) {
	t.Parallel()
	ss := newScheduleServer(t)
	ss.decode = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Header().Set("Content-Type", "application/problem+json")
		_, _ = w.Write([]byte(`{"detail":"bad content"}`))
	}
	p := ss.provider(t, oneTenant("t1", "c", "s"))
	if _, err := p.CreatePaymentGroup(context.Background(), "t1", scheduleGroupReq()); err == nil {
		t.Fatal("422 must surface an error")
	}
}

// roteiro AP_03: read the items back, including the per-item status the freeze rule
// depends on and the error_message the bank reports for a rejected line.
func TestC6GetPaymentGroup(t *testing.T) {
	t.Parallel()
	ss := newScheduleServer(t)
	p := ss.provider(t, oneTenant("t1", "c", "s"))

	g, err := p.GetPaymentGroup(context.Background(), "t1", "g-42")
	if err != nil {
		t.Fatalf("GetPaymentGroup: %v", err)
	}
	if g.ID != "g-42" || len(g.Items) != 2 {
		t.Fatalf("unexpected group: %+v", g)
	}
	if g.Items[0].ID != "i1" || g.Items[0].AmountCents != 1000 ||
		g.Items[0].Status != "READ_DATA" || g.Items[0].ProductType != "BOLETO" {
		t.Fatalf("item 0: %+v", g.Items[0])
	}
	// A PIX line has no due date at all: it must map to the zero time, not to a date.
	if !g.Items[1].DueDate.IsZero() || g.Items[1].Status != "DECODE_ERROR" ||
		g.Items[1].ErrorMessage == "" || g.Items[1].AmountCents != 250 {
		t.Fatalf("item 1: %+v", g.Items[1])
	}
}

func TestC6GetPaymentGroupRejectsEmptyID(t *testing.T) {
	t.Parallel()
	ss := newScheduleServer(t)
	p := ss.provider(t, oneTenant("t1", "c", "s"))
	if _, err := p.GetPaymentGroup(context.Background(), "t1", "  "); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want validation error, got %v", err)
	}
}

func TestC6GetPaymentGroupNotFound(t *testing.T) {
	t.Parallel()
	ss := newScheduleServer(t)
	ss.getItems = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":"NOT_FOUND"}`))
	}
	p := ss.provider(t, oneTenant("t1", "c", "s"))
	if _, err := p.GetPaymentGroup(context.Background(), "t1", "nope"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("404 should map to ErrNotFound, got %v", err)
	}
}

// roteiro AP_04: the DELETE body is a BARE ARRAY of {id}, not an object wrapping a
// list. Getting this wrong is a 400 the adapter would report as a generic failure.
func TestC6RemovePaymentGroupItems(t *testing.T) {
	t.Parallel()
	ss := newScheduleServer(t)
	p := ss.provider(t, oneTenant("t1", "c", "s"))

	if err := p.RemovePaymentGroupItems(context.Background(), "t1", "g1", []string{"i1", "i2"}); err != nil {
		t.Fatalf("RemovePaymentGroupItems: %v", err)
	}
	var sent []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(ss.body(), &sent); err != nil {
		t.Fatalf("body must be a bare array: %v (%s)", err, ss.body())
	}
	if len(sent) != 2 || sent[0].ID != "i1" || sent[1].ID != "i2" {
		t.Fatalf("unexpected body: %s", ss.body())
	}
}

func TestC6RemovePaymentGroupItemsRejectsBadInput(t *testing.T) {
	t.Parallel()
	ss := newScheduleServer(t)
	p := ss.provider(t, oneTenant("t1", "c", "s"))
	ctx := context.Background()

	if err := p.RemovePaymentGroupItems(ctx, "t1", "g1", nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty list: want validation, got %v", err)
	}
	if err := p.RemovePaymentGroupItems(ctx, "t1", "  ", []string{"i1"}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty group: want validation, got %v", err)
	}
	if err := p.RemovePaymentGroupItems(ctx, "t1", "g1", []string{" "}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty id: want validation, got %v", err)
	}
}

func TestC6RemovePaymentGroupItemsNotFound(t *testing.T) {
	t.Parallel()
	ss := newScheduleServer(t)
	ss.removeItems = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":"NOT_FOUND"}`))
	}
	p := ss.provider(t, oneTenant("t1", "c", "s"))
	if err := p.RemovePaymentGroupItems(context.Background(), "t1", "nope", []string{"i1"}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("404 should map to ErrNotFound, got %v", err)
	}
}

// roteiro AP_05: the single removal addresses the item's own sub-resource.
func TestC6RemovePaymentGroupItem(t *testing.T) {
	t.Parallel()
	ss := newScheduleServer(t)
	p := ss.provider(t, oneTenant("t1", "c", "s"))

	if err := p.RemovePaymentGroupItem(context.Background(), "t1", "g1", "i9"); err != nil {
		t.Fatalf("RemovePaymentGroupItem: %v", err)
	}
	if got := ss.path(); got != "/v1/schedule_payments/g1/items/i9" {
		t.Fatalf("unexpected path: %q", got)
	}
}

func TestC6RemovePaymentGroupItemRejectsEmpty(t *testing.T) {
	t.Parallel()
	ss := newScheduleServer(t)
	p := ss.provider(t, oneTenant("t1", "c", "s"))
	if err := p.RemovePaymentGroupItem(context.Background(), "t1", "g1", "  "); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want validation, got %v", err)
	}
}

func TestC6RemovePaymentGroupItemNotFound(t *testing.T) {
	t.Parallel()
	ss := newScheduleServer(t)
	ss.removeItem = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":"NOT_FOUND"}`))
	}
	p := ss.provider(t, oneTenant("t1", "c", "s"))
	if err := p.RemovePaymentGroupItem(context.Background(), "t1", "g1", "i9"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("404 should map to ErrNotFound, got %v", err)
	}
}

// roteiro AP_06: group id AND uploader_name travel in the body; both are required.
func TestC6SubmitPaymentGroup(t *testing.T) {
	t.Parallel()
	ss := newScheduleServer(t)
	p := ss.provider(t, oneTenant("t1", "c", "s"))

	if err := p.SubmitPaymentGroup(context.Background(), "t1", "g1", "Zé da Silva", "idem-1"); err != nil {
		t.Fatalf("SubmitPaymentGroup: %v", err)
	}
	var sent struct {
		GroupID      string `json:"group_id"`
		UploaderName string `json:"uploader_name"`
	}
	if err := json.Unmarshal(ss.body(), &sent); err != nil {
		t.Fatalf("decode sent body: %v (%s)", err, ss.body())
	}
	if sent.GroupID != "g1" || sent.UploaderName != "Zé da Silva" {
		t.Fatalf("unexpected body: %s", ss.body())
	}
	if ss.idemKey() != "idem-1" {
		t.Fatalf("idempotency key not forwarded: %q", ss.idemKey())
	}
}

func TestC6SubmitPaymentGroupRejectsMissingFields(t *testing.T) {
	t.Parallel()
	ss := newScheduleServer(t)
	p := ss.provider(t, oneTenant("t1", "c", "s"))
	ctx := context.Background()

	if err := p.SubmitPaymentGroup(ctx, "t1", "  ", "Zé", "k"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty group: want validation, got %v", err)
	}
	if err := p.SubmitPaymentGroup(ctx, "t1", "g1", " ", "k"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty uploader: want validation, got %v", err)
	}
}

func TestC6SubmitPaymentGroupNotFound(t *testing.T) {
	t.Parallel()
	ss := newScheduleServer(t)
	ss.submit = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":"NOT_FOUND"}`))
	}
	p := ss.provider(t, oneTenant("t1", "c", "s"))
	if err := p.SubmitPaymentGroup(context.Background(), "t1", "nope", "Zé", "idem"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("404 should map to ErrNotFound, got %v", err)
	}
}

func TestC6ScheduleMissingCredential(t *testing.T) {
	t.Parallel()
	ss := newScheduleServer(t)
	p := ss.provider(t, &fakeCreds{creds: map[string]ports.BankCredential{}})
	if _, err := p.ListOpenBoletos(context.Background(), "unknown"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("missing credential should propagate ErrNotFound, got %v", err)
	}
}

package c6

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// externalRefV1Pattern is the v1 contract's format for external_reference_id:
// 1..10 alphanumerics. It is a quarter of the v2 ceiling, which is why the two
// surfaces cannot share a reference derivation.
var externalRefV1Pattern = regexp.MustCompile(`^[a-zA-Z0-9]{1,10}$`)

// slipV1Server is a C6 Boleto Bancário v1 double.
type slipV1Server struct {
	*httptest.Server

	mu       sync.Mutex
	lastPath string
	lastBody []byte
	lastIdem string

	create http.HandlerFunc
	get    http.HandlerFunc
	update http.HandlerFunc
	cancel http.HandlerFunc
	pdf    http.HandlerFunc
}

const slipV1ResponseJSON = `{"id":"01M2KEFNXH680SBM714RX13CJT","originator_id":"000006572943",` +
	`"external_reference_id":"A1B2C3D4E5","amount":123.45,"status":"CREATED",` +
	`"emission_date":"2026-09-21","due_date":"2026-10-01","our_number":"10237537",` +
	`"billing_scheme":"21","billing_type":"3",` +
	`"digitable_line":"33690.00009 65729.430010 04489.482135 9 15770000012345",` +
	`"bar_code":"33697151800000012340000065729430010237538213",` +
	`"fine":{"type":"P","value":2.00,"dead_line":1},` +
	`"interest":{"type":"P","value":1.00,"dead_line":1},` +
	`"discount":{"discount_type":"P","first":{"value":10.00,"dead_line":10},` +
	`"second":{"value":5.00,"dead_line":5}}}`

func newSlipV1Server(t *testing.T) *slipV1Server {
	t.Helper()
	ss := &slipV1Server{}
	record := func(r *http.Request) {
		ss.mu.Lock()
		defer ss.mu.Unlock()
		ss.lastPath = r.URL.Path
		ss.lastIdem = r.Header.Get("Idempotency-Key")
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
	handle(mux, "POST /v1/bank_slips/", &ss.create, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(slipV1ResponseJSON))
	})
	handle(mux, "GET /v1/bank_slips/{id}", &ss.get, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(slipV1ResponseJSON))
	})
	handle(mux, "PUT /v1/bank_slips/{id}", &ss.update, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(slipV1ResponseJSON))
	})
	handle(mux, "PUT /v1/bank_slips/{id}/cancel", &ss.cancel, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	handle(mux, "GET /v1/bank_slips/{id}/pdf", &ss.pdf, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("%PDF-1.5\nfake"))
	})
	ss.Server = httptest.NewTLSServer(mux)
	t.Cleanup(ss.Close)
	return ss
}

func (ss *slipV1Server) provider(t *testing.T) *Provider {
	t.Helper()
	p, err := New(Config{
		BaseURL: ss.URL, TokenURL: ss.URL + "/oauth/token",
		HTTPClient: ss.Client(), BillingScheme: "21",
	}, oneTenant("t1", "c", "s"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func (ss *slipV1Server) snapshot() (path string, body []byte, idem string) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return ss.lastPath, ss.lastBody, ss.lastIdem
}

func slipV1Request() ports.BoletoRequest {
	return ports.BoletoRequest{
		TenantID:    "t1",
		BoletoID:    "a5164577b50d307635fe1cecc47cb6fa",
		AmountCents: 12345,
		DueDate:     time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
		Payer:       fullBoletoPayer(),
		Description: "Boleto do aluguel",
	}
}

// roteiro B_01: emissão simples, com juros e multa.
func TestC6CreatePlainBoleto(t *testing.T) {
	t.Parallel()
	ss := newSlipV1Server(t)
	p := ss.provider(t)

	req := slipV1Request()
	req.FineBps = 200            // 2% de multa
	req.MonthlyInterestBps = 100 // 1% ao mês de juros

	got, err := p.CreatePlainBoleto(context.Background(), "t1", req)
	if err != nil {
		t.Fatalf("CreatePlainBoleto: %v", err)
	}
	if got.TxID != "01M2KEFNXH680SBM714RX13CJT" || got.Status != "CREATED" {
		t.Fatalf("unexpected result: %+v", got)
	}
	// A v1 slip has no PIX leg. Saying so explicitly is what keeps "no QR" from being
	// mistaken for "the QR failed to come back".
	if got.Modality != ports.ModalityBoleto || got.QRCode != "" {
		t.Fatalf("v1 must never promise a QR: %+v", got)
	}
	if got.DigitableLine == "" || got.Barcode == "" || got.OurNumber == "" {
		t.Fatalf("printable artifacts missing: %+v", got)
	}

	path, body, idem := ss.snapshot()
	if path != "/v1/bank_slips/" {
		t.Fatalf("unexpected path: %q", path)
	}
	if idem != req.BoletoID {
		t.Fatalf("idempotency key not forwarded: %q", idem)
	}
	var sent struct {
		ExternalReferenceID string `json:"external_reference_id"`
		Amount              json.Number
		DueDate             string `json:"due_date"`
		BillingScheme       string `json:"billing_scheme"`
		Fine                struct {
			Type     string      `json:"type"`
			Value    json.Number `json:"value"`
			DeadLine int         `json:"dead_line"`
		} `json:"fine"`
		Interest struct {
			Type  string      `json:"type"`
			Value json.Number `json:"value"`
		} `json:"interest"`
		Payer struct {
			Name    string `json:"name"`
			TaxID   string `json:"tax_id"`
			Address struct {
				Street  string      `json:"street"`
				Number  json.Number `json:"number"`
				City    string      `json:"city"`
				State   string      `json:"state"`
				ZipCode string      `json:"zip_code"`
			} `json:"address"`
		} `json:"payer"`
	}
	if err := json.Unmarshal(body, &sent); err != nil {
		t.Fatalf("decode body: %v (%s)", err, body)
	}
	// The v1 reference pattern is 1..10 alphanumerics — the v2 derivation is 26 and
	// would be refused.
	if !externalRefV1Pattern.MatchString(sent.ExternalReferenceID) {
		t.Fatalf("external_reference_id %q does not fit the v1 pattern", sent.ExternalReferenceID)
	}
	if sent.Amount.String() != "123.45" || sent.DueDate != "2026-10-01" || sent.BillingScheme != "21" {
		t.Fatalf("unexpected body: %s", body)
	}
	if sent.Fine.Type != "P" || sent.Fine.Value.String() != "2.00" {
		t.Fatalf("fine must render as a percentage: %s", body)
	}
	if sent.Interest.Type != "P" || sent.Interest.Value.String() != "1.00" {
		t.Fatalf("interest must render as a percentage: %s", body)
	}
	// The v1 address keeps street and number apart, and carries no neighborhood.
	if sent.Payer.Address.Street != "Rua das Flores" || sent.Payer.Address.Number.String() != "123" {
		t.Fatalf("unexpected payer address: %s", body)
	}
}

// roteiro B_02: multa em VALOR fixo, não percentual.
func TestC6CreatePlainBoletoFixedFine(t *testing.T) {
	t.Parallel()
	ss := newSlipV1Server(t)
	p := ss.provider(t)

	req := slipV1Request()
	req.FineFixedCents = 500 // R$ 5,00

	if _, err := p.CreatePlainBoleto(context.Background(), "t1", req); err != nil {
		t.Fatalf("CreatePlainBoleto: %v", err)
	}
	_, body, _ := ss.snapshot()
	var sent struct {
		Fine struct {
			Type  string      `json:"type"`
			Value json.Number `json:"value"`
		} `json:"fine"`
	}
	_ = json.Unmarshal(body, &sent)
	if sent.Fine.Type != "V" || sent.Fine.Value.String() != "5.00" {
		t.Fatalf("fixed fine must render as a value: %s", body)
	}

	// Percentage AND fixed at once is a caller error: the bank carries ONE value with
	// ONE type, so there is no correct thing to send.
	req.FineBps = 200
	if _, err := p.CreatePlainBoleto(context.Background(), "t1", req); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("both fine forms: want validation, got %v", err)
	}
}

// roteiro B_03: desconto — e as TRÊS faixas que o v2 não tem.
func TestC6CreatePlainBoletoTieredDiscount(t *testing.T) {
	t.Parallel()
	ss := newSlipV1Server(t)
	p := ss.provider(t)

	req := slipV1Request()
	req.Discounts = []ports.BoletoDiscountTier{
		{DaysBeforeDue: 10, Bps: 1000}, // 10% até dez dias antes
		{DaysBeforeDue: 5, Bps: 500},   // 5% até cinco dias antes
		{DaysBeforeDue: 1, Bps: 200},   // 2% na véspera
	}
	got, err := p.CreatePlainBoleto(context.Background(), "t1", req)
	if err != nil {
		t.Fatalf("CreatePlainBoleto: %v", err)
	}
	if len(got.Discounts) != 2 {
		// The double echoes two bands; what matters is that they round-trip.
		t.Fatalf("unexpected echoed discounts: %+v", got.Discounts)
	}

	_, body, _ := ss.snapshot()
	var sent struct {
		Discount struct {
			DiscountType string `json:"discount_type"`
			First        struct {
				Value    json.Number `json:"value"`
				DeadLine int         `json:"dead_line"`
			} `json:"first"`
			Second struct {
				DeadLine int `json:"dead_line"`
			} `json:"second"`
			Third struct {
				DeadLine int `json:"dead_line"`
			} `json:"third"`
		} `json:"discount"`
	}
	if err := json.Unmarshal(body, &sent); err != nil {
		t.Fatalf("decode body: %v (%s)", err, body)
	}
	if sent.Discount.DiscountType != "P" || sent.Discount.First.Value.String() != "10.00" {
		t.Fatalf("unexpected discount: %s", body)
	}
	// first > second > third, strictly — the bank's own rule.
	if sent.Discount.First.DeadLine != 10 || sent.Discount.Second.DeadLine != 5 || sent.Discount.Third.DeadLine != 1 {
		t.Fatalf("deadlines must be strictly decreasing: %s", body)
	}
}

func TestC6CreatePlainBoletoDiscountValidation(t *testing.T) {
	t.Parallel()
	ss := newSlipV1Server(t)
	p := ss.provider(t)
	ctx := context.Background()

	bad := map[string][]ports.BoletoDiscountTier{
		"four_tiers": {
			{DaysBeforeDue: 20, Bps: 100}, {DaysBeforeDue: 15, Bps: 100},
			{DaysBeforeDue: 10, Bps: 100}, {DaysBeforeDue: 5, Bps: 100},
		},
		// One discount_type covers the whole schedule, so a mixed list has no correct
		// rendering — the bank would apply the wrong form to one of the bands.
		"mixed_forms":     {{DaysBeforeDue: 10, Bps: 100}, {DaysBeforeDue: 5, FixedCents: 100}},
		"equal_deadlines": {{DaysBeforeDue: 5, Bps: 100}, {DaysBeforeDue: 5, Bps: 50}},
		"ascending":       {{DaysBeforeDue: 5, Bps: 100}, {DaysBeforeDue: 10, Bps: 50}},
		"empty_tier":      {{DaysBeforeDue: 5}},
		"both_forms":      {{DaysBeforeDue: 5, Bps: 100, FixedCents: 100}},
	}
	for name, tiers := range bad {
		req := slipV1Request()
		req.Discounts = tiers
		if _, err := p.CreatePlainBoleto(ctx, "t1", req); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("%s: want validation, got %v", name, err)
		}
	}
}

// The v1 create has no payment-validity field at all. Dropping one silently would
// register a slip payable for longer than the caller intended.
func TestC6CreatePlainBoletoRefusesWhatV1CannotCarry(t *testing.T) {
	t.Parallel()
	ss := newSlipV1Server(t)
	p := ss.provider(t)
	ctx := context.Background()

	withValidity := slipV1Request()
	withValidity.ValidUntil = time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	if _, err := p.CreatePlainBoleto(ctx, "t1", withValidity); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("ValidUntil: want validation, got %v", err)
	}

	// Asking for BolePix here would produce a slip with no QR and no explanation.
	asBolepix := slipV1Request()
	asBolepix.Modality = ports.ModalityBolepix
	if _, err := p.CreatePlainBoleto(ctx, "t1", asBolepix); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("bolepix modality: want validation, got %v", err)
	}

	noID := slipV1Request()
	noID.BoletoID = " "
	if _, err := p.CreatePlainBoleto(ctx, "t1", noID); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty boleto id: want validation, got %v", err)
	}
}

// A 201 without the bank's id would let a retry re-bill: the app reads a non-empty
// TxID as the billing-finalized marker.
func TestC6CreatePlainBoletoRejectsMissingID(t *testing.T) {
	t.Parallel()
	ss := newSlipV1Server(t)
	p := ss.provider(t)
	ss.create = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"amount":123.45,"our_number":"1"}`))
	}
	if _, err := p.CreatePlainBoleto(context.Background(), "t1", slipV1Request()); !errors.Is(err, shared.ErrUnavailable) {
		t.Fatalf("want ErrUnavailable, got %v", err)
	}
}

// roteiro B_05: consulta.
func TestC6GetPlainBoleto(t *testing.T) {
	t.Parallel()
	ss := newSlipV1Server(t)
	p := ss.provider(t)

	got, err := p.GetPlainBoleto(context.Background(), "t1", "01M2KEFNXH680SBM714RX13CJT")
	if err != nil {
		t.Fatalf("GetPlainBoleto: %v", err)
	}
	if got.AmountCents != 12345 || got.Status != "CREATED" || got.DueDate.IsZero() {
		t.Fatalf("unexpected result: %+v", got)
	}
	if got.FineBps != 200 || got.MonthlyInterestBps != 100 {
		t.Fatalf("registered rates not echoed: %+v", got)
	}
	if len(got.Discounts) != 2 || got.Discounts[0].Bps != 1000 || got.Discounts[0].DaysBeforeDue != 10 {
		t.Fatalf("discount schedule not echoed: %+v", got.Discounts)
	}
	if path, _, _ := ss.snapshot(); path != "/v1/bank_slips/01M2KEFNXH680SBM714RX13CJT" {
		t.Fatalf("unexpected path: %q", path)
	}
	if _, err := p.GetPlainBoleto(context.Background(), "t1", "  "); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty id: want validation, got %v", err)
	}
}

func TestC6GetPlainBoletoNotFound(t *testing.T) {
	t.Parallel()
	ss := newSlipV1Server(t)
	p := ss.provider(t)
	ss.get = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":"NOT_FOUND"}`))
	}
	if _, err := p.GetPlainBoleto(context.Background(), "t1", "nope"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("404 should map to ErrNotFound, got %v", err)
	}
}

// roteiro B_04: alteração.
func TestC6UpdatePlainBoleto(t *testing.T) {
	t.Parallel()
	ss := newSlipV1Server(t)
	p := ss.provider(t)

	amount := int64(20000)
	due := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	if _, err := p.UpdatePlainBoleto(context.Background(), "t1", "slip-1", ports.BoletoPatch{
		AmountCents: &amount, DueDate: &due,
	}); err != nil {
		t.Fatalf("UpdatePlainBoleto: %v", err)
	}
	path, body, _ := ss.snapshot()
	if path != "/v1/bank_slips/slip-1" {
		t.Fatalf("unexpected path: %q", path)
	}
	var sent map[string]any
	if err := json.Unmarshal(body, &sent); err != nil {
		t.Fatalf("decode body: %v (%s)", err, body)
	}
	if sent["amount"] == nil || sent["due_date"] != "2026-11-01" {
		t.Fatalf("unexpected body: %s", body)
	}
	// A field the caller left alone must be ABSENT, not zero.
	if _, ok := sent["fine"]; ok {
		t.Fatalf("untouched fee must be omitted: %s", body)
	}
}

func TestC6UpdatePlainBoletoValidation(t *testing.T) {
	t.Parallel()
	ss := newSlipV1Server(t)
	p := ss.provider(t)
	ctx := context.Background()
	zero := int64(0)
	zeroTime := time.Time{}

	// The contract requires at least one property; an empty patch is always a bug.
	if _, err := p.UpdatePlainBoleto(ctx, "t1", "slip-1", ports.BoletoPatch{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty patch: want validation, got %v", err)
	}
	// A patch that only touches what v1 cannot amend is an empty patch on the wire.
	desc := "nova descrição"
	if _, err := p.UpdatePlainBoleto(ctx, "t1", "slip-1", ports.BoletoPatch{Description: &desc}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("description-only patch: want validation, got %v", err)
	}
	if _, err := p.UpdatePlainBoleto(ctx, "t1", "slip-1", ports.BoletoPatch{AmountCents: &zero}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("zero amount: want validation, got %v", err)
	}
	if _, err := p.UpdatePlainBoleto(ctx, "t1", "slip-1", ports.BoletoPatch{DueDate: &zeroTime}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("zero due date: want validation, got %v", err)
	}
	if _, err := p.UpdatePlainBoleto(ctx, "t1", "  ", ports.BoletoPatch{AmountCents: &zero}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty id: want validation, got %v", err)
	}
}

// roteiro B_08: baixa.
func TestC6CancelPlainBoleto(t *testing.T) {
	t.Parallel()
	ss := newSlipV1Server(t)
	p := ss.provider(t)

	if err := p.CancelPlainBoleto(context.Background(), "t1", "slip-1"); err != nil {
		t.Fatalf("CancelPlainBoleto: %v", err)
	}
	if path, _, _ := ss.snapshot(); path != "/v1/bank_slips/slip-1/cancel" {
		t.Fatalf("unexpected path: %q", path)
	}
	if err := p.CancelPlainBoleto(context.Background(), "t1", " "); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty id: want validation, got %v", err)
	}
}

// roteiro B_06: PDF. Both wire shapes are accepted, and the signature decides.
func TestC6GetPlainBoletoPDF(t *testing.T) {
	t.Parallel()
	ss := newSlipV1Server(t)
	p := ss.provider(t)

	doc, err := p.GetPlainBoletoPDF(context.Background(), "t1", "slip-1")
	if err != nil {
		t.Fatalf("GetPlainBoletoPDF: %v", err)
	}
	if doc.ContentType != pdfMediaType || string(doc.Content[:5]) != "%PDF-" {
		t.Fatalf("unexpected document: %+v", doc.ContentType)
	}

	ss.pdf = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		encoded := base64.StdEncoding.EncodeToString([]byte("%PDF-1.5\nenvelope"))
		_, _ = w.Write([]byte(`{"base64_pdf_file":"` + encoded + `"}`))
	}
	doc, err = p.GetPlainBoletoPDF(context.Background(), "t1", "slip-1")
	if err != nil {
		t.Fatalf("base64 envelope: %v", err)
	}
	if string(doc.Content) != "%PDF-1.5\nenvelope" {
		t.Fatalf("envelope not unwrapped: %q", doc.Content)
	}

	// Anything that is not a PDF must be refused rather than handed back labelled as
	// one: a corrupt file is indistinguishable from a good one to the payer.
	ss.pdf = func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<html>erro</html>`))
	}
	if _, err := p.GetPlainBoletoPDF(context.Background(), "t1", "slip-1"); !errors.Is(err, shared.ErrUnavailable) {
		t.Fatalf("non-PDF: want ErrUnavailable, got %v", err)
	}
}

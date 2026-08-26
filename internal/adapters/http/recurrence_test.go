package http_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
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
	"github.com/ia-dev-sindireceita/payment/internal/domain/recurrence"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// pixRecFixture wires a Server with the PIX Automático surface backed by the in-memory
// stub, plus a seeded, priced, credentialed tenant and a SECOND tenant used to prove
// there is no cross-tenant oracle.
type pixRecFixture struct {
	handler   http.Handler
	tenantID  string
	otherID   string
	store     *persistence.Store
	bank      *bank.StubProvider
	now       time.Time
	recSvc    *app.RecurrenceService
	webhooks  *app.WebhookService
	otherAuth string
}

const otherTenantToken = "ttok-other"

// newPixRecFixtureFlag builds the fixture with the PIX Automático routes on or off, so
// the dark-ship flag is exercised in BOTH positions (a flag only tested in one state
// is a flag whose other state ships untested).
func newPixRecFixtureFlag(t *testing.T, flagOn bool) *pixRecFixture {
	t.Helper()
	store := persistence.NewStore()
	creds := secret.NewStore(nil)
	stub := bank.NewStubProvider(creds)
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	stub.SetClock(func() time.Time { return now })
	deps := app.Deps{
		Payments:    store,
		Tenants:     store,
		Pricing:     store,
		Ledger:      store,
		Processed:   store,
		Recs:        store,
		CobRs:       store,
		Bus:         inmemory.NewBus(),
		Bank:        stub,
		Pix:         stub,
		RecReader:   stub,
		CobRReader:  stub,
		SolicRecs:   stub,
		LocRecs:     stub,
		Credentials: creds,
		Clock:       system.Clock{},
		IDs:         system.IDProvider{},
	}
	admin := app.NewAdminService(deps)
	tn, err := admin.CreateTenant(context.Background(), "Acme")
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	other, err := admin.CreateTenant(context.Background(), "Rival")
	if err != nil {
		t.Fatalf("seed other tenant: %v", err)
	}
	creds.Set(tn.ID(), ports.BankCredential{ClientID: "c6-acme", Secret: "s"})
	creds.Set(other.ID(), ports.BankCredential{ClientID: "c6-rival", Secret: "s"})
	for _, endpoint := range []string{app.RecCreateEndpoint, app.CobRCreateEndpoint} {
		if _, err := admin.SetEndpointPrice(context.Background(), tn.ID(), endpoint, 25); err != nil {
			t.Fatalf("seed price %s: %v", endpoint, err)
		}
	}
	auth := httpadapter.NewStaticTokenAuth(map[string]string{
		tenantToken:      tn.ID(),
		otherTenantToken: other.ID(),
	}, []string{adminToken}, nil)
	recSvc := app.NewRecurrenceService(deps)
	srv := httpadapter.NewServer(httpadapter.Config{
		Charges:       app.NewChargeService(deps),
		Pix:           app.NewPixService(deps),
		Recurrence:    recSvc,
		PixRecurrence: flagOn,
		Admin:         admin,
		Webhooks:      app.NewWebhookService(deps),
		TenantAuth:    auth,
		AdminAuth:     auth,
		WebhookAuth:   auth,
	})
	return &pixRecFixture{
		handler: srv.Router(), tenantID: tn.ID(), otherID: other.ID(), store: store,
		bank: stub, now: now, recSvc: recSvc, webhooks: app.NewWebhookService(deps),
		otherAuth: otherTenantToken,
	}
}

func newPixRecFixture(t *testing.T) *pixRecFixture { return newPixRecFixtureFlag(t, true) }

func idem(key string) map[string]string { return map[string]string{"Idempotency-Key": key} }

// mandateBody is the create-mandate request used across the tests.
func mandateBody(locID int64, journeyTxID string, amountCents int64) map[string]any {
	return map[string]any{
		"contrato":      "CT-2026-001",
		"objeto":        "Mensalidade",
		"devedor":       map[string]any{"tax_id": "02989131415", "name": "Beltrano da Silva"},
		"data_inicial":  "2026-09-01",
		"periodicidade": "MENSAL",
		"retry_policy":  "PERMITE_3R_7D",
		"loc_id":        locID,
		"journey_txid":  journeyTxID,
		"amount_cents":  amountCents,
	}
}

// approveMandate drives the mandate to APROVADA the ONLY way production can: the bank
// says so and the reconciled recurrence webhook records it. Reaching into the store to
// flip the status would test a state the real system can never produce.
func (f *pixRecFixture) approveMandate(t *testing.T, idRec string) {
	t.Helper()
	if _, err := f.bank.ApproveRec(context.Background(), f.tenantID, idRec); err != nil {
		t.Fatalf("approve at bank: %v", err)
	}
	if err := f.webhooks.HandleRecEvent(context.Background(), app.RecEvent{
		TenantID: f.tenantID, IDRec: idRec, EventKey: idRec + "|rec|APROVADA",
	}); err != nil {
		t.Fatalf("approve mandate via webhook: %v", err)
	}
}

// --- flag ---

// TestRecurrenceRoutesAbsentWhenFlagOff proves the dark-ship: with the flag off the
// routes do not exist at all, so rollback is a config flip and not a deploy.
func TestRecurrenceRoutesAbsentWhenFlagOff(t *testing.T) {
	t.Parallel()
	f := newPixRecFixtureFlag(t, false)
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/v1/pix/locrec"},
		{http.MethodPost, "/v1/pix/rec"},
		{http.MethodPost, "/v1/pix/solicrec"},
		{http.MethodPost, "/v1/pix/cobr"},
	} {
		rec := do(t, f.handler, tc.method, tc.path, tenantToken, idem("k"), map[string]any{})
		if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s %s with flag off: want 404/405, got %d", tc.method, tc.path, rec.Code)
		}
	}
}

// TestRecurrenceServiceUnwiredIs503 proves a flag-on/service-nil deployment degrades
// instead of panicking — the flag and the service are independent knobs.
func TestRecurrenceServiceUnwiredIs503(t *testing.T) {
	t.Parallel()
	store := persistence.NewStore()
	creds := secret.NewStore(nil)
	deps := app.Deps{
		Payments: store, Tenants: store, Pricing: store, Ledger: store, Processed: store,
		Bus: inmemory.NewBus(), Credentials: creds, Clock: system.Clock{}, IDs: system.IDProvider{},
	}
	admin := app.NewAdminService(deps)
	tn, err := admin.CreateTenant(context.Background(), "Acme")
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	auth := httpadapter.NewStaticTokenAuth(map[string]string{tenantToken: tn.ID()}, []string{adminToken}, nil)
	srv := httpadapter.NewServer(httpadapter.Config{
		PixRecurrence: true, Recurrence: nil,
		Admin: admin, TenantAuth: auth, AdminAuth: auth, WebhookAuth: auth,
	})
	rec := do(t, srv.Router(), http.MethodPost, "/v1/pix/locrec", tenantToken, idem("k1"), nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unwired recurrence: want 503, got %d (%s)", rec.Code, rec.Body.String())
	}
}

// --- auth and boundary ---

func TestRecurrenceRequiresAuth(t *testing.T) {
	t.Parallel()
	f := newPixRecFixture(t)
	rec := do(t, f.handler, http.MethodPost, "/v1/pix/locrec", "", idem("k1"), nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: want 401, got %d", rec.Code)
	}
}

func TestCreateMandateRequiresIdempotencyKey(t *testing.T) {
	t.Parallel()
	f := newPixRecFixture(t)
	rec := do(t, f.handler, http.MethodPost, "/v1/pix/rec", tenantToken, nil, mandateBody(0, "", 0))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing Idempotency-Key: want 400, got %d", rec.Code)
	}
}

// TestCreateMandateRejectsUnknownField is the anti mass-assignment guard: a field the
// contract does not define must be refused, not silently ignored.
func TestCreateMandateRejectsUnknownField(t *testing.T) {
	t.Parallel()
	f := newPixRecFixture(t)
	body := mandateBody(0, "", 0)
	body["tenant_id"] = "someone-else"
	rec := do(t, f.handler, http.MethodPost, "/v1/pix/rec", tenantToken, idem("k1"), body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown field: want 400, got %d (%s)", rec.Code, rec.Body.String())
	}
}

// TestGetMandateCrossTenantIsNotFound proves the mandate id space is not an existence
// oracle: another tenant's real idRec reads as 404, exactly like a nonexistent one.
func TestGetMandateCrossTenantIsNotFound(t *testing.T) {
	t.Parallel()
	f := newPixRecFixture(t)
	idRec := f.createMandate(t, 0, "", 0)

	victim := do(t, f.handler, http.MethodGet, "/v1/pix/rec/"+idRec, f.otherAuth, nil, nil)
	ghost := do(t, f.handler, http.MethodGet, "/v1/pix/rec/RN000000000000000000000000000", f.otherAuth, nil, nil)
	if victim.Code != http.StatusNotFound || ghost.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant read: want 404/404, got %d/%d", victim.Code, ghost.Code)
	}
	if victim.Body.String() != ghost.Body.String() {
		t.Fatalf("cross-tenant read leaks existence: %q vs %q", victim.Body.String(), ghost.Body.String())
	}
}

// --- Jornada 3, end to end ---

// createMandate runs the first three steps of the journey and returns the idRec.
func (f *pixRecFixture) createMandate(t *testing.T, locID int64, journeyTxID string, amountCents int64) string {
	t.Helper()
	rec := do(t, f.handler, http.MethodPost, "/v1/pix/rec", tenantToken, idem("rec-"+journeyTxID), mandateBody(locID, journeyTxID, amountCents))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create mandate: %d (%s)", rec.Code, rec.Body.String())
	}
	var out struct {
		IDRec  string `json:"id_rec"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode mandate: %v", err)
	}
	if out.Status != string(recurrence.RecCriada) {
		t.Fatalf("a fresh mandate must be CRIADA (not chargeable), got %q", out.Status)
	}
	return out.IDRec
}

// TestJornada3EndToEnd walks the whole journey against the stub: immediate charge →
// location → mandate bound to both → composite QR → approval via the reconciled
// webhook → recurring charge. It is the test that proves the surface is a JOURNEY and
// not six unrelated endpoints.
func TestJornada3EndToEnd(t *testing.T) {
	t.Parallel()
	f := newPixRecFixture(t)

	// 1. immediate charge — its txid is what the composite QR settles.
	pix := do(t, f.handler, http.MethodPost, "/v1/pix", tenantToken, idem("pix-1"),
		map[string]any{"amount_cents": 9900, "currency": "BRL", "expires_in_seconds": 1800})
	if pix.Code != http.StatusCreated {
		t.Fatalf("create immediate charge: %d (%s)", pix.Code, pix.Body.String())
	}
	var charge struct {
		TxID string `json:"txid"`
	}
	if err := json.Unmarshal(pix.Body.Bytes(), &charge); err != nil {
		t.Fatalf("decode charge: %v", err)
	}

	// 2. payload location.
	loc := do(t, f.handler, http.MethodPost, "/v1/pix/locrec", tenantToken, idem("loc-1"), nil)
	if loc.Code != http.StatusCreated {
		t.Fatalf("create locrec: %d (%s)", loc.Code, loc.Body.String())
	}
	var location struct {
		ID       int64  `json:"id"`
		Location string `json:"location"`
	}
	if err := json.Unmarshal(loc.Body.Bytes(), &location); err != nil {
		t.Fatalf("decode locrec: %v", err)
	}
	if location.ID <= 0 || location.Location == "" {
		t.Fatalf("locrec must carry an id and a URL, got %+v", location)
	}

	// 3. mandate bound to the location AND the charge txid.
	idRec := f.createMandate(t, location.ID, charge.TxID, 9900)

	// 4. the composite QR — with NO txid in the query: the binding was persisted at
	//    creation, so the shop never has to keep a mandate→charge map of its own.
	qr := do(t, f.handler, http.MethodGet, "/v1/pix/rec/"+idRec+"?qr=true", tenantToken, nil, nil)
	if qr.Code != http.StatusOK {
		t.Fatalf("compose QR: %d (%s)", qr.Code, qr.Body.String())
	}
	var withQR struct {
		QR *struct {
			Jornada       string `json:"jornada"`
			PixCopiaECola string `json:"pix_copia_e_cola"`
		} `json:"qr"`
	}
	if err := json.Unmarshal(qr.Body.Bytes(), &withQR); err != nil {
		t.Fatalf("decode qr: %v", err)
	}
	if withQR.QR == nil || withQR.QR.Jornada != "JORNADA_3" || withQR.QR.PixCopiaECola == "" {
		t.Fatalf("want a composed JORNADA_3 QR, got %+v", withQR.QR)
	}

	// 5. before approval, a recurring charge MUST be refused — the payer has not
	//    authorized anything yet.
	early := do(t, f.handler, http.MethodPost, "/v1/pix/cobr", tenantToken, idem("cobr-early"),
		map[string]any{"id_rec": idRec, "txid": "tx-cycle-1", "due_date": "2026-09-01", "amount_cents": 9900})
	if early.Code != http.StatusConflict {
		t.Fatalf("charge before approval: want 409, got %d (%s)", early.Code, early.Body.String())
	}

	// 6. the payer approves; the reconciled webhook records it durably.
	f.approveMandate(t, idRec)

	// 7. now the cycle charge is accepted.
	cobr := do(t, f.handler, http.MethodPost, "/v1/pix/cobr", tenantToken, idem("cobr-1"),
		map[string]any{"id_rec": idRec, "txid": "tx-cycle-1", "due_date": "2026-09-01", "amount_cents": 9900})
	if cobr.Code != http.StatusCreated {
		t.Fatalf("originate cobr: %d (%s)", cobr.Code, cobr.Body.String())
	}
	var charged struct {
		TxID   string `json:"txid"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(cobr.Body.Bytes(), &charged); err != nil {
		t.Fatalf("decode cobr: %v", err)
	}
	if charged.TxID != "tx-cycle-1" {
		t.Fatalf("cobr txid: want tx-cycle-1, got %q", charged.TxID)
	}

	// 8. the charge is billed exactly once, and re-posting the same txid does not bill
	//    again (anti-double-bill on the money seam).
	repeat := do(t, f.handler, http.MethodPost, "/v1/pix/cobr", tenantToken, idem("cobr-1-retry"),
		map[string]any{"id_rec": idRec, "txid": "tx-cycle-1", "due_date": "2026-09-01", "amount_cents": 9900})
	if repeat.Code != http.StatusCreated {
		t.Fatalf("retry cobr: %d (%s)", repeat.Code, repeat.Body.String())
	}
	entries, err := f.store.ListLedgerEntries(context.Background(), f.tenantID)
	if err != nil {
		t.Fatalf("list ledger: %v", err)
	}
	var cobrBills int
	for _, e := range entries {
		if e.Endpoint() == app.CobRCreateEndpoint {
			cobrBills++
		}
	}
	if cobrBills != 1 {
		t.Fatalf("a retried origination must bill once, billed %d times", cobrBills)
	}
}

// TestChargeAboveMandateIsRefused proves the over-charge gate reaches the wire: a
// fixed-value mandate caps every cycle, and exceeding it is a 409 (a state conflict),
// never a 400 that would tell an integrator to "fix its payload".
func TestChargeAboveMandateIsRefused(t *testing.T) {
	t.Parallel()
	f := newPixRecFixture(t)
	idRec := f.createMandate(t, 0, "tx-cap", 5000)
	f.approveMandate(t, idRec)

	over := do(t, f.handler, http.MethodPost, "/v1/pix/cobr", tenantToken, idem("cobr-over"),
		map[string]any{"id_rec": idRec, "txid": "tx-over", "due_date": "2026-09-01", "amount_cents": 5001})
	if over.Code != http.StatusConflict {
		t.Fatalf("over-charge: want 409, got %d (%s)", over.Code, over.Body.String())
	}
	if !strings.Contains(over.Body.String(), "exceeds") {
		t.Fatalf("over-charge must say why: %s", over.Body.String())
	}
}

// TestQRUnavailableIsConflictNotEmptyString proves we never hand back a blank QR. The
// mandate below was bound to no charge, so the bank cannot compose a JORNADA_3 QR for
// the txid asked for; the caller is told, rather than being given something that would
// render as a broken QR in front of a payer.
func TestQRUnavailableIsConflictNotEmptyString(t *testing.T) {
	t.Parallel()
	f := newPixRecFixture(t)
	idRec := f.createMandate(t, 0, "", 0)

	rec := do(t, f.handler, http.MethodGet, "/v1/pix/rec/"+idRec+"?qr=true&txid=tx-never-created", tenantToken, nil, nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("uncomposable QR: want 409, got %d (%s)", rec.Code, rec.Body.String())
	}
}

// TestCancelMandateStopsFurtherCharges proves a revoked mandate cannot keep debiting.
func TestCancelMandateStopsFurtherCharges(t *testing.T) {
	t.Parallel()
	f := newPixRecFixture(t)
	idRec := f.createMandate(t, 0, "tx-cancel", 0)
	f.approveMandate(t, idRec)

	if rec := do(t, f.handler, http.MethodDelete, "/v1/pix/rec/"+idRec, tenantToken, nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("cancel mandate: %d (%s)", rec.Code, rec.Body.String())
	}
	after := do(t, f.handler, http.MethodPost, "/v1/pix/cobr", tenantToken, idem("cobr-after-cancel"),
		map[string]any{"id_rec": idRec, "txid": "tx-after", "due_date": "2026-09-01", "amount_cents": 1000})
	if after.Code != http.StatusConflict {
		t.Fatalf("charge after cancel: want 409, got %d (%s)", after.Code, after.Body.String())
	}
}

// TestSolicRecExpiryBoundary proves the BACEN CMT-APR-SOLI-016 window is enforced at
// OUR boundary, so a tenant gets a precise error instead of an opaque upstream 400.
func TestSolicRecExpiryBoundary(t *testing.T) {
	t.Parallel()
	f := newPixRecFixture(t)
	idRec := f.createMandate(t, 0, "tx-solic", 0)

	for name, expires := range map[string]time.Time{
		"past":    time.Now().UTC().Add(-time.Hour),
		"too_far": time.Now().UTC().Add(31 * 24 * time.Hour),
	} {
		rec := do(t, f.handler, http.MethodPost, "/v1/pix/solicrec", tenantToken, idem("solic-"+name),
			map[string]any{
				"id_rec": idRec, "tax_id": "02989131415", "agencia": "0001",
				"conta": "123456", "ispb_participante": "12345678",
				"expires_at": expires.Format(time.RFC3339),
			})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expires_at %s: want 400, got %d (%s)", name, rec.Code, rec.Body.String())
		}
	}

	ok := do(t, f.handler, http.MethodPost, "/v1/pix/solicrec", tenantToken, idem("solic-ok"),
		map[string]any{
			"id_rec": idRec, "tax_id": "02989131415", "agencia": "0001",
			"conta": "123456", "ispb_participante": "12345678",
			"expires_at": time.Now().UTC().Add(48 * time.Hour).Format(time.RFC3339),
		})
	if ok.Code != http.StatusCreated {
		t.Fatalf("valid solicrec: %d (%s)", ok.Code, ok.Body.String())
	}
}

// --- remaining surface ---

// TestCobRLifecycleRoutes exercises read, retry and cancel of one instalment against a
// live mandate.
func TestCobRLifecycleRoutes(t *testing.T) {
	t.Parallel()
	f := newPixRecFixture(t)
	idRec := f.createMandate(t, 0, "tx-life", 5000)
	f.approveMandate(t, idRec)

	created := do(t, f.handler, http.MethodPost, "/v1/pix/cobr", tenantToken, idem("cobr-life"),
		map[string]any{"id_rec": idRec, "txid": "tx-cycle", "due_date": "2026-09-01", "amount_cents": 4000})
	if created.Code != http.StatusCreated {
		t.Fatalf("originate: %d (%s)", created.Code, created.Body.String())
	}

	read := do(t, f.handler, http.MethodGet, "/v1/pix/cobr/tx-cycle", tenantToken, nil, nil)
	if read.Code != http.StatusOK {
		t.Fatalf("read cobr: %d (%s)", read.Code, read.Body.String())
	}
	var got struct {
		TxID        string `json:"txid"`
		AmountCents int64  `json:"amount_cents"`
	}
	if err := json.Unmarshal(read.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.TxID != "tx-cycle" || got.AmountCents != 4000 {
		t.Fatalf("read cobr: %+v", got)
	}

	retry := do(t, f.handler, http.MethodPost, "/v1/pix/cobr/tx-cycle/retentativa/2026-09-10", tenantToken, nil,
		map[string]any{"id_rec": idRec})
	if retry.Code != http.StatusOK {
		t.Fatalf("retry: %d (%s)", retry.Code, retry.Body.String())
	}

	cancelled := do(t, f.handler, http.MethodDelete, "/v1/pix/cobr/tx-cycle", tenantToken, nil, nil)
	if cancelled.Code != http.StatusOK {
		t.Fatalf("cancel instalment: %d (%s)", cancelled.Code, cancelled.Body.String())
	}
	if !strings.Contains(cancelled.Body.String(), "CANCELADA") {
		t.Fatalf("cancel must report the new status: %s", cancelled.Body.String())
	}
}

// TestCobRHasNoAmendRoute pins the absence of the route this surface first shipped with.
// PUT /v1/pix/cobr/{txid} advertised "revise the amount", which the bank cannot honour —
// on the cobr surface PUT is the CREATE and the only revisable field is
// status=CANCELADA. A route that accepts a new amount and silently does not apply it is
// worse than no route: the caller believes the instalment changed.
func TestCobRHasNoAmendRoute(t *testing.T) {
	t.Parallel()
	f := newPixRecFixture(t)
	rec := do(t, f.handler, http.MethodPut, "/v1/pix/cobr/tx-whatever", tenantToken, idem("k"),
		map[string]any{"id_rec": "RN1", "due_date": "2026-09-05", "amount_cents": 4500})
	if rec.Code != http.StatusMethodNotAllowed && rec.Code != http.StatusNotFound {
		t.Fatalf("PUT on a cobr must not exist: got %d (%s)", rec.Code, rec.Body.String())
	}
}

// TestCancelCobRCrossTenantIsNotFound proves a txid guessed from another tenant cannot
// be cancelled, and reads identically to a txid that never existed.
func TestCancelCobRCrossTenantIsNotFound(t *testing.T) {
	t.Parallel()
	f := newPixRecFixture(t)
	idRec := f.createMandate(t, 0, "tx-victim", 0)
	f.approveMandate(t, idRec)
	if rec := do(t, f.handler, http.MethodPost, "/v1/pix/cobr", tenantToken, idem("c-victim"),
		map[string]any{"id_rec": idRec, "txid": "tx-victim-cycle", "due_date": "2026-09-01", "amount_cents": 1000}); rec.Code != http.StatusCreated {
		t.Fatalf("originate: %d (%s)", rec.Code, rec.Body.String())
	}
	victim := do(t, f.handler, http.MethodDelete, "/v1/pix/cobr/tx-victim-cycle", f.otherAuth, nil, nil)
	ghost := do(t, f.handler, http.MethodDelete, "/v1/pix/cobr/tx-does-not-exist", f.otherAuth, nil, nil)
	if victim.Code != http.StatusNotFound || ghost.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant cancel: want 404/404, got %d/%d", victim.Code, ghost.Code)
	}
	if victim.Body.String() != ghost.Body.String() {
		t.Fatalf("cross-tenant cancel leaks existence: %q vs %q", victim.Body.String(), ghost.Body.String())
	}
}

// TestRetryAfterCancelIsRefused proves a revoked mandate cannot reach back and retry a
// debit against a payer who already withdrew their authorization.
func TestRetryAfterCancelIsRefused(t *testing.T) {
	t.Parallel()
	f := newPixRecFixture(t)
	idRec := f.createMandate(t, 0, "tx-revoked", 0)
	f.approveMandate(t, idRec)
	if rec := do(t, f.handler, http.MethodPost, "/v1/pix/cobr", tenantToken, idem("c1"),
		map[string]any{"id_rec": idRec, "txid": "tx-c1", "due_date": "2026-09-01", "amount_cents": 1000}); rec.Code != http.StatusCreated {
		t.Fatalf("originate: %d", rec.Code)
	}
	if rec := do(t, f.handler, http.MethodDelete, "/v1/pix/rec/"+idRec, tenantToken, nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("cancel: %d (%s)", rec.Code, rec.Body.String())
	}
	retry := do(t, f.handler, http.MethodPost, "/v1/pix/cobr/tx-c1/retentativa/2026-09-10", tenantToken, nil,
		map[string]any{"id_rec": idRec})
	if retry.Code != http.StatusConflict {
		t.Fatalf("retry after cancel: want 409, got %d (%s)", retry.Code, retry.Body.String())
	}
}

// TestLocRecReadAndUnlinkRoutes covers the location lifecycle, including that a
// non-numeric id is a 400 rather than being reported as a missing location.
func TestLocRecReadAndUnlinkRoutes(t *testing.T) {
	t.Parallel()
	f := newPixRecFixture(t)

	created := do(t, f.handler, http.MethodPost, "/v1/pix/locrec", tenantToken, idem("loc-1"), nil)
	if created.Code != http.StatusCreated {
		t.Fatalf("mint: %d (%s)", created.Code, created.Body.String())
	}
	var loc struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &loc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	path := "/v1/pix/locrec/" + strconv.FormatInt(loc.ID, 10)
	if rec := do(t, f.handler, http.MethodGet, path, tenantToken, nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("read location: %d (%s)", rec.Code, rec.Body.String())
	}
	if rec := do(t, f.handler, http.MethodDelete, path+"/idrec", tenantToken, nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("unlink: %d (%s)", rec.Code, rec.Body.String())
	}
	if rec := do(t, f.handler, http.MethodGet, "/v1/pix/locrec/not-a-number", tenantToken, nil, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("non-numeric id: want 400, got %d", rec.Code)
	}
	// Another tenant's location must read as not-found, never as someone else's URL.
	if rec := do(t, f.handler, http.MethodGet, path, f.otherAuth, nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant location read: want 404, got %d (%s)", rec.Code, rec.Body.String())
	}
}

// TestGetSolicRecRoute covers the activation-request read.
func TestGetSolicRecRoute(t *testing.T) {
	t.Parallel()
	f := newPixRecFixture(t)
	idRec := f.createMandate(t, 0, "tx-solic-read", 0)

	created := do(t, f.handler, http.MethodPost, "/v1/pix/solicrec", tenantToken, idem("solic-1"),
		map[string]any{
			"id_rec": idRec, "tax_id": "32159366000102", "agencia": "0001",
			"conta": "123456", "ispb_participante": "12345678",
			"expires_at": time.Now().UTC().Add(48 * time.Hour).Format(time.RFC3339),
		})
	if created.Code != http.StatusCreated {
		t.Fatalf("create solicrec: %d (%s)", created.Code, created.Body.String())
	}
	var solic struct {
		IDSolicRec string `json:"id_solic_rec"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &solic); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec := do(t, f.handler, http.MethodGet, "/v1/pix/solicrec/"+solic.IDSolicRec, tenantToken, nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("read solicrec: %d (%s)", rec.Code, rec.Body.String())
	}
}

// TestMandateResponseDoesNotEchoPayerPII proves the mandate response never carries the
// payer's document or name back. They are the only titular PII this service stores
// (ADR-0008), every read that exposes them carries an art.13 obligation, and nothing in
// this response needs them.
func TestMandateResponseDoesNotEchoPayerPII(t *testing.T) {
	t.Parallel()
	f := newPixRecFixture(t)
	rec := do(t, f.handler, http.MethodPost, "/v1/pix/rec", tenantToken, idem("rec-pii"), mandateBody(0, "tx-pii", 0))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d (%s)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, secret := range []string{"02989131415", "Beltrano"} {
		if strings.Contains(body, secret) {
			t.Fatalf("mandate response echoes payer PII (%q): %s", secret, body)
		}
	}
}

// TestPixTxidRouteStillReachable guards the chi ordering: the literal recurrence
// segments are registered before "/pix/{txid}", so adding them must not have swallowed
// the immediate-charge read.
func TestPixTxidRouteStillReachable(t *testing.T) {
	t.Parallel()
	f := newPixRecFixture(t)
	created := do(t, f.handler, http.MethodPost, "/v1/pix", tenantToken, idem("pix-order"),
		map[string]any{"amount_cents": 100, "currency": "BRL", "expires_in_seconds": 600})
	if created.Code != http.StatusCreated {
		t.Fatalf("create charge: %d (%s)", created.Code, created.Body.String())
	}
	var charge struct {
		TxID string `json:"txid"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &charge); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec := do(t, f.handler, http.MethodGet, "/v1/pix/"+charge.TxID, tenantToken, nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/pix/{txid} broke: %d (%s)", rec.Code, rec.Body.String())
	}
}

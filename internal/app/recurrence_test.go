package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
	"github.com/ia-dev-sindireceita/payment/internal/domain/recurrence"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// recurrenceServiceHarness wires a RecurrenceService over the in-memory store's
// real transactional UoW (so SaveCobR + audit Append commit together) and the stub
// bank as the CobR origination port.
func recurrenceServiceHarness(t *testing.T) (*app.RecurrenceService, *harness) {
	t.Helper()
	h := newHarness(t)
	h.deps.Recs = h.store
	h.deps.CobRs = h.store
	h.deps.Audit = h.store
	h.deps.UoW = h.store
	h.deps.CobRReader = h.bank
	return app.NewRecurrenceService(h.deps), h
}

// seedMandate persists an APROVADA mandate for (tenant, idRec) in the durable store.
func seedMandate(t *testing.T, h *harness, tenant, idRec string, status recurrence.RecStatus) {
	t.Helper()
	at := time.Unix(1000, 0).UTC()
	dev, err := recurrence.NewDevedor("12345678901", "Fulano")
	if err != nil {
		t.Fatalf("devedor: %v", err)
	}
	rec, err := recurrence.NewRec(recurrence.NewRecParams{
		IDRec:         idRec,
		TenantID:      tenant,
		BankID:        "c6",
		Contrato:      "C-1",
		Devedor:       dev,
		DataInicial:   "2026-07-01",
		Periodicidade: recurrence.RecMensal,
		ValorCents:    1000,
	}, at)
	if err != nil {
		t.Fatalf("new rec: %v", err)
	}
	if status != recurrence.RecCriada {
		if err := rec.Transition(status, at.Add(time.Minute)); err != nil {
			t.Fatalf("transition: %v", err)
		}
	}
	if err := h.store.SaveRec(context.Background(), rec); err != nil {
		t.Fatalf("save rec: %v", err)
	}
}

func validOriginate() app.OriginateCobRInput {
	return app.OriginateCobRInput{
		TenantID:   "t1",
		OperatorID: "op-1",
		IDRec:      "RN1",
		TxID:       "tx-1",
		Vencimento: "2026-08-01",
		ValorCents: 500,
	}
}

func TestOriginateCobRValidation(t *testing.T) {
	t.Parallel()
	svc, _ := recurrenceServiceHarness(t)
	cases := []app.OriginateCobRInput{
		{TenantID: "", IDRec: "RN1", TxID: "tx"},
		{TenantID: "t1", IDRec: "", TxID: "tx"},
		{TenantID: "t1", IDRec: "RN1", TxID: ""},
	}
	for i, c := range cases {
		if _, err := svc.OriginateCobR(context.Background(), c); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("case %d: want validation, got %v", i, err)
		}
	}
}

func TestOriginateCobRUnconfiguredFailsClosed(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.deps.Recs = h.store
	h.deps.CobRs = h.store
	h.deps.Audit = h.store
	h.deps.UoW = h.store
	// CobRReader intentionally left nil.
	svc := app.NewRecurrenceService(h.deps)
	if _, err := svc.OriginateCobR(context.Background(), validOriginate()); !errors.Is(err, shared.ErrUnavailable) {
		t.Fatalf("want unavailable, got %v", err)
	}
}

func TestOriginateCobRNoMandate(t *testing.T) {
	t.Parallel()
	svc, _ := recurrenceServiceHarness(t)
	// No mandate seeded → the gate refuses before any bank call.
	if _, err := svc.OriginateCobR(context.Background(), validOriginate()); !errors.Is(err, recurrence.ErrMandateNotFound) {
		t.Fatalf("want ErrMandateNotFound, got %v", err)
	}
}

func TestOriginateCobRMandateNotApproved(t *testing.T) {
	t.Parallel()
	for _, st := range []recurrence.RecStatus{
		recurrence.RecCriada,
		recurrence.RecRejeitada,
		recurrence.RecExpirada,
		recurrence.RecCancelada,
	} {
		svc, h := recurrenceServiceHarness(t)
		seedMandate(t, h, "t1", "RN1", st)
		if _, err := svc.OriginateCobR(context.Background(), validOriginate()); !errors.Is(err, recurrence.ErrMandateNotApproved) {
			t.Fatalf("status %s: want ErrMandateNotApproved, got %v", st, err)
		}
		// Nothing was persisted: the refusal happened before the bank/durable write.
		if got, err := h.store.FindCobRByTxID(context.Background(), "t1", "tx-1"); err == nil {
			t.Fatalf("status %s: no charge should be persisted, got %v", st, got)
		}
		if n := len(h.store.AuditEntries()); n != 0 {
			t.Fatalf("status %s: no audit entry should be appended, got %d", st, n)
		}
	}
}

func TestOriginateCobRTenantIsolation(t *testing.T) {
	t.Parallel()
	svc, h := recurrenceServiceHarness(t)
	// An APROVADA mandate exists for t1; a request under t1 but the mandate keyed to
	// another tenant must not authorize. Seed for "other" and originate as "t1".
	seedMandate(t, h, "other", "RN1", recurrence.RecAprovada)
	if _, err := svc.OriginateCobR(context.Background(), validOriginate()); !errors.Is(err, recurrence.ErrMandateNotFound) {
		t.Fatalf("cross-tenant mandate must not authorize, got %v", err)
	}
}

func TestOriginateCobRApprovedHappyPath(t *testing.T) {
	t.Parallel()
	svc, h := recurrenceServiceHarness(t)
	seedMandate(t, h, "t1", "RN1", recurrence.RecAprovada)

	cobr, err := svc.OriginateCobR(context.Background(), validOriginate())
	if err != nil {
		t.Fatalf("originate: %v", err)
	}
	if cobr.TxID() != "tx-1" || cobr.IDRec() != "RN1" || cobr.Status() != recurrence.CobRCriada {
		t.Fatalf("unexpected cobr: %+v", cobr)
	}
	// Persisted durably.
	got, err := h.store.FindCobRByTxID(context.Background(), "t1", "tx-1")
	if err != nil {
		t.Fatalf("charge not persisted: %v", err)
	}
	if got.ValorCents() != 500 {
		t.Fatalf("valor: %d", got.ValorCents())
	}
	// Originated at the bank (the stub recorded the charge).
	if _, err := h.bank.GetCobR(context.Background(), "t1", "tx-1"); err != nil {
		t.Fatalf("charge not originated at bank: %v", err)
	}
	// Exactly one audit entry, attributed and recording the origination of this txid.
	entries := h.store.AuditEntries()
	if len(entries) != 1 {
		t.Fatalf("want 1 audit entry, got %d", len(entries))
	}
	e := entries[0]
	if e.Action() != audit.ActionCobRCreated || e.TxID() != "tx-1" || e.OperatorID() != "op-1" || e.TenantID() != "t1" {
		t.Fatalf("unexpected audit entry: %+v", e)
	}
}

func TestOriginateCobRIdempotentRetry(t *testing.T) {
	t.Parallel()
	svc, h := recurrenceServiceHarness(t)
	seedMandate(t, h, "t1", "RN1", recurrence.RecAprovada)

	if _, err := svc.OriginateCobR(context.Background(), validOriginate()); err != nil {
		t.Fatalf("first: %v", err)
	}
	if _, err := svc.OriginateCobR(context.Background(), validOriginate()); err != nil {
		t.Fatalf("retry: %v", err)
	}
	// A retry must not double-bill or double-audit.
	if n := len(h.store.AuditEntries()); n != 1 {
		t.Fatalf("retry must not re-audit, got %d entries", n)
	}
}

// failingCobR wraps the stub and forces CreateCobR to fail, exercising the bank
// error branch (no charge persisted, no audit).
type failingCobR struct {
	ports.CobRProvider
	err error
}

func (f failingCobR) CreateCobR(context.Context, string, ports.CreateCobRRequest) (ports.CobRResult, error) {
	return ports.CobRResult{}, f.err
}

func TestOriginateCobRBankErrorPropagates(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.deps.Recs = h.store
	h.deps.CobRs = h.store
	h.deps.Audit = h.store
	h.deps.UoW = h.store
	h.deps.CobRReader = failingCobR{CobRProvider: h.bank, err: errors.New("boom")}
	svc := app.NewRecurrenceService(h.deps)
	seedMandate(t, h, "t1", "RN1", recurrence.RecAprovada)

	if _, err := svc.OriginateCobR(context.Background(), validOriginate()); err == nil {
		t.Fatal("want bank error, got nil")
	}
	// The bank failed AFTER the gate but BEFORE persistence: nothing durable changed.
	if _, err := h.store.FindCobRByTxID(context.Background(), "t1", "tx-1"); err == nil {
		t.Fatal("no charge should be persisted on bank failure")
	}
	if n := len(h.store.AuditEntries()); n != 0 {
		t.Fatalf("no audit on bank failure, got %d", n)
	}
}

// seedMandateValor persists an APROVADA mandate whose authorized value is
// valorCents, for the over-charge gate cases (seedMandate fixes it at 1000).
func seedMandateValor(t *testing.T, h *harness, tenant, idRec string, valorCents int64) {
	t.Helper()
	at := time.Unix(1000, 0).UTC()
	dev, err := recurrence.NewDevedor("12345678901", "Fulano")
	if err != nil {
		t.Fatalf("devedor: %v", err)
	}
	rec, err := recurrence.NewRec(recurrence.NewRecParams{
		IDRec:         idRec,
		TenantID:      tenant,
		BankID:        "c6",
		Contrato:      "C-1",
		Devedor:       dev,
		DataInicial:   "2026-07-01",
		Periodicidade: recurrence.RecMensal,
		ValorCents:    valorCents,
	}, at)
	if err != nil {
		t.Fatalf("new rec: %v", err)
	}
	if err := rec.Transition(recurrence.RecAprovada, at.Add(time.Minute)); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if err := h.store.SaveRec(context.Background(), rec); err != nil {
		t.Fatalf("save rec: %v", err)
	}
}

func TestOriginateCobROverChargeRefused(t *testing.T) {
	t.Parallel()
	svc, h := recurrenceServiceHarness(t)
	seedMandate(t, h, "t1", "RN1", recurrence.RecAprovada) // authorizes 1000
	in := validOriginate()
	in.ValorCents = 1500 // above the mandate ceiling
	if _, err := svc.OriginateCobR(context.Background(), in); !errors.Is(err, recurrence.ErrChargeExceedsMandate) {
		t.Fatalf("over-charge: want ErrChargeExceedsMandate, got %v", err)
	}
	// Refused before the bank/durable write: nothing persisted, nothing audited.
	if got, err := h.store.FindCobRByTxID(context.Background(), "t1", "tx-1"); err == nil {
		t.Fatalf("no charge should be persisted on over-charge refusal, got %v", got)
	}
	if n := len(h.store.AuditEntries()); n != 0 {
		t.Fatalf("no audit on over-charge refusal, got %d", n)
	}
}

func TestOriginateCobRAtCeilingAllowed(t *testing.T) {
	t.Parallel()
	svc, h := recurrenceServiceHarness(t)
	seedMandate(t, h, "t1", "RN1", recurrence.RecAprovada) // authorizes 1000
	in := validOriginate()
	in.ValorCents = 1000 // exactly the ceiling — allowed
	cobr, err := svc.OriginateCobR(context.Background(), in)
	if err != nil {
		t.Fatalf("charge at the ceiling should originate, got %v", err)
	}
	if cobr.ValorCents() != 1000 {
		t.Fatalf("valor: %d", cobr.ValorCents())
	}
}

func TestOriginateCobRVariableMandateUncapped(t *testing.T) {
	t.Parallel()
	svc, h := recurrenceServiceHarness(t)
	seedMandateValor(t, h, "t1", "RN1", 0) // variable mandate: no ceiling
	in := validOriginate()
	in.ValorCents = 999999 // any amount is allowed for a variable mandate
	if _, err := svc.OriginateCobR(context.Background(), in); err != nil {
		t.Fatalf("variable mandate must not cap the charge, got %v", err)
	}
}

// --- mandate journey (Jornada 3) ---

// mandateJourneyHarness adds the mandate/activation/location ports the tenant-facing
// journey needs on top of recurrenceServiceHarness, plus a seeded, priced tenant so
// CreateMandate can resolve and bill it.
func mandateJourneyHarness(t *testing.T) (*app.RecurrenceService, *harness, string) {
	t.Helper()
	h := newHarness(t)
	h.deps.Recs = h.store
	h.deps.CobRs = h.store
	h.deps.Audit = h.store
	h.deps.UoW = h.store
	h.deps.CobRReader = h.bank
	h.deps.RecReader = h.bank
	h.deps.SolicRecs = h.bank
	h.deps.LocRecs = h.bank

	admin := app.NewAdminService(h.deps)
	tn, err := admin.CreateTenant(context.Background(), "Acme")
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	h.creds.Set(tn.ID(), ports.BankCredential{ClientID: "cid", Secret: "shh"})
	if _, err := admin.SetEndpointPrice(context.Background(), tn.ID(), app.RecCreateEndpoint, 25); err != nil {
		t.Fatalf("seed price: %v", err)
	}
	return app.NewRecurrenceService(h.deps), h, tn.ID()
}

func mandateInput(tenantID, journeyTxID string, locID, amountCents int64) app.CreateMandateInput {
	return app.CreateMandateInput{
		TenantID:            tenantID,
		Contrato:            "CT-1",
		Objeto:              "Mensalidade",
		DevedorDoc:          "02989131415",
		DevedorNome:         "Beltrano da Silva",
		DataInicial:         "2026-09-01",
		Periodicidade:       "MENSAL",
		PoliticaRetentativa: "PERMITE_3R_7D",
		LocID:               locID,
		JornadaTxID:         journeyTxID,
		ValorRecCents:       amountCents,
		IdempotencyKey:      "idem-" + journeyTxID,
	}
}

// TestCreateMandateIsBornUnchargeable is the invariant the whole product rests on: a
// mandate we just registered is CRIADA, and no charge may be originated against it
// until the PAYER authorizes it. If this ever regresses, the platform would debit
// people who never agreed to anything.
func TestCreateMandateIsBornUnchargeable(t *testing.T) {
	t.Parallel()
	svc, _, tenantID := mandateJourneyHarness(t)
	ctx := context.Background()

	rec, res, err := svc.CreateMandate(ctx, mandateInput(tenantID, "tx-1", 0, 0))
	if err != nil {
		t.Fatalf("create mandate: %v", err)
	}
	if rec.Status() != recurrence.RecCriada {
		t.Fatalf("fresh mandate must be CRIADA, got %q", rec.Status())
	}
	if res.IDRec == "" {
		t.Fatal("bank must return an idRec")
	}
	_, err = svc.OriginateCobR(ctx, app.OriginateCobRInput{
		TenantID: tenantID, IDRec: rec.IDRec(), TxID: "tx-cycle", Vencimento: "2026-09-01", ValorCents: 100,
	})
	if !errors.Is(err, recurrence.ErrMandateNotApproved) {
		t.Fatalf("charge against an unapproved mandate: want ErrMandateNotApproved, got %v", err)
	}
}

// TestCreateMandatePersistsJourneyBinding proves the loc/txid binding survives, which
// is what lets the QR be re-composed later without the caller keeping its own map.
func TestCreateMandatePersistsJourneyBinding(t *testing.T) {
	t.Parallel()
	svc, h, tenantID := mandateJourneyHarness(t)
	ctx := context.Background()

	loc, err := svc.CreateLocRec(ctx, app.CreateLocRecInput{TenantID: tenantID, IdempotencyKey: "loc-1"})
	if err != nil {
		t.Fatalf("create locrec: %v", err)
	}
	rec, _, err := svc.CreateMandate(ctx, mandateInput(tenantID, "tx-imediata", loc.ID, 9900))
	if err != nil {
		t.Fatalf("create mandate: %v", err)
	}

	stored, err := h.store.FindRecByID(ctx, tenantID, rec.IDRec())
	if err != nil {
		t.Fatalf("reload mandate: %v", err)
	}
	if stored.LocID() != loc.ID || stored.JornadaTxID() != "tx-imediata" {
		t.Fatalf("journey binding not persisted: loc=%d txid=%q", stored.LocID(), stored.JornadaTxID())
	}
	if stored.ValorCents() != 9900 {
		t.Fatalf("authorized value not persisted: %d", stored.ValorCents())
	}

	// And the QR read defaults to the persisted txid, with no txid supplied.
	qr, err := svc.GetMandateQR(ctx, tenantID, rec.IDRec(), "")
	if err != nil {
		t.Fatalf("compose QR: %v", err)
	}
	if qr.DadosQR.Jornada != "JORNADA_3" || qr.DadosQR.PixCopiaECola == "" {
		t.Fatalf("want a composed JORNADA_3 QR, got %+v", qr.DadosQR)
	}
}

// TestCreateMandateIsIdempotent proves a retried registration neither creates a second
// mandate nor double-bills nor double-audits.
func TestCreateMandateIsIdempotent(t *testing.T) {
	t.Parallel()
	svc, h, tenantID := mandateJourneyHarness(t)
	ctx := context.Background()

	first, _, err := svc.CreateMandate(ctx, mandateInput(tenantID, "tx-1", 0, 0))
	if err != nil {
		t.Fatalf("create mandate: %v", err)
	}
	second, _, err := svc.CreateMandate(ctx, mandateInput(tenantID, "tx-1", 0, 0))
	if err != nil {
		t.Fatalf("retry create mandate: %v", err)
	}
	if first.IDRec() != second.IDRec() {
		t.Fatalf("retry produced a second mandate: %q vs %q", first.IDRec(), second.IDRec())
	}
	entries, err := h.store.ListLedgerEntries(ctx, tenantID)
	if err != nil {
		t.Fatalf("list ledger: %v", err)
	}
	var bills int
	for _, e := range entries {
		if e.Endpoint() == app.RecCreateEndpoint {
			bills++
		}
	}
	if bills != 1 {
		t.Fatalf("retried registration billed %d times, want 1", bills)
	}
}

// TestCreateMandateRejectsBadPayer proves the payer document is validated in the core,
// at OUR boundary, before any PII crosses to the bank.
func TestCreateMandateRejectsBadPayer(t *testing.T) {
	t.Parallel()
	svc, _, tenantID := mandateJourneyHarness(t)
	in := mandateInput(tenantID, "tx-1", 0, 0)
	in.DevedorDoc = "123"
	if _, _, err := svc.CreateMandate(context.Background(), in); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("short document: want ErrValidation, got %v", err)
	}
}

// TestCancelMandateIsIdempotent proves a repeated revocation is a no-op rather than an
// error or a duplicate audit entry — retries are normal on a revocation path.
func TestCancelMandateIsIdempotent(t *testing.T) {
	t.Parallel()
	svc, h, tenantID := mandateJourneyHarness(t)
	ctx := context.Background()

	rec, _, err := svc.CreateMandate(ctx, mandateInput(tenantID, "tx-1", 0, 0))
	if err != nil {
		t.Fatalf("create mandate: %v", err)
	}
	for i := 0; i < 2; i++ {
		if _, err := svc.CancelMandate(ctx, tenantID, "", rec.IDRec()); err != nil {
			t.Fatalf("cancel #%d: %v", i+1, err)
		}
	}
	stored, err := h.store.FindRecByID(ctx, tenantID, rec.IDRec())
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if stored.Status() != recurrence.RecCancelada {
		t.Fatalf("status after cancel: %q", stored.Status())
	}
	var cancels int
	for _, e := range h.store.AuditEntries() {
		if e.Action() == audit.ActionRecCancelled {
			cancels++
		}
	}
	if cancels != 1 {
		t.Fatalf("idempotent cancel wrote %d audit entries, want 1", cancels)
	}
}

// TestRequestConfirmationExpiryWindow proves the BACEN CMT-APR-SOLI-016 ceiling is
// enforced here, so a tenant gets a precise error rather than an opaque upstream 400.
func TestRequestConfirmationExpiryWindow(t *testing.T) {
	t.Parallel()
	svc, _, tenantID := mandateJourneyHarness(t)
	ctx := context.Background()

	rec, _, err := svc.CreateMandate(ctx, mandateInput(tenantID, "tx-1", 0, 0))
	if err != nil {
		t.Fatalf("create mandate: %v", err)
	}
	now := time.Unix(1000, 0).UTC() // the harness clock
	base := app.RequestConfirmationInput{
		TenantID: tenantID, IDRec: rec.IDRec(), CPF: "02989131415",
		Agencia: "0001", Conta: "123456", ISPBParticipante: "12345678",
		IdempotencyKey: "solic-1",
	}
	for name, expires := range map[string]time.Time{
		"past":        now.Add(-time.Hour),
		"exactly_30d": now.Add(30 * 24 * time.Hour),
		"beyond_30d":  now.Add(31 * 24 * time.Hour),
	} {
		in := base
		in.ExpiraEm = expires
		if _, err := svc.RequestConfirmation(ctx, in); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("expires_at %s: want ErrValidation, got %v", name, err)
		}
	}
	ok := base
	ok.ExpiraEm = now.Add(48 * time.Hour)
	if _, err := svc.RequestConfirmation(ctx, ok); err != nil {
		t.Fatalf("valid window: %v", err)
	}
}

// TestCancelCobRStopsOneInstalmentNotTheMandate proves the asymmetry that matters:
// cancelling an instalment is allowed even once the mandate itself is gone (cancelling
// a debit is always the safe direction), it records the transition and its audit entry,
// and it is idempotent.
func TestCancelCobRStopsOneInstalmentNotTheMandate(t *testing.T) {
	t.Parallel()
	svc, h, tenantID := mandateJourneyHarness(t)
	ctx := context.Background()

	rec, _, err := svc.CreateMandate(ctx, mandateInput(tenantID, "tx-1", 0, 5000))
	if err != nil {
		t.Fatalf("create mandate: %v", err)
	}
	if _, err := h.bank.ApproveRec(ctx, tenantID, rec.IDRec()); err != nil {
		t.Fatalf("approve at bank: %v", err)
	}
	wh := app.NewWebhookService(h.deps)
	if err := wh.HandleRecEvent(ctx, app.RecEvent{
		TenantID: tenantID, IDRec: rec.IDRec(), EventKey: rec.IDRec() + "|rec|APROVADA",
	}); err != nil {
		t.Fatalf("record approval: %v", err)
	}
	if _, err := svc.OriginateCobR(ctx, app.OriginateCobRInput{
		TenantID: tenantID, IDRec: rec.IDRec(), TxID: "tx-cycle", Vencimento: "2026-09-01", ValorCents: 5000,
	}); err != nil {
		t.Fatalf("originate: %v", err)
	}

	// Revoke the MANDATE first. Cancelling the instalment must still work — refusing it
	// here would leave a scheduled debit standing against a payer who withdrew consent.
	if _, err := svc.CancelMandate(ctx, tenantID, "", rec.IDRec()); err != nil {
		t.Fatalf("cancel mandate: %v", err)
	}
	if _, err := svc.CancelCobR(ctx, tenantID, "", "tx-cycle"); err != nil {
		t.Fatalf("cancel instalment after mandate revoked: %v", err)
	}
	stored, err := h.store.FindCobRByTxID(ctx, tenantID, "tx-cycle")
	if err != nil {
		t.Fatalf("reload charge: %v", err)
	}
	if stored.Status() != recurrence.CobRCancelada {
		t.Fatalf("charge status after cancel: %q", stored.Status())
	}

	// Idempotent: a second cancel neither errors nor writes a second audit entry.
	if _, err := svc.CancelCobR(ctx, tenantID, "", "tx-cycle"); err != nil {
		t.Fatalf("second cancel: %v", err)
	}
	var cancels int
	for _, e := range h.store.AuditEntries() {
		if e.Action() == audit.ActionCobRCancelled {
			cancels++
		}
	}
	if cancels != 1 {
		t.Fatalf("idempotent cancel wrote %d audit entries, want 1", cancels)
	}
}

// TestCancelCobRIsTenantScoped proves one tenant cannot cancel another's instalment by
// guessing a txid — the charge is scoped BEFORE the bank is asked to do anything.
func TestCancelCobRIsTenantScoped(t *testing.T) {
	t.Parallel()
	svc, _, tenantID := mandateJourneyHarness(t)
	if _, err := svc.CancelCobR(context.Background(), tenantID, "", "tx-belongs-to-nobody"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("unknown charge: want ErrNotFound, got %v", err)
	}
}

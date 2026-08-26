package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/bank"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
	"github.com/ia-dev-sindireceita/payment/internal/domain/recurrence"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// fakeRecurrence wraps the in-memory stub so the unused Rec/CobR methods keep their
// real behaviour while GetRec/GetCobR are overridable per test (to inject not-found,
// transient errors, and to count reconcile calls — the dedup/rollback assertions).
type fakeRecurrence struct {
	*bank.StubProvider
	getRec    func(ctx context.Context, tenantID, idRec string) (ports.RecResult, error)
	getCobR   func(ctx context.Context, tenantID, txID string) (ports.CobRResult, error)
	recCalls  int
	cobrCalls int
}

func (f *fakeRecurrence) GetRec(ctx context.Context, tenantID, idRec string) (ports.RecResult, error) {
	f.recCalls++
	if f.getRec != nil {
		return f.getRec(ctx, tenantID, idRec)
	}
	return f.StubProvider.GetRec(ctx, tenantID, idRec)
}

func (f *fakeRecurrence) GetCobR(ctx context.Context, tenantID, txID string) (ports.CobRResult, error) {
	f.cobrCalls++
	if f.getCobR != nil {
		return f.getCobR(ctx, tenantID, txID)
	}
	return f.StubProvider.GetCobR(ctx, tenantID, txID)
}

// recurrenceHarness builds a webhook service whose recurrence readers are the given
// fake (or the raw stub when fake is nil).
func recurrenceHarness(t *testing.T, fake *fakeRecurrence) (*app.WebhookService, *harness) {
	t.Helper()
	h := newHarness(t)
	// Use the in-memory store's real transactional UoW (not the autocommit
	// fallback) so MarkProcessed participates in the unit of work and a transient
	// reconcile failure genuinely rolls the dedup mark back, mirroring production.
	h.deps.UoW = h.store
	if fake != nil {
		h.deps.RecReader = fake
		h.deps.CobRReader = fake
	} else {
		h.deps.RecReader = h.bank
		h.deps.CobRReader = h.bank
	}
	return app.NewWebhookService(h.deps), h
}

func TestHandleRecEventValidation(t *testing.T) {
	t.Parallel()
	wh, _ := recurrenceHarness(t, &fakeRecurrence{})
	cases := []app.RecEvent{
		{TenantID: "", IDRec: "r", EventKey: "e"},
		{TenantID: "t", IDRec: "", EventKey: "e"},
		{TenantID: "t", IDRec: "r", EventKey: ""},
	}
	for i, c := range cases {
		if err := wh.HandleRecEvent(context.Background(), c); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("rec case %d: want validation, got %v", i, err)
		}
	}
}

func TestHandleCobREventValidation(t *testing.T) {
	t.Parallel()
	wh, _ := recurrenceHarness(t, &fakeRecurrence{})
	cases := []app.CobREvent{
		{TenantID: "", TxID: "tx", EventKey: "e"},
		{TenantID: "t", TxID: "", EventKey: "e"},
		{TenantID: "t", TxID: "tx", EventKey: ""},
	}
	for i, c := range cases {
		if err := wh.HandleCobREvent(context.Background(), c); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("cobr case %d: want validation, got %v", i, err)
		}
	}
}

// A nil recurrence reader leaves the dispatch unwired: the handler must fail closed
// rather than nil-panic.
func TestHandleRecurrenceUnconfiguredFailsClosed(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	wh := app.NewWebhookService(h.deps) // no RecReader/CobRReader wired
	if err := wh.HandleRecEvent(context.Background(), app.RecEvent{TenantID: "t1", IDRec: "r", EventKey: "e"}); !errors.Is(err, shared.ErrUnavailable) {
		t.Fatalf("rec: want unavailable, got %v", err)
	}
	if err := wh.HandleCobREvent(context.Background(), app.CobREvent{TenantID: "t1", TxID: "tx", EventKey: "e"}); !errors.Is(err, shared.ErrUnavailable) {
		t.Fatalf("cobr: want unavailable, got %v", err)
	}
}

// A first delivery reconciles the mandate (GetRec) and is acked; a replay of the
// same event is a no-op that does NOT reconcile again (dedup before reconcile).
func TestHandleRecEventReconcilesAndDedups(t *testing.T) {
	t.Parallel()
	fake := &fakeRecurrence{}
	wh, h := recurrenceHarness(t, fake)
	fake.StubProvider = h.bank

	for i := 0; i < 2; i++ {
		if err := wh.HandleRecEvent(context.Background(), app.RecEvent{TenantID: "t1", IDRec: "RN123", EventKey: "rec|APROVADA"}); err != nil {
			t.Fatalf("delivery %d: %v", i, err)
		}
	}
	// The stub returns ErrNotFound for the unseeded RN123 → acked and dropped; the
	// reconcile runs exactly once (the replay is deduped before the read).
	if fake.recCalls != 1 {
		t.Fatalf("want exactly 1 reconcile (dedup before reconcile), got %d", fake.recCalls)
	}
}

// An unknown mandate (GetRec → ErrNotFound) is acked and dropped: no error, and the
// event is recorded processed so a redelivery does not reconcile forever.
func TestHandleRecEventUnknownMandateAcked(t *testing.T) {
	t.Parallel()
	fake := &fakeRecurrence{getRec: func(context.Context, string, string) (ports.RecResult, error) {
		return ports.RecResult{}, shared.ErrNotFound
	}}
	wh, h := recurrenceHarness(t, fake)
	fake.StubProvider = h.bank
	if err := wh.HandleRecEvent(context.Background(), app.RecEvent{TenantID: "t1", IDRec: "ghost", EventKey: "k1"}); err != nil {
		t.Fatalf("unknown mandate should be acked, got %v", err)
	}
	if err := wh.HandleRecEvent(context.Background(), app.RecEvent{TenantID: "t1", IDRec: "ghost", EventKey: "k1"}); err != nil {
		t.Fatalf("replay: %v", err)
	}
	if fake.recCalls != 1 {
		t.Fatalf("want 1 reconcile (second deduped), got %d", fake.recCalls)
	}
}

// A transient reconcile failure rolls back the dedup mark so C6's redelivery is
// reprocessed and eventually settles, rather than being swallowed as a duplicate.
func TestHandleRecEventTransientErrorRollsBackMark(t *testing.T) {
	t.Parallel()
	fail := true
	fake := &fakeRecurrence{getRec: func(context.Context, string, string) (ports.RecResult, error) {
		if fail {
			return ports.RecResult{}, shared.ErrUnavailable
		}
		return ports.RecResult{IDRec: "r", Status: ports.RecAprovada}, nil
	}}
	wh, h := recurrenceHarness(t, fake)
	fake.StubProvider = h.bank

	if err := wh.HandleRecEvent(context.Background(), app.RecEvent{TenantID: "t1", IDRec: "r", EventKey: "same"}); !errors.Is(err, shared.ErrUnavailable) {
		t.Fatalf("want transient error, got %v", err)
	}
	fail = false // bank recovers; the redelivery must be reprocessed (mark rolled back)
	if err := wh.HandleRecEvent(context.Background(), app.RecEvent{TenantID: "t1", IDRec: "r", EventKey: "same"}); err != nil {
		t.Fatalf("redelivery after recovery: %v", err)
	}
	if fake.recCalls != 2 {
		t.Fatalf("want 2 reconciles (mark rolled back on transient), got %d", fake.recCalls)
	}
}

// CobR mirrors Rec: reconcile via GetCobR, dedup before reconcile, transient rolls back.
func TestHandleCobREventReconcilesAndDedups(t *testing.T) {
	t.Parallel()
	fake := &fakeRecurrence{}
	wh, h := recurrenceHarness(t, fake)
	fake.StubProvider = h.bank
	for i := 0; i < 2; i++ {
		if err := wh.HandleCobREvent(context.Background(), app.CobREvent{TenantID: "t1", TxID: "tx9", EventKey: "cobr|9"}); err != nil {
			t.Fatalf("delivery %d: %v", i, err)
		}
	}
	if fake.cobrCalls != 1 {
		t.Fatalf("want exactly 1 reconcile, got %d", fake.cobrCalls)
	}
}

func TestHandleCobREventTransientErrorRollsBackMark(t *testing.T) {
	t.Parallel()
	fail := true
	fake := &fakeRecurrence{getCobR: func(context.Context, string, string) (ports.CobRResult, error) {
		if fail {
			return ports.CobRResult{}, shared.ErrUnavailable
		}
		return ports.CobRResult{TxID: "tx", Status: "CONCLUIDA", ValorCents: 100}, nil
	}}
	wh, h := recurrenceHarness(t, fake)
	fake.StubProvider = h.bank
	if err := wh.HandleCobREvent(context.Background(), app.CobREvent{TenantID: "t1", TxID: "tx", EventKey: "k"}); !errors.Is(err, shared.ErrUnavailable) {
		t.Fatalf("want transient error, got %v", err)
	}
	fail = false
	if err := wh.HandleCobREvent(context.Background(), app.CobREvent{TenantID: "t1", TxID: "tx", EventKey: "k"}); err != nil {
		t.Fatalf("redelivery: %v", err)
	}
	if fake.cobrCalls != 2 {
		t.Fatalf("want 2 reconciles, got %d", fake.cobrCalls)
	}
}

// The reconcile read genuinely runs against a seeded mandate/charge in the stub
// (end-to-end through the real stub reader, not just the fake).
func TestHandleRecurrenceAgainstStub(t *testing.T) {
	t.Parallel()
	wh, h := recurrenceHarness(t, nil)
	rec, err := h.bank.CreateRec(context.Background(), "t1", ports.CreateRecRequest{
		Vinculo:             ports.RecVinculo{Contrato: "C1"},
		Calendario:          ports.RecCalendario{DataInicial: "2026-07-01", Periodicidade: ports.RecMensal},
		PoliticaRetentativa: ports.Retry3R7D,
	})
	if err != nil {
		t.Fatalf("seed rec: %v", err)
	}
	if err := wh.HandleRecEvent(context.Background(), app.RecEvent{TenantID: "t1", IDRec: rec.IDRec, EventKey: "rec-" + rec.IDRec}); err != nil {
		t.Fatalf("handle rec: %v", err)
	}
	cobr, err := h.bank.CreateCobR(context.Background(), "t1", ports.CreateCobRRequest{IDRec: rec.IDRec, TxID: "tx-seed", ValorCents: 500})
	if err != nil {
		t.Fatalf("seed cobr: %v", err)
	}
	if err := wh.HandleCobREvent(context.Background(), app.CobREvent{TenantID: "t1", TxID: cobr.TxID, EventKey: "cobr-" + cobr.TxID}); err != nil {
		t.Fatalf("handle cobr: %v", err)
	}
}

// --- durable recording (the link that makes the cycle chargeable at all) ---

// seedBankMandate registers a mandate at the stub with a payer, so the reconcile read
// returns something representable as a durable aggregate.
func seedBankMandate(t *testing.T, h *harness, tenantID string, amountCents int64) string {
	t.Helper()
	res, err := h.bank.CreateRec(context.Background(), tenantID, ports.CreateRecRequest{
		Vinculo: ports.RecVinculo{
			Contrato: "CT-1",
			Devedor:  ports.RecDevedor{CPF: "02989131415", Nome: "Beltrano da Silva"},
		},
		Calendario:          ports.RecCalendario{DataInicial: "2026-09-01", Periodicidade: ports.RecMensal},
		PoliticaRetentativa: ports.Retry3R7D,
		ValorRecCents:       amountCents,
		IdempotencyKey:      "seed-" + tenantID,
	})
	if err != nil {
		t.Fatalf("seed mandate at bank: %v", err)
	}
	return res.IDRec
}

// TestRecWebhookRecordsApproval is the load-bearing test of this whole feature. The
// payer authorizes the mandate inside their own bank; the ONLY way that fact reaches
// us is the reconciled webhook. If it is not RECORDED here, every mandate stays CRIADA
// forever and every recurring charge is refused — the product does not work.
func TestRecWebhookRecordsApproval(t *testing.T) {
	t.Parallel()
	wh, h := recurrenceHarness(t, nil)
	ctx := context.Background()
	h.creds.Set("t-rec", ports.BankCredential{ClientID: "cid", Secret: "shh"})
	idRec := seedBankMandate(t, h, "t-rec", 9900)

	// First notification: the mandate is still CRIADA at the bank.
	if err := wh.HandleRecEvent(ctx, app.RecEvent{TenantID: "t-rec", IDRec: idRec, EventKey: idRec + "|rec|CRIADA"}); err != nil {
		t.Fatalf("first notification: %v", err)
	}
	stored, err := h.store.FindRecByID(ctx, "t-rec", idRec)
	if err != nil {
		t.Fatalf("mandate must be recorded on first sight: %v", err)
	}
	if stored.Status() != recurrence.RecCriada {
		t.Fatalf("status: want CRIADA, got %q", stored.Status())
	}
	if stored.ValorCents() != 9900 {
		t.Fatalf("authorized ceiling must be recorded, got %d", stored.ValorCents())
	}

	// The payer approves out-of-band; the next notification reconciles APROVADA.
	if _, err := h.bank.ApproveRec(ctx, "t-rec", idRec); err != nil {
		t.Fatalf("approve at bank: %v", err)
	}
	if err := wh.HandleRecEvent(ctx, app.RecEvent{TenantID: "t-rec", IDRec: idRec, EventKey: idRec + "|rec|APROVADA"}); err != nil {
		t.Fatalf("approval notification: %v", err)
	}
	stored, err = h.store.FindRecByID(ctx, "t-rec", idRec)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if stored.Status() != recurrence.RecAprovada {
		t.Fatalf("approval was not recorded: status %q", stored.Status())
	}

	// The transition is in the append-only trail, once per real status change.
	var criada, aprovada int
	for _, e := range h.store.AuditEntries() {
		switch e.Action() {
		case audit.ActionRecCreated:
			criada++
		case audit.ActionRecApproved:
			aprovada++
		}
	}
	if criada != 1 || aprovada != 1 {
		t.Fatalf("audit trail: want 1 created + 1 approved, got %d + %d", criada, aprovada)
	}
}

// TestRecWebhookRedeliveryDoesNotReAudit proves a redelivery that reconciles to the
// SAME status is a no-op — C6 redelivers, and an inflated trail is a trail nobody
// trusts.
func TestRecWebhookRedeliveryDoesNotReAudit(t *testing.T) {
	t.Parallel()
	wh, h := recurrenceHarness(t, nil)
	ctx := context.Background()
	h.creds.Set("t-redeliver", ports.BankCredential{ClientID: "cid", Secret: "shh"})
	idRec := seedBankMandate(t, h, "t-redeliver", 0)

	if err := wh.HandleRecEvent(ctx, app.RecEvent{TenantID: "t-redeliver", IDRec: idRec, EventKey: idRec + "|rec|CRIADA"}); err != nil {
		t.Fatalf("first: %v", err)
	}
	// A DIFFERENT event key (so the dedup mark does not short-circuit it) reconciling
	// to the same status: the durable state is already there, so nothing is written.
	if err := wh.HandleRecEvent(ctx, app.RecEvent{TenantID: "t-redeliver", IDRec: idRec, EventKey: idRec + "|rec|CRIADA|again"}); err != nil {
		t.Fatalf("redelivery: %v", err)
	}
	var created int
	for _, e := range h.store.AuditEntries() {
		if e.Action() == audit.ActionRecCreated {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("redelivery re-audited: %d entries, want 1", created)
	}
}

// TestRecWebhookOutOfOrderIsAckedAndDropped proves a stale notification cannot walk a
// mandate backwards. C6 would redeliver a 5xx forever and no retry could make an
// illegal transition legal, so the delivery is acked and the state left alone.
func TestRecWebhookOutOfOrderIsAckedAndDropped(t *testing.T) {
	t.Parallel()
	wh, h := recurrenceHarness(t, nil)
	ctx := context.Background()
	h.creds.Set("t-stale", ports.BankCredential{ClientID: "cid", Secret: "shh"})
	idRec := seedBankMandate(t, h, "t-stale", 0)

	if _, err := h.bank.ApproveRec(ctx, "t-stale", idRec); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if err := wh.HandleRecEvent(ctx, app.RecEvent{TenantID: "t-stale", IDRec: idRec, EventKey: idRec + "|rec|APROVADA"}); err != nil {
		t.Fatalf("approval: %v", err)
	}
	// A stale CRIADA notification arrives late.
	if _, err := h.bank.SetRecStatus(ctx, "t-stale", idRec, ports.RecCriada); err != nil {
		t.Fatalf("rewind bank view: %v", err)
	}
	if err := wh.HandleRecEvent(ctx, app.RecEvent{TenantID: "t-stale", IDRec: idRec, EventKey: idRec + "|rec|CRIADA|late"}); err != nil {
		t.Fatalf("stale notification must be acked, got %v", err)
	}
	stored, err := h.store.FindRecByID(ctx, "t-stale", idRec)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if stored.Status() != recurrence.RecAprovada {
		t.Fatalf("a stale event walked the mandate backwards to %q", stored.Status())
	}
}

// TestRecWebhookIsTenantScoped proves the recorded mandate belongs to the tenant the
// authenticated channel resolved to, and that another tenant cannot see it.
func TestRecWebhookIsTenantScoped(t *testing.T) {
	t.Parallel()
	wh, h := recurrenceHarness(t, nil)
	ctx := context.Background()
	h.creds.Set("t-owner", ports.BankCredential{ClientID: "cid", Secret: "shh"})
	h.creds.Set("t-rival", ports.BankCredential{ClientID: "cid2", Secret: "shh"})
	idRec := seedBankMandate(t, h, "t-owner", 0)

	if err := wh.HandleRecEvent(ctx, app.RecEvent{TenantID: "t-owner", IDRec: idRec, EventKey: idRec + "|rec|CRIADA"}); err != nil {
		t.Fatalf("record: %v", err)
	}
	if _, err := h.store.FindRecByID(ctx, "t-rival", idRec); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant read: want not-found, got %v", err)
	}
}

// TestCobRWebhookRecordsSettlement proves the charge side records too, so the cycle is
// auditable and a settled charge is not re-settled by a redelivery.
func TestCobRWebhookRecordsSettlement(t *testing.T) {
	t.Parallel()
	wh, h := recurrenceHarness(t, nil)
	ctx := context.Background()
	h.creds.Set("t-cobr", ports.BankCredential{ClientID: "cid", Secret: "shh"})
	idRec := seedBankMandate(t, h, "t-cobr", 0)
	if _, err := h.bank.CreateCobR(ctx, "t-cobr", ports.CreateCobRRequest{
		IDRec: idRec, TxID: "tx-cycle-1", ValorCents: 9900,
	}); err != nil {
		t.Fatalf("seed charge: %v", err)
	}

	if err := wh.HandleCobREvent(ctx, app.CobREvent{TenantID: "t-cobr", TxID: "tx-cycle-1", EventKey: "tx-cycle-1|cobr|CRIADA"}); err != nil {
		t.Fatalf("record charge: %v", err)
	}
	stored, err := h.store.FindCobRByTxID(ctx, "t-cobr", "tx-cycle-1")
	if err != nil {
		t.Fatalf("charge must be recorded: %v", err)
	}
	if stored.IDRec() != idRec || stored.ValorCents() != 9900 {
		t.Fatalf("charge recorded wrong: idRec=%q valor=%d", stored.IDRec(), stored.ValorCents())
	}
}

// TestRecWebhookUnrepresentableMandateIsDropped proves a bank mandate we cannot model
// (here: no payer at all) is acked and dropped rather than half-persisted or retried
// forever. A partially-built aggregate would be worse than none.
func TestRecWebhookUnrepresentableMandateIsDropped(t *testing.T) {
	t.Parallel()
	wh, h := recurrenceHarness(t, nil)
	ctx := context.Background()
	h.creds.Set("t-nodevedor", ports.BankCredential{ClientID: "cid", Secret: "shh"})
	res, err := h.bank.CreateRec(ctx, "t-nodevedor", ports.CreateRecRequest{
		Vinculo:             ports.RecVinculo{Contrato: "CT-1"}, // no devedor
		Calendario:          ports.RecCalendario{DataInicial: "2026-09-01", Periodicidade: ports.RecMensal},
		PoliticaRetentativa: ports.Retry3R7D,
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := wh.HandleRecEvent(ctx, app.RecEvent{TenantID: "t-nodevedor", IDRec: res.IDRec, EventKey: "e1"}); err != nil {
		t.Fatalf("must ack, got %v", err)
	}
	if _, err := h.store.FindRecByID(ctx, "t-nodevedor", res.IDRec); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("an unrepresentable mandate must not be persisted, got %v", err)
	}
}

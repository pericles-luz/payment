package http_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/bank"
	httpadapter "github.com/ia-dev-sindireceita/payment/internal/adapters/http"
	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/system"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// recFixture is a webhook server whose recurrence reconcile-read ports are wired to
// the stub (the production-default fixture leaves them nil). It seeds a tenant +
// callback ref like newFixtureAuth so the shared dispatch authenticates the channel.
type recFixture struct {
	handler  http.Handler
	tenantID string
	stub     *bank.StubProvider
}

func newRecFixture(t *testing.T) *recFixture {
	t.Helper()
	store := persistence.NewStore()
	creds := secret.NewStore(nil)
	stub := bank.NewStubProvider(creds)
	deps := app.Deps{
		Payments: store, Tenants: store, Pricing: store, Ledger: store, Processed: store,
		Bus: nil, Bank: stub, Credentials: creds,
		RecReader: stub, CobRReader: stub,
		UoW:   store,
		Clock: system.Clock{}, IDs: system.IDProvider{},
	}
	admin := app.NewAdminService(deps)
	tn, err := admin.CreateTenant(context.Background(), "Acme")
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	creds.Set(tn.ID(), ports.BankCredential{ClientID: tenantClientID, Secret: "s"})

	webhookRefs := map[string]httpadapter.WebhookIdentity{
		webhookRef: {TenantID: tn.ID(), ClientID: tenantClientID},
	}
	auth := httpadapter.NewStaticTokenAuth(map[string]string{tenantToken: tn.ID()}, nil, webhookRefs)
	srv := httpadapter.NewServer(httpadapter.Config{
		Charges:     app.NewChargeService(deps),
		Admin:       admin,
		Webhooks:    app.NewWebhookService(deps),
		TenantAuth:  auth,
		AdminAuth:   auth,
		WebhookAuth: auth,
	})
	return &recFixture{handler: srv.Router(), tenantID: tn.ID(), stub: stub}
}

func recBody(externalID, service, status string) map[string]any {
	return map[string]any{"external_id": externalID, "client_id": tenantClientID, "service": service, "status": status}
}

// A recurrence notification (service=rec / service=cobr) is routed through the
// shared C6 dispatch, reconciled, and acked 202 — even for an unknown id (dropped,
// not infinitely redelivered), proving the dispatch reaches the recurrence handlers.
func TestRecurrenceWebhookDispatch(t *testing.T) {
	t.Parallel()
	f := newRecFixture(t)
	ctx := context.Background()

	// Seed a real mandate + charge so the reconcile read finds authoritative state.
	rec, err := f.stub.CreateRec(ctx, f.tenantID, ports.CreateRecRequest{
		Vinculo:             ports.RecVinculo{Contrato: "CT"},
		Calendario:          ports.RecCalendario{DataInicial: "2026-08-01", Periodicidade: ports.RecMensal},
		PoliticaRetentativa: ports.Retry3R7D,
	})
	if err != nil {
		t.Fatalf("seed rec: %v", err)
	}
	cobr, err := f.stub.CreateCobR(ctx, f.tenantID, ports.CreateCobRRequest{IDRec: rec.IDRec, TxID: "tx-1", ValorCents: 100})
	if err != nil {
		t.Fatalf("seed cobr: %v", err)
	}

	url := "/webhooks/c6/" + webhookRef
	cases := []struct {
		name string
		body map[string]any
	}{
		{"rec known", recBody(rec.IDRec, "rec", "APROVADA")},
		{"cobr known", recBody(cobr.TxID, "cobr", "CONCLUIDA")},
		{"rec unknown acked", recBody("ghost-rec", "REC", "EXPIRADA")}, // case-insensitive + unknown → 202
		{"cobr unknown acked", recBody("ghost-tx", "CobR", "CRIADA")},  // mixed-case service token
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := do(t, f.handler, http.MethodPost, url, "", nil, tc.body)
			if rec.Code != http.StatusAccepted {
				t.Fatalf("%s: want 202, got %d (%s)", tc.name, rec.Code, rec.Body.String())
			}
		})
	}
}

// An unconfigured recurrence reader (production default) fails closed: a recurrence
// notification is NOT silently acked as if handled.
func TestRecurrenceWebhookUnwiredFailsClosed(t *testing.T) {
	t.Parallel()
	f := newFixtureAuth(t, nil) // default fixture leaves RecReader/CobRReader nil
	rec := do(t, f.handler, http.MethodPost, "/webhooks/c6/"+webhookRef, "", nil, recBody("RN1", "rec", "APROVADA"))
	if rec.Code == http.StatusAccepted {
		t.Fatalf("unwired recurrence dispatch must not 202, got %d", rec.Code)
	}
}

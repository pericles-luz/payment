package c6

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// credsWithKey is a per-tenant store whose tenant carries a configured PIX
// creditor key (chave do recebedor), the production wiring the adapter injects
// when a request omits one (ADR-0004 / SIN-65862).
func credsWithKey(tenant, clientID, secret, creditorKey string) *fakeCreds {
	return &fakeCreds{creds: map[string]ports.BankCredential{
		tenant: {TenantID: tenant, ClientID: clientID, Secret: secret, CreditorKey: creditorKey},
	}}
}

// captureChargeChave overrides the cob create handler to record the BACEN "chave"
// the adapter PUT, then returns a minimal valid cob so CreateCharge succeeds.
func captureChargeChave(ts *testServer, got *string) {
	ts.createHandler = func(w http.ResponseWriter, r *http.Request) {
		var body pixChargeRequestBody
		_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
		*got = body.Chave
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"txid":"tx-cob","status":"ATIVA","valor":{"original":"10.00"}}`))
	}
}

// TestCreateChargeInjectsConfiguredCreditorKey: the generic cob create injects the
// tenant's configured chave when the request omits one (opção (a): no app surface
// carries the key).
func TestCreateChargeInjectsConfiguredCreditorKey(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t)
	var gotChave string
	captureChargeChave(ts, &gotChave)
	p := ts.provider(t, credsWithKey("t1", "c", "s", "tenant-config@pix.example"))

	if _, err := p.CreateCharge(context.Background(), "t1", ports.ChargeRequest{
		TenantID: "t1", PaymentID: "pay-1", AmountCents: 1000, Currency: "BRL",
		// CreditorKey intentionally empty: the client boundary never carries it.
	}); err != nil {
		t.Fatalf("CreateCharge: %v", err)
	}
	if gotChave != "tenant-config@pix.example" {
		t.Fatalf("configured chave not injected: %q", gotChave)
	}
}

// TestCreateChargeRequestKeyOverridesConfig: a non-empty per-request key (the
// optional port-level override) wins over the configured key.
func TestCreateChargeRequestKeyOverridesConfig(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t)
	var gotChave string
	captureChargeChave(ts, &gotChave)
	p := ts.provider(t, credsWithKey("t1", "c", "s", "tenant-config@pix.example"))

	if _, err := p.CreateCharge(context.Background(), "t1", ports.ChargeRequest{
		TenantID: "t1", PaymentID: "pay-1", AmountCents: 1000, Currency: "BRL",
		CreditorKey: "  override@pix.example  ",
	}); err != nil {
		t.Fatalf("CreateCharge: %v", err)
	}
	if gotChave != "override@pix.example" {
		t.Fatalf("request override not honored/trimmed: %q", gotChave)
	}
}

// TestCreateChargeBothEmptyOmitsChave: when neither the request nor the config
// supplies a key, the chave is omitted (the wire field is omitempty). Turning this
// into a fail-fast adapter-boundary error is gated on CTO rule-3 authorization to
// update the existing create-charge tests that omit a key (SIN-65862); this test
// pins the current, non-breaking behavior so that flip is a deliberate change.
func TestCreateChargeBothEmptyOmitsChave(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t)
	var gotChave string
	captureChargeChave(ts, &gotChave)
	p := ts.provider(t, oneTenant("t1", "c", "s")) // credential without a creditor key

	if _, err := p.CreateCharge(context.Background(), "t1", ports.ChargeRequest{
		TenantID: "t1", PaymentID: "pay-1", AmountCents: 1000, Currency: "BRL",
	}); err != nil {
		t.Fatalf("CreateCharge: %v", err)
	}
	if gotChave != "" {
		t.Fatalf("chave should be omitted when unconfigured, got %q", gotChave)
	}
}

// TestCreateImmediateChargeInjectsConfiguredCreditorKey: the immediate cob create
// path injects the configured chave the same way as the generic surface.
func TestCreateImmediateChargeInjectsConfiguredCreditorKey(t *testing.T) {
	t.Parallel()
	ts := newPixTestServer(t)
	p := ts.provider(t, credsWithKey("t1", "c", "s", "imm-config@pix.example"), nil)

	if _, err := p.CreateImmediateCharge(context.Background(), "t1", ports.ChargeRequest{
		TenantID: "t1", PaymentID: "pay-1", AmountCents: 1000,
	}, time.Hour); err != nil {
		t.Fatalf("CreateImmediateCharge: %v", err)
	}
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.lastReqBody.Chave != "imm-config@pix.example" {
		t.Fatalf("configured chave not injected on immediate cob: %q", ts.lastReqBody.Chave)
	}
}

// TestCreateDueChargeInjectsConfiguredCreditorKey: the cobv register path injects
// the configured chave when the request omits one.
func TestCreateDueChargeInjectsConfiguredCreditorKey(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	p := ps.provider(t, credsWithKey("t1", "c", "s", "cobv-config@pix.example"))

	req := cobvReq("t1")
	req.CreditorKey = "" // client boundary carries no key
	if _, err := p.CreateDueCharge(context.Background(), "t1", req); err != nil {
		t.Fatalf("CreateDueCharge: %v", err)
	}
	var sent cobvRequestBody
	if err := json.Unmarshal(ps.body(), &sent); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if sent.Chave != "cobv-config@pix.example" {
		t.Fatalf("configured chave not injected on cobv: %q", sent.Chave)
	}
}

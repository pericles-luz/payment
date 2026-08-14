package http_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/bank"
	httpadapter "github.com/ia-dev-sindireceita/payment/internal/adapters/http"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/messaging/inmemory"
	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/system"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// idemCtr hands out a unique idempotency key per charge so repeated posts in one
// test are not collapsed by idempotency into the first payment.
var idemCtr atomic.Int64

func nextKey() string { return "rk-" + strconv.FormatInt(idemCtr.Add(1), 10) }

// labelBank is a minimal BankProvider whose CreateCharge stamps the bank's label
// onto the result TxID, so an e2e test can read the POST /v1/charges response's
// tx_id to assert WHICH bank handled the request.
type labelBank struct{ label string }

func (b labelBank) CreateCharge(_ context.Context, _ string, _ ports.ChargeRequest) (ports.ChargeResult, error) {
	return ports.ChargeResult{TxID: b.label, Status: "pending"}, nil
}
func (b labelBank) GetCharge(_ context.Context, _ string, _ string) (ports.ChargeResult, error) {
	return ports.ChargeResult{TxID: b.label}, nil
}

// multiBankFixture wires a two-bank registry ("c6" + "itau") behind the charge
// service and a BankResolver, with the credential store seeded per the scenario.
type multiBankFixture struct {
	handler http.Handler
	tenant  string
}

// newMultiBankFixture seeds a tenant, prices pix.create, and configures the tenant's
// bank credentials for the banks named in configured. Both banks are always wired
// (have an adapter); only the listed ones get a tenant credential.
func newMultiBankFixture(t *testing.T, configured ...string) *multiBankFixture {
	t.Helper()
	store := persistence.NewStore()
	creds := secret.NewStore(nil)
	bus := inmemory.NewBus()

	reg := bank.NewRegistry()
	reg.Register("c6", bank.ProviderSet{Bank: labelBank{"c6"}})
	reg.Register("itau", bank.ProviderSet{Bank: labelBank{"itau"}})
	routers := bank.NewRouters(reg)

	deps := app.Deps{
		Payments:    store,
		Tenants:     store,
		Pricing:     store,
		Ledger:      store,
		Processed:   store,
		Bus:         bus,
		Bank:        routers.Bank,
		Credentials: creds,
		Clock:       system.Clock{},
		IDs:         system.IDProvider{},
	}
	admin := app.NewAdminService(deps)
	tn, err := admin.CreateTenant(context.Background(), "Acme")
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	if _, err := admin.SetEndpointPrice(context.Background(), tn.ID(), "pix.create", 50); err != nil {
		t.Fatalf("seed price: %v", err)
	}
	for _, b := range configured {
		if err := creds.SetBankCredential(context.Background(), tn.ID(), b, "cid-"+b, "secret"); err != nil {
			t.Fatalf("seed cred %s: %v", b, err)
		}
	}

	auth := httpadapter.NewStaticTokenAuth(map[string]string{tenantToken: tn.ID()}, []string{adminToken}, nil)
	srv := httpadapter.NewServer(httpadapter.Config{
		Charges:      app.NewChargeService(deps),
		Admin:        admin,
		TenantAuth:   auth,
		AdminAuth:    auth,
		BankResolver: httpadapter.NewBankResolver(reg.Banks(), creds),
	})
	return &multiBankFixture{handler: srv.Router(), tenant: tn.ID()}
}

// postCharge posts a charge with the given header + optional body bank field and
// returns the HTTP status and the response tx_id (the bank that handled it).
func postCharge(t *testing.T, f *multiBankFixture, headers map[string]string, bodyBank string) (int, string) {
	t.Helper()
	h := map[string]string{"Idempotency-Key": nextKey()}
	for k, v := range headers {
		h[k] = v
	}
	body := map[string]any{"endpoint": "pix.create", "amount_cents": 2500, "currency": "BRL"}
	if bodyBank != "" {
		body["bank"] = bodyBank
	}
	rec := do(t, f.handler, http.MethodPost, "/v1/charges", tenantToken, h, body)
	if rec.Code != http.StatusCreated {
		return rec.Code, ""
	}
	var pv struct {
		TxID string `json:"tx_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &pv); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return rec.Code, pv.TxID
}

// TestRoutingHeaderSelectsConfiguredBank: a tenant with ≥2 configured banks routes
// to the bank named in the X-Bank-Id header (acceptance criterion 1).
func TestRoutingHeaderSelectsConfiguredBank(t *testing.T) {
	f := newMultiBankFixture(t, "c6", "itau")
	if code, tx := postCharge(t, f, map[string]string{"X-Bank-Id": "itau"}, ""); code != http.StatusCreated || tx != "itau" {
		t.Fatalf("want 201 routed to itau, got code=%d tx=%q", code, tx)
	}
	if code, tx := postCharge(t, f, map[string]string{"X-Bank-Id": "c6"}, ""); code != http.StatusCreated || tx != "c6" {
		t.Fatalf("want 201 routed to c6, got code=%d tx=%q", code, tx)
	}
}

// TestRoutingBodyFieldOverridesHeader: the DTO `bank` field is the canonical write
// selector and overrides the header (ADR-0007 / SIN-66022).
func TestRoutingBodyFieldOverridesHeader(t *testing.T) {
	f := newMultiBankFixture(t, "c6", "itau")
	if code, tx := postCharge(t, f, map[string]string{"X-Bank-Id": "c6"}, "itau"); code != http.StatusCreated || tx != "itau" {
		t.Fatalf("want body field itau to win over header c6, got code=%d tx=%q", code, tx)
	}
}

// TestRoutingRejectsUnconfiguredBank: a bank not configured for the tenant (even if
// wired) is rejected with the uniform not-found, leaking no existence signal
// (acceptance criterion 2; confused-deputy / no-oracle).
func TestRoutingRejectsUnconfiguredBank(t *testing.T) {
	f := newMultiBankFixture(t, "c6") // itau is wired but NOT configured for this tenant
	if code, _ := postCharge(t, f, map[string]string{"X-Bank-Id": "itau"}, ""); code != http.StatusNotFound {
		t.Fatalf("want 404 for an unconfigured bank, got %d", code)
	}
	// A bank with no wired adapter at all is the SAME 404 (no distinction).
	if code, _ := postCharge(t, f, map[string]string{"X-Bank-Id": "bb"}, ""); code != http.StatusNotFound {
		t.Fatalf("want 404 for an unwired bank, got %d", code)
	}
	// A control-char-bearing slug (NUL/key-injection attempt) is rejected the same way.
	if code, _ := postCharge(t, f, map[string]string{"X-Bank-Id": "c6\x00evil"}, ""); code != http.StatusNotFound {
		t.Fatalf("want 404 for a control-char slug, got %d", code)
	}
	// The same deny-by-default applies to the body `bank` field selector (the rebind
	// path), not just the header.
	if code, _ := postCharge(t, f, nil, "itau"); code != http.StatusNotFound {
		t.Fatalf("want 404 for an unconfigured body bank field, got %d", code)
	}
}

// TestRoutingSingleBankDefault: a tenant configured for exactly one bank, with no
// selector, routes to that bank — retro-compatible default (acceptance criterion 3).
func TestRoutingSingleBankDefault(t *testing.T) {
	f := newMultiBankFixture(t, "itau") // only itau configured
	if code, tx := postCharge(t, f, nil, ""); code != http.StatusCreated || tx != "itau" {
		t.Fatalf("want default routing to the single configured bank itau, got code=%d tx=%q", code, tx)
	}
}

// TestRoutingMultiBankDefaultFallsBackToC6: a tenant with >1 configured bank and no
// selector falls back to the default bank c6 (no ambiguous guess).
func TestRoutingMultiBankDefaultFallsBackToC6(t *testing.T) {
	f := newMultiBankFixture(t, "c6", "itau")
	if code, tx := postCharge(t, f, nil, ""); code != http.StatusCreated || tx != "c6" {
		t.Fatalf("want default fallback to c6, got code=%d tx=%q", code, tx)
	}
}

// --- BankResolver unit tests (no-oracle, tenant isolation, normalization) ---

func TestBankResolverExplicitSelector(t *testing.T) {
	creds := secret.NewStore(nil)
	_ = creds.SetBankCredential(context.Background(), "t-a", "c6", "c", "s")
	_ = creds.SetBankCredential(context.Background(), "t-a", "itau", "c", "s")
	r := httpadapter.NewBankResolver([]string{"c6", "itau"}, creds)

	cases := []struct {
		name, tenant, requested, want string
		wantErr                       bool
	}{
		{"configured itau", "t-a", "itau", "itau", false},
		{"case-insensitive", "t-a", "ITAU", "itau", false},
		{"unwired bank", "t-a", "bb", "", true},
		{"wired but unconfigured for tenant", "t-b", "itau", "", true},
		{"nul char", "t-a", "c6\x00x", "", true},
	}
	for _, c := range cases {
		got, err := r.Resolve(context.Background(), c.tenant, c.requested)
		if c.wantErr {
			if err == nil {
				t.Errorf("%s: want error, got %q", c.name, got)
			} else if !errors.Is(err, shared.ErrNotFound) {
				t.Errorf("%s: want not-found error (no oracle), got %v", c.name, err)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%s: got (%q,%v) want %q", c.name, got, err, c.want)
		}
	}
}

func TestBankResolverDefaultSelector(t *testing.T) {
	creds := secret.NewStore(nil)
	_ = creds.SetBankCredential(context.Background(), "single", "itau", "c", "s")
	_ = creds.SetBankCredential(context.Background(), "multi", "c6", "c", "s")
	_ = creds.SetBankCredential(context.Background(), "multi", "itau", "c", "s")
	r := httpadapter.NewBankResolver([]string{"c6", "itau"}, creds)

	if got, _ := r.Resolve(context.Background(), "single", ""); got != "itau" {
		t.Fatalf("single-bank tenant default: want itau, got %q", got)
	}
	if got, _ := r.Resolve(context.Background(), "multi", ""); got != ports.BankIDC6 {
		t.Fatalf("multi-bank tenant default: want c6 fallback, got %q", got)
	}
	if got, _ := r.Resolve(context.Background(), "none", ""); got != ports.BankIDC6 {
		t.Fatalf("no-cred tenant default: want c6 fallback, got %q", got)
	}
}

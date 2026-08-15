package http_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	httpadapter "github.com/ia-dev-sindireceita/payment/internal/adapters/http"
	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/system"
	"github.com/ia-dev-sindireceita/payment/internal/app"
)

// clientFixture wires a server with the model (b) empresa-cliente provisioning
// surface enabled: a REAL in-memory account-key store backs the authenticator (so a
// seeded key really authenticates as its Account) and a REAL in-memory tenant store
// backs the provisioning service (no DB mock — rule 5), so a create actually
// persists and can be read back.
type clientFixture struct {
	handler   http.Handler
	tenants   *persistence.Store
	seededKey string // plaintext account-key for acctSeeded
}

const clientsPath = "/v1/clients"

// newClientFixtureFlag builds the fixture with the model (b) flag as given and the
// provisioner optionally wired (to exercise the fail-closed 503 when it is nil).
func newClientFixtureFlag(t *testing.T, flagOn, provisionerWired bool) *clientFixture {
	t.Helper()
	keys := persistence.NewAccountKeyStore(system.Clock{})
	seeded, err := keys.PutKey(context.Background(), acctSeeded)
	if err != nil {
		t.Fatalf("seed key: %v", err)
	}
	tenants := persistence.NewStore()
	auth := httpadapter.NewStaticTokenAuth(
		map[string]string{akTenantToken: "emp-x"},
		[]string{akAdminToken}, nil)
	cfg := httpadapter.Config{
		TenantAuth:         auth,
		AdminAuth:          auth,
		WebhookAuth:        auth,
		AccountKeyAuth:     keys,
		AccountKeySelector: flagOn,
	}
	if provisionerWired {
		cfg.ClientProvisioner = app.NewClientProvisioningService(tenants, system.IDProvider{}, system.Clock{})
	}
	srv := httpadapter.NewServer(cfg)
	return &clientFixture{handler: srv.Router(), tenants: tenants, seededKey: seeded}
}

func newClientFixture(t *testing.T) *clientFixture { return newClientFixtureFlag(t, true, true) }

// clientResponse mirrors the /v1/clients success body.
type clientResponse struct {
	TenantID  string `json:"tenant_id"`
	AccountID string `json:"account_id"`
	Name      string `json:"name"`
}

// TestProvisionClientHappyPath: a Conta creates an empresa-cliente with its
// account-key. It gets 201 + a tenant_id, the account_id echoes the KEY's Account
// (not any body input), and the tenant is really persisted under that Account.
func TestProvisionClientHappyPath(t *testing.T) {
	t.Parallel()
	f := newClientFixture(t)

	rec := do(t, f.handler, http.MethodPost, clientsPath, f.seededKey,
		map[string]string{"Idempotency-Key": "cli-1"}, map[string]string{"name": "Loja X"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d (%s)", rec.Code, rec.Body.String())
	}
	var v clientResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if v.TenantID == "" || v.AccountID != acctSeeded || v.Name != "Loja X" {
		t.Fatalf("unexpected view: %+v", v)
	}
	got, err := f.tenants.FindTenantByID(context.Background(), v.TenantID)
	if err != nil {
		t.Fatalf("persisted tenant not found: %v", err)
	}
	if got.AccountID() != acctSeeded {
		t.Fatalf("persisted account = %q, want %q", got.AccountID(), acctSeeded)
	}
}

// TestProvisionClientNoBodyDefaultsName: the body is optional — with no body the
// empresa-cliente is still created (name defaults) and bound to the key's Account.
func TestProvisionClientNoBodyDefaultsName(t *testing.T) {
	t.Parallel()
	f := newClientFixture(t)

	rec := do(t, f.handler, http.MethodPost, clientsPath, f.seededKey,
		map[string]string{"Idempotency-Key": "cli-1"}, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d (%s)", rec.Code, rec.Body.String())
	}
	var v clientResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if v.TenantID == "" || v.AccountID != acctSeeded || v.Name == "" {
		t.Fatalf("unexpected view: %+v", v)
	}
}

// TestProvisionClientRejectsAccountIDInBody is the T6 boundary regression: a body
// that tries to smuggle an account_id is rejected (400, unknown field) and NO tenant
// is created — a Conta can never steer the binding to another Account via the body.
func TestProvisionClientRejectsAccountIDInBody(t *testing.T) {
	t.Parallel()
	f := newClientFixture(t)

	rec := do(t, f.handler, http.MethodPost, clientsPath, f.seededKey,
		map[string]string{"Idempotency-Key": "cli-1"},
		map[string]string{"name": "Loja X", "account_id": "acct-EVIL"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for account_id in body, got %d (%s)", rec.Code, rec.Body.String())
	}
	// Nothing was created — no tenant under the caller's Account nor the attacker's.
	all, err := f.tenants.ListTenants(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 0 {
		t.Fatalf("a tenant was created despite the rejected body: %d", len(all))
	}
}

// TestProvisionClientMissingIdempotencyKey → 400.
func TestProvisionClientMissingIdempotencyKey(t *testing.T) {
	t.Parallel()
	f := newClientFixture(t)
	rec := do(t, f.handler, http.MethodPost, clientsPath, f.seededKey, nil,
		map[string]string{"name": "Loja X"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d (%s)", rec.Code, rec.Body.String())
	}
}

// TestProvisionClientUnauthorized: a missing bearer, a tenant token (no ak_ shape)
// and an unknown ak_ key are all rejected with the uniform 401 (no oracle,
// deny-by-default).
func TestProvisionClientUnauthorized(t *testing.T) {
	t.Parallel()
	f := newClientFixture(t)
	cases := []struct{ name, bearer string }{
		{"no bearer", ""},
		{"tenant token (no ak_ shape)", akTenantToken},
		{"unknown ak_ key", "ak_not_a_real_key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := do(t, f.handler, http.MethodPost, clientsPath, tc.bearer,
				map[string]string{"Idempotency-Key": "cli-x"}, map[string]string{"name": "x"})
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("want 401, got %d (%s)", rec.Code, rec.Body.String())
			}
		})
	}
}

// TestProvisionClientReplayReturnsSameTenant: a retry under the SAME Idempotency-Key
// returns the SAME empresa-cliente (201) and does NOT create a duplicate.
func TestProvisionClientReplayReturnsSameTenant(t *testing.T) {
	t.Parallel()
	f := newClientFixture(t)

	first := do(t, f.handler, http.MethodPost, clientsPath, f.seededKey,
		map[string]string{"Idempotency-Key": "cli-1"}, map[string]string{"name": "Loja X"})
	if first.Code != http.StatusCreated {
		t.Fatalf("first: want 201, got %d", first.Code)
	}
	var a clientResponse
	_ = json.Unmarshal(first.Body.Bytes(), &a)

	replay := do(t, f.handler, http.MethodPost, clientsPath, f.seededKey,
		map[string]string{"Idempotency-Key": "cli-1"}, map[string]string{"name": "Loja Y"})
	if replay.Code != http.StatusCreated {
		t.Fatalf("replay: want 201, got %d (%s)", replay.Code, replay.Body.String())
	}
	var b clientResponse
	_ = json.Unmarshal(replay.Body.Bytes(), &b)
	if b.TenantID != a.TenantID {
		t.Fatalf("replay tenant_id = %q, want same as first %q", b.TenantID, a.TenantID)
	}
	all, err := f.tenants.ListTenants(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("persisted %d tenants, want 1 (replay must not duplicate)", len(all))
	}
}

// TestProvisionClientRouteAbsentWhenFlagOff: with model (b) off the /v1/clients
// route does not exist (rollback = config flip). A valid account-key gets a
// route-absent response, not a provisioning.
func TestProvisionClientRouteAbsentWhenFlagOff(t *testing.T) {
	t.Parallel()
	f := newClientFixtureFlag(t, false, true)
	rec := do(t, f.handler, http.MethodPost, clientsPath, f.seededKey,
		map[string]string{"Idempotency-Key": "cli-1"}, map[string]string{"name": "x"})
	if rec.Code == http.StatusCreated {
		t.Fatalf("route should not provision when the flag is off, got %d", rec.Code)
	}
	if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want route-absent (404/405), got %d (%s)", rec.Code, rec.Body.String())
	}
	all, _ := f.tenants.ListTenants(context.Background())
	if len(all) != 0 {
		t.Fatalf("a tenant was provisioned despite the flag being off: %d", len(all))
	}
}

// TestProvisionClientFailsClosedWithoutProvisioner: the route is gated by the flag,
// but with no provisioner wired it fails closed (503) rather than panicking.
func TestProvisionClientFailsClosedWithoutProvisioner(t *testing.T) {
	t.Parallel()
	f := newClientFixtureFlag(t, true, false) // flag on, ClientProvisioner nil
	rec := do(t, f.handler, http.MethodPost, clientsPath, f.seededKey,
		map[string]string{"Idempotency-Key": "cli-1"}, map[string]string{"name": "x"})
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503 without a wired provisioner, got %d (%s)", rec.Code, rec.Body.String())
	}
}

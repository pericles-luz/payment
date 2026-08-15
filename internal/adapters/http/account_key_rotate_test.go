package http_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	httpadapter "github.com/ia-dev-sindireceita/payment/internal/adapters/http"
	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/system"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/accountkey"
)

// akFixture wires a server with the model (b) account-key emission surface enabled:
// a REAL in-memory account-key store (no DB mock) backs both the authenticator and
// the mint service, so a rotation actually invalidates the old key and the new key
// really authenticates. It seeds one existing key for acctSeeded so the self-rotate
// route has a live credential to present.
type akFixture struct {
	handler   http.Handler
	keys      *persistence.AccountKeyStore
	seededKey string // the plaintext of the pre-provisioned key for acctSeeded
}

const (
	akAdminToken  = "ak-admin-tok"
	akTenantToken = "ak-tenant-tok"
	acctSeeded    = "acct-seeded"
)

// newAKFixtureFlag builds the fixture with the model (b) flag set as given, so the
// same wiring covers the enabled behaviour and the flag-off inert case. mintWired
// toggles whether the AccountKeyMint service is supplied (to exercise the admin
// route's fail-closed 503 when it is nil).
func newAKFixtureFlag(t *testing.T, flagOn, mintWired bool) *akFixture {
	t.Helper()
	keys := persistence.NewAccountKeyStore(system.Clock{})
	// Seed the Account's first key out-of-band (as the admin bootstrap would), so the
	// self-rotate route can authenticate with it.
	seeded, err := keys.PutKey(context.Background(), acctSeeded)
	if err != nil {
		t.Fatalf("seed key: %v", err)
	}
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
	if mintWired {
		cfg.AccountKeyMint = app.NewAccountKeyService(keys, system.Clock{})
	}
	srv := httpadapter.NewServer(cfg)
	return &akFixture{handler: srv.Router(), keys: keys, seededKey: seeded}
}

func newAKFixture(t *testing.T) *akFixture { return newAKFixtureFlag(t, true, true) }

const (
	akRotatePath = "/v1/account-key"
)

// decodeMintView unmarshals the mint response shape used by both routes.
type mintView struct {
	AccountID string `json:"account_id"`
	Secret    string `json:"secret"`
	Status    string `json:"status"`
}

// TestSelfRotateHappyPath: an Account rotates its OWN key with its existing key. It
// gets 201 + a fresh ak_ secret that authenticates, and the OLD key stops working
// (rotate invalidates the previous key immediately).
func TestSelfRotateHappyPath(t *testing.T) {
	t.Parallel()
	f := newAKFixture(t)

	rec := do(t, f.handler, http.MethodPost, akRotatePath, f.seededKey,
		map[string]string{"Idempotency-Key": "idem-1"}, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d (%s)", rec.Code, rec.Body.String())
	}
	var v mintView
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if v.AccountID != acctSeeded || v.Status != "created" || !accountkey.HasSecretShape(v.Secret) {
		t.Fatalf("unexpected view: %+v", v)
	}
	// The new secret authenticates; the old one no longer does.
	if acct, ok := f.keys.AuthenticateAccountKey(context.Background(), v.Secret); !ok || acct != acctSeeded {
		t.Fatalf("new key does not authenticate: acct=%q ok=%v", acct, ok)
	}
	if _, ok := f.keys.AuthenticateAccountKey(context.Background(), f.seededKey); ok {
		t.Fatalf("old key still authenticates after rotation")
	}
}

// TestSelfRotateReplayIs409: a retried rotation under the SAME Idempotency-Key is
// collapsed to 409 with NO secret in the body (display-once, never returned twice),
// and the key minted by the first call still authenticates (no double-mint).
func TestSelfRotateReplayIs409(t *testing.T) {
	t.Parallel()
	f := newAKFixture(t)

	first := do(t, f.handler, http.MethodPost, akRotatePath, f.seededKey,
		map[string]string{"Idempotency-Key": "idem-1"}, nil)
	if first.Code != http.StatusCreated {
		t.Fatalf("first rotate: want 201, got %d", first.Code)
	}
	var v mintView
	_ = json.Unmarshal(first.Body.Bytes(), &v)

	// Re-present the ORIGINAL key (still valid because the first mint's new key is the
	// live one; the seeded key was invalidated). We authenticate with v.Secret's owner
	// via the new key to reach the handler, then replay the same Idempotency-Key.
	replay := do(t, f.handler, http.MethodPost, akRotatePath, v.Secret,
		map[string]string{"Idempotency-Key": "idem-1"}, nil)
	if replay.Code != http.StatusConflict {
		t.Fatalf("replay: want 409, got %d (%s)", replay.Code, replay.Body.String())
	}
	if strings.Contains(replay.Body.String(), v.Secret) || strings.Contains(replay.Body.String(), "ak_") {
		t.Fatalf("409 body leaked a secret: %s", replay.Body.String())
	}
	// No double-mint: the first-call key still authenticates.
	if acct, ok := f.keys.AuthenticateAccountKey(context.Background(), v.Secret); !ok || acct != acctSeeded {
		t.Fatalf("first-call key stopped working after replay: acct=%q ok=%v", acct, ok)
	}
}

// TestSelfRotateMissingIdempotencyKey → 400.
func TestSelfRotateMissingIdempotencyKey(t *testing.T) {
	t.Parallel()
	f := newAKFixture(t)
	rec := do(t, f.handler, http.MethodPost, akRotatePath, f.seededKey, nil, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d (%s)", rec.Code, rec.Body.String())
	}
}

// TestSelfRotateUnauthorized: a non-account-key bearer and an unknown ak_ key are
// both rejected with the uniform 401 (no oracle).
func TestSelfRotateUnauthorized(t *testing.T) {
	t.Parallel()
	f := newAKFixture(t)
	cases := []struct {
		name   string
		bearer string
	}{
		{"no bearer", ""},
		{"tenant token (no ak_ shape)", akTenantToken},
		{"unknown ak_ key", "ak_not_a_real_key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := do(t, f.handler, http.MethodPost, akRotatePath, tc.bearer,
				map[string]string{"Idempotency-Key": "idem-x"}, nil)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("want 401, got %d (%s)", rec.Code, rec.Body.String())
			}
		})
	}
}

// TestSelfRotateRouteAbsentWhenFlagOff: with model (b) off, the /v1/account-key
// route does not exist at all (rollback = config flip). A valid account-key bearer
// gets a 404-class response, not a rotation.
func TestSelfRotateRouteAbsentWhenFlagOff(t *testing.T) {
	t.Parallel()
	f := newAKFixtureFlag(t, false, true)
	rec := do(t, f.handler, http.MethodPost, akRotatePath, f.seededKey,
		map[string]string{"Idempotency-Key": "idem-1"}, nil)
	if rec.Code == http.StatusCreated {
		t.Fatalf("route should not mint when the flag is off, got %d", rec.Code)
	}
	if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want route-absent (404/405), got %d (%s)", rec.Code, rec.Body.String())
	}
	// The seeded key is untouched (no rotation happened).
	if _, ok := f.keys.AuthenticateAccountKey(context.Background(), f.seededKey); !ok {
		t.Fatalf("seeded key was invalidated despite the flag being off")
	}
}

// --- admin bootstrap route ---

func adminMintPath(accountID string) string { return "/admin/accounts/" + accountID + "/account-key" }

// TestAdminBootstrapHappyPath: an admin mints the FIRST key for a fresh Account; the
// returned secret authenticates as that account.
func TestAdminBootstrapHappyPath(t *testing.T) {
	t.Parallel()
	f := newAKFixture(t)
	rec := do(t, f.handler, http.MethodPost, adminMintPath("acct-verz"), akAdminToken,
		map[string]string{"Idempotency-Key": "boot-1"}, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d (%s)", rec.Code, rec.Body.String())
	}
	var v mintView
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if v.AccountID != "acct-verz" || !accountkey.HasSecretShape(v.Secret) {
		t.Fatalf("unexpected view: %+v", v)
	}
	if acct, ok := f.keys.AuthenticateAccountKey(context.Background(), v.Secret); !ok || acct != "acct-verz" {
		t.Fatalf("bootstrapped key does not authenticate: acct=%q ok=%v", acct, ok)
	}
}

// TestAdminBootstrapRequiresAdmin: a tenant token (no admin role) is denied; the
// bootstrap surface is admin-only (deny-by-default).
func TestAdminBootstrapRequiresAdmin(t *testing.T) {
	t.Parallel()
	f := newAKFixture(t)
	rec := do(t, f.handler, http.MethodPost, adminMintPath("acct-verz"), akTenantToken,
		map[string]string{"Idempotency-Key": "boot-1"}, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 for a non-admin token, got %d (%s)", rec.Code, rec.Body.String())
	}
}

// TestAdminBootstrapMissingIdempotencyKey → 400.
func TestAdminBootstrapMissingIdempotencyKey(t *testing.T) {
	t.Parallel()
	f := newAKFixture(t)
	rec := do(t, f.handler, http.MethodPost, adminMintPath("acct-verz"), akAdminToken, nil, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d (%s)", rec.Code, rec.Body.String())
	}
}

// TestAdminBootstrapBlankAccountID: a whitespace-only account id in the path is
// rejected at the boundary (400) without reaching the minter — no echo of input.
func TestAdminBootstrapBlankAccountID(t *testing.T) {
	t.Parallel()
	f := newAKFixture(t)
	rec := do(t, f.handler, http.MethodPost, adminMintPath("%20"), akAdminToken,
		map[string]string{"Idempotency-Key": "boot-1"}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for a blank account id, got %d (%s)", rec.Code, rec.Body.String())
	}
}

// TestAdminBootstrapFailsClosedWithoutMinter: the admin route is always registered,
// but with no mint service wired it fails closed (503) rather than panicking.
func TestAdminBootstrapFailsClosedWithoutMinter(t *testing.T) {
	t.Parallel()
	f := newAKFixtureFlag(t, true, false) // flag on, but AccountKeyMint nil
	rec := do(t, f.handler, http.MethodPost, adminMintPath("acct-verz"), akAdminToken,
		map[string]string{"Idempotency-Key": "boot-1"}, nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503 without a wired minter, got %d (%s)", rec.Code, rec.Body.String())
	}
}

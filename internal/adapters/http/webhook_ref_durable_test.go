package http_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	httpadapter "github.com/ia-dev-sindireceita/payment/internal/adapters/http"
	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/system"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/webhookref"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// countingRefStore records how many times LookupWebhookRef is called so a test can
// prove a malformed ref is rejected BEFORE the store is consulted.
type countingRefStore struct {
	tenantID string
	found    bool
	calls    int
}

func (c *countingRefStore) PutWebhookRef(context.Context, []byte, string) error { return nil }
func (c *countingRefStore) LookupWebhookRef(_ context.Context, _ []byte) (string, bool, error) {
	c.calls++
	return c.tenantID, c.found, nil
}

// erroringRefStore models an infrastructure fault on lookup.
type erroringRefStore struct{}

func (erroringRefStore) PutWebhookRef(context.Context, []byte, string) error { return nil }
func (erroringRefStore) LookupWebhookRef(context.Context, []byte) (string, bool, error) {
	return "", false, errors.New("db down")
}

// TestWebhookAuthDurableFallbackAfterRestart is the F1 acceptance: a ref persisted in
// the durable store authenticates to its tenant even when the bootstrap map is EMPTY —
// i.e. after a restart that reads NO PAYMENT_WEBHOOK_REFS env, reconstructing the auth
// from the DB alone.
func TestWebhookAuthDurableFallbackAfterRestart(t *testing.T) {
	t.Parallel()
	store := persistence.NewWebhookRefStore()
	ref, _ := webhookref.Generate()
	sum := webhookref.Sum(ref)
	if err := store.PutWebhookRef(context.Background(), sum[:], "emp-42"); err != nil {
		t.Fatalf("seed store: %v", err)
	}

	// Fresh authenticator, EMPTY bootstrap map — only the durable store is wired.
	auth := httpadapter.NewStaticTokenAuthWithRoles(nil, nil, nil).WithWebhookRefStore(store)

	id, ok := auth.AuthenticateWebhookCtx(context.Background(), ref)
	if !ok || id.TenantID != "emp-42" {
		t.Fatalf("durable-only auth = (%+v, %v), want (emp-42, true)", id, ok)
	}
	// The legacy context-free method delegates to the same path.
	if id2, ok2 := auth.AuthenticateWebhook(ref); !ok2 || id2.TenantID != "emp-42" {
		t.Fatalf("AuthenticateWebhook delegation = (%+v, %v)", id2, ok2)
	}
}

// TestWebhookAuthMalformedRefSkipsStore proves the structural gate runs BEFORE the
// store: a malformed ref denies without ever consulting the durable store (no
// path-traversal reaches persistence, no oracle).
func TestWebhookAuthMalformedRefSkipsStore(t *testing.T) {
	t.Parallel()
	spy := &countingRefStore{tenantID: "emp-42", found: true}
	auth := httpadapter.NewStaticTokenAuthWithRoles(nil, nil, nil).WithWebhookRefStore(spy)

	for _, bad := range []string{"", "../secret", strings.Repeat("A", 42), strings.Repeat("A", 44)} {
		if _, ok := auth.AuthenticateWebhookCtx(context.Background(), bad); ok {
			t.Fatalf("malformed ref %q must not authenticate", bad)
		}
	}
	if spy.calls != 0 {
		t.Fatalf("store consulted %d times for malformed refs, want 0", spy.calls)
	}
}

// TestWebhookAuthUnknownRefIsNonOracle proves a well-formed but unregistered ref denies
// identically to any miss (store returns not-found).
func TestWebhookAuthUnknownRefIsNonOracle(t *testing.T) {
	t.Parallel()
	spy := &countingRefStore{found: false}
	auth := httpadapter.NewStaticTokenAuthWithRoles(nil, nil, nil).WithWebhookRefStore(spy)
	ref, _ := webhookref.Generate()
	if _, ok := auth.AuthenticateWebhookCtx(context.Background(), ref); ok {
		t.Fatal("unregistered ref must not authenticate")
	}
	if spy.calls != 1 {
		t.Fatalf("store consulted %d times, want 1 (well-formed miss reaches the store)", spy.calls)
	}
}

// TestWebhookAuthStoreErrorFailsClosed proves an infrastructure fault denies (fail
// closed) rather than authenticating — and is indistinguishable from a miss.
func TestWebhookAuthStoreErrorFailsClosed(t *testing.T) {
	t.Parallel()
	auth := httpadapter.NewStaticTokenAuthWithRoles(nil, nil, nil).WithWebhookRefStore(erroringRefStore{})
	ref, _ := webhookref.Generate()
	if _, ok := auth.AuthenticateWebhookCtx(context.Background(), ref); ok {
		t.Fatal("a store read error must fail closed (deny)")
	}
}

// TestWebhookAuthBootstrapMapTakesPrecedence proves retrocompat: a ref in the env
// bootstrap map resolves WITHOUT consulting the store (the store is only a fallback on
// a map miss), and the bootstrap ClientID is preserved for the body cross-check.
func TestWebhookAuthBootstrapMapTakesPrecedence(t *testing.T) {
	t.Parallel()
	bootRef := strings.Repeat("A", 43)
	spy := &countingRefStore{tenantID: "emp-store", found: true}
	auth := httpadapter.NewStaticTokenAuthWithRoles(nil, nil, map[string]httpadapter.WebhookIdentity{
		bootRef: {TenantID: "emp-boot", ClientID: "c6-client"},
	}).WithWebhookRefStore(spy)

	id, ok := auth.AuthenticateWebhookCtx(context.Background(), bootRef)
	if !ok || id.TenantID != "emp-boot" || id.ClientID != "c6-client" {
		t.Fatalf("bootstrap map miss: got (%+v, %v)", id, ok)
	}
	if spy.calls != 0 {
		t.Fatalf("store consulted %d times for a bootstrap-map hit, want 0", spy.calls)
	}
}

// TestWebhookAuthNoStoreIsEnvOnly proves the retrocompat default: with no store wired a
// ref absent from the bootstrap map denies (previous env-only behaviour, unchanged).
func TestWebhookAuthNoStoreIsEnvOnly(t *testing.T) {
	t.Parallel()
	auth := httpadapter.NewStaticTokenAuthWithRoles(nil, nil, nil)
	ref, _ := webhookref.Generate()
	if _, ok := auth.AuthenticateWebhookCtx(context.Background(), ref); ok {
		t.Fatal("with no store and empty bootstrap, every ref must deny")
	}
}

// clientWebhookResponse mirrors the /v1/clients body including the F1 webhook fields.
type clientWebhookResponse struct {
	TenantID    string `json:"tenant_id"`
	AccountID   string `json:"account_id"`
	Name        string `json:"name"`
	WebhookRef  string `json:"webhook_ref"`
	WebhookPath string `json:"webhook_path"`
}

// TestProvisionClientReturnsDurableWebhookRef is the end-to-end F1 acceptance at the
// handler: POST /v1/clients mints a durable ref (display-once in the body), and that
// SAME ref — read back from the store as if after a restart — authenticates to the new
// tenant. An idempotent replay omits the ref (display-once).
func TestProvisionClientReturnsDurableWebhookRef(t *testing.T) {
	t.Parallel()
	keys := persistence.NewAccountKeyStore(system.Clock{})
	seeded, err := keys.PutKey(context.Background(), acctSeeded)
	if err != nil {
		t.Fatalf("seed key: %v", err)
	}
	tenants := persistence.NewStore()
	refStore := persistence.NewWebhookRefStore()
	auth := httpadapter.NewStaticTokenAuth(nil, nil, nil).WithWebhookRefStore(refStore)
	srv := httpadapter.NewServer(httpadapter.Config{
		TenantAuth:         auth,
		AdminAuth:          auth,
		WebhookAuth:        auth,
		AccountKeyAuth:     keys,
		AccountKeySelector: true,
		ClientProvisioner: app.NewClientProvisioningService(tenants, system.IDProvider{}, system.Clock{}).
			WithWebhookRefMinter(app.NewWebhookRefMintService(refStore)),
	})
	handler := srv.Router()

	rec := do(t, handler, http.MethodPost, clientsPath, seeded,
		map[string]string{"Idempotency-Key": "cli-1"}, map[string]string{"name": "Loja X"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d (%s)", rec.Code, rec.Body.String())
	}
	var v clientWebhookResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !webhookref.Valid(v.WebhookRef) {
		t.Fatalf("response webhook_ref not well-formed: %q", v.WebhookRef)
	}
	if v.WebhookPath != "/webhooks/c6/"+v.WebhookRef {
		t.Fatalf("webhook_path = %q, want /webhooks/c6/<ref>", v.WebhookPath)
	}
	// Durable: the minted ref authenticates to the new tenant via a fresh authenticator
	// over the same store (simulating a restart that lost the env).
	fresh := httpadapter.NewStaticTokenAuth(nil, nil, nil).WithWebhookRefStore(refStore)
	id, ok := fresh.AuthenticateWebhook(v.WebhookRef)
	if !ok || id.TenantID != v.TenantID {
		t.Fatalf("minted ref auth = (%+v, %v), want tenant %s", id, ok, v.TenantID)
	}

	// Idempotent replay: same client, NO ref re-shown.
	rec2 := do(t, handler, http.MethodPost, clientsPath, seeded,
		map[string]string{"Idempotency-Key": "cli-1"}, map[string]string{"name": "Loja X"})
	if rec2.Code != http.StatusCreated {
		t.Fatalf("replay want 201, got %d", rec2.Code)
	}
	var v2 clientWebhookResponse
	if err := json.Unmarshal(rec2.Body.Bytes(), &v2); err != nil {
		t.Fatalf("decode replay: %v", err)
	}
	if v2.TenantID != v.TenantID {
		t.Fatalf("replay tenant = %s, want %s", v2.TenantID, v.TenantID)
	}
	if v2.WebhookRef != "" {
		t.Fatalf("replay must omit webhook_ref (display-once), got %q", v2.WebhookRef)
	}
}

// TestWebhookAuthDurablePathPopulatesClientID is the B4 acceptance (SIN-69585): when a
// cred store is wired, the durable-store resolution populates ClientID so the handler's
// body cross-check (defense-in-depth item 3) is preserved for refs resolved from the DB.
func TestWebhookAuthDurablePathPopulatesClientID(t *testing.T) {
	t.Parallel()
	store := persistence.NewWebhookRefStore()
	ref, _ := webhookref.Generate()
	sum := webhookref.Sum(ref)
	if err := store.PutWebhookRef(context.Background(), sum[:], "emp-b4"); err != nil {
		t.Fatalf("seed store: %v", err)
	}

	// Seed the credential store with a known ClientID.
	credStore := secret.NewStore(map[string]ports.BankCredential{
		"emp-b4": {TenantID: "emp-b4", BankID: ports.BankIDC6, ClientID: "c6-client-b4", Secret: "s"},
	})

	auth := httpadapter.NewStaticTokenAuthWithRoles(nil, nil, nil).
		WithWebhookRefStore(store).
		WithCredentialStore(credStore)

	id, ok := auth.AuthenticateWebhookCtx(context.Background(), ref)
	if !ok {
		t.Fatal("durable ref must authenticate")
	}
	if id.TenantID != "emp-b4" {
		t.Fatalf("tenant = %q, want emp-b4", id.TenantID)
	}
	if id.ClientID != "c6-client-b4" {
		t.Fatalf("ClientID = %q, want c6-client-b4 (B4 cross-check restored)", id.ClientID)
	}
}

// TestWebhookAuthDurablePathClientIDMissIsOK proves the cross-check is skipped (not
// errored) when the credential store has no entry for the tenant — the channel ref is
// always the authoritative gate (B4 best-effort contract).
func TestWebhookAuthDurablePathClientIDMissIsOK(t *testing.T) {
	t.Parallel()
	store := persistence.NewWebhookRefStore()
	ref, _ := webhookref.Generate()
	sum := webhookref.Sum(ref)
	if err := store.PutWebhookRef(context.Background(), sum[:], "emp-nocred"); err != nil {
		t.Fatalf("seed store: %v", err)
	}
	// Cred store has NO entry for emp-nocred → GetBankCredential returns ErrNotFound.
	auth := httpadapter.NewStaticTokenAuthWithRoles(nil, nil, nil).
		WithWebhookRefStore(store).
		WithCredentialStore(secret.NewStore(nil))

	id, ok := auth.AuthenticateWebhookCtx(context.Background(), ref)
	if !ok || id.TenantID != "emp-nocred" {
		t.Fatalf("must still authenticate; got (%+v, %v)", id, ok)
	}
	if id.ClientID != "" {
		t.Fatalf("ClientID should be empty on a miss, got %q", id.ClientID)
	}
}

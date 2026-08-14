package app_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/system"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// recordingWriter is a CredentialWriter that records its last call and returns a
// configurable error. Used to assert the use-case never leaks the secret into a
// returned error.
type recordingWriter struct {
	gotTenant, gotBank, gotClient, gotSecret string
	called                                   bool
	err                                      error
}

func (w *recordingWriter) SetBankCredential(_ context.Context, tenantID, bankID, clientID, secret string) error {
	w.called = true
	w.gotTenant, w.gotBank, w.gotClient, w.gotSecret = tenantID, bankID, clientID, secret
	return w.err
}

func newCredDeps(creds ports.CredentialWriter) app.Deps {
	store := persistence.NewStore()
	return app.Deps{
		Tenants:    store,
		Pricing:    store,
		CredWriter: creds,
		Clock:      system.Clock{},
		IDs:        &seqIDs{},
	}
}

func TestSetBankCredentialRequiresExistingTenant(t *testing.T) {
	t.Parallel()
	w := &recordingWriter{}
	admin := app.NewAdminService(newCredDeps(w))

	err := admin.SetBankCredential(context.Background(), "ghost", ports.BankIDC6, "cid", "shh")
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want ErrNotFound for unknown tenant, got %v", err)
	}
	if w.called {
		t.Fatal("writer must not be called when the tenant does not exist")
	}
}

func TestSetBankCredentialHappyPath(t *testing.T) {
	t.Parallel()
	store := persistence.NewStore()
	creds := secret.NewStore(nil)
	deps := app.Deps{
		Tenants:    store,
		Pricing:    store,
		CredWriter: creds,
		Clock:      system.Clock{},
		IDs:        &seqIDs{},
	}
	admin := app.NewAdminService(deps)

	tn, err := admin.CreateTenant(context.Background(), "Acme")
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	if err := admin.SetBankCredential(context.Background(), tn.ID(), ports.BankIDC6, "client-123", "top-secret"); err != nil {
		t.Fatalf("set credential: %v", err)
	}
	got, err := creds.GetBankCredential(context.Background(), tn.ID(), ports.BankIDC6)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got.ClientID != "client-123" || got.Secret != "top-secret" || got.TenantID != tn.ID() {
		t.Fatalf("credential not stored as written: %+v", got)
	}
}

func TestSetBankCredentialNeverLeaksSecretInError(t *testing.T) {
	t.Parallel()
	const secretVal = "S3cr3t-do-not-leak"
	store := persistence.NewStore()
	w := &recordingWriter{err: errors.New("vault unavailable")}
	deps := app.Deps{
		Tenants:    store,
		Pricing:    store,
		CredWriter: w,
		Clock:      system.Clock{},
		IDs:        &seqIDs{},
	}
	admin := app.NewAdminService(deps)
	tn, err := admin.CreateTenant(context.Background(), "Acme")
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	err = admin.SetBankCredential(context.Background(), tn.ID(), ports.BankIDC6, "client-123", secretVal)
	if err == nil {
		t.Fatal("want error from writer")
	}
	if strings.Contains(err.Error(), secretVal) {
		t.Fatalf("secret leaked into error: %q", err.Error())
	}
	if !w.called || w.gotSecret != secretVal {
		t.Fatal("writer should have received the secret transiently")
	}
}

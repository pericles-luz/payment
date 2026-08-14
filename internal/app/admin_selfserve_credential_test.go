package app_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// TestSelfServeCredentialWritesSameAsAdmin asserts the self-serve write reaches the
// same CredentialWriter port with the same (tenant, bank) key and value as the
// admin write — the two surfaces persist identical credential state (SIN-69196 §1).
func TestSelfServeCredentialWritesSameAsAdmin(t *testing.T) {
	t.Parallel()
	store := persistence.NewStore()
	creds := secret.NewStore(nil)
	admin := app.NewAdminService(app.Deps{
		Tenants: store, Pricing: store, CredWriter: creds, Clock: fixedClock{t: epoch()}, IDs: &seqIDs{},
	})
	tn, err := admin.CreateTenant(context.Background(), "Acme")
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	if err := admin.SetBankCredentialSelfServe(context.Background(), tn.ID(), ports.BankIDC6, "cid-self", "sup3r-secret"); err != nil {
		t.Fatalf("self-serve write: %v", err)
	}
	got, err := creds.GetBankCredential(context.Background(), tn.ID(), ports.BankIDC6)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got.ClientID != "cid-self" || got.Secret != "sup3r-secret" || got.TenantID != tn.ID() {
		t.Fatalf("credential not stored as written: %+v", got)
	}
}

// TestSelfServeCredentialAuditOrigin is the R1 assertion: the self-serve write
// records a credential.set audit entry stamped origin='self-serve' (distinct from
// the admin path's origin='admin'), with account_id derived server-side and NO
// secret/client id in any field.
func TestSelfServeCredentialAuditOrigin(t *testing.T) {
	t.Parallel()
	admin, log, _ := newAuditAdmin(t)
	ctx := app.WithOperatorID(context.Background(), auditOperator)

	const secretVal = "S3cr3t-do-not-record"
	const clientID = "client-must-not-leak"
	tn, err := admin.CreateTenant(ctx, "Acme")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	// One admin write, then one self-serve write on the same tenant.
	if err := admin.SetBankCredential(ctx, tn.ID(), ports.BankIDC6, "cid-admin", "admin-secret"); err != nil {
		t.Fatalf("admin write: %v", err)
	}
	if err := admin.SetBankCredentialSelfServe(ctx, tn.ID(), ports.BankIDC6, clientID, secretVal); err != nil {
		t.Fatalf("self-serve write: %v", err)
	}

	entries := log.Entries()
	// entries: [tenant.create, credential.set(admin), credential.set(self-serve)]
	if len(entries) != 3 {
		t.Fatalf("want 3 audit entries, got %d", len(entries))
	}
	adminCred, selfCred := entries[1], entries[2]
	if adminCred.Action() != audit.ActionSetBankCredential || adminCred.Origin() != audit.OriginAdmin {
		t.Fatalf("admin entry: action=%q origin=%q, want credential.set/admin", adminCred.Action(), adminCred.Origin())
	}
	if selfCred.Action() != audit.ActionSetBankCredential || selfCred.Origin() != audit.OriginSelfServe {
		t.Fatalf("self-serve entry: action=%q origin=%q, want credential.set/self-serve", selfCred.Action(), selfCred.Origin())
	}
	// account_id is derived server-side (self-account of the tenant).
	if selfCred.AccountID() == "" {
		t.Fatal("self-serve entry missing account_id attribution")
	}
	// No secret or client id anywhere in the self-serve entry's fields.
	rendered := strings.Join([]string{
		selfCred.ID(), selfCred.OperatorID(), string(selfCred.Action()),
		selfCred.TenantID(), selfCred.BankID(), selfCred.Origin(), selfCred.AccountID(),
	}, "|")
	if strings.Contains(rendered, secretVal) || strings.Contains(rendered, clientID) {
		t.Fatalf("self-serve audit entry leaked secret/client id: %q", rendered)
	}
}

// TestSelfServeCredentialRejectsUnknownBank pins the app-layer defense-in-depth:
// even the self-serve path re-validates the bank against the known set (an unknown
// bank is a validation error, never a write). The HTTP boundary additionally
// restricts self-serve to its own allow-list; this is the second layer.
func TestSelfServeCredentialRejectsUnknownBank(t *testing.T) {
	t.Parallel()
	store := persistence.NewStore()
	w := &recordingWriter{}
	admin := app.NewAdminService(app.Deps{
		Tenants: store, Pricing: store, CredWriter: w, Clock: fixedClock{t: epoch()}, IDs: &seqIDs{},
	})
	tn, err := admin.CreateTenant(context.Background(), "Acme")
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	err = admin.SetBankCredentialSelfServe(context.Background(), tn.ID(), "nubank", "cid", "shh")
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want validation error for unknown bank, got %v", err)
	}
	if w.called {
		t.Fatal("writer must not be called for an unknown bank")
	}
}

// TestSelfServeCredentialNeverLeaksSecretInError mirrors the admin guarantee: a
// writer failure surfaces an error that never contains the secret.
func TestSelfServeCredentialNeverLeaksSecretInError(t *testing.T) {
	t.Parallel()
	const secretVal = "S3cr3t-do-not-leak"
	store := persistence.NewStore()
	w := &recordingWriter{err: errors.New("vault unavailable")}
	admin := app.NewAdminService(app.Deps{
		Tenants: store, Pricing: store, CredWriter: w, Clock: fixedClock{t: epoch()}, IDs: &seqIDs{},
	})
	tn, err := admin.CreateTenant(context.Background(), "Acme")
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	err = admin.SetBankCredentialSelfServe(context.Background(), tn.ID(), ports.BankIDC6, "cid", secretVal)
	if err == nil {
		t.Fatal("want error from writer")
	}
	if strings.Contains(err.Error(), secretVal) {
		t.Fatalf("secret leaked into error: %q", err.Error())
	}
}

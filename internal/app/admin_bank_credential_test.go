package app_test

import (
	"context"
	"errors"
	"testing"

	auditlog "github.com/ia-dev-sindireceita/payment/internal/adapters/audit/inmemory"
	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// newBankCredAdmin wires an AdminService over a real (in-memory) audit log,
// credential store and tenant store, and seeds one tenant so the per-bank
// credential write can be asserted end-to-end. It returns the credential store so
// the persisted (tenant, bank) credential can be read back.
func newBankCredAdmin(t *testing.T) (*app.AdminService, *auditlog.Log, *secret.Store, string) {
	t.Helper()
	store := persistence.NewStore()
	log := auditlog.NewLog()
	creds := secret.NewStore(nil)
	admin := app.NewAdminService(app.Deps{
		Tenants:    store,
		Pricing:    store,
		CredWriter: creds,
		Audit:      log,
		Clock:      fixedClock{t: epoch()},
		IDs:        &seqIDs{},
	})
	tn, err := admin.CreateTenant(context.Background(), "Acme")
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	return admin, log, creds, tn.ID()
}

// TestSetBankCredentialPersistsPerBank pins the multi-bank write: a credential set
// for an explicit bank is stored under the (tenant, bank) pair (SIN-66015 /
// ADR-0007).
func TestSetBankCredentialPersistsPerBank(t *testing.T) {
	t.Parallel()
	admin, _, creds, tenantID := newBankCredAdmin(t)
	ctx := app.WithOperatorID(context.Background(), auditOperator)

	if err := admin.SetBankCredential(ctx, tenantID, "c6", "cid-c6", "sec-c6"); err != nil {
		t.Fatalf("set c6 credential: %v", err)
	}
	got, err := creds.GetBankCredential(ctx, tenantID, ports.BankIDC6)
	if err != nil {
		t.Fatalf("read c6 credential: %v", err)
	}
	if got.ClientID != "cid-c6" || got.BankID != ports.BankIDC6 {
		t.Fatalf("credential not keyed by (tenant, c6): %+v", got)
	}
}

// TestSetBankCredentialDefaultsToC6 pins retro-compat: an empty bank resolves to
// the default bank (c6) so legacy single-bank callers keep working unchanged.
func TestSetBankCredentialDefaultsToC6(t *testing.T) {
	t.Parallel()
	admin, _, creds, tenantID := newBankCredAdmin(t)
	ctx := context.Background()

	if err := admin.SetBankCredential(ctx, tenantID, "", "cid", "sec"); err != nil {
		t.Fatalf("set credential with empty bank: %v", err)
	}
	got, err := creds.GetBankCredential(ctx, tenantID, ports.BankIDC6)
	if err != nil {
		t.Fatalf("read default-bank credential: %v", err)
	}
	if got.ClientID != "cid" {
		t.Fatalf("empty bank did not default to c6: %+v", got)
	}
}

// TestSetBankCredentialNormalizesBank pins that a mixed-case / padded slug is
// normalized before keying, so "  C6 " writes the same pair as "c6".
func TestSetBankCredentialNormalizesBank(t *testing.T) {
	t.Parallel()
	admin, _, creds, tenantID := newBankCredAdmin(t)
	ctx := context.Background()

	if err := admin.SetBankCredential(ctx, tenantID, "  C6 ", "cid", "sec"); err != nil {
		t.Fatalf("set credential with padded bank: %v", err)
	}
	if _, err := creds.GetBankCredential(ctx, tenantID, ports.BankIDC6); err != nil {
		t.Fatalf("normalized credential not found under c6: %v", err)
	}
}

// TestSetBankCredentialRejectsUnknownBank pins deny-by-default at the use-case:
// an unknown bank slug is a validation error and nothing is written.
func TestSetBankCredentialRejectsUnknownBank(t *testing.T) {
	t.Parallel()
	admin, _, creds, tenantID := newBankCredAdmin(t)
	ctx := context.Background()

	err := admin.SetBankCredential(ctx, tenantID, "itau", "cid", "sec")
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation for unknown bank, got %v", err)
	}
	if _, gerr := creds.GetBankCredential(ctx, tenantID, "itau"); gerr == nil {
		t.Fatalf("unknown-bank credential must not be stored")
	}
}

// TestSetBankCredentialAuditRecordsBankID is the audit assertion: the credential
// write records the non-secret bank id on the entry so the trail names WHICH bank
// was set, while still never carrying the secret or client id.
func TestSetBankCredentialAuditRecordsBankID(t *testing.T) {
	t.Parallel()
	admin, log, _, tenantID := newBankCredAdmin(t)
	ctx := app.WithOperatorID(context.Background(), auditOperator)

	if err := admin.SetBankCredential(ctx, tenantID, "c6", "cid", "top-secret"); err != nil {
		t.Fatalf("set credential: %v", err)
	}

	var found bool
	for _, e := range log.Entries() {
		if e.Action() != audit.ActionSetBankCredential {
			continue
		}
		found = true
		if e.BankID() != ports.BankIDC6 {
			t.Fatalf("audit entry bank_id: want %q, got %q", ports.BankIDC6, e.BankID())
		}
	}
	if !found {
		t.Fatalf("no credential.set audit entry recorded")
	}
}

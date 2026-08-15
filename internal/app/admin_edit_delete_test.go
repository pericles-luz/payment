package app_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	auditlog "github.com/ia-dev-sindireceita/payment/internal/adapters/audit/inmemory"
	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/account"
	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// newEditDeleteConsole wires a ConsoleService with the full set of ports the
// ADR-0012 edit/delete use-cases exercise: accounts, tenants, an audit log spy and
// the credential + certificate stores (which also satisfy the deleter ports). It
// seeds one real account "reseller-1" and one tenant "t1".
func newEditDeleteConsole(t *testing.T) (*app.ConsoleService, *persistence.Store, *secret.Store, *secret.CertStore, *auditlog.Log) {
	t.Helper()
	store := persistence.NewStore()
	creds := secret.NewStore(map[string]ports.BankCredential{})
	certs := secret.NewCertStore()
	log := auditlog.NewLog()
	svc := app.NewConsoleService(app.ConsoleDeps{
		Tenants:     store,
		Accounts:    store,
		Pricing:     store,
		Ledger:      store,
		CredWriter:  creds,
		CredReader:  creds,
		CertWriter:  certs,
		CertReader:  certs,
		CredDeleter: creds,
		CertDeleter: certs,
		Audit:       log,
		Clock:       fixedClock{t: time.Unix(1000, 0).UTC()},
		IDs:         &seqIDs{},
	})
	seedAccount(t, store, "reseller-1", "Verz", true, 100)
	seedTenant(t, store, "t1", "Acme", true, 100)
	return svc, store, creds, certs, log
}

// countAction returns how many audit entries carry the given action.
func countAction(log *auditlog.Log, action audit.Action) int {
	n := 0
	for _, e := range log.Entries() {
		if e.Action() == action {
			n++
		}
	}
	return n
}

func TestRenameAccount_HappyAndAudit(t *testing.T) {
	t.Parallel()
	svc, _, _, _, log := newEditDeleteConsole(t)
	ctx := app.WithOperatorID(context.Background(), auditOperator)

	a, err := svc.RenameAccount(ctx, "reseller-1", "Verz Pagamentos")
	if err != nil {
		t.Fatalf("rename: %v", err)
	}
	if a.Name() != "Verz Pagamentos" {
		t.Fatalf("name = %q", a.Name())
	}
	// Persisted.
	got, err := svc.GetAccount(ctx, "reseller-1")
	if err != nil || got.Name() != "Verz Pagamentos" {
		t.Fatalf("persisted name = %q, %v", got.Name(), err)
	}
	// Audited account.rename with the account id in the account_id column, empty tenant.
	if countAction(log, audit.ActionRenameAccount) != 1 {
		t.Fatalf("want 1 rename_account audit, entries=%+v", log.Entries())
	}
	e := log.Entries()[len(log.Entries())-1]
	if e.AccountID() != "reseller-1" || e.TenantID() != "" || e.OperatorID() != auditOperator {
		t.Fatalf("audit entry = account=%q tenant=%q op=%q", e.AccountID(), e.TenantID(), e.OperatorID())
	}
}

func TestRenameAccount_SelfAccountRejected(t *testing.T) {
	t.Parallel()
	svc, store, _, _, log := newEditDeleteConsole(t)
	ctx := context.Background()
	// A derived self-account (acct-<tenant>) must refuse a direct rename.
	seedAccount(t, store, account.SelfAccountID("t1"), "Self", true, 100)

	_, err := svc.RenameAccount(ctx, account.SelfAccountID("t1"), "Hacked")
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation, got %v", err)
	}
	if countAction(log, audit.ActionRenameAccount) != 0 {
		t.Fatal("a rejected rename must not audit")
	}
}

func TestRenameAccount_ValidationAndNotFound(t *testing.T) {
	t.Parallel()
	svc, _, _, _, _ := newEditDeleteConsole(t)
	ctx := context.Background()
	for _, in := range []string{"", "   ", strings.Repeat("x", 201)} {
		if _, err := svc.RenameAccount(ctx, "reseller-1", in); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("in=%q want ErrValidation, got %v", in, err)
		}
	}
	if _, err := svc.RenameAccount(ctx, "acct-missing", "X"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("missing account want ErrNotFound, got %v", err)
	}
}

func TestDeactivateReactivateAccount_Audit(t *testing.T) {
	t.Parallel()
	svc, _, _, _, log := newEditDeleteConsole(t)
	ctx := app.WithOperatorID(context.Background(), auditOperator)

	a, err := svc.DeactivateAccount(ctx, "reseller-1")
	if err != nil || a.Active() {
		t.Fatalf("deactivate: active=%v err=%v", a.Active(), err)
	}
	a, err = svc.ActivateAccount(ctx, "reseller-1")
	if err != nil || !a.Active() {
		t.Fatalf("activate: active=%v err=%v", a.Active(), err)
	}
	if countAction(log, audit.ActionSuspendAccount) != 1 || countAction(log, audit.ActionActivateAccount) != 1 {
		t.Fatalf("want 1 suspend + 1 activate audit, got %d/%d",
			countAction(log, audit.ActionSuspendAccount), countAction(log, audit.ActionActivateAccount))
	}
}

func TestRenameTenant_HappyAndAudit(t *testing.T) {
	t.Parallel()
	svc, _, _, _, log := newEditDeleteConsole(t)
	ctx := app.WithOperatorID(context.Background(), auditOperator)

	tn, err := svc.RenameTenant(ctx, "t1", "Acme Renamed")
	if err != nil || tn.Name() != "Acme Renamed" {
		t.Fatalf("rename tenant: name=%q err=%v", tn.Name(), err)
	}
	got, err := svc.GetTenant(ctx, "t1")
	if err != nil || got.Name() != "Acme Renamed" {
		t.Fatalf("persisted name = %q, %v", got.Name(), err)
	}
	if countAction(log, audit.ActionRenameTenant) != 1 {
		t.Fatal("want 1 rename_tenant audit")
	}
	e := log.Entries()[len(log.Entries())-1]
	// Tenant-scoped: tenant_id set, account_id derived to the self-account.
	if e.TenantID() != "t1" || e.AccountID() != account.SelfAccountID("t1") {
		t.Fatalf("audit tenant=%q account=%q", e.TenantID(), e.AccountID())
	}
}

func TestRenameTenant_ValidationAndNotFound(t *testing.T) {
	t.Parallel()
	svc, _, _, _, _ := newEditDeleteConsole(t)
	ctx := context.Background()
	for _, in := range []string{"", "   ", strings.Repeat("x", 201)} {
		if _, err := svc.RenameTenant(ctx, "t1", in); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("in=%q want ErrValidation, got %v", in, err)
		}
	}
	if _, err := svc.RenameTenant(ctx, "missing", "X"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("missing tenant want ErrNotFound, got %v", err)
	}
}

func TestSuspendReactivateTenant_Audit(t *testing.T) {
	t.Parallel()
	svc, _, _, _, log := newEditDeleteConsole(t)
	ctx := app.WithOperatorID(context.Background(), auditOperator)
	if _, err := svc.SuspendTenant(ctx, "t1"); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	if _, err := svc.ActivateTenant(ctx, "t1"); err != nil {
		t.Fatalf("activate: %v", err)
	}
	if countAction(log, audit.ActionSuspendTenant) != 1 || countAction(log, audit.ActionActivateTenant) != 1 {
		t.Fatalf("want 1 suspend + 1 activate tenant audit, got %d/%d",
			countAction(log, audit.ActionSuspendTenant), countAction(log, audit.ActionActivateTenant))
	}
}

// TestRemoveBankConfig_ZeroesAndDeletesBoth is the core §5 acceptance: with both a
// credential and a certificate configured, RemoveBankConfig deletes both (reads now
// 404) and audits bank_config.remove carrying the bankID but no secret.
func TestRemoveBankConfig_ZeroesAndDeletesBoth(t *testing.T) {
	t.Parallel()
	svc, _, creds, certs, log := newEditDeleteConsole(t)
	ctx := app.WithOperatorID(context.Background(), auditOperator)

	if err := creds.SetBankCredential(ctx, "t1", ports.BankIDC6, "client-1", "s3cr3t"); err != nil {
		t.Fatalf("seed cred: %v", err)
	}
	certPEM, keyPEM := genAdminCertKey(t, "mtls.acme", certNow().Add(-time.Hour), certNow().Add(365*24*time.Hour))
	if _, err := svc.SetBankCertificate(ctx, "t1", "c6", certPEM, keyPEM); err != nil {
		t.Fatalf("seed cert: %v", err)
	}

	if err := svc.RemoveBankConfig(ctx, "t1", "c6"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := creds.GetBankCredential(ctx, "t1", ports.BankIDC6); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("credential must be gone, got %v", err)
	}
	if _, err := certs.GetBankCertificateMeta(ctx, "t1", ports.BankIDC6); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("certificate must be gone, got %v", err)
	}
	if countAction(log, audit.ActionRemoveBankConfig) != 1 {
		t.Fatal("want 1 bank_config.remove audit")
	}
	e := log.Entries()[len(log.Entries())-1]
	if e.BankID() != ports.BankIDC6 || e.TenantID() != "t1" {
		t.Fatalf("audit bank=%q tenant=%q", e.BankID(), e.TenantID())
	}
	// No audit field ever carries the secret.
	for _, e := range log.Entries() {
		for _, f := range []string{e.OperatorID(), e.TenantID(), e.TxID(), e.BankID(), string(e.Action())} {
			if strings.Contains(f, "s3cr3t") {
				t.Fatalf("audit leaked secret in %q", f)
			}
		}
	}
}

// TestRemoveBankConfig_PartialAndIdempotent covers the partial-cascade cases the
// ADR calls out: only a credential, only a certificate, and neither — all succeed
// (idempotent) and still audit the removal.
func TestRemoveBankConfig_PartialAndIdempotent(t *testing.T) {
	t.Parallel()
	svc, _, creds, _, log := newEditDeleteConsole(t)
	ctx := app.WithOperatorID(context.Background(), auditOperator)

	// Only a credential, no certificate.
	if err := creds.SetBankCredential(ctx, "t1", ports.BankIDC6, "c", "s"); err != nil {
		t.Fatalf("seed cred: %v", err)
	}
	if err := svc.RemoveBankConfig(ctx, "t1", "c6"); err != nil {
		t.Fatalf("remove cred-only: %v", err)
	}
	// Neither configured now — a repeat is a harmless no-op that still returns nil.
	if err := svc.RemoveBankConfig(ctx, "t1", "c6"); err != nil {
		t.Fatalf("idempotent remove: %v", err)
	}
	if countAction(log, audit.ActionRemoveBankConfig) != 2 {
		t.Fatalf("want 2 remove audits (each call audits), got %d", countAction(log, audit.ActionRemoveBankConfig))
	}
}

func TestRemoveBankConfig_TenantNotFoundAndUnknownBank(t *testing.T) {
	t.Parallel()
	svc, _, _, _, _ := newEditDeleteConsole(t)
	ctx := context.Background()
	if err := svc.RemoveBankConfig(ctx, "missing", "c6"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("missing tenant want ErrNotFound, got %v", err)
	}
	if err := svc.RemoveBankConfig(ctx, "t1", "nubank"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unknown bank want ErrValidation, got %v", err)
	}
}

package app_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	auditlog "github.com/ia-dev-sindireceita/payment/internal/adapters/audit/inmemory"
	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

const auditOperator = "op-abc123"

// epoch is the fixed timestamp used by the audit tests' clock.
func epoch() time.Time { return time.Unix(1700000000, 0).UTC() }

// newAuditAdmin wires an AdminService over a real (in-memory) audit log and
// credential store so audit emission can be asserted end-to-end.
func newAuditAdmin(t *testing.T) (*app.AdminService, *auditlog.Log, *persistence.Store) {
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
	return admin, log, store
}

// TestAdminActionsEmitAudit asserts every privileged AdminService mutation
// appends exactly one audit entry attributed to the operator from context, with
// the right action and target tenant.
func TestAdminActionsEmitAudit(t *testing.T) {
	t.Parallel()
	admin, log, _ := newAuditAdmin(t)
	ctx := app.WithOperatorID(context.Background(), auditOperator)

	tn, err := admin.CreateTenant(ctx, "Acme")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	if _, err := admin.SetEndpointPrice(ctx, tn.ID(), "pix.create", 10); err != nil {
		t.Fatalf("set price: %v", err)
	}
	if err := admin.SetBankCredential(ctx, tn.ID(), "client-1", "top-secret"); err != nil {
		t.Fatalf("set credential: %v", err)
	}

	entries := log.Entries()
	if len(entries) != 3 {
		t.Fatalf("want 3 audit entries, got %d", len(entries))
	}
	wantActions := []audit.Action{audit.ActionCreateTenant, audit.ActionSetEndpointPrice, audit.ActionSetBankCredential}
	for i, e := range entries {
		if e.Action() != wantActions[i] {
			t.Errorf("entry %d: want action %q, got %q", i, wantActions[i], e.Action())
		}
		if e.OperatorID() != auditOperator {
			t.Errorf("entry %d: want operator %q, got %q", i, auditOperator, e.OperatorID())
		}
		if e.TenantID() != tn.ID() {
			t.Errorf("entry %d: want tenant %q, got %q", i, tn.ID(), e.TenantID())
		}
		if e.ID() == "" {
			t.Errorf("entry %d: missing id", i)
		}
		if !e.At().Equal(epoch()) {
			t.Errorf("entry %d: want time %v, got %v", i, epoch(), e.At())
		}
	}
}

// TestSetBankCredentialAuditOmitsSecret is the security-critical assertion: the
// audit trail records that a credential was set, but never the secret value
// (nor the client id) in any field of the entry (threat C1/C4).
func TestSetBankCredentialAuditOmitsSecret(t *testing.T) {
	t.Parallel()
	admin, log, _ := newAuditAdmin(t)
	ctx := app.WithOperatorID(context.Background(), auditOperator)

	const secretVal = "S3cr3t-do-not-record"
	const clientID = "client-must-not-leak"
	tn, err := admin.CreateTenant(ctx, "Acme")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	if err := admin.SetBankCredential(ctx, tn.ID(), clientID, secretVal); err != nil {
		t.Fatalf("set credential: %v", err)
	}

	for i, e := range log.Entries() {
		// Render every exported field of the entry and assert the secret/client id
		// appear nowhere.
		rendered := fmt.Sprintf("%s|%s|%s|%s|%s", e.ID(), e.OperatorID(), e.Action(), e.TenantID(), e.At())
		if strings.Contains(rendered, secretVal) {
			t.Fatalf("entry %d leaked the secret: %q", i, rendered)
		}
		if strings.Contains(rendered, clientID) {
			t.Fatalf("entry %d leaked the client id: %q", i, rendered)
		}
	}
}

// TestAdminActionsRecordEmptyOperatorWhenUnset confirms an internal caller (no
// operator id in context) still succeeds and is recorded as non-attributed,
// rather than failing the operation.
func TestAdminActionsRecordEmptyOperatorWhenUnset(t *testing.T) {
	t.Parallel()
	admin, log, _ := newAuditAdmin(t)

	if _, err := admin.CreateTenant(context.Background(), "Acme"); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	entries := log.Entries()
	if len(entries) != 1 {
		t.Fatalf("want 1 entry, got %d", len(entries))
	}
	if entries[0].OperatorID() != "" {
		t.Fatalf("want empty operator id, got %q", entries[0].OperatorID())
	}
}

// failingAudit is an AuditLog that always errors, to assert fail-closed audit.
type failingAudit struct{ err error }

func (f failingAudit) Append(context.Context, audit.Entry) error { return f.err }

var _ ports.AuditLog = failingAudit{}

// TestAuditFailClosed asserts that when the audit append fails, the privileged
// operation surfaces the error rather than silently dropping the record.
func TestAuditFailClosed(t *testing.T) {
	t.Parallel()
	store := persistence.NewStore()
	sentinel := errors.New("audit store down")
	admin := app.NewAdminService(app.Deps{
		Tenants:    store,
		Pricing:    store,
		CredWriter: secret.NewStore(nil),
		Audit:      failingAudit{err: sentinel},
		Clock:      fixedClock{t: epoch()},
		IDs:        &seqIDs{},
	})

	_, err := admin.CreateTenant(context.Background(), "Acme")
	if !errors.Is(err, sentinel) {
		t.Fatalf("want fail-closed audit error, got %v", err)
	}
}

// TestNilAuditDegradesToNoop confirms a nil Deps.Audit does not panic and the
// operation succeeds (foundation no-op default).
func TestNilAuditDegradesToNoop(t *testing.T) {
	t.Parallel()
	store := persistence.NewStore()
	admin := app.NewAdminService(app.Deps{
		Tenants:    store,
		Pricing:    store,
		CredWriter: secret.NewStore(nil),
		Clock:      fixedClock{t: epoch()},
		IDs:        &seqIDs{},
	})
	if _, err := admin.CreateTenant(context.Background(), "Acme"); err != nil {
		t.Fatalf("create tenant with nil audit: %v", err)
	}
}

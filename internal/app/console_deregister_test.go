package app_test

import (
	"context"
	"errors"
	"testing"

	"time"

	auditlog "github.com/ia-dev-sindireceita/payment/internal/adapters/audit/inmemory"
	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// newConsoleForDeregisterTest builds a console wired with a recording deregistrar and a
// credential store that records read/delete ordering.
func newConsoleForDeregisterTest(t *testing.T, dereg ports.WebhookDeregistrar, order *orderRecorder, _ *[]string) *app.ConsoleService {
	t.Helper()
	store := persistence.NewStore()
	log := auditlog.NewLog()
	svc := app.NewConsoleService(app.ConsoleDeps{
		Tenants:            store,
		Accounts:           store,
		Pricing:            store,
		Ledger:             store,
		CredDeleter:        order,
		Creds:              order,
		WebhookDeregistrar: dereg,
		Audit:              log,
		Clock:              fixedClock{t: time.Unix(1000, 0).UTC()},
		IDs:                &seqIDs{},
	})
	seedTenant(t, store, "t1", "Acme", true, 100)
	return svc
}

// Removing a bank configuration used to delete only OUR side, leaving the PSP registered
// against a tenant whose credential had just been deleted: it would keep POSTing
// notifications we could no longer authenticate or reconcile. These tests pin the fix and,
// more importantly, its ORDERING — deregistration authenticates with the very credential
// the removal is about to delete, so doing it afterwards is impossible.

type recordingDeregistrar struct {
	calls   []string
	pixKey  string
	failAll error
}

func (r *recordingDeregistrar) DeleteWebhook(_ context.Context, _, pixKey string) error {
	r.calls = append(r.calls, "pix")
	r.pixKey = pixKey
	return r.failAll
}

func (r *recordingDeregistrar) DeleteRecWebhook(context.Context, string) error {
	r.calls = append(r.calls, "rec")
	return r.failAll
}

func (r *recordingDeregistrar) DeleteCobRWebhook(context.Context, string) error {
	r.calls = append(r.calls, "cobr")
	return r.failAll
}

// orderRecorder proves the sequence: the credential must still be readable when the PSP
// calls happen, and deleted only afterwards.
type orderRecorder struct {
	events *[]string
	cred   ports.BankCredential
}

func (o *orderRecorder) GetBankCredential(context.Context, string, string) (ports.BankCredential, error) {
	*o.events = append(*o.events, "read-credential")
	return o.cred, nil
}

func (o *orderRecorder) DeleteBankCredential(context.Context, string, string) error {
	*o.events = append(*o.events, "delete-credential")
	return nil
}

func TestRemoveBankConfigDeregistersBeforeDeleting(t *testing.T) {
	t.Parallel()
	var events []string
	rec := &recordingDeregistrar{}
	order := &orderRecorder{events: &events, cred: ports.BankCredential{CreditorKey: "123e4567-e89b-12d3-a456-426614174000"}}

	svc := newConsoleForDeregisterTest(t, rec, order, &events)
	if err := svc.RemoveBankConfig(context.Background(), "t1", ports.BankIDC6); err != nil {
		t.Fatalf("RemoveBankConfig: %v", err)
	}

	if len(rec.calls) != 3 {
		t.Fatalf("every channel with a delete must be deregistered, got %v", rec.calls)
	}
	if rec.pixKey != "123e4567-e89b-12d3-a456-426614174000" {
		t.Fatalf("the PIX callback is keyed by the creditor key, got %q", rec.pixKey)
	}
	// The credential must be READ (for the key) before it is DELETED.
	readAt, deleteAt := indexOf(events, "read-credential"), indexOf(events, "delete-credential")
	if readAt == -1 || deleteAt == -1 || readAt > deleteAt {
		t.Fatalf("credential must be read before deletion, events=%v", events)
	}
}

// A PSP failure must not block the removal: the operator asked for the configuration to
// go, and refusing because the bank is briefly unavailable leaves them stuck with exactly
// the residue this feature removes.
func TestRemoveBankConfigSurvivesDeregisterFailure(t *testing.T) {
	t.Parallel()
	var events []string
	rec := &recordingDeregistrar{failAll: errors.New("psp unavailable")}
	order := &orderRecorder{events: &events, cred: ports.BankCredential{CreditorKey: "k"}}

	svc := newConsoleForDeregisterTest(t, rec, order, &events)
	if err := svc.RemoveBankConfig(context.Background(), "t1", ports.BankIDC6); err != nil {
		t.Fatalf("a PSP failure must not fail the removal: %v", err)
	}
	if indexOf(events, "delete-credential") == -1 {
		t.Fatal("the credential must still be deleted")
	}
}

// An already-absent registration is not a failure worth reporting.
func TestRemoveBankConfigTreatsNotFoundAsDone(t *testing.T) {
	t.Parallel()
	var events []string
	rec := &recordingDeregistrar{failAll: shared.ErrNotFound}
	order := &orderRecorder{events: &events, cred: ports.BankCredential{CreditorKey: "k"}}

	svc := newConsoleForDeregisterTest(t, rec, order, &events)
	if err := svc.RemoveBankConfig(context.Background(), "t1", ports.BankIDC6); err != nil {
		t.Fatalf("RemoveBankConfig: %v", err)
	}
}

func indexOf(list []string, want string) int {
	for i, v := range list {
		if v == want {
			return i
		}
	}
	return -1
}

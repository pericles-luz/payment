package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/account"
	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

// newWebhookConsole builds a ConsoleService wired with the account plane + the
// outbound-webhook store over real in-memory adapters (no DB mock). It seeds one real
// Conta ("verz-1") so the account-existence + self-account guards can be exercised.
func newWebhookConsole(t *testing.T) (*app.ConsoleService, *persistence.Store) {
	t.Helper()
	store := persistence.NewStore()
	webhooks := persistence.NewOutboundWebhookStore()
	svc := app.NewConsoleService(app.ConsoleDeps{
		Tenants:          store,
		Accounts:         store,
		Ledger:           store,
		Audit:            store,
		OutboundWebhooks: webhooks,
		Clock:            fixedClock{t: time.Unix(9000, 0).UTC()},
		IDs:              &seqIDs{},
	})
	real := account.Rehydrate("verz-1", "Verz", true, time.Unix(1, 0).UTC())
	if err := store.SaveAccount(context.Background(), real); err != nil {
		t.Fatalf("seed account: %v", err)
	}
	return svc, store
}

func TestSetOutboundWebhookCreateThenUpdate(t *testing.T) {
	t.Parallel()
	svc, store := newWebhookConsole(t)
	ctx := app.WithOperatorID(context.Background(), "op-1")

	// First provisioning returns the signing secret display-once.
	cfg, secret, err := svc.SetOutboundWebhook(ctx, "verz-1", "https://verz.example.com/hook", true)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if secret == "" {
		t.Fatal("first provisioning must return the signing secret display-once")
	}
	if cfg.URL() != "https://verz.example.com/hook" || !cfg.Enabled() {
		t.Errorf("config = %+v", cfg)
	}

	// Read back: configured, no secret exposed via Get (the service never returns it here).
	got, ok, err := svc.GetOutboundWebhook(ctx, "verz-1")
	if err != nil || !ok {
		t.Fatalf("get = ok %v err %v", ok, err)
	}
	firstSecret := got.SigningSecret()

	// Update keeps the secret and returns "" (write-only, never re-shown).
	cfg2, secret2, err := svc.SetOutboundWebhook(ctx, "verz-1", "https://verz.example.com/hook2", false)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if secret2 != "" {
		t.Error("update must NOT return a secret (write-only, secret preserved)")
	}
	if cfg2.URL() != "https://verz.example.com/hook2" || cfg2.Enabled() {
		t.Errorf("update not applied: %+v", cfg2)
	}
	got2, _, _ := svc.GetOutboundWebhook(ctx, "verz-1")
	if got2.SigningSecret() != firstSecret {
		t.Error("update changed the signing secret; it must be preserved")
	}

	// Two audit entries: set (create) + set (update), account-scoped.
	assertWebhookAudit(t, store, audit.ActionSetOutboundWebhook, 2)
}

func TestSetOutboundWebhookValidationError(t *testing.T) {
	t.Parallel()
	svc, store := newWebhookConsole(t)
	ctx := app.WithOperatorID(context.Background(), "op-1")
	if _, _, err := svc.SetOutboundWebhook(ctx, "verz-1", "http://insecure", true); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("non-https URL: err = %v; want validation", err)
	}
	// No audit written for a rejected write.
	if n := countWebhookAudit(store); n != 0 {
		t.Errorf("audit entries = %d; want 0 on validation failure", n)
	}
}

func TestRotateOutboundWebhookSecret(t *testing.T) {
	t.Parallel()
	svc, store := newWebhookConsole(t)
	ctx := app.WithOperatorID(context.Background(), "op-1")
	_, first, err := svc.SetOutboundWebhook(ctx, "verz-1", "https://e.example.com/h", true)
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	cfg, rotated, err := svc.RotateOutboundWebhookSecret(ctx, "verz-1")
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if rotated == "" || rotated == first {
		t.Errorf("rotate returned %q (first %q); want a fresh secret", rotated, first)
	}
	if cfg.SigningSecret() != rotated {
		t.Error("rotated config does not hold the new secret")
	}
	got, _, _ := svc.GetOutboundWebhook(ctx, "verz-1")
	if got.SigningSecret() != rotated {
		t.Error("persisted secret not rotated")
	}
	assertWebhookAudit(t, store, audit.ActionRotateOutboundWebhookSecret, 1)
}

func TestRotateOutboundWebhookSecretMissing(t *testing.T) {
	t.Parallel()
	svc, _ := newWebhookConsole(t)
	ctx := app.WithOperatorID(context.Background(), "op-1")
	if _, _, err := svc.RotateOutboundWebhookSecret(ctx, "verz-1"); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("rotate with no config = %v; want ErrNotFound", err)
	}
}

func TestRemoveOutboundWebhook(t *testing.T) {
	t.Parallel()
	svc, store := newWebhookConsole(t)
	ctx := app.WithOperatorID(context.Background(), "op-1")
	if _, _, err := svc.SetOutboundWebhook(ctx, "verz-1", "https://e.example.com/h", true); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := svc.RemoveOutboundWebhook(ctx, "verz-1"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, ok, err := svc.GetOutboundWebhook(ctx, "verz-1"); err != nil || ok {
		t.Errorf("get after remove = ok %v err %v; want ok=false", ok, err)
	}
	// Remove is idempotent.
	if err := svc.RemoveOutboundWebhook(ctx, "verz-1"); err != nil {
		t.Fatalf("second remove: %v", err)
	}
	assertWebhookAudit(t, store, audit.ActionRemoveOutboundWebhook, 2)
}

func TestOutboundWebhookRejectsSelfAccount(t *testing.T) {
	t.Parallel()
	svc, store := newWebhookConsole(t)
	ctx := app.WithOperatorID(context.Background(), "op-1")
	self := account.SelfAccountID("tnt-1") // "acct-tnt-1"
	selfAcct := account.Rehydrate(self, "Self", true, time.Unix(1, 0).UTC())
	if err := store.SaveAccount(ctx, selfAcct); err != nil {
		t.Fatalf("seed self account: %v", err)
	}
	if _, _, err := svc.SetOutboundWebhook(ctx, self, "https://e.example.com/h", true); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("self-account set = %v; want ErrNotFound (refused)", err)
	}
	if _, ok, err := svc.GetOutboundWebhook(ctx, self); !errors.Is(err, shared.ErrNotFound) && ok {
		t.Errorf("self-account get should be refused (ErrNotFound); ok=%v err=%v", ok, err)
	}
}

func TestOutboundWebhookUnknownAccount(t *testing.T) {
	t.Parallel()
	svc, _ := newWebhookConsole(t)
	ctx := context.Background()
	if _, _, err := svc.GetOutboundWebhook(ctx, "nope"); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("unknown account = %v; want ErrNotFound", err)
	}
}

func TestOutboundWebhookUnavailableWhenStoreNil(t *testing.T) {
	t.Parallel()
	store := persistence.NewStore()
	svc := app.NewConsoleService(app.ConsoleDeps{
		Accounts: store,
		Audit:    store,
		Clock:    fixedClock{t: time.Unix(9000, 0).UTC()},
		IDs:      &seqIDs{},
	})
	real := account.Rehydrate("verz-1", "Verz", true, time.Unix(1, 0).UTC())
	_ = store.SaveAccount(context.Background(), real)
	if _, _, err := svc.GetOutboundWebhook(context.Background(), "verz-1"); !errors.Is(err, app.ErrOutboundWebhookUnavailable) {
		t.Errorf("get with nil store = %v; want ErrOutboundWebhookUnavailable", err)
	}
	if _, _, err := svc.SetOutboundWebhook(context.Background(), "verz-1", "https://e.com/h", true); !errors.Is(err, app.ErrOutboundWebhookUnavailable) {
		t.Errorf("set with nil store = %v; want ErrOutboundWebhookUnavailable", err)
	}
	if err := svc.RemoveOutboundWebhook(context.Background(), "verz-1"); !errors.Is(err, app.ErrOutboundWebhookUnavailable) {
		t.Errorf("remove with nil store = %v; want ErrOutboundWebhookUnavailable", err)
	}
}

func assertWebhookAudit(t *testing.T, store *persistence.Store, action audit.Action, want int) {
	t.Helper()
	got := 0
	for _, e := range store.AuditEntries() {
		if e.Action() != action {
			continue
		}
		got++
		if e.AccountID() != "verz-1" {
			t.Errorf("audit account = %q; want verz-1", e.AccountID())
		}
		if e.TenantID() != "" {
			t.Errorf("audit tenant = %q; want empty (account-scoped)", e.TenantID())
		}
		if e.OperatorID() != "op-1" {
			t.Errorf("audit operator = %q; want op-1", e.OperatorID())
		}
	}
	if got != want {
		t.Errorf("audit %q count = %d; want %d", action, got, want)
	}
}

func countWebhookAudit(store *persistence.Store) int {
	n := 0
	for _, e := range store.AuditEntries() {
		switch e.Action() {
		case audit.ActionSetOutboundWebhook, audit.ActionRotateOutboundWebhookSecret, audit.ActionRemoveOutboundWebhook:
			n++
		}
	}
	return n
}

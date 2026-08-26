package postgres_test

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/postgres"
	"github.com/ia-dev-sindireceita/payment/internal/domain/outboundwebhook"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

func newWebhookVault(t *testing.T, db *sql.DB) *postgres.OutboundWebhookVault {
	t.Helper()
	return postgres.NewOutboundWebhookVault(db, testCipher(t), fixedClock{t: time.Unix(1700000000, 0).UTC()})
}

// TestOutboundWebhookVaultRoundTripSurvivesRestart: a config written via the port is
// readable — with the signing secret ciphertext at rest — after the store is recreated
// over the SAME database file (a process restart).
func TestOutboundWebhookVaultRoundTripSurvivesRestart(t *testing.T) {
	t.Parallel()
	dsn, db := openVaultDB(t)
	ctx := context.Background()

	cfg, err := outboundwebhook.New("acct-verz", "https://verz.example.com/hook", "whsec_original", true, time.Unix(1700000000, 0).UTC())
	if err != nil {
		t.Fatalf("new config: %v", err)
	}
	if err := newWebhookVault(t, db).UpsertOutboundWebhook(ctx, cfg); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	_ = db.Close()

	db2, err := postgres.Open(dsn)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = db2.Close() })
	got, err := newWebhookVault(t, db2).GetOutboundWebhook(ctx, "acct-verz")
	if err != nil {
		t.Fatalf("get after restart: %v", err)
	}
	if got.URL() != "https://verz.example.com/hook" || got.SigningSecret() != "whsec_original" || !got.Enabled() {
		t.Errorf("round-trip mismatch: %+v", got)
	}
}

// TestOutboundWebhookVaultSecretCiphertextAtRest proves the signing secret is NEVER
// stored in plaintext — the durable column holds ciphertext.
func TestOutboundWebhookVaultSecretCiphertextAtRest(t *testing.T) {
	t.Parallel()
	_, db := openVaultDB(t)
	ctx := context.Background()
	cfg, _ := outboundwebhook.New("acct-1", "https://e.com/h", "whsec_PLAINTEXT_MARKER", false, time.Unix(1700000000, 0).UTC())
	if err := newWebhookVault(t, db).UpsertOutboundWebhook(ctx, cfg); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	var sealed []byte
	if err := db.QueryRowContext(ctx, `SELECT signing_secret_sealed FROM account_outbound_webhook WHERE account_id = $1`, "acct-1").Scan(&sealed); err != nil {
		t.Fatalf("read sealed: %v", err)
	}
	if len(sealed) == 0 {
		t.Fatal("sealed column empty")
	}
	if bytes.Contains(sealed, []byte("whsec_PLAINTEXT_MARKER")) {
		t.Error("signing secret stored in plaintext at rest")
	}
}

// TestOutboundWebhookVaultAADRowBinding proves a sealed secret is bound to its
// account_id: relocating the ciphertext to a different account's row fails to open.
func TestOutboundWebhookVaultAADRowBinding(t *testing.T) {
	t.Parallel()
	_, db := openVaultDB(t)
	ctx := context.Background()
	v := newWebhookVault(t, db)
	cfg, _ := outboundwebhook.New("acct-A", "https://e.com/h", "whsec_A", true, time.Unix(1700000000, 0).UTC())
	if err := v.UpsertOutboundWebhook(ctx, cfg); err != nil {
		t.Fatalf("upsert A: %v", err)
	}
	// Copy A's sealed secret into a forged row for acct-B (confused-deputy / relocation).
	var sealed []byte
	if err := db.QueryRowContext(ctx, `SELECT signing_secret_sealed FROM account_outbound_webhook WHERE account_id = $1`, "acct-A").Scan(&sealed); err != nil {
		t.Fatalf("read A sealed: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO account_outbound_webhook (account_id, url, signing_secret_sealed, enabled, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		"acct-B", "https://e.com/h", sealed, 1, "2026-08-17T00:00:00Z", "2026-08-17T00:00:00Z"); err != nil {
		t.Fatalf("forge B row: %v", err)
	}
	if _, err := v.GetOutboundWebhook(ctx, "acct-B"); err == nil {
		t.Error("relocated ciphertext opened for acct-B; AAD row-binding not enforced")
	}
}

func TestOutboundWebhookVaultUpsertUpdates(t *testing.T) {
	t.Parallel()
	_, db := openVaultDB(t)
	ctx := context.Background()
	v := newWebhookVault(t, db)
	c1, _ := outboundwebhook.New("acct-1", "https://a.example.com/h", "whsec_1", true, time.Unix(1700000000, 0).UTC())
	if err := v.UpsertOutboundWebhook(ctx, c1); err != nil {
		t.Fatalf("upsert 1: %v", err)
	}
	c2 := outboundwebhook.Rehydrate("acct-1", "https://b.example.com/h", "whsec_2", false,
		time.Unix(1700000000, 0).UTC(), time.Unix(1700003600, 0).UTC())
	if err := v.UpsertOutboundWebhook(ctx, c2); err != nil {
		t.Fatalf("upsert 2: %v", err)
	}
	got, err := v.GetOutboundWebhook(ctx, "acct-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.URL() != "https://b.example.com/h" || got.SigningSecret() != "whsec_2" || got.Enabled() {
		t.Errorf("update not applied: %+v", got)
	}
}

func TestOutboundWebhookVaultGetNotFound(t *testing.T) {
	t.Parallel()
	_, db := openVaultDB(t)
	if _, err := newWebhookVault(t, db).GetOutboundWebhook(context.Background(), "nope"); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("get missing = %v; want ErrNotFound", err)
	}
}

func TestOutboundWebhookVaultDeleteIdempotent(t *testing.T) {
	t.Parallel()
	_, db := openVaultDB(t)
	ctx := context.Background()
	v := newWebhookVault(t, db)
	// Delete on empty is a no-op (idempotent).
	if err := v.DeleteOutboundWebhook(ctx, "acct-1"); err != nil {
		t.Fatalf("delete absent: %v", err)
	}
	cfg, _ := outboundwebhook.New("acct-1", "https://e.com/h", "whsec_1", true, time.Unix(1700000000, 0).UTC())
	if err := v.UpsertOutboundWebhook(ctx, cfg); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := v.DeleteOutboundWebhook(ctx, "acct-1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := v.GetOutboundWebhook(ctx, "acct-1"); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("get after delete = %v; want ErrNotFound", err)
	}
	// Second delete is still a no-op.
	if err := v.DeleteOutboundWebhook(ctx, "acct-1"); err != nil {
		t.Fatalf("second delete: %v", err)
	}
}

// TestOutboundWebhookVaultWrongKEKFailsClosed proves a config sealed under one KEK
// cannot be opened under another (tamper / wrong-key surfaces as an error).
func TestOutboundWebhookVaultWrongKEKFailsClosed(t *testing.T) {
	t.Parallel()
	_, db := openVaultDB(t)
	ctx := context.Background()
	cfg, _ := outboundwebhook.New("acct-1", "https://e.com/h", "whsec_1", true, time.Unix(1700000000, 0).UTC())
	if err := newWebhookVault(t, db).UpsertOutboundWebhook(ctx, cfg); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	wrong := postgres.NewOutboundWebhookVault(db, otherCipher(t), fixedClock{t: time.Unix(1700000000, 0).UTC()})
	if _, err := wrong.GetOutboundWebhook(ctx, "acct-1"); err == nil {
		t.Error("opened config under the wrong KEK; want fail-closed")
	}
}

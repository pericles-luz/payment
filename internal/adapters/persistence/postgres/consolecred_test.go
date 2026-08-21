package postgres_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"database/sql"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/consoleauth"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/postgres"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	domain "github.com/ia-dev-sindireceita/payment/internal/domain/consoleauth"
)

// compile-time checks that the durable console adapters satisfy the app ports the
// wiring hands to ConsoleAuthService (the swap-in for consoleauth.MemStore).
var (
	_ app.ConsoleCredentialStore = (*postgres.ConsoleCredentialVault)(nil)
	_ app.TOTPReplayStore        = (*postgres.ConsoleReplayStore)(nil)
)

// totpCodeAt derives the 6-digit RFC 6238 code for a base32 secret at instant `at`,
// replicating the domain's HOTP/SHA1/30s parameters so a test can present a code the
// verifier will accept. It is test-only generation of what the domain only verifies.
func totpCodeAt(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	s := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
	if err != nil {
		t.Fatalf("decode totp secret: %v", err)
	}
	counter := uint64(at.Unix() / 30)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])
	return fmt.Sprintf("%06d", bin%1_000_000)
}

// otherCipher builds an AES-256 cipher from a DIFFERENT fixed key than testCipher, to
// prove a credential sealed under one KEK cannot be opened under another.
func otherCipher(t *testing.T) *secret.Cipher {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = 0x11
	}
	c, err := secret.NewCipher(key)
	if err != nil {
		t.Fatalf("other cipher: %v", err)
	}
	return c
}

// TestConsoleCredentialVaultRoundTripSurvivesRestart is the core acceptance
// criterion (SIN-69432): a credential provisioned via the port is readable — and a
// login factor against it valid — after the store is recreated over the SAME database
// file (the restart the CEO surfaced), with the TOTP secret ciphertext at rest.
func TestConsoleCredentialVaultRoundTripSurvivesRestart(t *testing.T) {
	dsn, db := openVaultDB(t)
	clk := fixedClock{t: time.Unix(1700000000, 0).UTC()}

	// Fresh DB: no credential provisioned yet.
	v1 := postgres.NewConsoleCredentialVault(db, testCipher(t), clk)
	if _, ok, err := v1.GetCredential(context.Background()); err != nil || ok {
		t.Fatalf("fresh GetCredential = ok %v err %v; want ok=false err=nil", ok, err)
	}

	const password = "correct-horse-battery-staple"
	hash, err := domain.HashPassword(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	totpSecret, err := domain.GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("generate totp: %v", err)
	}
	cred := domain.NewCredential("pericles.luz", hash, totpSecret)
	if err := v1.SaveCredential(context.Background(), cred); err != nil {
		t.Fatalf("save credential: %v", err)
	}
	_ = db.Close()

	// Simulated restart: reopen a store over the same file with a fresh cipher (same
	// KEK) and a fresh DB handle.
	db2, err := postgres.Open(dsn)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = db2.Close() })
	v2 := postgres.NewConsoleCredentialVault(db2, testCipher(t), clk)
	got, ok, err := v2.GetCredential(context.Background())
	if err != nil || !ok {
		t.Fatalf("post-restart GetCredential = ok %v err %v; want ok=true", ok, err)
	}
	if got.Username() != "pericles.luz" {
		t.Errorf("username = %q; want pericles.luz", got.Username())
	}
	if !got.VerifyPassword(password) {
		t.Error("password did not verify after restart")
	}
	if got.TOTPSecret() != totpSecret {
		t.Error("totp secret did not round-trip after restart")
	}
	// A valid TOTP code against the restored secret is accepted (login factor works).
	code := totpCodeAt(t, got.TOTPSecret(), clk.t)
	if _, ok := domain.VerifyTOTP(got.TOTPSecret(), code, clk.t); !ok {
		t.Error("regenerated TOTP code not accepted against restored secret")
	}
}

// TestConsoleCredentialVaultSaveUpsert asserts SaveCredential upserts on the username
// (a rare legitimate re-provision after an explicit wipe updates rather than errors).
func TestConsoleCredentialVaultSaveUpsert(t *testing.T) {
	_, db := openVaultDB(t)
	clk := fixedClock{t: time.Unix(1700000000, 0).UTC()}
	v := postgres.NewConsoleCredentialVault(db, testCipher(t), clk)

	h1, _ := domain.HashPassword("first")
	s1, _ := domain.GenerateTOTPSecret()
	if err := v.SaveCredential(context.Background(), domain.NewCredential("op", h1, s1)); err != nil {
		t.Fatalf("save 1: %v", err)
	}
	h2, _ := domain.HashPassword("second")
	s2, _ := domain.GenerateTOTPSecret()
	if err := v.SaveCredential(context.Background(), domain.NewCredential("op", h2, s2)); err != nil {
		t.Fatalf("save 2: %v", err)
	}
	got, ok, err := v.GetCredential(context.Background())
	if err != nil || !ok {
		t.Fatalf("get = ok %v err %v", ok, err)
	}
	if !got.VerifyPassword("second") || got.VerifyPassword("first") {
		t.Error("upsert did not replace the password hash")
	}
	if got.TOTPSecret() != s2 {
		t.Error("upsert did not replace the totp secret")
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM console_credential`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Errorf("row count = %d; want 1 (upsert, not insert)", n)
	}
}

// TestConsoleCredentialVaultTOTPSecretCiphertextAtRest asserts the durable column
// holds ciphertext, not the plaintext base32 secret (encrypted-at-rest bar).
func TestConsoleCredentialVaultTOTPSecretCiphertextAtRest(t *testing.T) {
	_, db := openVaultDB(t)
	clk := fixedClock{t: time.Unix(1700000000, 0).UTC()}
	v := postgres.NewConsoleCredentialVault(db, testCipher(t), clk)

	totpSecret, err := domain.GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("generate totp: %v", err)
	}
	hash, _ := domain.HashPassword("pw")
	if err := v.SaveCredential(context.Background(), domain.NewCredential("op", hash, totpSecret)); err != nil {
		t.Fatalf("save: %v", err)
	}
	var sealed []byte
	if err := db.QueryRow(`SELECT totp_secret_sealed FROM console_credential`).Scan(&sealed); err != nil {
		t.Fatalf("read raw: %v", err)
	}
	if strings.Contains(string(sealed), totpSecret) {
		t.Fatal("plaintext TOTP secret found in the durable column")
	}
}

// TestConsoleCredentialVaultOpenFailsWithWrongKey ensures a credential sealed under
// one KEK cannot be opened under another (fail-closed decrypt).
func TestConsoleCredentialVaultOpenFailsWithWrongKey(t *testing.T) {
	_, db := openVaultDB(t)
	clk := fixedClock{t: time.Unix(1700000000, 0).UTC()}
	v := postgres.NewConsoleCredentialVault(db, testCipher(t), clk)
	totpSecret, _ := domain.GenerateTOTPSecret()
	hash, _ := domain.HashPassword("pw")
	if err := v.SaveCredential(context.Background(), domain.NewCredential("op", hash, totpSecret)); err != nil {
		t.Fatalf("save: %v", err)
	}
	v2 := postgres.NewConsoleCredentialVault(db, otherCipher(t), clk)
	if _, ok, err := v2.GetCredential(context.Background()); err == nil {
		t.Fatalf("GetCredential under wrong key = ok %v err nil; want error", ok)
	}
}

// TestConsoleCredentialVaultAADBindsUsername ensures the sealed TOTP secret is bound
// to its row's username: relocating the ciphertext to another username fails to open
// (defense in depth beyond the row lookup — secret.ConsoleAAD).
func TestConsoleCredentialVaultAADBindsUsername(t *testing.T) {
	_, db := openVaultDB(t)
	clk := fixedClock{t: time.Unix(1700000000, 0).UTC()}
	v := postgres.NewConsoleCredentialVault(db, testCipher(t), clk)
	totpSecret, _ := domain.GenerateTOTPSecret()
	hash, _ := domain.HashPassword("pw")
	if err := v.SaveCredential(context.Background(), domain.NewCredential("alice", hash, totpSecret)); err != nil {
		t.Fatalf("save: %v", err)
	}
	// Relocate the row to a different username WITHOUT resealing — the AAD no longer
	// matches, so the open must fail.
	if _, err := db.Exec(`UPDATE console_credential SET username = 'mallory'`); err != nil {
		t.Fatalf("relocate: %v", err)
	}
	if _, ok, err := v.GetCredential(context.Background()); err == nil {
		t.Fatalf("GetCredential after row relocation = ok %v err nil; want AAD open failure", ok)
	}
}

// TestConsoleReplayStoreRoundTripSurvivesRestart verifies the durable replay guard
// keeps the last consumed step across a restart, so a code cannot be replayed after a
// redeploy (an in-memory guard would re-open the window every restart).
func TestConsoleReplayStoreRoundTripSurvivesRestart(t *testing.T) {
	dsn, db := openVaultDB(t)
	clk := fixedClock{t: time.Unix(1700000000, 0).UTC()}
	r1 := postgres.NewConsoleReplayStore(db, clk)

	if step, err := r1.LastStep(context.Background(), "op"); err != nil || step != 0 {
		t.Fatalf("fresh LastStep = %d err %v; want 0", step, err)
	}
	if err := r1.SetLastStep(context.Background(), "op", 56789); err != nil {
		t.Fatalf("set last step: %v", err)
	}
	// Upsert with a later step.
	if err := r1.SetLastStep(context.Background(), "op", 56790); err != nil {
		t.Fatalf("update last step: %v", err)
	}
	_ = db.Close()

	db2, err := postgres.Open(dsn)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = db2.Close() })
	r2 := postgres.NewConsoleReplayStore(db2, clk)
	if step, err := r2.LastStep(context.Background(), "op"); err != nil || step != 56790 {
		t.Fatalf("post-restart LastStep = %d err %v; want 56790", step, err)
	}
	if step, err := r2.LastStep(context.Background(), "unknown"); err != nil || step != 0 {
		t.Fatalf("unknown subject LastStep = %d err %v; want 0", step, err)
	}
}

// TestConsoleAdaptersSurfaceDBErrors ensures every port method fails closed (returns
// an error, never a silent success) when the underlying DB is unavailable — a closed
// handle stands in for any transient store fault so the use-case layer's fail-closed
// paths (Provisioned=true on read error, replay=replayed on error) are reachable.
func TestConsoleAdaptersSurfaceDBErrors(t *testing.T) {
	_, db := openVaultDB(t)
	clk := fixedClock{t: time.Unix(1700000000, 0).UTC()}
	cv := postgres.NewConsoleCredentialVault(db, testCipher(t), clk)
	rs := postgres.NewConsoleReplayStore(db, clk)
	_ = db.Close() // force every subsequent query/exec to error

	hash, _ := domain.HashPassword("pw")
	if err := cv.SaveCredential(context.Background(), domain.NewCredential("op", hash, "GEZDGNBVGY3TQOJQ")); err == nil {
		t.Error("SaveCredential on closed DB = nil; want error")
	}
	if _, _, err := cv.GetCredential(context.Background()); err == nil {
		t.Error("GetCredential on closed DB = nil; want error")
	}
	if err := rs.SetLastStep(context.Background(), "op", 7); err == nil {
		t.Error("SetLastStep on closed DB = nil; want error")
	}
	if _, err := rs.LastStep(context.Background(), "op"); err == nil {
		t.Error("LastStep on closed DB = nil; want error")
	}
}

// buildConsoleService wires a ConsoleAuthService over the durable adapters at a given
// clock (sessions stay in-memory — losing a session on restart is acceptable).
func buildConsoleService(t *testing.T, db *sql.DB, clk fixedClock) *app.ConsoleAuthService {
	t.Helper()
	creds := postgres.NewConsoleCredentialVault(db, testCipher(t), clk)
	replay := postgres.NewConsoleReplayStore(db, clk)
	sessions := consoleauth.NewMemStore()
	return app.NewConsoleAuthService(creds, sessions, replay, clk,
		app.ConsoleAuthConfig{Username: "pericles.luz", BootstrapToken: "deploy-token"})
}

// TestConsoleBootstrapSurvivesRestartThenLocked drives the full use-case through the
// durable adapters: bootstrap provisions once, a login succeeds, and after a
// simulated restart the credential is still there (Provisioned) so a SECOND bootstrap
// is refused with ErrBootstrapLocked (the "409 on 2nd bootstrap after restart"
// acceptance criterion) — the caveat SIN-69261 is closed.
func TestConsoleBootstrapSurvivesRestartThenLocked(t *testing.T) {
	dsn, db := openVaultDB(t)
	clk := fixedClock{t: time.Unix(1700000000, 0).UTC()}

	svc1 := buildConsoleService(t, db, clk)
	res, err := svc1.Bootstrap(context.Background(), "deploy-token")
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	// Login works within the first process lifetime.
	code := totpCodeAt(t, res.TOTPSecret, clk.t)
	if _, err := svc1.Login(context.Background(), "pericles.luz", res.Password, code); err != nil {
		t.Fatalf("login pre-restart: %v", err)
	}
	_ = db.Close()

	// Simulated restart: brand-new handles/services over the same file.
	db2, err := postgres.Open(dsn)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = db2.Close() })
	svc2 := buildConsoleService(t, db2, clk)

	if !svc2.Provisioned(context.Background()) {
		t.Fatal("credential did not survive restart (Provisioned=false)")
	}
	// A second bootstrap after the restart is refused — single-use is durable.
	if _, err := svc2.Bootstrap(context.Background(), "deploy-token"); err != app.ErrBootstrapLocked {
		t.Fatalf("2nd bootstrap after restart = %v; want ErrBootstrapLocked", err)
	}
	// The original credential still logs in after the restart. Use a later clock so
	// the fresh TOTP step advances past the one consumed pre-restart (the durable
	// replay guard rejects a re-used step).
	later := fixedClock{t: clk.t.Add(60 * time.Second)}
	svcLater := buildConsoleService(t, db2, later)
	code2 := totpCodeAt(t, res.TOTPSecret, later.t)
	if _, err := svcLater.Login(context.Background(), "pericles.luz", res.Password, code2); err != nil {
		t.Fatalf("login post-restart: %v", err)
	}
}

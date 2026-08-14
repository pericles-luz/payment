package config

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// TestLogLoadedBankCreds_OnlyNonSecretPairs pins the startup observability line
// (SIN-66015 AC2/AC3): logLoadedBankCreds emits the loaded (tenant, bank) pairs
// and a count at info level, sorted for a stable line, and NEVER any secret
// material (clientID, secret, or creditor key).
func TestLogLoadedBankCreds_OnlyNonSecretPairs(t *testing.T) {
	const (
		secretA     = "s3cr:et:tail-A"
		clientA     = "client-id-AAAA"
		secretB     = "topsecret-BBBB"
		clientB     = "client-id-BBBB"
		creditorKey = "tenant@pix.example.com"
	)
	creds := map[string]ports.BankCredential{
		bankCredKey("tenantA", "c6"):   {TenantID: "tenantA", BankID: "c6", ClientID: clientA, Secret: secretA},
		bankCredKey("tenantA", "itau"): {TenantID: "tenantA", BankID: "itau", ClientID: clientB, Secret: secretB, CreditorKey: creditorKey},
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	logLoadedBankCreds(creds, logger)
	out := buf.String()

	if !strings.Contains(out, "loaded bank credentials") || !strings.Contains(out, "count=2") {
		t.Fatalf("missing info line or count=2: %q", out)
	}
	for _, want := range []string{"tenantA/c6", "tenantA/itau"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing non-secret pair %q in %q", want, out)
		}
	}
	for _, bad := range []string{secretA, clientA, secretB, clientB, creditorKey} {
		if strings.Contains(out, bad) {
			t.Fatalf("sensitive material %q leaked into startup log: %q", bad, out)
		}
	}
}

// TestLogLoadedBankCreds_SortedAndCountsEmpty pins the deterministic ordering of
// the pair list and that an empty map still logs a count=0 line (so "no
// credentials configured" is visible at startup rather than silent).
func TestLogLoadedBankCreds_SortedAndCountsEmpty(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	creds := map[string]ports.BankCredential{
		bankCredKey("zeta", "itau"): {TenantID: "zeta", BankID: "itau", ClientID: "z", Secret: "z"},
		bankCredKey("alpha", "c6"):  {TenantID: "alpha", BankID: "c6", ClientID: "a", Secret: "a"},
	}
	logLoadedBankCreds(creds, logger)
	out := buf.String()
	if ai, zi := strings.Index(out, "alpha/c6"), strings.Index(out, "zeta/itau"); ai < 0 || zi < 0 || ai > zi {
		t.Fatalf("pairs not sorted (alpha before zeta): %q", out)
	}

	buf.Reset()
	logLoadedBankCreds(map[string]ports.BankCredential{}, logger)
	if out := buf.String(); !strings.Contains(out, "count=0") {
		t.Fatalf("empty map should log count=0: %q", out)
	}
}

// TestLogLoadedBankCreds_NilLoggerDoesNotPanic guards the defensive fallback to
// the default logger.
func TestLogLoadedBankCreds_NilLoggerDoesNotPanic(t *testing.T) {
	logLoadedBankCreds(map[string]ports.BankCredential{
		bankCredKey("t", "c6"): {TenantID: "t", BankID: "c6", ClientID: "c", Secret: "s"},
	}, nil)
}

// TestFromEnv_StartupLogSurfacesPairsWithoutSecrets is the end-to-end boundary
// test (SIN-66015 AC2/AC4): loading the config emits the startup line via the
// default logger. It exercises BOTH a valid 4-field entry and a legacy 3-field
// entry whose secret contains ':' (the documented ambiguity). The misparse of the
// legacy entry surfaces as an UNEXPECTED orphan (tenant, bank) pair in the startup
// line — which is exactly the detection signal the log exists for — while no
// secret tail ever reaches the log.
func TestFromEnv_StartupLogSurfacesPairsWithoutSecrets(t *testing.T) {
	// Not parallel: mutates process env and the default logger.
	prev := slog.Default()
	var buf bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	for _, k := range []string{
		"PAYMENT_HTTP_ADDR", "PAYMENT_DB_PATH", "PAYMENT_TENANT_TOKENS",
		"PAYMENT_ADMIN_TOKENS", "PAYMENT_OPERATOR_TOKENS", "PAYMENT_WEBHOOK_REFS",
		"PAYMENT_BANK_CREDITOR_KEYS", "PAYMENT_RABBIT_URL",
	} {
		t.Setenv(k, "")
	}

	const (
		secret4 = "SEKRET4:withcolon" // valid 4-field secret, has ':'
		client4 = "CLIENT4NONSECRET"  // valid 4-field clientID
		legCID  = "cidL"              // legacy intended clientID -> misparsed as bank
		legSecA = "AABB"              // legacy secret head -> misparsed as clientID
		legSecB = "CCDD"              // legacy secret tail -> stored as secret
	)
	t.Setenv("PAYMENT_BANK_CREDS",
		"tenant4:itau:"+client4+":"+secret4+", tenantL:"+legCID+":"+legSecA+":"+legSecB)

	cfg := FromEnv()

	// Valid 4-field entry parsed at its explicit bank.
	if c, ok := cfg.BankCreds[bankCredKey("tenant4", "itau")]; !ok || c.ClientID != client4 || c.Secret != secret4 {
		t.Fatalf("4-field entry not parsed correctly: %+v", cfg.BankCreds)
	}
	// Documented ambiguity: the legacy colon-secret entry parsed as the 4-field
	// form, so the intended clientID landed in the BANK slot — an orphan pair.
	if _, ok := cfg.BankCreds[bankCredKey("tenantL", legCID)]; !ok {
		t.Fatalf("legacy colon-secret entry did not produce the documented orphan pair: %+v", cfg.BankCreds)
	}

	out := buf.String()
	if !strings.Contains(out, "loaded bank credentials") {
		t.Fatalf("startup line not emitted: %q", out)
	}
	// Both pairs surface — including the orphan, so an operator spots the misparse.
	for _, want := range []string{"tenant4/itau", "tenantL/" + legCID} {
		if !strings.Contains(out, want) {
			t.Fatalf("startup line missing pair %q: %q", want, out)
		}
	}
	// No secret material in the log: the valid secret/clientID and the legacy
	// secret head/tail must all be absent.
	for _, bad := range []string{secret4, client4, legSecA, legSecB} {
		if strings.Contains(out, bad) {
			t.Fatalf("sensitive material %q leaked into startup log: %q", bad, out)
		}
	}
}

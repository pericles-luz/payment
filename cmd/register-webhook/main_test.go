package main

import (
	"bytes"
	"context"
	"log"
	"strings"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// fakeRegistrar is an in-memory ports.PixWebhookRegistrar double: it records every
// registered URL keyed by (tenant, pixKey) and can be told to fail a given
// operation. It mirrors the PSP's keyed-by-PIX-key idempotency (a re-PUT replaces).
type fakeRegistrar struct {
	stored      map[string]string // "tenant|key" -> url
	registerErr map[string]error  // "tenant|key" -> error to return on Register
	getErr      map[string]error  // "tenant|key" -> error to return on Get
	getURL      map[string]string // override the URL returned by Get (mismatch tests)
}

func newFakeRegistrar() *fakeRegistrar {
	return &fakeRegistrar{
		stored:      map[string]string{},
		registerErr: map[string]error{},
		getErr:      map[string]error{},
		getURL:      map[string]string{},
	}
}

func key(tenant, pixKey string) string { return tenant + "|" + pixKey }

func (f *fakeRegistrar) RegisterWebhook(_ context.Context, tenantID, pixKey, webhookURL string) error {
	k := key(tenantID, pixKey)
	if err := f.registerErr[k]; err != nil {
		return err
	}
	f.stored[k] = webhookURL
	return nil
}

func (f *fakeRegistrar) GetWebhook(_ context.Context, tenantID, pixKey string) (ports.WebhookRegistration, error) {
	k := key(tenantID, pixKey)
	if err := f.getErr[k]; err != nil {
		return ports.WebhookRegistration{}, err
	}
	if u, ok := f.getURL[k]; ok {
		return ports.WebhookRegistration{WebhookURL: u}, nil
	}
	return ports.WebhookRegistration{WebhookURL: f.stored[k]}, nil
}

func cred(tenant, chave string) ports.BankCredential {
	return ports.BankCredential{TenantID: tenant, ClientID: "c", Secret: "s", CreditorKey: chave}
}

func TestRegisterAllSuccess(t *testing.T) {
	reg := newFakeRegistrar()
	refs := map[string]string{"refA": "t1", "refB": "t2"}
	creds := map[string]ports.BankCredential{
		"t1": cred("t1", "acme@pix.example"),
		"t2": cred("t2", "globex@pix.example"),
	}
	var out bytes.Buffer
	logger := log.New(&out, "", 0)

	if err := registerAll(context.Background(), reg, refs, creds, "https://payment.lmhost.com.br", logger); err != nil {
		t.Fatalf("registerAll: %v", err)
	}
	if reg.stored[key("t1", "acme@pix.example")] != "https://payment.lmhost.com.br/webhooks/c6/refA" {
		t.Fatalf("t1 url wrong: %q", reg.stored[key("t1", "acme@pix.example")])
	}
	if reg.stored[key("t2", "globex@pix.example")] != "https://payment.lmhost.com.br/webhooks/c6/refB" {
		t.Fatalf("t2 url wrong: %q", reg.stored[key("t2", "globex@pix.example")])
	}
	// The secret ref and full PIX key must never appear in the log.
	logs := out.String()
	for _, secret := range []string{"refA", "refB", "acme@pix.example", "globex@pix.example"} {
		if strings.Contains(logs, secret) {
			t.Fatalf("log leaked secret %q:\n%s", secret, logs)
		}
	}
	if !strings.Contains(logs, "OK (registered + confirmed)") {
		t.Fatalf("expected success log, got:\n%s", logs)
	}
}

// Re-running registerAll twice yields the same single stored URL (idempotent).
func TestRegisterAllIdempotent(t *testing.T) {
	reg := newFakeRegistrar()
	refs := map[string]string{"refA": "t1"}
	creds := map[string]ports.BankCredential{"t1": cred("t1", "acme@pix.example")}
	logger := log.New(&bytes.Buffer{}, "", 0)

	for i := 0; i < 2; i++ {
		if err := registerAll(context.Background(), reg, refs, creds, "https://x", logger); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
	if len(reg.stored) != 1 {
		t.Fatalf("idempotent re-run must keep a single registration, got %d", len(reg.stored))
	}
}

func TestRegisterAllMissingCreditorKey(t *testing.T) {
	reg := newFakeRegistrar()
	refs := map[string]string{"refA": "t1"}
	creds := map[string]ports.BankCredential{"t1": cred("t1", "")} // no key
	var out bytes.Buffer
	logger := log.New(&out, "", 0)

	err := registerAll(context.Background(), reg, refs, creds, "https://x", logger)
	if err == nil {
		t.Fatal("expected failure when a tenant has no creditor key")
	}
	if len(reg.stored) != 0 {
		t.Fatalf("nothing should be registered, got %d", len(reg.stored))
	}
	if !strings.Contains(out.String(), "provisioning gap") {
		t.Fatalf("expected provisioning-gap log, got:\n%s", out.String())
	}
}

func TestRegisterAllRegisterFailureIsCollected(t *testing.T) {
	reg := newFakeRegistrar()
	reg.registerErr[key("t2", "globex@pix.example")] = shared.ErrUnavailable
	refs := map[string]string{"refA": "t1", "refB": "t2"}
	creds := map[string]ports.BankCredential{
		"t1": cred("t1", "acme@pix.example"),
		"t2": cred("t2", "globex@pix.example"),
	}
	logger := log.New(&bytes.Buffer{}, "", 0)

	err := registerAll(context.Background(), reg, refs, creds, "https://x", logger)
	if err == nil || !strings.Contains(err.Error(), "1 of 2") {
		t.Fatalf("expected aggregated 1-of-2 failure, got %v", err)
	}
	// The healthy tenant still got registered (one bad tenant doesn't abort the rest).
	if reg.stored[key("t1", "acme@pix.example")] == "" {
		t.Fatal("healthy tenant should still be registered")
	}
}

func TestRegisterAllConfirmFailureIsCollected(t *testing.T) {
	reg := newFakeRegistrar()
	reg.getErr[key("t1", "acme@pix.example")] = shared.ErrNotFound
	refs := map[string]string{"refA": "t1"}
	creds := map[string]ports.BankCredential{"t1": cred("t1", "acme@pix.example")}
	var out bytes.Buffer
	logger := log.New(&out, "", 0)

	if err := registerAll(context.Background(), reg, refs, creds, "https://x", logger); err == nil {
		t.Fatal("expected failure when confirmation read fails")
	}
	if !strings.Contains(out.String(), "FAILED to confirm") {
		t.Fatalf("expected confirm-failure log, got:\n%s", out.String())
	}
}

func TestRegisterAllConfirmMismatchIsCollected(t *testing.T) {
	reg := newFakeRegistrar()
	refs := map[string]string{"refA": "t1"}
	creds := map[string]ports.BankCredential{"t1": cred("t1", "acme@pix.example")}
	// The PSP reports a different URL than we PUT.
	reg.getURL[key("t1", "acme@pix.example")] = "https://evil.example/webhooks/c6/other"
	var out bytes.Buffer
	logger := log.New(&out, "", 0)

	err := registerAll(context.Background(), reg, refs, creds, "https://x", logger)
	if err == nil {
		t.Fatal("expected failure on confirmation mismatch")
	}
	logs := out.String()
	if !strings.Contains(logs, "MISMATCH") {
		t.Fatalf("expected mismatch log, got:\n%s", logs)
	}
	// Neither URL (both ref-bearing) may be printed.
	if strings.Contains(logs, "evil.example") || strings.Contains(logs, "/webhooks/c6/") {
		t.Fatalf("mismatch log leaked a URL:\n%s", logs)
	}
}

func TestMaskKey(t *testing.T) {
	tests := []struct{ in, want string }{
		{"acme@pix.example", "a***e"},
		{"abcd", "****"},
		{"a", "****"},
		{"", "****"},
		{"+5511999998888", "+***8"},
	}
	for _, tc := range tests {
		if got := maskKey(tc.in); got != tc.want {
			t.Fatalf("maskKey(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// run refuses to proceed against the stub / without mTLS / without refs. These
// guard the operator from a cert-less or stub run (secure-by-default). Each
// subtest clears then sets the PAYMENT_* env via t.Setenv (so it cannot run in
// parallel) and asserts the matching refusal.
func TestRunRefusesUnsafeConfig(t *testing.T) {
	logger := log.New(&bytes.Buffer{}, "", 0)
	clearEnv := func(t *testing.T) {
		for _, k := range []string{
			"PAYMENT_C6_BASE_URL", "PAYMENT_C6_TOKEN_URL",
			"PAYMENT_C6_CLIENT_CERT", "PAYMENT_C6_CLIENT_KEY",
			"PAYMENT_WEBHOOK_REFS", "PAYMENT_BANK_CREDS",
		} {
			t.Setenv(k, "")
		}
	}

	t.Run("no base url", func(t *testing.T) {
		clearEnv(t)
		if err := run(logger); err == nil || !strings.Contains(err.Error(), "PAYMENT_C6_BASE_URL") {
			t.Fatalf("expected base-url refusal, got %v", err)
		}
	})
	t.Run("no mtls", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("PAYMENT_C6_BASE_URL", "https://api.c6.example")
		t.Setenv("PAYMENT_C6_TOKEN_URL", "https://api.c6.example/token")
		if err := run(logger); err == nil || !strings.Contains(err.Error(), "mTLS") {
			t.Fatalf("expected mTLS refusal, got %v", err)
		}
	})
	t.Run("no refs", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("PAYMENT_C6_BASE_URL", "https://api.c6.example")
		t.Setenv("PAYMENT_C6_TOKEN_URL", "https://api.c6.example/token")
		t.Setenv("PAYMENT_C6_CLIENT_CERT", "/tmp/does-not-exist-cert.pem")
		t.Setenv("PAYMENT_C6_CLIENT_KEY", "/tmp/does-not-exist-key.pem")
		// PAYMENT_WEBHOOK_REFS stays empty: the refs gate must trip before the cert
		// load, so the refusal names the refs (deterministic ordering).
		if err := run(logger); err == nil || !strings.Contains(err.Error(), "PAYMENT_WEBHOOK_REFS") {
			t.Fatalf("expected refs gate refusal, got %v", err)
		}
	})
}

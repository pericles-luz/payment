package outboundwebhook_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/outboundwebhook"
)

// expectedSig recomputes the reference signature independently of the implementation, so
// the test pins the wire contract (a receiver library must be able to reproduce it).
func expectedSig(secret string, ts int64, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(ts, 10)))
	mac.Write([]byte("."))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// T-HMAC-sign: Sign produces the HMAC-SHA256 of "<ts>.<body>" under the secret, prefixed
// sha256=, and is deterministic.
func TestSignMatchesReferenceHMAC(t *testing.T) {
	t.Parallel()
	secret := "whsec_supersecret"
	ts := int64(1755440000)
	body := []byte(`{"event_key":"ek-1","event_type":"payment.paid"}`)

	got := outboundwebhook.Sign(secret, ts, body)
	if want := expectedSig(secret, ts, body); got != want {
		t.Fatalf("Sign = %q, want %q", got, want)
	}
	if !strings.HasPrefix(got, "sha256=") {
		t.Fatalf("signature %q missing fixed sha256= algorithm tag", got)
	}
	// Deterministic: same inputs, same output.
	if again := outboundwebhook.Sign(secret, ts, body); again != got {
		t.Fatalf("Sign not deterministic: %q vs %q", again, got)
	}
}

// T-HMAC-tamper: changing the body OR the timestamp changes the MAC (both are bound in),
// and a wrong secret never verifies — the anti-forgery / anti-replay property (§5, S2/E2).
func TestSignDetectsTamper(t *testing.T) {
	t.Parallel()
	secret := "whsec_supersecret"
	ts := int64(1755440000)
	body := []byte(`{"amount":100}`)
	base := outboundwebhook.Sign(secret, ts, body)

	// Tampered body.
	if outboundwebhook.Sign(secret, ts, []byte(`{"amount":999}`)) == base {
		t.Fatal("tampered body produced the same signature")
	}
	// Replayed with a fresh timestamp: the signed timestamp is bound in, so the MAC differs.
	if outboundwebhook.Sign(secret, ts+1, body) == base {
		t.Fatal("changed timestamp produced the same signature (replay not detected)")
	}
	// Wrong secret.
	if outboundwebhook.Sign("whsec_other", ts, body) == base {
		t.Fatal("wrong secret produced the same signature")
	}
}

// The Config.Sign method signs with the config's own transient secret and equals the
// package function over that secret — so the forwarder never touches the raw secret.
func TestConfigSignUsesOwnSecret(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 17, 15, 0, 0, 0, time.UTC)
	secret, err := outboundwebhook.GenerateSigningSecret()
	if err != nil {
		t.Fatalf("gen secret: %v", err)
	}
	cfg, err := outboundwebhook.New("acct-1", "https://hooks.example.com/x", secret, true, now)
	if err != nil {
		t.Fatalf("new config: %v", err)
	}
	ts := now.Unix()
	body := []byte(`{"hello":"world"}`)
	if got, want := cfg.Sign(ts, body), outboundwebhook.Sign(secret, ts, body); got != want {
		t.Fatalf("Config.Sign = %q, want %q", got, want)
	}
}

// T-REDACT: the signing secret never appears in the signature output (it is a MAC, not the
// key) nor in the Config's structured-log value (LogValue redacts it).
func TestSecretNeverLeaksInSignatureOrLog(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 17, 15, 0, 0, 0, time.UTC)
	secret := "whsec_topsecretvalue"
	cfg, err := outboundwebhook.New("acct-1", "https://hooks.example.com/x", secret, true, now)
	if err != nil {
		t.Fatalf("new config: %v", err)
	}
	sig := cfg.Sign(now.Unix(), []byte("body"))
	if strings.Contains(sig, secret) || strings.Contains(sig, "topsecret") {
		t.Fatalf("signature leaked the secret: %q", sig)
	}
	// LogValue must redact the secret.
	rendered := cfg.LogValue().String()
	if strings.Contains(rendered, secret) || strings.Contains(rendered, "topsecret") {
		t.Fatalf("LogValue leaked the secret: %q", rendered)
	}
	if !strings.Contains(rendered, "[REDACTED]") {
		t.Fatalf("LogValue did not redact the secret: %q", rendered)
	}
}

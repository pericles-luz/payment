package secret_test

import (
	"bytes"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
)

// TestOutboundWebhookAADBindsAndSeparates proves the outbound-webhook AAD is
// account-bound, length-prefixed (no collision across account boundaries) and carries
// a distinct domain tag so it never collides with the bank-vault or console schemes.
func TestOutboundWebhookAADBindsAndSeparates(t *testing.T) {
	t.Parallel()
	a := secret.OutboundWebhookAAD("acct-1")
	if !bytes.Contains(a, []byte("payment/outbound-webhook/row/v1")) {
		t.Errorf("AAD missing domain tag: %q", a)
	}
	// Different accounts → different AAD.
	if bytes.Equal(a, secret.OutboundWebhookAAD("acct-2")) {
		t.Error("AAD collides across accounts")
	}
	// Length-prefixing prevents ("ab","")-vs-("a","b")-style ambiguity; here just prove
	// two accounts that would concatenate ambiguously stay distinct.
	if bytes.Equal(secret.OutboundWebhookAAD("aab"), secret.OutboundWebhookAAD("aa")) {
		t.Error("AAD ambiguous under concatenation")
	}
	// Distinct from the other binding schemes.
	if bytes.Equal(secret.OutboundWebhookAAD("x"), secret.ConsoleAAD("x")) {
		t.Error("outbound-webhook AAD collides with console AAD")
	}
	if bytes.Equal(secret.OutboundWebhookAAD("x"), secret.RowAAD("x", "")) {
		t.Error("outbound-webhook AAD collides with bank-vault RowAAD")
	}
}

// TestOutboundWebhookAADRoundTrip proves a seal bound to one account fails to open
// under a different account's AAD.
func TestOutboundWebhookAADRoundTrip(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x5A}, 32)
	c, err := secret.NewCipher(key)
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	sealed, err := c.SealWithAAD([]byte("whsec_secret"), secret.OutboundWebhookAAD("acct-1"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	// Correct AAD opens.
	got, err := c.OpenWithAAD(sealed, secret.OutboundWebhookAAD("acct-1"))
	if err != nil || string(got) != "whsec_secret" {
		t.Fatalf("open correct AAD = %q, %v", got, err)
	}
	// Wrong account AAD fails.
	if _, err := c.OpenWithAAD(sealed, secret.OutboundWebhookAAD("acct-2")); err == nil {
		t.Error("opened under wrong account AAD; row-binding not enforced")
	}
}

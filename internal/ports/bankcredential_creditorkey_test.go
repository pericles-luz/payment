package ports_test

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

const routingKey = "do-not-print-this-routing-key@pix.example"

func credWithCreditorKey() ports.BankCredential {
	return ports.BankCredential{TenantID: "ten-1", ClientID: "cid-9", Secret: "sec", CreditorKey: routingKey}
}

// TestBankCredentialStringRedactsCreditorKey asserts the routing-sensitive
// creditor key (chave do recebedor) never reaches a Stringer-driven format verb.
// The key is not a secret but it IS fund-routing data; an error/log path that
// prints a credential must not leak it (threat C1/C4; ADR-0004 / SIN-65862).
func TestBankCredentialStringRedactsCreditorKey(t *testing.T) {
	t.Parallel()
	c := credWithCreditorKey()
	for _, verb := range []string{"%v", "%s", "%+v"} {
		out := fmt.Sprintf(verb, c)
		if strings.Contains(out, routingKey) {
			t.Fatalf("%s leaked the creditor key: %q", verb, out)
		}
		if !strings.Contains(out, "REDACTED") {
			t.Fatalf("%s missing redaction marker: %q", verb, out)
		}
	}
}

// TestBankCredentialLogValueRedactsCreditorKey asserts structured logging never
// emits the creditor key, even when the credential is logged as an attribute.
func TestBankCredentialLogValueRedactsCreditorKey(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	logger.Info("credential resolved", "credential", credWithCreditorKey())

	out := buf.String()
	if strings.Contains(out, routingKey) {
		t.Fatalf("slog leaked the creditor key: %q", out)
	}
	if !strings.Contains(out, "creditor_key=[REDACTED]") {
		t.Fatalf("slog missing creditor_key redaction marker: %q", out)
	}
}

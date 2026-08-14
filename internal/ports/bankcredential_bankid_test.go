package ports_test

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// credMultiBank carries an explicit, non-secret bank id alongside a secret and a
// routing-sensitive creditor key.
func credMultiBank() ports.BankCredential {
	return ports.BankCredential{
		TenantID:    "ten-1",
		BankID:      "itau",
		ClientID:    "cid-9",
		Secret:      "do-not-print-this-secret",
		CreditorKey: "do-not-print-this-routing-key@pix.example",
	}
}

// TestBankCredentialStringExposesBankID asserts the non-secret bank id IS surfaced
// by Stringer (it is needed in logs/audit to reconstruct which bank routed a
// charge, ADR-0007 T4) while the secret and creditor key stay redacted.
func TestBankCredentialStringExposesBankID(t *testing.T) {
	t.Parallel()
	c := credMultiBank()
	for _, verb := range []string{"%v", "%s", "%+v"} {
		out := fmt.Sprintf(verb, c)
		if !strings.Contains(out, "itau") {
			t.Fatalf("%s dropped non-secret bank id: %q", verb, out)
		}
		if strings.Contains(out, c.Secret) || strings.Contains(out, c.CreditorKey) {
			t.Fatalf("%s leaked a sensitive field: %q", verb, out)
		}
		if !strings.Contains(out, "REDACTED") {
			t.Fatalf("%s missing redaction marker: %q", verb, out)
		}
	}
}

// TestBankCredentialLogValueExposesBankID asserts structured logging emits the
// bank id as a non-secret attribute while keeping the secret and creditor key
// redacted (ADR-0007 T4).
func TestBankCredentialLogValueExposesBankID(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	logger.Info("credential resolved", "credential", credMultiBank())

	out := buf.String()
	if !strings.Contains(out, "bank_id=itau") {
		t.Fatalf("slog missing bank_id attribute: %q", out)
	}
	c := credMultiBank()
	if strings.Contains(out, c.Secret) || strings.Contains(out, c.CreditorKey) {
		t.Fatalf("slog leaked a sensitive field: %q", out)
	}
	if !strings.Contains(out, "secret=[REDACTED]") || !strings.Contains(out, "creditor_key=[REDACTED]") {
		t.Fatalf("slog missing redaction markers: %q", out)
	}
}

package ports_test

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

const redactSecret = "do-not-print-this-secret"

func newCred() ports.BankCredential {
	return ports.BankCredential{TenantID: "ten-1", ClientID: "cid-9", Secret: redactSecret}
}

// TestBankCredentialStringRedactsSecret asserts no fmt verb that uses Stringer
// (%v/%s/%+v) prints the secret.
func TestBankCredentialStringRedactsSecret(t *testing.T) {
	t.Parallel()
	c := newCred()
	for _, verb := range []string{"%v", "%s", "%+v"} {
		out := fmt.Sprintf(verb, c)
		if strings.Contains(out, redactSecret) {
			t.Fatalf("%s leaked the secret: %q", verb, out)
		}
		if !strings.Contains(out, "REDACTED") {
			t.Fatalf("%s missing redaction marker: %q", verb, out)
		}
		if !strings.Contains(out, "cid-9") || !strings.Contains(out, "ten-1") {
			t.Fatalf("%s dropped non-secret fields: %q", verb, out)
		}
	}
}

// TestBankCredentialLogValueRedactsSecret asserts structured logging never emits
// the secret even when the credential is logged as an attribute value.
func TestBankCredentialLogValueRedactsSecret(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	logger.Info("credential stored", "credential", newCred())

	out := buf.String()
	if strings.Contains(out, redactSecret) {
		t.Fatalf("slog leaked the secret: %q", out)
	}
	if !strings.Contains(out, "REDACTED") {
		t.Fatalf("slog missing redaction marker: %q", out)
	}
	if !strings.Contains(out, "cid-9") || !strings.Contains(out, "ten-1") {
		t.Fatalf("slog dropped non-secret fields: %q", out)
	}
}

func TestChargeResultAmountReconciled(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		expected int64
		received int64
		want     bool
	}{
		{"exact match settles", 1050, 1050, true},
		{"partial payment does not reconcile", 1050, 500, false},
		{"overpayment does not reconcile", 1050, 1100, false},
		{"unpaid charge does not reconcile", 1050, 0, false},
		{"degenerate zero-expected never reconciles", 0, 0, false},
		{"zero-expected with receipt never reconciles", 0, 100, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := ports.ChargeResult{
				Status:              "paid",
				ExpectedAmountCents: tc.expected,
				ReceivedAmountCents: tc.received,
			}
			if got := r.AmountReconciled(); got != tc.want {
				t.Fatalf("AmountReconciled(expected=%d, received=%d): want %v, got %v",
					tc.expected, tc.received, tc.want, got)
			}
		})
	}
}

func TestPixChargeResultAmountReconciled(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		expected int64
		received int64
		want     bool
	}{
		{"exact match settles", 1050, 1050, true},
		{"partial payment does not reconcile", 1050, 500, false},
		{"overpayment does not reconcile", 1050, 1100, false},
		{"unpaid charge does not reconcile", 1050, 0, false},
		{"degenerate zero-expected never reconciles", 0, 0, false},
		{"zero-expected with receipt never reconciles", 0, 100, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := ports.PixChargeResult{
				Status:              "CONCLUIDA",
				ExpectedAmountCents: tc.expected,
				ReceivedAmountCents: tc.received,
			}
			if got := r.AmountReconciled(); got != tc.want {
				t.Fatalf("AmountReconciled(expected=%d, received=%d): want %v, got %v",
					tc.expected, tc.received, tc.want, got)
			}
		})
	}
}

func TestPixDueChargeResultAmountReconciled(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		expected int64
		received int64
		want     bool
	}{
		{"exact match settles", 1050, 1050, true},
		{"partial payment does not reconcile", 1050, 500, false},
		{"overpayment does not reconcile", 1050, 1100, false},
		{"unpaid charge does not reconcile", 1050, 0, false},
		{"degenerate zero-expected never reconciles", 0, 0, false},
		{"zero-expected with receipt never reconciles", 0, 100, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := ports.PixDueChargeResult{
				Status:              "CONCLUIDA",
				ExpectedAmountCents: tc.expected,
				ReceivedAmountCents: tc.received,
			}
			if got := r.AmountReconciled(); got != tc.want {
				t.Fatalf("AmountReconciled(expected=%d, received=%d): want %v, got %v",
					tc.expected, tc.received, tc.want, got)
			}
		})
	}
}

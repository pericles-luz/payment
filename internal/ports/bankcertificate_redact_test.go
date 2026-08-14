package ports_test

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

const certPrivateKey = "-----BEGIN PRIVATE KEY-----\nDO-NOT-PRINT-THIS-KEY\n-----END PRIVATE KEY-----"

func certWithKey() ports.BankCertificate {
	return ports.BankCertificate{
		TenantID: "ten-1",
		BankID:   "c6",
		CertPEM:  "-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----",
		KeyPEM:   certPrivateKey,
	}
}

// TestBankCertificateStringRedactsKey asserts the private key never reaches a
// Stringer-driven format verb (threat C1/C4), mirroring BankCredential.
func TestBankCertificateStringRedactsKey(t *testing.T) {
	t.Parallel()
	c := certWithKey()
	for _, verb := range []string{"%v", "%s", "%+v"} {
		out := fmt.Sprintf(verb, c)
		if strings.Contains(out, "DO-NOT-PRINT-THIS-KEY") {
			t.Fatalf("%s leaked the private key: %q", verb, out)
		}
		if !strings.Contains(out, "REDACTED") {
			t.Fatalf("%s missing redaction marker: %q", verb, out)
		}
	}
}

// TestBankCertificateLogValueRedactsKey asserts structured logging never emits the
// private key, even when the certificate is logged as an attribute.
func TestBankCertificateLogValueRedactsKey(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	logger.Info("certificate stored", "certificate", certWithKey())

	out := buf.String()
	if strings.Contains(out, "DO-NOT-PRINT-THIS-KEY") {
		t.Fatalf("slog leaked the private key: %q", out)
	}
	if !strings.Contains(out, "key_pem=[REDACTED]") {
		t.Fatalf("slog missing key_pem redaction marker: %q", out)
	}
}

// TestBankCertificateCertPresenceAbsent pins the absent-cert branch of the
// presence helper used in String()/LogValue().
func TestBankCertificateCertPresenceAbsent(t *testing.T) {
	t.Parallel()
	c := ports.BankCertificate{TenantID: "t", BankID: "c6"}
	if out := fmt.Sprintf("%v", c); !strings.Contains(out, "[absent]") {
		t.Fatalf("empty CertPEM should render as [absent]: %q", out)
	}
}

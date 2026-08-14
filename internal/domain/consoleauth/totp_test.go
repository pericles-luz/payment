package consoleauth

import (
	"strings"
	"testing"
	"time"
)

// currentCode computes the valid TOTP for a secret at a moment, using the same
// primitive the verifier uses, so tests do not hard-code a golden value.
func currentCode(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	key, err := decodeSecret(secret)
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}
	return hotp(key, uint64(at.Unix()/totpPeriod))
}

func TestVerifyTOTPMatchAndStep(t *testing.T) {
	t.Parallel()
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	code := currentCode(t, secret, now)
	step, ok := VerifyTOTP(secret, code, now)
	if !ok {
		t.Fatal("current code did not verify")
	}
	if want := now.Unix() / totpPeriod; step != want {
		t.Fatalf("step = %d, want %d", step, want)
	}
}

func TestVerifyTOTPSkewWindow(t *testing.T) {
	t.Parallel()
	secret, _ := GenerateTOTPSecret()
	base := time.Unix(1_700_000_000, 0).UTC()
	// A code minted one step in the past is accepted (±1 skew) when verified now.
	prev := base.Add(-totpPeriod * time.Second)
	code := currentCode(t, secret, prev)
	if _, ok := VerifyTOTP(secret, code, base); !ok {
		t.Fatal("code from previous step should verify within skew")
	}
	// Two steps away is outside the window.
	old := base.Add(-2 * totpPeriod * time.Second)
	oldCode := currentCode(t, secret, old)
	if _, ok := VerifyTOTP(secret, oldCode, base); ok {
		t.Fatal("code two steps old should NOT verify")
	}
}

func TestVerifyTOTPRejects(t *testing.T) {
	t.Parallel()
	secret, _ := GenerateTOTPSecret()
	now := time.Unix(1_700_000_000, 0).UTC()
	cases := []struct {
		name, secret, code string
	}{
		{"wrong-code", secret, "000000"},
		{"short-code", secret, "123"},
		{"long-code", secret, "1234567"},
		{"empty-code", secret, ""},
		{"bad-secret", "not base32 !!!", currentCode(t, secret, now)},
		{"empty-secret", "", "123456"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, ok := VerifyTOTP(tc.secret, tc.code, now); ok {
				t.Fatalf("%s unexpectedly verified", tc.name)
			}
		})
	}
}

func TestVerifyTOTPLowercaseAndSpaces(t *testing.T) {
	t.Parallel()
	secret, _ := GenerateTOTPSecret()
	now := time.Unix(1_700_000_000, 0).UTC()
	code := currentCode(t, secret, now)
	// Authenticator apps display the secret lower-cased and grouped by spaces; the
	// verifier must tolerate that form of the SAME secret.
	munged := strings.ToLower(secret[:4] + " " + secret[4:])
	if _, ok := VerifyTOTP(munged, code, now); !ok {
		t.Fatal("lower-cased/spaced secret should still verify")
	}
}

func TestOTPAuthURI(t *testing.T) {
	t.Parallel()
	uri := OTPAuthURI("Pagamentos Admin", "pericles.luz", "ABCDEF")
	for _, want := range []string{
		"otpauth://totp/",
		"secret=ABCDEF",
		"issuer=Pagamentos+Admin",
		"algorithm=SHA1",
		"digits=6",
		"period=30",
	} {
		if !strings.Contains(uri, want) {
			t.Fatalf("otpauth URI %q missing %q", uri, want)
		}
	}
}

func TestGenerateTOTPSecretDecodes(t *testing.T) {
	t.Parallel()
	s, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	key, err := decodeSecret(s)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(key) != totpSecretBytes {
		t.Fatalf("secret decodes to %d bytes, want %d", len(key), totpSecretBytes)
	}
}

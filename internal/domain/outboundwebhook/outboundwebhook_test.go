package outboundwebhook_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/outboundwebhook"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

var testNow = time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)

func TestGenerateSigningSecretShapeAndUniqueness(t *testing.T) {
	t.Parallel()
	s1, err := outboundwebhook.GenerateSigningSecret()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if !strings.HasPrefix(s1, "whsec_") {
		t.Errorf("secret %q missing whsec_ prefix", s1)
	}
	// whsec_ + base64url(32 bytes) = 6 + 43 chars.
	if len(s1) != 6+43 {
		t.Errorf("secret length = %d; want 49", len(s1))
	}
	s2, err := outboundwebhook.GenerateSigningSecret()
	if err != nil {
		t.Fatalf("generate 2: %v", err)
	}
	if s1 == s2 {
		t.Error("two generated secrets are equal; entropy source is broken")
	}
}

func TestValidateURL(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{"valid https", "https://example.com/webhooks/sind", false},
		{"valid https with port+query", "https://host.example.com:8443/hook?x=1", false},
		{"trims whitespace", "  https://example.com/h  ", false},
		{"empty", "", true},
		{"blank", "   ", true},
		{"http rejected", "http://example.com/h", true},
		{"ftp rejected", "ftp://example.com/h", true},
		{"no scheme", "example.com/h", true},
		{"no host", "https:///path", true},
		{"embedded credentials", "https://user:pass@example.com/h", true},
		{"not a url", "https://%zz", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := outboundwebhook.ValidateURL(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ValidateURL(%q) = %q, nil; want error", tc.in, got)
				}
				if !errorsIsValidation(err) {
					t.Errorf("ValidateURL(%q) err = %v; want a validation error", tc.in, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateURL(%q) unexpected err: %v", tc.in, err)
			}
			if got != strings.TrimSpace(tc.in) {
				t.Errorf("ValidateURL(%q) = %q; want trimmed input", tc.in, got)
			}
		})
	}
}

func TestValidateURLTooLong(t *testing.T) {
	t.Parallel()
	long := "https://example.com/" + strings.Repeat("a", 2100)
	if _, err := outboundwebhook.ValidateURL(long); err == nil {
		t.Fatal("expected error for over-long URL")
	}
}

func TestNewInvariants(t *testing.T) {
	t.Parallel()
	if _, err := outboundwebhook.New("", "https://e.com/h", "whsec_x", true, testNow); err == nil {
		t.Error("empty account id should fail")
	}
	if _, err := outboundwebhook.New("acct-1", "http://e.com/h", "whsec_x", true, testNow); err == nil {
		t.Error("non-https URL should fail")
	}
	if _, err := outboundwebhook.New("acct-1", "https://e.com/h", "  ", true, testNow); err == nil {
		t.Error("empty signing secret should fail")
	}
	cfg, err := outboundwebhook.New(" acct-1 ", "https://e.com/h", "whsec_secret", true, testNow)
	if err != nil {
		t.Fatalf("valid New: %v", err)
	}
	if cfg.AccountID() != "acct-1" {
		t.Errorf("account id = %q; want trimmed acct-1", cfg.AccountID())
	}
	if cfg.URL() != "https://e.com/h" || cfg.SigningSecret() != "whsec_secret" || !cfg.Enabled() {
		t.Errorf("fields not set: %+v", cfg)
	}
	if !cfg.CreatedAt().Equal(testNow) || !cfg.UpdatedAt().Equal(testNow) {
		t.Error("timestamps not stamped to now on New")
	}
}

func TestSetURLAndEnabled(t *testing.T) {
	t.Parallel()
	cfg, _ := outboundwebhook.New("acct-1", "https://e.com/h", "whsec_secret", false, testNow)
	later := testNow.Add(time.Hour)
	if err := cfg.SetURL("http://bad", later); err == nil {
		t.Error("SetURL should reject non-https")
	}
	if cfg.URL() != "https://e.com/h" {
		t.Error("SetURL should not mutate on validation error")
	}
	if err := cfg.SetURL("https://new.example.com/h2", later); err != nil {
		t.Fatalf("SetURL valid: %v", err)
	}
	if cfg.URL() != "https://new.example.com/h2" || !cfg.UpdatedAt().Equal(later) {
		t.Error("SetURL did not apply url + updated_at")
	}
	cfg.SetEnabled(true, later.Add(time.Minute))
	if !cfg.Enabled() {
		t.Error("SetEnabled(true) not applied")
	}
}

func TestRotateSecret(t *testing.T) {
	t.Parallel()
	cfg, _ := outboundwebhook.New("acct-1", "https://e.com/h", "whsec_old", true, testNow)
	later := testNow.Add(time.Hour)
	newSecret, err := cfg.RotateSecret(later)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if newSecret == "whsec_old" || cfg.SigningSecret() != newSecret {
		t.Error("rotate did not replace the secret")
	}
	if !strings.HasPrefix(newSecret, "whsec_") {
		t.Errorf("rotated secret %q missing prefix", newSecret)
	}
	if !cfg.UpdatedAt().Equal(later) {
		t.Error("rotate did not stamp updated_at")
	}
}

func TestRehydrate(t *testing.T) {
	t.Parallel()
	created := testNow
	updated := testNow.Add(2 * time.Hour)
	cfg := outboundwebhook.Rehydrate("acct-9", "https://e.com/h", "whsec_r", false, created, updated)
	if cfg.AccountID() != "acct-9" || cfg.URL() != "https://e.com/h" || cfg.SigningSecret() != "whsec_r" ||
		cfg.Enabled() || !cfg.CreatedAt().Equal(created) || !cfg.UpdatedAt().Equal(updated) {
		t.Errorf("rehydrate mismatch: %+v", cfg)
	}
}

func TestLogValueRedactsSecret(t *testing.T) {
	t.Parallel()
	cfg, _ := outboundwebhook.New("acct-1", "https://e.com/h", "whsec_super_secret", true, testNow)
	v := cfg.LogValue()
	s := v.String()
	if strings.Contains(s, "whsec_super_secret") {
		t.Errorf("LogValue leaked the signing secret: %s", s)
	}
	if !strings.Contains(s, "[REDACTED]") {
		t.Errorf("LogValue missing [REDACTED]: %s", s)
	}
	// Non-secret descriptors are present.
	if !strings.Contains(s, "acct-1") || !strings.Contains(s, "https://e.com/h") {
		t.Errorf("LogValue missing non-secret fields: %s", s)
	}
}

func errorsIsValidation(err error) bool {
	return errors.Is(err, shared.ErrValidation)
}

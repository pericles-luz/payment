package config

import (
	"bytes"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// TestParseBankCreds is a white-box, table-driven test for the per-tenant bank
// credential parser. It pins three properties:
//   - a secret containing ':' is preserved verbatim (SplitN n=3, not truncated);
//   - structurally malformed entries are skipped AND logged at warn level so a
//     misconfiguration is observable instead of failing opaquely at the PSP;
//   - no secret material ever reaches the log output.
func TestParseBankCreds(t *testing.T) {
	const colonSecret = "p4ss:w0rd:with:colons"

	cases := []struct {
		name      string
		in        string
		wantCreds map[string]ports.BankCredential
		wantWarn  bool
		// noLeak, when non-empty, is a secret value that must NOT appear anywhere
		// in the emitted log for this case.
		noLeak string
	}{
		{
			name: "valid single entry",
			in:   "tenantA:cidA:secA",
			wantCreds: map[string]ports.BankCredential{
				"tenantA": {TenantID: "tenantA", ClientID: "cidA", Secret: "secA"},
			},
		},
		{
			name: "secret containing colons is preserved not truncated",
			in:   "tenantA:cidA:" + colonSecret,
			wantCreds: map[string]ports.BankCredential{
				"tenantA": {TenantID: "tenantA", ClientID: "cidA", Secret: colonSecret},
			},
			noLeak: colonSecret,
		},
		{
			name: "surrounding whitespace is trimmed",
			in:   " tenantA : cidA : secA ",
			wantCreds: map[string]ports.BankCredential{
				"tenantA": {TenantID: "tenantA", ClientID: "cidA", Secret: "secA"},
			},
		},
		{
			name:      "too few fields skipped with warning",
			in:        "tenantA:only2",
			wantCreds: map[string]ports.BankCredential{},
			wantWarn:  true,
		},
		{
			name:      "empty tenant skipped with warning",
			in:        ":cidA:secA",
			wantCreds: map[string]ports.BankCredential{},
			wantWarn:  true,
			noLeak:    "secA",
		},
		{
			name:      "empty client id skipped with warning",
			in:        "tenantA::secA",
			wantCreds: map[string]ports.BankCredential{},
			wantWarn:  true,
			noLeak:    "secA",
		},
		{
			name:      "empty secret skipped with warning",
			in:        "tenantA:cidA:",
			wantCreds: map[string]ports.BankCredential{},
			wantWarn:  true,
		},
		{
			name: "valid and malformed mixed keeps valid and warns on malformed",
			in:   "tenantA:cidA:secA, bad:only2, tenantB:cidB:secB",
			wantCreds: map[string]ports.BankCredential{
				"tenantA": {TenantID: "tenantA", ClientID: "cidA", Secret: "secA"},
				"tenantB": {TenantID: "tenantB", ClientID: "cidB", Secret: "secB"},
			},
			wantWarn: true,
		},
		{
			name:      "empty input yields empty map and no warning",
			in:        "",
			wantCreds: map[string]ports.BankCredential{},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

			got := parseBankCreds(tc.in, logger)
			if !reflect.DeepEqual(got, tc.wantCreds) {
				t.Fatalf("creds = %+v, want %+v", got, tc.wantCreds)
			}

			gotWarn := strings.Contains(buf.String(), "level=WARN")
			if gotWarn != tc.wantWarn {
				t.Fatalf("warn logged = %v, want %v; log=%q", gotWarn, tc.wantWarn, buf.String())
			}

			if tc.noLeak != "" && strings.Contains(buf.String(), tc.noLeak) {
				t.Fatalf("secret value %q leaked into log: %q", tc.noLeak, buf.String())
			}
		})
	}
}

// TestParseBankCredsNilLoggerDoesNotPanic guards the defensive fallback to the
// default logger when a nil logger is passed.
func TestParseBankCredsNilLogger(t *testing.T) {
	got := parseBankCreds("tenantA:cidA:secA", nil)
	cred, ok := got["tenantA"]
	if !ok || cred.Secret != "secA" {
		t.Fatalf("nil-logger parse: %+v", got)
	}
}

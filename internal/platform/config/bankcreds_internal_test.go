package config

import (
	"bytes"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// wantCreds builds an expected credential map keyed the same composite (tenant,
// bank) way the parser keys it (ADR-0007).
func wantCreds(entries ...ports.BankCredential) map[string]ports.BankCredential {
	m := make(map[string]ports.BankCredential, len(entries))
	for _, c := range entries {
		m[bankCredKey(c.TenantID, c.BankID)] = c
	}
	return m
}

// TestParseBankCreds is a white-box, table-driven test for the per-(tenant, bank)
// bank credential parser (ADR-0007 / SIN-66021). It pins:
//   - a legacy 3-field "tenant:clientID:secret" entry maps to the default bank c6;
//   - a 4-field "tenant:bank:clientID:secret" entry keeps its explicit bank, and
//     two banks for the same tenant coexist (composite keying, no overwrite);
//   - the secret is the greedy ':'-tolerant tail (a secret with ':' is preserved);
//   - an empty bank field defaults to c6;
//   - the DOCUMENTED ambiguity: a legacy entry whose secret contains ':' is read
//     as the 4-field form (pinned so the behaviour is explicit, not accidental);
//   - structurally malformed entries are skipped AND logged at warn level;
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
			name:      "legacy 3-field entry defaults to bank c6",
			in:        "tenantA:cidA:secA",
			wantCreds: wantCreds(ports.BankCredential{TenantID: "tenantA", BankID: "c6", ClientID: "cidA", Secret: "secA"}),
		},
		{
			name:      "4-field entry keeps its explicit bank",
			in:        "tenantA:itau:cidA:secA",
			wantCreds: wantCreds(ports.BankCredential{TenantID: "tenantA", BankID: "itau", ClientID: "cidA", Secret: "secA"}),
		},
		{
			name: "two banks for the same tenant coexist (no overwrite)",
			in:   "tenantA:c6:cid6:sec6, tenantA:itau:cidI:secI",
			wantCreds: wantCreds(
				ports.BankCredential{TenantID: "tenantA", BankID: "c6", ClientID: "cid6", Secret: "sec6"},
				ports.BankCredential{TenantID: "tenantA", BankID: "itau", ClientID: "cidI", Secret: "secI"},
			),
		},
		{
			name:      "empty bank field defaults to c6",
			in:        "tenantA::cidA:secA",
			wantCreds: wantCreds(ports.BankCredential{TenantID: "tenantA", BankID: "c6", ClientID: "cidA", Secret: "secA"}),
		},
		{
			name:      "secret containing colons is preserved not truncated (4-field greedy tail)",
			in:        "tenantA:c6:cidA:" + colonSecret,
			wantCreds: wantCreds(ports.BankCredential{TenantID: "tenantA", BankID: "c6", ClientID: "cidA", Secret: colonSecret}),
			noLeak:    colonSecret,
		},
		{
			name: "documented ambiguity: legacy colon-bearing secret is read as 4-field",
			in:   "tenantA:cidA:p4ss:w0rd",
			// The 4-token entry is the new form: bank=cidA, clientID=p4ss, secret=w0rd.
			// A legacy colon-secret MUST migrate to the explicit 4-field form.
			wantCreds: wantCreds(ports.BankCredential{TenantID: "tenantA", BankID: "cidA", ClientID: "p4ss", Secret: "w0rd"}),
		},
		{
			name:      "surrounding whitespace is trimmed (legacy)",
			in:        " tenantA : cidA : secA ",
			wantCreds: wantCreds(ports.BankCredential{TenantID: "tenantA", BankID: "c6", ClientID: "cidA", Secret: "secA"}),
		},
		{
			name:      "surrounding whitespace is trimmed (4-field)",
			in:        " tenantA : itau : cidA : secA ",
			wantCreds: wantCreds(ports.BankCredential{TenantID: "tenantA", BankID: "itau", ClientID: "cidA", Secret: "secA"}),
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
			wantCreds: wantCreds(
				ports.BankCredential{TenantID: "tenantA", BankID: "c6", ClientID: "cidA", Secret: "secA"},
				ports.BankCredential{TenantID: "tenantB", BankID: "c6", ClientID: "cidB", Secret: "secB"},
			),
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
	cred, ok := got[bankCredKey("tenantA", "c6")]
	if !ok || cred.Secret != "secA" {
		t.Fatalf("nil-logger parse: %+v", got)
	}
}

package config

import (
	"bytes"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// TestMergeCreditorKeys is a white-box, table-driven test for the per-tenant PIX
// creditor-key (chave do recebedor) merge. It pins:
//   - a configured key is folded into the matching tenant's BankCredential, and a
//     per-request override is NOT this layer's concern (it stays in the adapter);
//   - a key for a tenant with no bank credential is skipped (no half-credential);
//   - structurally malformed / empty entries are skipped AND logged at warn level
//     so a misconfiguration is observable instead of failing opaquely at the PSP;
//   - the routing-sensitive key value NEVER reaches the log output (threat C1/C4).
func TestMergeCreditorKeys(t *testing.T) {
	const routingKey = "acme-routing@pix.example"

	base := func() map[string]ports.BankCredential {
		return map[string]ports.BankCredential{
			bankCredKey("tenantA", "c6"): {TenantID: "tenantA", BankID: "c6", ClientID: "cidA", Secret: "secA"},
			bankCredKey("tenantB", "c6"): {TenantID: "tenantB", BankID: "c6", ClientID: "cidB", Secret: "secB"},
		}
	}

	cases := []struct {
		name string
		in   string
		// want is the expected creditor key per tenant after the merge; tenants not
		// listed must keep an empty creditor key.
		want map[string]string
		// noLeak, when non-empty, is a key value that must NOT appear in the logs.
		noLeak string
	}{
		{
			name: "key folded into matching tenant",
			in:   "tenantA:" + routingKey,
			want: map[string]string{"tenantA": routingKey, "tenantB": ""},
		},
		{
			name: "multiple tenants each get their key, surrounding space trimmed",
			in:   " tenantA : a@pix.example , tenantB:b@pix.example ",
			want: map[string]string{"tenantA": "a@pix.example", "tenantB": "b@pix.example"},
		},
		{
			name: "EVP uuid key (no colon) folded verbatim",
			in:   "tenantA:123e4567-e89b-12d3-a456-426614174000",
			want: map[string]string{"tenantA": "123e4567-e89b-12d3-a456-426614174000"},
		},
		{
			name:   "key for tenant with no bank credential is skipped",
			in:     "ghost:" + routingKey,
			want:   map[string]string{"tenantA": "", "tenantB": ""},
			noLeak: routingKey,
		},
		{
			name: "malformed entry without a colon is skipped",
			in:   "tenantA-no-key",
			want: map[string]string{"tenantA": "", "tenantB": ""},
		},
		{
			name: "empty key after colon is skipped",
			in:   "tenantA:",
			want: map[string]string{"tenantA": "", "tenantB": ""},
		},
		{
			name: "empty tenant before colon is skipped",
			in:   ":" + routingKey,
			want: map[string]string{"tenantA": "", "tenantB": ""},
		},
		{
			name: "empty input leaves credentials untouched",
			in:   "",
			want: map[string]string{"tenantA": "", "tenantB": ""},
		},
		{
			name: "later entry for the same tenant wins",
			in:   "tenantA:first@pix.example,tenantA:second@pix.example",
			want: map[string]string{"tenantA": "second@pix.example"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

			got := mergeCreditorKeys(base(), tc.in, logger)

			for tenant, wantKey := range tc.want {
				cred, ok := got[bankCredKey(tenant, "c6")]
				if !ok {
					t.Fatalf("tenant %q dropped from credential map", tenant)
				}
				if cred.CreditorKey != wantKey {
					t.Fatalf("tenant %q creditor key: want %q, got %q", tenant, wantKey, cred.CreditorKey)
				}
				// The merge must never disturb the OAuth2 identity it folds into.
				if cred.ClientID == "" || cred.Secret == "" {
					t.Fatalf("tenant %q lost its bank identity: %+v", tenant, cred)
				}
			}
			if tc.noLeak != "" && strings.Contains(buf.String(), tc.noLeak) {
				t.Fatalf("creditor key %q leaked into log: %q", tc.noLeak, buf.String())
			}
		})
	}
}

// TestMergeCreditorKeysMultiBank pins the 3-field "tenant:bank:creditorKey" form
// (ADR-0007): the key is folded into the credential at the SAME (tenant, bank)
// pair, the legacy 2-field form still targets c6, and a key for a bank the tenant
// did not configure is skipped (no half-credential, no cross-bank leak).
func TestMergeCreditorKeysMultiBank(t *testing.T) {
	creds := map[string]ports.BankCredential{
		bankCredKey("t1", "c6"):   {TenantID: "t1", BankID: "c6", ClientID: "c6-cid", Secret: "c6-sec"},
		bankCredKey("t1", "itau"): {TenantID: "t1", BankID: "itau", ClientID: "itau-cid", Secret: "itau-sec"},
	}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// 3-field targets itau; 2-field legacy targets c6; the bradesco key has no
	// matching credential and is dropped.
	got := mergeCreditorKeys(creds, "t1:itau:itau@pix.example, t1:c6@pix.example, t1:bradesco:ghost@pix.example", logger)

	if k := got[bankCredKey("t1", "itau")].CreditorKey; k != "itau@pix.example" {
		t.Fatalf("itau creditor key = %q, want itau@pix.example", k)
	}
	if k := got[bankCredKey("t1", "c6")].CreditorKey; k != "c6@pix.example" {
		t.Fatalf("c6 creditor key = %q, want c6@pix.example", k)
	}
	if _, ok := got[bankCredKey("t1", "bradesco")]; ok {
		t.Fatal("a creditor key for an unconfigured bank must not synthesize a credential")
	}
	// The routing-sensitive key value never reaches the log.
	if strings.Contains(buf.String(), "ghost@pix.example") {
		t.Fatalf("creditor key leaked into log: %q", buf.String())
	}
}

// TestMergeCreditorKeysNilInputs asserts the merge is total: a nil credential map
// and a nil logger are both tolerated (defensive, since the helper is called from
// FromEnv with whatever parseBankCreds returned).
func TestMergeCreditorKeysNilInputs(t *testing.T) {
	got := mergeCreditorKeys(nil, "ghost:k@pix.example", nil)
	if got == nil {
		t.Fatalf("merge returned a nil map")
	}
	if len(got) != 0 {
		t.Fatalf("a key for an absent tenant must not synthesize a credential: %+v", got)
	}
	if !reflect.DeepEqual(got, map[string]ports.BankCredential{}) {
		t.Fatalf("want empty map, got %+v", got)
	}
}

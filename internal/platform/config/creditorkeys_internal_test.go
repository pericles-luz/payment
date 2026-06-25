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
			"tenantA": {TenantID: "tenantA", ClientID: "cidA", Secret: "secA"},
			"tenantB": {TenantID: "tenantB", ClientID: "cidB", Secret: "secB"},
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
				cred, ok := got[tenant]
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

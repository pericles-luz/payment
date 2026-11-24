package custody

import (
	"regexp"
	"strings"
	"testing"
)

// These tests pin the shape of FiscalSignerVaultPolicy (ADR-0007, amended
// 2026-10-05). Its behaviour against a real Vault — two tenants importing and
// signing through one login, export and key reconfiguration denied — is proven
// by TestLiveVaultTwoTenantsImportAndSign (env-gated).

var policyPathRe = regexp.MustCompile(`path "([^"]+)"\s*\{\s*capabilities\s*=\s*\[([^\]]*)\]`)

func policyRules(t *testing.T) map[string]string {
	t.Helper()
	rules := map[string]string{}
	for _, m := range policyPathRe.FindAllStringSubmatch(FiscalSignerVaultPolicy, -1) {
		rules[m[1]] = strings.ReplaceAll(m[2], " ", "")
	}
	if len(rules) == 0 {
		t.Fatal("no path rules parsed from FiscalSignerVaultPolicy")
	}
	return rules
}

func TestVaultPolicyExactRules(t *testing.T) {
	want := map[string]string{
		"transit/sign/a1.*":     `"update"`,
		"transit/keys/+":        `"read","delete"`,
		"transit/keys/+/config": `"update"`,
		"transit/keys/+/import": `"update"`,
		"transit/wrapping_key":  `"read"`,
	}
	got := policyRules(t)
	if len(got) != len(want) {
		t.Errorf("policy has %d rules, want %d: %v", len(got), len(want), got)
	}
	for path, caps := range want {
		if got[path] != caps {
			t.Errorf("rule %q = [%s], want [%s]", path, got[path], caps)
		}
	}
}

// TestVaultPolicyNeverGrantsExportOrReconfig is the custody invariant: no rule
// may reach transit/export, key rotation, or overwrite an existing key via
// import_version; /config is reachable only to set deletion_allowed (shred).
func TestVaultPolicyNeverGrantsExportOrReconfig(t *testing.T) {
	lower := strings.ToLower(FiscalSignerVaultPolicy)
	for _, forbidden := range []string{"export\"", "transit/export", "/rotate", "/trim", "import_version", "backup", "restore", "\"sudo\"", "\"create\""} {
		if strings.Contains(lower, forbidden) {
			t.Errorf("SECURITY: policy mentions %q", forbidden)
		}
	}
	for path := range policyRules(t) {
		if strings.HasPrefix(path, "transit/keys/") && strings.HasSuffix(path, "*") {
			t.Errorf("SECURITY: %q is a trailing glob under transit/keys/ — it would reach /config and /export sub-paths", path)
		}
	}
}

// TestVaultPolicyConfigOnlyDeletionAllowed: the config rule must be pinned to
// deletion_allowed=true, or it would let the app flip exportable=true.
func TestVaultPolicyConfigOnlyDeletionAllowed(t *testing.T) {
	re := regexp.MustCompile(`(?s)path "transit/keys/\+/config" \{(.*?)\n\}`)
	m := re.FindStringSubmatch(FiscalSignerVaultPolicy)
	if m == nil {
		t.Fatal("config rule not found")
	}
	body := strings.Join(strings.Fields(m[1]), " ")
	if !strings.Contains(body, `allowed_parameters = { "deletion_allowed" = [true] }`) {
		t.Errorf("SECURITY: config rule not restricted to deletion_allowed=true: %s", body)
	}
}

// TestVaultPolicyNotTemplated guards the regression that started this: a
// policy templated on the entity's company_id lets one serve login sign for a
// single tenant only.
func TestVaultPolicyNotTemplated(t *testing.T) {
	if strings.Contains(FiscalSignerVaultPolicy, "{{") {
		t.Error("policy must not be templated: one serve login signs for every tenant")
	}
}

// TestVaultPolicySignGlobMatchesProductionKeyNames ties the sign rule to the
// key names the signer actually emits.
func TestVaultPolicySignGlobMatchesProductionKeyNames(t *testing.T) {
	v, err := NewVaultTransitSigner(VaultTransitConfig{Address: "http://x", Certs: NewMemoryCertStore()})
	if err != nil {
		t.Fatal(err)
	}
	prefix := strings.TrimSuffix("transit/sign/a1.*", "*")
	for _, companyID := range []string{"tenant_47064135000184", "abc123_11222333000181"} {
		path := "transit/sign/" + v.keyName(companyID, "deadbeef")
		if !strings.HasPrefix(path, prefix) {
			t.Errorf("sign path %q not covered by %q", path, "transit/sign/a1.*")
		}
	}
}

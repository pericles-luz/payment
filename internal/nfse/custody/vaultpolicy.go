package custody

import "strings"

// FiscalSignerVaultPolicy is the Vault ACL policy for the AppRole the serve
// (and the nfse-import-a1 CLI) authenticate with (ADR-0007, amended
// 2026-10-05). The runbook §4 installs exactly this text; tests pin its shape
// and the live-Vault suite proves its behaviour.
//
// It is deliberately NOT templated on identity.entity.metadata.company_id. A
// single serve process signs for every tenant with one AppRole login, and a
// login carries one identity — a templated policy would let it sign for exactly
// one tenant and deny the rest. Tenant isolation lives in the application
// (API key → tenant → company_id, and the signer's (company_id, serial) check);
// Vault's job is non-exportable custody, audit, and crypto-shred.
//
// Path choices:
//   - sign is limited to the a1.* key namespace;
//   - keys/+ (one segment, no trailing glob) grants read on the key itself
//     only — never /config, /rotate, /trim or /export sub-paths. A trailing
//     "a1.*" glob would also out-rank keys/+/import in Vault's priority rules
//     (the earlier wildcard loses) and silently deny the import;
//   - keys/+/import creates a NEW key; it cannot overwrite an existing one
//     (that is /import_version, not granted);
//   - keys/+/config accepts ONLY deletion_allowed=true (allowed_parameters),
//     and keys/+ allows delete: together they let a rotation crypto-shred the
//     replaced certificate's key. exportable, allow_plaintext_backup and every
//     other config parameter stay denied;
//   - no transit/export path exists anywhere: with exportable=false on import,
//     that absence is what keeps the A1 private key inside Vault.
const FiscalSignerVaultPolicy = `path "transit/sign/a1.*" {
  capabilities = ["update"]
}
path "transit/keys/+" {
  capabilities = ["read", "delete"]
}
path "transit/keys/+/config" {
  capabilities = ["update"]
  allowed_parameters = {
    "deletion_allowed" = [true]
  }
}
path "transit/keys/+/import" {
  capabilities = ["update"]
}
path "transit/wrapping_key" {
  capabilities = ["read"]
}
`

// FiscalSignerVaultPolicyFor is FiscalSignerVaultPolicy for a dedicated
// Transit mount and key prefix — e.g. ("payment-transit", "payment-a1") for the
// payment gateway, whose AppRole must never reach go-mei-das's "transit/a1.*"
// keys. With its own mount, keys/+ covers only that service's keys.
func FiscalSignerVaultPolicyFor(mount, keyPrefix string) string {
	return strings.NewReplacer(
		`"transit/sign/a1.*"`, `"`+mount+`/sign/`+keyPrefix+`.*"`,
		`"transit/`, `"`+mount+`/`,
	).Replace(FiscalSignerVaultPolicy)
}

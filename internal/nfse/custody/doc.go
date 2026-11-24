// Package custody is the NFS-e MEI certificate-custody bounded context
// (Modelo B). It defines the two hexagonal ports that isolate the rest of the
// system from private-key material — FiscalSigner and CertStore — plus the
// homologation adapters used to prove the contract with a TEST certificate.
//
// Design authority: SecurityEngineer custody recommendation SIN-67486 (§3
// tenant isolation, §5 lifecycle, §6 ports). Architecture: SIN-67526 plan.
//
// Hard invariant (SIN-67528): no REAL client A1 private-key material is ever
// loaded, persisted, or logged by anything in this package. The plaintext
// private key never crosses the FiscalSigner boundary — adapters delegate the
// two sensitive operations (XMLDSIG digest signing and mTLS client auth) to a
// key that stays inside the adapter (a KMS/HSM in production, an ephemeral
// in-memory test key here). CertStore only ever accepts and returns the public
// X.509 chain plus minimal metadata (serial, notAfter, a hash of the holder
// CNPJ) — never a private key.
package custody

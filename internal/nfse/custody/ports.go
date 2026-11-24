package custody

import (
	"context"
	"crypto/tls"
	"crypto/x509"
)

// FiscalSigner performs the two private-key operations NFS-e emission needs —
// XMLDSIG signing (SignDigest) and mTLS client authentication
// (ClientCertificate) — without ever exposing private-key material across this
// boundary. Adapters delegate to a non-exportable key held by a KMS/HSM in
// production, or to an ephemeral in-memory test key in homologation. The
// plaintext private key never crosses this port: callers only ever hand in a
// digest and receive a signature, or receive a tls.Certificate whose
// PrivateKey is a crypto.Signer that delegates back to the adapter.
//
// Spec: SIN-67486 §6. This is the seam a future Vault Transit / KES / PKCS#11
// adapter plugs into without the domain, worker, or messaging layers changing.
type FiscalSigner interface {
	// SignDigest signs digest with the key identified by (companyID,
	// certSerial) and returns the raw signature. digest is the already-hashed
	// input (e.g. the SHA-256 of the XMLDSIG SignedInfo). Signing with a key
	// that does not belong to companyID fails closed with ErrNotProvisioned;
	// an expired certificate fails closed with ErrCertExpired.
	SignDigest(ctx context.Context, companyID, certSerial string, digest []byte) (sig []byte, err error)

	// ClientCertificate returns the tls.Certificate to present for mTLS client
	// auth against the ADN. Its PrivateKey is a crypto.Signer that delegates
	// signing back to the adapter — the private key never materialises in the
	// application process.
	ClientCertificate(ctx context.Context, companyID string) (tls.Certificate, error)
}

// CertStore persists ONLY the public X.509 chain plus minimal metadata, scoped
// per tenant (companyID). No private-key material is ever accepted or returned;
// the port's types make that a compile-time guarantee (x509.Certificate carries
// only public material). Delete is the crypto-shred trigger: in production it
// pairs with deleting the non-exportable key in the KMS, which is the genuine,
// irreversible erasure (LGPD art. 18, VI — SIN-67486 §4).
//
// Spec: SIN-67486 §6; isolation §3; lifecycle §5.
type CertStore interface {
	// PutA1 stores (or replaces, on rotation) the public chain + metadata for
	// companyID. chain[0] is the leaf. Returns ErrEmptyChain for an empty
	// chain and ErrEmptyCompanyID for a missing tenant id.
	PutA1(ctx context.Context, companyID string, chain []*x509.Certificate, meta A1Meta) error

	// Get returns the stored public chain + metadata for companyID, or
	// ErrCertNotFound when the tenant has no certificate on file.
	Get(ctx context.Context, companyID string) (chain []*x509.Certificate, meta A1Meta, err error)

	// Delete removes companyID's public chain + metadata (crypto-shred
	// trigger). Deleting a tenant with nothing on file is a no-op.
	Delete(ctx context.Context, companyID string) error
}

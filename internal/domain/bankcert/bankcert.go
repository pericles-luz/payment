// Package bankcert parses and validates a per-bank mTLS client certificate and
// its private key before the material is committed to the credential vault
// (SIN-66087). It computes the certificate's PUBLIC metadata (subject CN, issuer,
// serial, SHA-256 fingerprint, validity window) and confirms the certificate and
// the key form a matching pair, returning a named shared.ValidationError on any
// malformed or mismatched input so the boundary surfaces an HTTP 400 — never a
// 500. The private key is NEVER inspected for, nor echoed into, any returned
// value: only public metadata leaves this package (threat C1/C4).
//
// crypto/x509, crypto/tls, crypto/sha256 and encoding/pem are Go stdlib (not
// vendor SDKs), so importing them keeps this parse logic pure and free of I/O
// while honouring the hexagonal rule. The use-case owns the policy decisions that
// need a clock (expiry-at-upload); this package only extracts and matches.
package bankcert

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

// Certificate is the PUBLIC, non-secret metadata extracted from a leaf X.509
// certificate. It carries NO private-key material and is safe to expose to the
// admin UI and to log.
type Certificate struct {
	SubjectCN         string
	Issuer            string
	SerialNumber      string
	FingerprintSHA256 string // lowercase hex of the SHA-256 over the DER bytes
	NotBefore         time.Time
	NotAfter          time.Time
}

// ParseCert decodes a single PEM-encoded leaf certificate and returns its public
// metadata. A body that is not a well-formed PEM CERTIFICATE block, or whose DER
// does not parse as an X.509 certificate, yields a named ValidationError (mapped
// to HTTP 400 at the boundary) — never a panic or a 500. It does NOT check the
// validity period: expiry-at-upload is a policy the use-case applies with its
// clock (a not-yet-valid certificate is intentionally extractable so the UI can
// badge a pre-provisioned rotation cert).
func ParseCert(certPEM string) (Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return Certificate{}, shared.NewValidationError("cert_pem", "not a valid PEM certificate")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return Certificate{}, shared.NewValidationError("cert_pem", "malformed certificate")
	}
	sum := sha256.Sum256(c.Raw)
	return Certificate{
		SubjectCN:         c.Subject.CommonName,
		Issuer:            c.Issuer.String(),
		SerialNumber:      c.SerialNumber.String(),
		FingerprintSHA256: hex.EncodeToString(sum[:]),
		NotBefore:         c.NotBefore,
		NotAfter:          c.NotAfter,
	}, nil
}

// Parse validates the certificate/key PAIR: it parses the leaf certificate's
// public metadata (ParseCert) and confirms keyPEM is the private key that matches
// it in one idiomatic tls.X509KeyPair call (which parses PKCS#1/PKCS#8/EC keys and
// verifies the key matches the leaf's public key). A malformed certificate, a
// malformed key, or a mismatched pair all yield a named ValidationError (HTTP
// 400); the returned message never includes key material, and a malformed key and
// a mismatched pair return the SAME message so the error is not an oracle over the
// key. Expiry is NOT checked here (see ParseCert).
func Parse(certPEM, keyPEM string) (Certificate, error) {
	meta, err := ParseCert(certPEM)
	if err != nil {
		return Certificate{}, err
	}
	if _, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM)); err != nil {
		return Certificate{}, shared.NewValidationError("key_pem", "private key does not match certificate")
	}
	return meta, nil
}

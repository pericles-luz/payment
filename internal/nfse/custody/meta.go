package custody

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"
	"time"
)

// Domain errors. All access-control failures are fail-closed sentinels so
// callers can branch with errors.Is without string matching.
var (
	// ErrCertNotFound is returned by CertStore.Get when the tenant has no
	// certificate on file.
	ErrCertNotFound = errors.New("custody: certificate not found for tenant")
	// ErrNotProvisioned is returned by FiscalSigner when no key matches the
	// (companyID, certSerial) pair — including the cross-tenant case, which
	// fails closed as "not found" rather than leaking existence.
	ErrNotProvisioned = errors.New("custody: no signing key provisioned for tenant/serial")
	// ErrCertExpired is returned when a signing key's certificate is past
	// notAfter. Emission fails closed before ever reaching the ADN.
	ErrCertExpired = errors.New("custody: certificate expired")
	// ErrEmptyChain is returned by CertStore.PutA1 for an empty chain.
	ErrEmptyChain = errors.New("custody: certificate chain is empty")
	// ErrEmptyCompanyID is returned when a tenant id is required but missing.
	ErrEmptyCompanyID = errors.New("custody: companyID required")
)

// A1Meta is the minimal, non-secret metadata persisted alongside the public
// chain (LGPD minimisation, SIN-67486 §4). It deliberately carries NO private
// material and NOT the raw holder document — only a hash of the CNPJ.
type A1Meta struct {
	// Serial is the certificate serial number in lowercase hex; together with
	// companyID it identifies the signing key.
	Serial string
	// NotAfter is the certificate expiry (UTC), tracked for the lifecycle job
	// and the a1_cert_expiry_days metric (SIN-67486 §5).
	NotAfter time.Time
	// CNPJHash is the SHA-256 (hex) of the holder CNPJ digits — never the raw
	// value, so the store leaks no personal document.
	CNPJHash string
	// Subject is the leaf certificate subject Common Name, kept for operator
	// display only. It contains no secret.
	Subject string
}

// ExpiresInDays reports whole days until NotAfter relative to now (negative
// once expired). Backs the a1_cert_expiry_days metric and D-30/15/7/1 alerts.
func (m A1Meta) ExpiresInDays(now time.Time) int {
	return int(m.NotAfter.Sub(now).Hours() / 24)
}

// IsExpired reports whether the certificate is past its validity at now.
func (m A1Meta) IsExpired(now time.Time) bool {
	return !now.Before(m.NotAfter)
}

// A1MetaFromLeaf derives the persisted metadata from a leaf certificate and the
// holder CNPJ. The CNPJ is hashed, never stored raw.
func A1MetaFromLeaf(leaf *x509.Certificate, cnpj string) A1Meta {
	if leaf == nil {
		return A1Meta{CNPJHash: HashCNPJ(cnpj)}
	}
	return A1Meta{
		Serial:   SerialHex(leaf),
		NotAfter: leaf.NotAfter.UTC(),
		CNPJHash: HashCNPJ(cnpj),
		Subject:  leaf.Subject.CommonName,
	}
}

// SerialHex returns the certificate serial number as lowercase hex, or "" for a
// nil certificate/serial.
func SerialHex(c *x509.Certificate) string {
	if c == nil || c.SerialNumber == nil {
		return ""
	}
	return strings.ToLower(c.SerialNumber.Text(16))
}

// HashCNPJ returns the SHA-256 (hex) of the digits of cnpj. Non-digit
// characters (dots, slashes, dashes) are stripped so formatting does not change
// the hash.
func HashCNPJ(cnpj string) string {
	sum := sha256.Sum256([]byte(onlyDigits(cnpj)))
	return hex.EncodeToString(sum[:])
}

func onlyDigits(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// EncodeChainPEM serialises a PUBLIC X.509 chain to PEM. It returns ErrEmptyChain
// for an empty chain. Only public certificate DER is ever emitted — there is no
// code path here that could serialise a private key.
func EncodeChainPEM(chain []*x509.Certificate) (string, error) {
	if len(chain) == 0 {
		return "", ErrEmptyChain
	}
	var b strings.Builder
	for _, c := range chain {
		if c == nil {
			return "", ErrEmptyChain
		}
		if err := pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}); err != nil {
			return "", err
		}
	}
	return b.String(), nil
}

// DecodeChainPEM parses a PEM-encoded public chain back into certificates. It
// accepts only CERTIFICATE blocks; any other block type (notably a private key)
// is rejected so a poisoned row can never smuggle key material back in.
func DecodeChainPEM(s string) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := []byte(s)
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			return nil, errors.New("custody: non-certificate PEM block rejected")
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, ErrEmptyChain
	}
	return out, nil
}

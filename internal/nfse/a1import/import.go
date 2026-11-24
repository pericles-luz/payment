// Package a1import onboards a MEI's A1 certificate (.pfx + password) into NFS-e
// custody: it decodes and validates the PKCS#12, imports the private key into
// Vault Transit as non-exportable, and stores only the public chain + metadata
// in the CertStore. Both the API (PUT /api/v1/nfse/certificate) and the
// nfse-import-a1 CLI drive this same code.
//
// The plaintext private key exists only for the duration of Import, in the
// calling process (ADR-0007, amended 2026-10-05). It is never logged, never
// persisted, and scrubbed best-effort before returning.
package a1import

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"time"

	"software.sslmate.com/src/go-pkcs12"

	"github.com/ia-dev-sindireceita/payment/internal/nfse/custody"
)

// MaxPFXSize bounds the accepted .pfx. Real A1 files are a few KiB; the cap
// keeps a hostile upload from turning PKCS#12 decoding into a CPU/memory sink.
const MaxPFXSize = 64 << 10

// Errors a boundary can branch on with errors.Is. Messages are safe to show to
// the end user: none carries the password or key material.
var (
	ErrEmptyPFX         = errors.New("a1import: certificate file is empty")
	ErrPFXTooLarge      = errors.New("a1import: certificate file is too large")
	ErrWrongPassword    = errors.New("a1import: wrong certificate password")
	ErrInvalidPFX       = errors.New("a1import: file is not a valid PKCS#12 (.pfx/.p12) certificate")
	ErrNoCNPJ           = errors.New("a1import: certificate carries no CNPJ (not an ICP-Brasil e-CNPJ)")
	ErrCNPJMismatch     = errors.New("a1import: certificate CNPJ differs from the informed CNPJ")
	ErrCertNotYetValid  = errors.New("a1import: certificate is not valid yet")
	ErrNotSigningCert   = errors.New("a1import: certificate is not allowed to sign (no digitalSignature key usage)")
	ErrEmptyTenant      = errors.New("a1import: tenant required")
	ErrUntrustedChain   = errors.New("a1import: certificate was not issued under ICP-Brasil")
	ErrOlderCertificate = errors.New("a1import: certificate expires before the one already on file")
)

// KeyCustody puts the private key into non-exportable custody and retires the
// key of a replaced certificate. custody.VaultTransitSigner implements it.
type KeyCustody interface {
	ImportA1Key(ctx context.Context, companyID string, leaf *x509.Certificate, key *rsa.PrivateKey) error
	// RetireA1Key crypto-shreds the key of (companyID, serial); an absent key
	// is not an error.
	RetireA1Key(ctx context.Context, companyID, serial string) error
}

// Result describes the certificate now in custody.
type Result struct {
	// CompanyID is the custody id (custody.CompanyIDFor(tenant, CNPJ)).
	CompanyID string
	// CNPJ is the holder CNPJ read from the certificate (digits).
	CNPJ string
	// Meta is what the CertStore persisted (serial, expiry, subject).
	Meta custody.A1Meta
	// RetiredSerial is the serial of the certificate this import replaced,
	// whose key was crypto-shredded; empty on a first import or a re-import of
	// the same certificate.
	RetiredSerial string
}

// Importer is the A1 onboarding use-case.
type Importer struct {
	keys          KeyCustody
	certs         custody.CertStore
	now           func() time.Time
	roots         *x509.CertPool
	intermediates *x509.CertPool
}

// Option configures an Importer.
type Option func(*Importer)

// WithClock overrides the validity clock (test hook).
func WithClock(now func() time.Time) Option { return func(i *Importer) { i.now = now } }

// WithTrust replaces the ICP-Brasil trust anchors and intermediates (tests, or
// a homologation environment that adds its test CA to ICPBrasilRoots()).
func WithTrust(roots, intermediates *x509.CertPool) Option {
	return func(i *Importer) { i.roots, i.intermediates = roots, intermediates }
}

// New wires an Importer. By default a certificate must chain to the embedded
// ICP-Brasil roots (ICPBrasilRoots).
func New(keys KeyCustody, certs custody.CertStore, opts ...Option) *Importer {
	i := &Importer{keys: keys, certs: certs, now: time.Now, roots: ICPBrasilRoots(), intermediates: ICPBrasilIntermediates()}
	for _, o := range opts {
		o(i)
	}
	return i
}

// Import validates pfx and puts it into custody for tenantID. expectedCNPJ is
// optional; when given it must equal the certificate holder, so a client
// cannot attach another company's certificate to the CNPJ it claims to be.
//
// Order: decode → validate (RSA, validity window, signing usage, ICP-Brasil
// chain, CNPJ, not older than the certificate on file) → import the key into
// Vault → retire the replaced certificate's key → store the public chain.
//
// The new key goes into Vault before the CertStore row points at it, so a
// half-done import never leaves a certificate on file that cannot sign. The old
// key is shredded BEFORE the row is switched: if the shred fails the import
// fails and is retried (both steps are idempotent), so a rotation never leaves
// an orphan signing key in Vault that nothing references.
func (i *Importer) Import(ctx context.Context, tenantID string, pfx []byte, password, expectedCNPJ string) (Result, error) {
	if tenantID == "" {
		return Result{}, ErrEmptyTenant
	}
	switch {
	case len(pfx) == 0:
		return Result{}, ErrEmptyPFX
	case len(pfx) > MaxPFXSize:
		return Result{}, ErrPFXTooLarge
	}

	rawKey, leaf, cas, err := pkcs12.DecodeChain(pfx, password)
	if err != nil {
		if errors.Is(err, pkcs12.ErrIncorrectPassword) {
			return Result{}, ErrWrongPassword
		}
		return Result{}, fmt.Errorf("%w: %v", ErrInvalidPFX, err)
	}
	key, ok := rawKey.(*rsa.PrivateKey)
	if !ok {
		return Result{}, custody.ErrUnsupportedKey
	}
	defer scrubRSA(key)

	now := i.now()
	switch {
	case now.Before(leaf.NotBefore):
		return Result{}, ErrCertNotYetValid
	case !now.Before(leaf.NotAfter):
		return Result{}, custody.ErrCertExpired
	case leaf.KeyUsage != 0 && leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0:
		return Result{}, ErrNotSigningCert
	}
	chain, err := i.verifyChain(leaf, cas, now)
	if err != nil {
		return Result{}, err
	}
	cnpj, ok := CNPJFromCert(leaf)
	if !ok {
		return Result{}, ErrNoCNPJ
	}
	if expectedCNPJ != "" && digits(expectedCNPJ) != cnpj {
		return Result{}, ErrCNPJMismatch
	}

	companyID := custody.CompanyIDFor(tenantID, cnpj)
	meta := custody.A1MetaFromLeaf(leaf, cnpj)
	var retire string
	switch _, current, err := i.certs.Get(ctx, companyID); {
	case errors.Is(err, custody.ErrCertNotFound):
	case err != nil:
		return Result{}, err
	case current.Serial != meta.Serial:
		// Refuse a downgrade before touching Vault: re-sending last year's
		// file would otherwise shred the renewed certificate's key.
		if meta.NotAfter.Before(current.NotAfter) {
			return Result{}, ErrOlderCertificate
		}
		retire = current.Serial
	}

	if err := i.keys.ImportA1Key(ctx, companyID, leaf, key); err != nil {
		return Result{}, err
	}
	if retire != "" {
		if err := i.keys.RetireA1Key(ctx, companyID, retire); err != nil {
			return Result{}, fmt.Errorf("retire previous certificate key: %w", err)
		}
	}
	if err := i.certs.PutA1(ctx, companyID, chain, meta); err != nil {
		return Result{}, err
	}
	return Result{CompanyID: companyID, CNPJ: cnpj, Meta: meta, RetiredSerial: retire}, nil
}

// verifyChain checks that leaf chains to the trust anchors at now, using the
// .pfx's own CA certificates plus the embedded intermediates. It returns the
// chain to store and present in mTLS: leaf + intermediates, without the root.
func (i *Importer) verifyChain(leaf *x509.Certificate, cas []*x509.Certificate, now time.Time) ([]*x509.Certificate, error) {
	inter := i.intermediates.Clone()
	for _, c := range cas {
		inter.AddCert(c)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots:         i.roots,
		Intermediates: inter,
		CurrentTime:   now,
		// ICP-Brasil e-CNPJ leaves carry clientAuth/emailProtection; the
		// signing permission itself is checked via KeyUsage above.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUntrustedChain, err)
	}
	best := chains[0]
	return best[:len(best)-1], nil
}

// Certificate returns the metadata of the certificate in custody for
// (tenantID, cnpj), or custody.ErrCertNotFound.
func (i *Importer) Certificate(ctx context.Context, tenantID, cnpj string) (custody.A1Meta, error) {
	if tenantID == "" {
		return custody.A1Meta{}, ErrEmptyTenant
	}
	_, meta, err := i.certs.Get(ctx, custody.CompanyIDFor(tenantID, cnpj))
	return meta, err
}

// scrubRSA overwrites the private parts of key. Best-effort: big.Int may have
// been copied by the runtime, but this shortens the window the key sits in the
// heap of a long-running process.
func scrubRSA(key *rsa.PrivateKey) {
	scrubInt(key.D)
	for _, p := range key.Primes {
		scrubInt(p)
	}
	scrubInt(key.Precomputed.Dp)
	scrubInt(key.Precomputed.Dq)
	scrubInt(key.Precomputed.Qinv)
}

func scrubInt(n *big.Int) {
	if n == nil {
		return
	}
	words := n.Bits()
	for i := range words {
		words[i] = 0
	}
	n.SetInt64(0)
}

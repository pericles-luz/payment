package custody

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

// ErrUnsupportedKey is returned when a loaded certificate's private key is not
// an RSA key. NFS-e / ICP-Brasil A1 certificates are RSA; an EC or unknown key
// is rejected fail-closed rather than silently mis-signed.
var ErrUnsupportedKey = errors.New("custody: only RSA A1 private keys are supported")

// ErrNoPrivateKey is returned when a PEM bundle carries a certificate but no
// private key block (or vice versa) — a FiscalSigner needs both.
var ErrNoPrivateKey = errors.New("custody: no private key found in certificate material")

// FileSigner is a FiscalSigner backed by an A1 certificate + private key loaded
// from an external file (PKCS#12 .pfx/.p12 or PEM). It exists ONLY for the
// env-gated live-homologation smoke driver (SIN-67538): it is never wired into
// `serve` or `worker`, where production custody is the non-exportable KMS
// adapter (ADR-0007). Like LocalTestSigner, the private key never crosses this
// port — ClientCertificate hands the TLS stack a delegating crypto.Signer and
// SignDigest signs in-adapter — so a real client A1 loaded here is never
// serialised back out or logged.
//
// It is safe for concurrent use.
type FileSigner struct {
	priv   *rsa.PrivateKey
	leaf   *x509.Certificate
	chain  []*x509.Certificate
	serial string

	now   func() time.Time
	audit func(AuditEvent)

	mu          sync.Mutex
	onHandshake func(crypto.SignerOpts)
}

// FileSignerOption configures a FileSigner.
type FileSignerOption func(*FileSigner)

// WithFileSignerClock overrides the signer clock (test hook), mirroring
// WithClock on LocalTestSigner.
func WithFileSignerClock(now func() time.Time) FileSignerOption {
	return func(s *FileSigner) { s.now = now }
}

// WithFileSignerAudit registers a sink invoked once per signing operation. The
// sink is never handed key material — AuditEvent carries none.
func WithFileSignerAudit(sink func(AuditEvent)) FileSignerOption {
	return func(s *FileSigner) { s.audit = sink }
}

// SetHandshakeObserver registers a callback invoked with the crypto.SignerOpts
// of each mTLS client-auth signature. The smoke driver uses it to report the
// signature scheme the ADN actually negotiated (RSA-PSS on TLS 1.3, PKCS#1 v1.5
// on TLS 1.2). It receives no key material.
func (s *FileSigner) SetHandshakeObserver(fn func(crypto.SignerOpts)) {
	s.mu.Lock()
	s.onHandshake = fn
	s.mu.Unlock()
}

// LoadFileSigner reads certificate material from data and returns a FileSigner.
// It sniffs the format: PEM-encoded input (a "-----BEGIN" block) is parsed as a
// cert+key bundle; anything else is treated as PKCS#12 and decoded with
// password. password is used for the PKCS#12 MAC/decryption and for an
// encrypted PEM private key; it is never logged or stored.
func LoadFileSigner(data []byte, password string, opts ...FileSignerOption) (*FileSigner, error) {
	if looksLikePEM(data) {
		return newFileSignerFromPEM(data, opts...)
	}
	return newFileSignerFromPKCS12(data, password, opts...)
}

// looksLikePEM reports whether data begins (after optional leading whitespace)
// with a PEM armour header.
func looksLikePEM(data []byte) bool {
	blk, _ := pem.Decode(data)
	return blk != nil
}

// newFileSignerFromPKCS12 decodes a .pfx/.p12 blob — legacy (RC2/3DES) or
// modern (AES) — keeping the CA certificates it carries as the chain. Real
// ICP-Brasil A1 files ship the full chain; x/crypto/pkcs12 refused them
// ("expected exactly two safe bags").
func newFileSignerFromPKCS12(pfx []byte, password string, opts ...FileSignerOption) (*FileSigner, error) {
	priv, cert, cas, err := pkcs12.DecodeChain(pfx, password)
	if err != nil {
		return nil, fmt.Errorf("custody: pkcs12 decode: %w", err)
	}
	rsaKey, ok := priv.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrUnsupportedKey
	}
	return newFileSigner(rsaKey, cert, append([]*x509.Certificate{cert}, cas...), opts...)
}

// newFileSignerFromPEM parses a PEM bundle containing exactly one certificate
// and one RSA private key (in either order). Extra CERTIFICATE blocks are kept
// as the intermediate chain. The private key must be unencrypted — the smoke
// runbook produces the bundle with `openssl pkcs12 -legacy -nodes`, so no PEM
// decryption is needed here (and the deprecated x509 PEM-decrypt API is avoided).
func newFileSignerFromPEM(bundle []byte, opts ...FileSignerOption) (*FileSigner, error) {
	var leaf *x509.Certificate
	var extra []*x509.Certificate
	var key *rsa.PrivateKey
	rest := bundle
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		switch {
		case blk.Type == "CERTIFICATE":
			c, err := x509.ParseCertificate(blk.Bytes)
			if err != nil {
				return nil, fmt.Errorf("custody: parse certificate: %w", err)
			}
			if leaf == nil {
				leaf = c
			} else {
				extra = append(extra, c)
			}
		case isPrivateKeyBlock(blk.Type):
			k, err := parseRSAPrivateKey(blk.Type, blk.Bytes)
			if err != nil {
				return nil, err
			}
			key = k
		}
	}
	if leaf == nil {
		return nil, ErrEmptyChain
	}
	if key == nil {
		return nil, ErrNoPrivateKey
	}
	chain := append([]*x509.Certificate{leaf}, extra...)
	return newFileSigner(key, leaf, chain, opts...)
}

func isPrivateKeyBlock(t string) bool {
	switch t {
	case "PRIVATE KEY", "RSA PRIVATE KEY":
		return true
	default:
		return false
	}
}

func parseRSAPrivateKey(blockType string, der []byte) (*rsa.PrivateKey, error) {
	if blockType == "RSA PRIVATE KEY" {
		return x509.ParsePKCS1PrivateKey(der)
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		// Fall back to PKCS#1 for a mislabelled block.
		if k1, err1 := x509.ParsePKCS1PrivateKey(der); err1 == nil {
			return k1, nil
		}
		return nil, fmt.Errorf("custody: parse private key: %w", err)
	}
	rsaKey, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrUnsupportedKey
	}
	return rsaKey, nil
}

// newFileSigner validates the parsed material and assembles the signer. It fails
// closed when the certificate's public key does not match the private key, so a
// mismatched cert/key pair can never present as a valid mTLS identity.
func newFileSigner(key *rsa.PrivateKey, leaf *x509.Certificate, chain []*x509.Certificate, opts ...FileSignerOption) (*FileSigner, error) {
	if key == nil {
		return nil, ErrNoPrivateKey
	}
	if leaf == nil || len(chain) == 0 {
		return nil, ErrEmptyChain
	}
	pub, ok := leaf.PublicKey.(*rsa.PublicKey)
	if !ok || pub.N.Cmp(key.PublicKey.N) != 0 || pub.E != key.PublicKey.E {
		return nil, fmt.Errorf("custody: certificate public key does not match private key")
	}
	s := &FileSigner{
		priv:   key,
		leaf:   leaf,
		chain:  chain,
		serial: SerialHex(leaf),
	}
	for _, o := range opts {
		o(s)
	}
	if s.now == nil {
		s.now = time.Now
	}
	return s, nil
}

// PublicChain returns the loaded public certificate chain (leaf first). Callers
// (the smoke driver) store it in a CertStore. It contains no private material.
func (s *FileSigner) PublicChain() []*x509.Certificate {
	out := make([]*x509.Certificate, len(s.chain))
	copy(out, s.chain)
	return out
}

// Serial returns the leaf certificate serial in lowercase hex — the certSerial
// the Emitter passes back to SignDigest.
func (s *FileSigner) Serial() string { return s.serial }

// Meta derives the persisted A1 metadata for holderCNPJ. The CNPJ is hashed,
// never stored raw, exactly as A1MetaFromLeaf does for the test signer.
func (s *FileSigner) Meta(holderCNPJ string) A1Meta {
	return A1MetaFromLeaf(s.leaf, holderCNPJ)
}

// SignDigest signs the XMLDSIG digest with the loaded key. It ignores companyID
// and certSerial matching (there is a single loaded key) but still fails closed
// on an expired certificate, mirroring LocalTestSigner. digest is the SHA-256 of
// the canonical SignedInfo; document signing stays PKCS#1 v1.5 SHA-256 per the
// NFS-e spec.
func (s *FileSigner) SignDigest(_ context.Context, companyID, certSerial string, digest []byte) ([]byte, error) {
	sig, err := s.signDocument(digest)
	s.emit(AuditEvent{CompanyID: companyID, CertSerial: certSerial, Op: "sign_digest", At: s.now().UTC(), Err: errText(err)})
	return sig, err
}

func (s *FileSigner) signDocument(digest []byte) ([]byte, error) {
	if !s.now().Before(s.leaf.NotAfter) {
		return nil, ErrCertExpired
	}
	return rsa.SignPKCS1v15(rand.Reader, s.priv, crypto.SHA256, digest)
}

// ClientCertificate returns the tls.Certificate to present for mTLS client auth.
// Its PrivateKey is a delegating crypto.Signer, so the raw RSA key never enters
// the TLS stack's view.
func (s *FileSigner) ClientCertificate(_ context.Context, companyID string) (tls.Certificate, error) {
	s.emit(AuditEvent{CompanyID: companyID, CertSerial: s.serial, Op: "client_certificate", At: s.now().UTC()})
	raw := make([][]byte, len(s.chain))
	for i, c := range s.chain {
		raw[i] = c.Raw
	}
	return tls.Certificate{
		Certificate: raw,
		Leaf:        s.leaf,
		PrivateKey: &fileDelegatedSigner{
			signer:  s,
			company: companyID,
			pub:     &s.priv.PublicKey,
		},
	}, nil
}

// signHandshake produces the mTLS CLIENT-AUTH signature with whatever scheme the
// ADN negotiated. TLS 1.3 (and TLS 1.2 with modern peers) selects RSA-PSS;
// legacy TLS 1.2 may select PKCS#1 v1.5. The peer, not this process, chooses the
// scheme in CertificateRequest, so both must be supported or the handshake
// fails. Emits a distinct "sign_handshake" audit op and notifies the handshake
// observer so document signing is never conflated with client-auth signing.
func (s *FileSigner) signHandshake(companyID string, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if !s.now().Before(s.leaf.NotAfter) {
		return nil, ErrCertExpired
	}
	s.mu.Lock()
	obs := s.onHandshake
	s.mu.Unlock()
	if obs != nil {
		obs(opts)
	}
	s.emit(AuditEvent{CompanyID: companyID, CertSerial: s.serial, Op: "sign_handshake", At: s.now().UTC()})
	if pss, ok := opts.(*rsa.PSSOptions); ok {
		return rsa.SignPSS(rand.Reader, s.priv, opts.HashFunc(), digest, pss)
	}
	return rsa.SignPKCS1v15(rand.Reader, s.priv, opts.HashFunc(), digest)
}

func (s *FileSigner) emit(ev AuditEvent) {
	if s.audit != nil {
		s.audit(ev)
	}
}

// fileDelegatedSigner is the crypto.Signer handed to the TLS stack. It holds the
// PUBLIC key only and delegates every Sign back to the FileSigner boundary,
// mirroring delegatedSigner for the test signer and a future KMS/HSM adapter.
type fileDelegatedSigner struct {
	signer  *FileSigner
	company string
	pub     crypto.PublicKey
}

func (d *fileDelegatedSigner) Public() crypto.PublicKey { return d.pub }

func (d *fileDelegatedSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return d.signer.signHandshake(d.company, digest, opts)
}

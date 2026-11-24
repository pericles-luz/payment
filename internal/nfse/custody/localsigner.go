package custody

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"sync"
	"time"
)

// AuditEvent is the non-secret record emitted for every signing operation
// (SIN-67486 §3, point 3). It carries the actor context needed to detect a
// cross-tenant anomaly — companyID, cert serial, operation, timestamp — and,
// by construction, NO key material and NO signed payload.
type AuditEvent struct {
	CompanyID  string
	CertSerial string
	Op         string // "sign_digest" | "sign_handshake" | "client_certificate"
	At         time.Time
	Err        string // empty on success; sentinel text on failure

	// Scheme records which RSA oracle served the signature — "pkcs1v15" or
	// "pss" — so a forensic reconstruction can distinguish a document (v1.5)
	// signature from an mTLS handshake (PSS) one (SIN-67541 AC #5). Empty for
	// non-signing ops. Never carries key material.
	Scheme string
	// Context records the signing context — "dps" (XMLDSIG document) or "mtls"
	// (client-auth handshake). Empty for non-signing ops.
	Context string
	// KeyRef is the non-secret KMS key reference (e.g. "a1.{company}.{serial}"),
	// present for adapters that route to an external KMS. It is a name, never key
	// material.
	KeyRef string
}

// LocalTestSigner is a homologation FiscalSigner backed by ephemeral, in-memory
// RSA TEST keys — one per (companyID, serial). It exists ONLY to prove the port
// contract with a test certificate. No real client A1 material is ever loaded,
// persisted, or logged (SIN-67528 hard invariant). The private key never leaves
// this adapter: SignDigest returns a signature, and ClientCertificate returns a
// tls.Certificate whose PrivateKey is a crypto.Signer that delegates back here
// — the exact shape a future KMS/HSM adapter takes.
//
// It is safe for concurrent use.
type LocalTestSigner struct {
	mu   sync.RWMutex
	keys map[string]*testKey // key: companyID + "\x00" + serial
	head map[string]string   // companyID -> serial of the most recent key

	// now is injectable so expiry can be tested deterministically. Defaults to
	// time.Now when nil.
	now func() time.Time
	// audit, when set, receives one AuditEvent per signing operation.
	audit func(AuditEvent)
}

type testKey struct {
	priv   *rsa.PrivateKey
	leaf   *x509.Certificate
	chain  []*x509.Certificate
	serial string
}

// LocalSignerOption configures a LocalTestSigner.
type LocalSignerOption func(*LocalTestSigner)

// WithClock overrides the signer's clock (test hook).
func WithClock(now func() time.Time) LocalSignerOption {
	return func(s *LocalTestSigner) { s.now = now }
}

// WithAuditSink registers a sink invoked once per signing operation. The sink
// must never be handed key material — AuditEvent carries none.
func WithAuditSink(sink func(AuditEvent)) LocalSignerOption {
	return func(s *LocalTestSigner) { s.audit = sink }
}

// NewLocalTestSigner returns an empty signer with no provisioned keys.
func NewLocalTestSigner(opts ...LocalSignerOption) *LocalTestSigner {
	s := &LocalTestSigner{
		keys: make(map[string]*testKey),
		head: make(map[string]string),
	}
	for _, o := range opts {
		o(s)
	}
	if s.now == nil {
		s.now = time.Now
	}
	return s
}

func mapKey(companyID, serial string) string { return companyID + "\x00" + serial }

// Provision generates a fresh ephemeral RSA TEST key + self-signed test leaf for
// companyID and returns its public chain + metadata. The returned material is
// entirely public; the private key stays inside the signer. Test-only: this is
// how the POC obtains a certificate without any real client A1.
func (s *LocalTestSigner) Provision(companyID, cnpj string, validFor time.Duration) ([]*x509.Certificate, A1Meta, error) {
	if companyID == "" {
		return nil, A1Meta{}, ErrEmptyCompanyID
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, A1Meta{}, err
	}
	serialInt, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, A1Meta{}, err
	}
	now := s.now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serialInt,
		Subject: pkix.Name{
			CommonName:   "TEST NFS-e A1 " + companyID,
			SerialNumber: HashCNPJ(cnpj), // holder document hashed, never raw
		},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(validFor),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, A1Meta{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, A1Meta{}, err
	}
	chain := []*x509.Certificate{leaf}
	serial := SerialHex(leaf)
	tk := &testKey{priv: priv, leaf: leaf, chain: chain, serial: serial}

	s.mu.Lock()
	s.keys[mapKey(companyID, serial)] = tk
	s.head[companyID] = serial
	s.mu.Unlock()

	return chain, A1MetaFromLeaf(leaf, cnpj), nil
}

// SignDigest signs digest with the (companyID, certSerial) key. It fails closed:
// an unknown or cross-tenant key yields ErrNotProvisioned, and an expired
// certificate yields ErrCertExpired — before any signature is produced.
func (s *LocalTestSigner) SignDigest(_ context.Context, companyID, certSerial string, digest []byte) ([]byte, error) {
	sig, err := s.signWith(companyID, certSerial, digest)
	s.emit(AuditEvent{CompanyID: companyID, CertSerial: certSerial, Op: "sign_digest", At: s.now().UTC(), Err: errText(err)})
	return sig, err
}

func (s *LocalTestSigner) signWith(companyID, certSerial string, digest []byte) ([]byte, error) {
	s.mu.RLock()
	tk, ok := s.keys[mapKey(companyID, certSerial)]
	s.mu.RUnlock()
	if !ok {
		return nil, ErrNotProvisioned
	}
	if !s.now().Before(tk.leaf.NotAfter) {
		return nil, ErrCertExpired
	}
	// NF-e / NFS-e uses SHA256withRSA (PKCS#1 v1.5). digest is the SHA-256 of
	// the SignedInfo, so it must be 32 bytes.
	return rsa.SignPKCS1v15(rand.Reader, tk.priv, crypto.SHA256, digest)
}

// ClientCertificate returns the tls.Certificate for companyID's most recently
// provisioned key. Its PrivateKey is a crypto.Signer that delegates to
// SignDigest, so the raw private key never enters the TLS stack's view.
func (s *LocalTestSigner) ClientCertificate(_ context.Context, companyID string) (tls.Certificate, error) {
	s.mu.RLock()
	serial, ok := s.head[companyID]
	var tk *testKey
	if ok {
		tk = s.keys[mapKey(companyID, serial)]
	}
	s.mu.RUnlock()
	s.emit(AuditEvent{CompanyID: companyID, CertSerial: serial, Op: "client_certificate", At: s.now().UTC(), Err: errText(boolErr(ok))})
	if !ok || tk == nil {
		return tls.Certificate{}, ErrNotProvisioned
	}
	raw := make([][]byte, len(tk.chain))
	for i, c := range tk.chain {
		raw[i] = c.Raw
	}
	return tls.Certificate{
		Certificate: raw,
		Leaf:        tk.leaf,
		PrivateKey: &delegatedSigner{
			signer:  s,
			company: companyID,
			serial:  serial,
			pub:     &tk.priv.PublicKey,
		},
	}, nil
}

// signHandshake signs digest for the mTLS CLIENT-AUTH handshake with the scheme
// the TLS stack negotiated with the ADN. This is deliberately distinct from
// SignDigest (XMLDSIG document signing), which is fixed to PKCS#1 v1.5 SHA-256
// by the NFS-e spec: the handshake scheme is chosen by the *peer*, not the
// application. TLS 1.3 mandates RSA-PSS in CertificateVerify and TLS 1.2 may
// pick either RSA-PSS or PKCS#1 v1.5, so both are supported here (SHA-256/384/
// 512) — otherwise a real mTLS handshake against the ADN homologação fails with
// the custodied test cert (SIN-67535). The private key never leaves the adapter;
// only a delegating crypto.Signer is handed to the TLS stack. It fails closed on
// an unknown/cross-tenant key, an expired certificate, or an unsupported hash —
// the same posture as signWith.
func (s *LocalTestSigner) signHandshake(companyID, certSerial string, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil {
		return nil, ErrNotProvisioned
	}
	switch opts.HashFunc() {
	case crypto.SHA256, crypto.SHA384, crypto.SHA512:
		// TLS-negotiable SHA-2 hashes only; SHA-1/MD5 fail closed below.
	default:
		return nil, ErrNotProvisioned
	}
	s.mu.RLock()
	tk, ok := s.keys[mapKey(companyID, certSerial)]
	s.mu.RUnlock()
	if !ok {
		return nil, ErrNotProvisioned
	}
	if !s.now().Before(tk.leaf.NotAfter) {
		return nil, ErrCertExpired
	}
	if pss, isPSS := opts.(*rsa.PSSOptions); isPSS {
		return rsa.SignPSS(rand.Reader, tk.priv, opts.HashFunc(), digest, pss)
	}
	return rsa.SignPKCS1v15(rand.Reader, tk.priv, opts.HashFunc(), digest)
}

func (s *LocalTestSigner) emit(ev AuditEvent) {
	if s.audit != nil {
		s.audit(ev)
	}
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func boolErr(ok bool) error {
	if ok {
		return nil
	}
	return ErrNotProvisioned
}

// delegatedSigner is a crypto.Signer whose Sign delegates back to the
// FiscalSigner boundary. It holds only the PUBLIC key; the private key stays in
// the adapter. This mirrors how a KMS/HSM-backed crypto.Signer behaves, so the
// mTLS path is identical across test and production adapters.
type delegatedSigner struct {
	signer  *LocalTestSigner
	company string
	serial  string
	pub     crypto.PublicKey
}

func (d *delegatedSigner) Public() crypto.PublicKey { return d.pub }

// Sign delegates the mTLS CLIENT-AUTH handshake signature back to the adapter.
// It supports the schemes a TLS peer may negotiate for an RSA client cert —
// RSA-PSS (TLS 1.3 / TLS 1.2) and PKCS#1 v1.5 (TLS 1.2) with SHA-256/384/512 —
// because the ADN, not this process, chooses the scheme in CertificateVerify.
// A KMS/HSM-backed crypto.Signer behaves identically, so the mTLS path is the
// same across the test and production adapters. Document (XMLDSIG) signing does
// NOT go through here — it uses SignDigest, which stays PKCS#1 v1.5 SHA-256 per
// the NFS-e spec. Emits a distinct "sign_handshake" audit op so client-auth
// signing is never conflated with document signing in the ledger.
func (d *delegatedSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	sig, err := d.signer.signHandshake(d.company, d.serial, digest, opts)
	d.signer.emit(AuditEvent{
		CompanyID:  d.company,
		CertSerial: d.serial,
		Op:         "sign_handshake",
		At:         d.signer.now().UTC(),
		Err:        errText(err),
	})
	return sig, err
}

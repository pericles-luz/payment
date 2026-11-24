package custody

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// testCert mints a self-signed RSA leaf + key for the FileSigner tests.
func testCert(t *testing.T, notAfter time.Time) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "smoke-test-a1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("createcert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsecert: %v", err)
	}
	return priv, leaf
}

// pemBundle serialises a key + cert(s) into a PEM bundle (key PKCS#8 first).
func pemBundle(t *testing.T, key *rsa.PrivateKey, certs ...*x509.Certificate) []byte {
	t.Helper()
	var b bytes.Buffer
	if key != nil {
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatalf("marshal key: %v", err)
		}
		_ = pem.Encode(&b, &pem.Block{Type: "PRIVATE KEY", Bytes: der})
	}
	for _, c := range certs {
		_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	return b.Bytes()
}

func TestLoadFileSignerFromPEM(t *testing.T) {
	key, leaf := testCert(t, time.Now().Add(48*time.Hour))
	s, err := LoadFileSigner(pemBundle(t, key, leaf), "")
	if err != nil {
		t.Fatalf("LoadFileSigner: %v", err)
	}
	if s.Serial() != SerialHex(leaf) {
		t.Errorf("serial = %q, want %q", s.Serial(), SerialHex(leaf))
	}
	if chain := s.PublicChain(); len(chain) != 1 || !chain[0].Equal(leaf) {
		t.Errorf("PublicChain mismatch: %+v", chain)
	}
	meta := s.Meta("47064135000184")
	if meta.CNPJHash != HashCNPJ("47064135000184") || meta.Serial != SerialHex(leaf) {
		t.Errorf("Meta mismatch: %+v", meta)
	}

	// SignDigest produces a PKCS#1 v1.5 signature verifiable against the leaf.
	digest := sha256.Sum256([]byte("signed-info"))
	sig, err := s.SignDigest(context.Background(), "co", s.Serial(), digest[:])
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
		t.Errorf("document signature does not verify: %v", err)
	}
}

func TestLoadFileSignerFromPEMWithChain(t *testing.T) {
	key, leaf := testCert(t, time.Now().Add(48*time.Hour))
	_, ca := testCert(t, time.Now().Add(72*time.Hour))
	s, err := LoadFileSigner(pemBundle(t, key, leaf, ca), "")
	if err != nil {
		t.Fatalf("LoadFileSigner: %v", err)
	}
	if chain := s.PublicChain(); len(chain) != 2 {
		t.Fatalf("chain len = %d, want 2", len(chain))
	}
}

func TestFileSignerClientCertificateAndHandshake(t *testing.T) {
	key, leaf := testCert(t, time.Now().Add(48*time.Hour))
	s, err := LoadFileSigner(pemBundle(t, key, leaf), "")
	if err != nil {
		t.Fatalf("LoadFileSigner: %v", err)
	}
	cert, err := s.ClientCertificate(context.Background(), "co")
	if err != nil {
		t.Fatalf("ClientCertificate: %v", err)
	}
	if len(cert.Certificate) == 0 || cert.Leaf == nil {
		t.Fatal("client certificate has no chain/leaf")
	}
	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		t.Fatal("PrivateKey is not a crypto.Signer (raw key leaked?)")
	}
	if _, isRSA := signer.Public().(*rsa.PublicKey); !isRSA {
		t.Fatalf("delegated signer public key type = %T", signer.Public())
	}

	digest := sha256.Sum256([]byte("certificate-verify"))

	// TLS 1.3 negotiates RSA-PSS.
	var captured crypto.SignerOpts
	s.SetHandshakeObserver(func(o crypto.SignerOpts) { captured = o })
	pss := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
	sig, err := signer.Sign(rand.Reader, digest[:], pss)
	if err != nil {
		t.Fatalf("handshake PSS sign: %v", err)
	}
	if err := rsa.VerifyPSS(&key.PublicKey, crypto.SHA256, digest[:], sig, pss); err != nil {
		t.Errorf("PSS handshake signature does not verify: %v", err)
	}
	if _, isPSS := captured.(*rsa.PSSOptions); !isPSS {
		t.Errorf("observer opts = %T, want *rsa.PSSOptions", captured)
	}

	// Legacy TLS 1.2 may negotiate PKCS#1 v1.5.
	sig2, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("handshake PKCS1v15 sign: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], sig2); err != nil {
		t.Errorf("PKCS1v15 handshake signature does not verify: %v", err)
	}
}

func TestFileSignerRejectsMismatchedKey(t *testing.T) {
	_, leaf := testCert(t, time.Now().Add(48*time.Hour))
	otherKey, _ := testCert(t, time.Now().Add(48*time.Hour))
	_, err := LoadFileSigner(pemBundle(t, otherKey, leaf), "")
	if err == nil {
		t.Fatal("expected error for mismatched key/cert pair")
	}
}

func TestFileSignerRejectsNonRSAKey(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ec genkey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatalf("marshal ec: %v", err)
	}
	_, leaf := testCert(t, time.Now().Add(48*time.Hour))
	var b bytes.Buffer
	_ = pem.Encode(&b, &pem.Block{Type: "PRIVATE KEY", Bytes: der})
	_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	_, err = LoadFileSigner(b.Bytes(), "")
	if !errors.Is(err, ErrUnsupportedKey) {
		t.Fatalf("err = %v, want ErrUnsupportedKey", err)
	}
}

func TestFileSignerMissingParts(t *testing.T) {
	key, leaf := testCert(t, time.Now().Add(48*time.Hour))
	if _, err := LoadFileSigner(pemBundle(t, key), ""); !errors.Is(err, ErrEmptyChain) {
		t.Errorf("key-only bundle err = %v, want ErrEmptyChain", err)
	}
	if _, err := LoadFileSigner(pemBundle(t, nil, leaf), ""); !errors.Is(err, ErrNoPrivateKey) {
		t.Errorf("cert-only bundle err = %v, want ErrNoPrivateKey", err)
	}
}

func TestFileSignerExpiredCertFailsClosed(t *testing.T) {
	key, leaf := testCert(t, time.Now().Add(-time.Hour)) // already expired
	s, err := LoadFileSigner(pemBundle(t, key, leaf), "")
	if err != nil {
		t.Fatalf("LoadFileSigner: %v", err)
	}
	digest := sha256.Sum256([]byte("x"))
	if _, err := s.SignDigest(context.Background(), "co", s.Serial(), digest[:]); !errors.Is(err, ErrCertExpired) {
		t.Errorf("SignDigest err = %v, want ErrCertExpired", err)
	}
	cert, _ := s.ClientCertificate(context.Background(), "co")
	signer := cert.PrivateKey.(crypto.Signer)
	if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256); !errors.Is(err, ErrCertExpired) {
		t.Errorf("handshake sign err = %v, want ErrCertExpired", err)
	}
}

func TestFileSignerAuditSink(t *testing.T) {
	key, leaf := testCert(t, time.Now().Add(48*time.Hour))
	var ops []string
	s, err := LoadFileSigner(pemBundle(t, key, leaf), "", WithFileSignerAudit(func(ev AuditEvent) {
		ops = append(ops, ev.Op)
	}))
	if err != nil {
		t.Fatalf("LoadFileSigner: %v", err)
	}
	digest := sha256.Sum256([]byte("x"))
	_, _ = s.SignDigest(context.Background(), "co", s.Serial(), digest[:])
	cert, _ := s.ClientCertificate(context.Background(), "co")
	_, _ = cert.PrivateKey.(crypto.Signer).Sign(rand.Reader, digest[:], crypto.SHA256)
	want := map[string]bool{"sign_digest": false, "client_certificate": false, "sign_handshake": false}
	for _, op := range ops {
		if _, ok := want[op]; ok {
			want[op] = true
		}
	}
	for op, seen := range want {
		if !seen {
			t.Errorf("audit sink missing op %q (got %v)", op, ops)
		}
	}
}

func TestLoadFileSignerBadPKCS12(t *testing.T) {
	if _, err := LoadFileSigner([]byte{0x01, 0x02, 0x03, 0x04}, "pw"); err == nil {
		t.Fatal("expected error decoding non-PKCS12 garbage")
	}
}

// TestLoadFileSignerFromPKCS12 covers the .pfx path using openssl to build a
// legacy (PBES1) PKCS#12 that x/crypto/pkcs12 can decode. Skips when openssl is
// unavailable so CI without it stays green.
func TestLoadFileSignerFromPKCS12(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not available")
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "k.pem")
	certPath := filepath.Join(dir, "c.pem")
	pfxPath := filepath.Join(dir, "b.pfx")

	if out, err := exec.Command(openssl, "req", "-x509", "-newkey", "rsa:2048",
		"-keyout", keyPath, "-out", certPath, "-days", "2", "-nodes",
		"-subj", "/CN=smoke-pfx").CombinedOutput(); err != nil {
		t.Skipf("openssl req failed (%v): %s", err, out)
	}
	if out, err := exec.Command(openssl, "pkcs12", "-export", "-legacy",
		"-inkey", keyPath, "-in", certPath, "-out", pfxPath,
		"-passout", "pass:testpass").CombinedOutput(); err != nil {
		t.Skipf("openssl pkcs12 -legacy failed (%v): %s", err, out)
	}
	data, err := os.ReadFile(pfxPath)
	if err != nil {
		t.Fatalf("read pfx: %v", err)
	}
	s, err := LoadFileSigner(data, "testpass")
	if err != nil {
		t.Fatalf("LoadFileSigner(pfx): %v", err)
	}
	if len(s.PublicChain()) == 0 || s.Serial() == "" {
		t.Fatalf("pfx signer not populated: chain=%d serial=%q", len(s.PublicChain()), s.Serial())
	}
	// Wrong password fails closed.
	if _, err := LoadFileSigner(data, "wrong"); err == nil {
		t.Error("expected error with wrong PKCS#12 password")
	}
}

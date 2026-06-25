package c6

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// certAuthority is a tiny in-memory CA used to mint the server and client certs
// for the mTLS handshake tests. Generating everything in-memory keeps secrets out
// of the repo (no committed PEM fixtures) while still exercising a real TLS
// RequireAndVerifyClientCert handshake end to end.
type certAuthority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newCA(t *testing.T) *certAuthority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	return &certAuthority{cert: cert, key: key}
}

func (ca *certAuthority) pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.cert)
	return p
}

// issue mints a leaf certificate (server or client) signed by the CA and returns
// it as a tls.Certificate plus its PEM cert/key bytes.
func (ca *certAuthority) issue(t *testing.T, cn string, serverAuth bool) (tls.Certificate, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if serverAuth {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
		tmpl.DNSNames = []string{"localhost"}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("x509 key pair: %v", err)
	}
	return tlsCert, certPEM, keyPEM
}

// writePEM writes cert/key PEM to temp files and returns their paths, mirroring
// how production loads the client cert from a path (secret only ever in a file).
func writePEM(t *testing.T, certPEM, keyPEM []byte) (string, string) {
	t.Helper()
	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

// mTLSServer starts an httptest server that REQUIRES and verifies a client cert
// signed by the given CA. It is unstarted then StartTLS'd so we control the
// TLSConfig (ClientAuth) exactly as the acceptance bar requires.
func mTLSServer(t *testing.T, ca *certAuthority, serverCert tls.Certificate) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    ca.pool(),
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// trustServer grafts the test CA onto a client's transport so it trusts the
// server's self-signed-by-CA cert without weakening verification (no
// InsecureSkipVerify). The client cert (if any) set by MTLSHTTPClient is left
// intact.
func trustServer(t *testing.T, c *http.Client, ca *certAuthority) {
	t.Helper()
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("unexpected transport %T", c.Transport)
	}
	tr.TLSClientConfig.RootCAs = ca.pool()
}

func TestMTLSHTTPClientPresentsClientCert(t *testing.T) {
	t.Parallel()
	ca := newCA(t)
	serverCert, _, _ := ca.issue(t, "127.0.0.1", true)
	srv := mTLSServer(t, ca, serverCert)

	_, clientCertPEM, clientKeyPEM := ca.issue(t, "payment-client", false)
	certPath, keyPath := writePEM(t, clientCertPEM, clientKeyPEM)

	c, err := MTLSHTTPClient(certPath, keyPath, 5*time.Second)
	if err != nil {
		t.Fatalf("MTLSHTTPClient: %v", err)
	}
	trustServer(t, c, ca)

	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatalf("expected the mTLS call to connect with a valid client cert, got: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: want 200, got %d", resp.StatusCode)
	}
}

func TestMTLSHTTPClientRejectedWithoutClientCert(t *testing.T) {
	t.Parallel()
	ca := newCA(t)
	serverCert, _, _ := ca.issue(t, "127.0.0.1", true)
	srv := mTLSServer(t, ca, serverCert)

	// A plain client (no client cert) that trusts the server still fails the
	// handshake because the server requires a verified client cert.
	c := defaultHTTPClient(5 * time.Second)
	trustServer(t, c, ca)

	if _, err := c.Get(srv.URL); err == nil {
		t.Fatal("expected the handshake to be rejected when no client cert is presented")
	}
}

func TestMTLSHTTPClientRejectedWithUntrustedClientCert(t *testing.T) {
	t.Parallel()
	serverCA := newCA(t)
	serverCert, _, _ := serverCA.issue(t, "127.0.0.1", true)
	srv := mTLSServer(t, serverCA, serverCert)

	// A client cert signed by a DIFFERENT CA the server does not trust.
	otherCA := newCA(t)
	_, certPEM, keyPEM := otherCA.issue(t, "rogue-client", false)
	certPath, keyPath := writePEM(t, certPEM, keyPEM)

	c, err := MTLSHTTPClient(certPath, keyPath, 5*time.Second)
	if err != nil {
		t.Fatalf("MTLSHTTPClient: %v", err)
	}
	trustServer(t, c, serverCA)

	if _, err := c.Get(srv.URL); err == nil {
		t.Fatal("expected the handshake to be rejected for a client cert from an untrusted CA")
	}
}

func TestMTLSHTTPClientLoadFailureFailsClosed(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name              string
		certPath, keyPath string
	}{
		{"missing files", "/nonexistent/client.crt", "/nonexistent/client.key"},
		{"empty paths", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := MTLSHTTPClient(tc.certPath, tc.keyPath, time.Second); err == nil {
				t.Fatal("expected a load error (fail-closed), got nil")
			}
		})
	}

	// A cert present but key mismatched (here: a key file holding the cert PEM)
	// must also fail to load rather than silently building a no-cert client.
	ca := newCA(t)
	_, certPEM, _ := ca.issue(t, "client", false)
	certPath, keyPath := writePEM(t, certPEM, certPEM) // key file is NOT a key
	if _, err := MTLSHTTPClient(certPath, keyPath, time.Second); err == nil {
		t.Fatal("expected a load error for a mismatched key, got nil")
	}
}

func TestMTLSHTTPClientPreservesTransportHardening(t *testing.T) {
	t.Parallel()
	ca := newCA(t)
	_, certPEM, keyPEM := ca.issue(t, "client", false)
	certPath, keyPath := writePEM(t, certPEM, keyPEM)

	c, err := MTLSHTTPClient(certPath, keyPath, 9*time.Second)
	if err != nil {
		t.Fatalf("MTLSHTTPClient: %v", err)
	}
	if c.Timeout != 9*time.Second {
		t.Fatalf("timeout not applied: %v", c.Timeout)
	}
	// Redirects stay disabled (anti-SSRF): CheckRedirect returns ErrUseLastResponse.
	if c.CheckRedirect == nil || c.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Fatal("expected redirects to remain disabled")
	}
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("unexpected transport %T", c.Transport)
	}
	if tr.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatal("expected MinVersion TLS 1.2 to be preserved")
	}
	if len(tr.TLSClientConfig.Certificates) != 1 {
		t.Fatalf("expected exactly one client cert, got %d", len(tr.TLSClientConfig.Certificates))
	}
}

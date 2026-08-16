package c6

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// seedCertStore stores a client cert/key under (tenantID, bankID) in a real
// in-memory CertStore (the documented in-memory adapter, not a DB mock) so the vault
// transport is exercised against production adapter behaviour.
func seedCertStore(t *testing.T, s *secret.CertStore, tenantID, bankID string, certPEM, keyPEM []byte) {
	t.Helper()
	if err := s.SetBankCertificate(context.Background(), ports.BankCertificate{
		TenantID: tenantID,
		BankID:   bankID,
		CertPEM:  string(certPEM),
		KeyPEM:   string(keyPEM),
	}); err != nil {
		t.Fatalf("seed cert store: %v", err)
	}
}

// tenantGet performs a GET carrying tenantID stamped on the context, exactly as the
// production request builders do (withTenant), so the mTLS transport selects the
// tenant's client certificate at handshake time.
func tenantGet(t *testing.T, c *http.Client, url, tenantID string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(withTenant(context.Background(), tenantID), http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	return c.Do(req)
}

// TestVaultMTLSPresentsTenantCertFromVault: the live handshake mounts the client
// certificate from the vault (keyed by the request's tenant), not from a path.
func TestVaultMTLSPresentsTenantCertFromVault(t *testing.T) {
	t.Parallel()
	ca := newCA(t)
	serverCert, _, _ := ca.issue(t, "127.0.0.1", true)
	srv := mTLSServer(t, ca, serverCert)

	_, clientCertPEM, clientKeyPEM := ca.issue(t, "verz-client", false)
	store := secret.NewCertStore()
	seedCertStore(t, store, "tenant-verz", ports.BankIDC6, clientCertPEM, clientKeyPEM)

	// No §8 path fallback: the cert can ONLY come from the vault.
	c, err := NewVaultMTLSClient(store, ports.BankIDC6, "", "", 5*time.Second)
	if err != nil {
		t.Fatalf("NewVaultMTLSClient: %v", err)
	}
	trustVaultServer(t, c, "tenant-verz", ca)

	resp, err := tenantGet(t, c, srv.URL, "tenant-verz")
	if err != nil {
		t.Fatalf("expected the mTLS call to connect with the vault client cert, got: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: want 200, got %d", resp.StatusCode)
	}
}

// TestVaultMTLSFallsBackToPathWhenNoRow: a tenant with no vault row uses the §8 path
// (bootstrap) certificate — env-as-bootstrap, mirroring the credential vault.
func TestVaultMTLSFallsBackToPathWhenNoRow(t *testing.T) {
	t.Parallel()
	ca := newCA(t)
	serverCert, _, _ := ca.issue(t, "127.0.0.1", true)
	srv := mTLSServer(t, ca, serverCert)

	// Bootstrap cert on disk (path §8); the vault is EMPTY for this tenant.
	_, bootCertPEM, bootKeyPEM := ca.issue(t, "bootstrap-client", false)
	certPath, keyPath := writePEM(t, bootCertPEM, bootKeyPEM)
	store := secret.NewCertStore()

	c, err := NewVaultMTLSClient(store, ports.BankIDC6, certPath, keyPath, 5*time.Second)
	if err != nil {
		t.Fatalf("NewVaultMTLSClient: %v", err)
	}
	trustVaultServer(t, c, "tenant-without-row", ca)

	resp, err := tenantGet(t, c, srv.URL, "tenant-without-row")
	if err != nil {
		t.Fatalf("expected the fallback bootstrap cert to connect, got: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: want 200, got %d", resp.StatusCode)
	}
}

// TestVaultMTLSTenantIsolation: two tenants present DIFFERENT client certificates —
// each transport is isolated, so tenant B never rides tenant A's authenticated
// connection. The server records the presented client CN per request.
func TestVaultMTLSTenantIsolation(t *testing.T) {
	t.Parallel()
	ca := newCA(t)
	serverCert, _, _ := ca.issue(t, "127.0.0.1", true)

	seenCN := make(chan string, 2)
	srv := mTLSServerRecording(t, ca, serverCert, seenCN)

	_, aCertPEM, aKeyPEM := ca.issue(t, "tenant-a-client", false)
	_, bCertPEM, bKeyPEM := ca.issue(t, "tenant-b-client", false)
	store := secret.NewCertStore()
	seedCertStore(t, store, "tenant-a", ports.BankIDC6, aCertPEM, aKeyPEM)
	seedCertStore(t, store, "tenant-b", ports.BankIDC6, bCertPEM, bKeyPEM)

	c, err := NewVaultMTLSClient(store, ports.BankIDC6, "", "", 5*time.Second)
	if err != nil {
		t.Fatalf("NewVaultMTLSClient: %v", err)
	}
	// Trust the server on BOTH tenant transports (build them first via a warm-up call
	// is unnecessary: RootCAs is grafted per tenant below).
	trustVaultServer(t, c, "tenant-a", ca)
	trustVaultServer(t, c, "tenant-b", ca)

	for _, tc := range []struct{ tenant, wantCN string }{
		{"tenant-a", "tenant-a-client"},
		{"tenant-b", "tenant-b-client"},
	} {
		resp, err := tenantGet(t, c, srv.URL, tc.tenant)
		if err != nil {
			t.Fatalf("%s: request failed: %v", tc.tenant, err)
		}
		resp.Body.Close()
		got := <-seenCN
		if got != tc.wantCN {
			t.Fatalf("%s presented CN %q, want %q (tenant isolation breach)", tc.tenant, got, tc.wantCN)
		}
	}
}

// TestVaultMTLSVaultErrorFailsClosed: a vault error OTHER than not-found (here a wrong
// KEK surfaced by a failing provider) fails the handshake closed rather than silently
// using the bootstrap identity.
func TestVaultMTLSVaultErrorFailsClosed(t *testing.T) {
	t.Parallel()
	ca := newCA(t)
	serverCert, _, _ := ca.issue(t, "127.0.0.1", true)
	srv := mTLSServer(t, ca, serverCert)

	// A bootstrap cert IS configured; the failing provider must NOT be masked by it.
	_, bootCertPEM, bootKeyPEM := ca.issue(t, "bootstrap-client", false)
	certPath, keyPath := writePEM(t, bootCertPEM, bootKeyPEM)

	c, err := NewVaultMTLSClient(failingCertProvider{}, ports.BankIDC6, certPath, keyPath, 5*time.Second)
	if err != nil {
		t.Fatalf("NewVaultMTLSClient: %v", err)
	}
	trustVaultServer(t, c, "tenant-broken", ca)

	if _, err := tenantGet(t, c, srv.URL, "tenant-broken"); err == nil {
		t.Fatal("expected the handshake to fail closed on a vault error, got nil")
	}
}

// TestVaultMTLSRequiresProvider: a nil provider is a wiring error (fail closed).
func TestVaultMTLSRequiresProvider(t *testing.T) {
	t.Parallel()
	if _, err := NewVaultMTLSClient(nil, ports.BankIDC6, "", "", time.Second); err == nil {
		t.Fatal("expected an error for a nil certificate provider")
	}
}

// TestVaultMTLSBootstrapLoadFailsClosed: a configured but unreadable §8 path fails the
// boot closed, exactly as MTLSHTTPClient does.
func TestVaultMTLSBootstrapLoadFailsClosed(t *testing.T) {
	t.Parallel()
	store := secret.NewCertStore()
	if _, err := NewVaultMTLSClient(store, ports.BankIDC6, "/nonexistent/c.crt", "/nonexistent/c.key", time.Second); err == nil {
		t.Fatal("expected a load error for an unreadable bootstrap cert path")
	}
}

// TestVaultMTLSNoCertPresentsNone: with neither a vault row nor a §8 path, the tenant
// presents no client cert and the mTLS-requiring server rejects the handshake (fail
// closed, matching the prior no-cert behaviour).
func TestVaultMTLSNoCertPresentsNone(t *testing.T) {
	t.Parallel()
	ca := newCA(t)
	serverCert, _, _ := ca.issue(t, "127.0.0.1", true)
	srv := mTLSServer(t, ca, serverCert)

	store := secret.NewCertStore()
	c, err := NewVaultMTLSClient(store, ports.BankIDC6, "", "", 5*time.Second)
	if err != nil {
		t.Fatalf("NewVaultMTLSClient: %v", err)
	}
	trustVaultServer(t, c, "tenant-none", ca)

	if _, err := tenantGet(t, c, srv.URL, "tenant-none"); err == nil {
		t.Fatal("expected the handshake to be rejected when no client cert is available")
	}
}

// failingCertProvider is a CertProvider whose read always fails with a non-not-found
// error (the shape of a wrong-KEK / corrupt-blob failure).
type failingCertProvider struct{}

func (failingCertProvider) LoadTLSCertificate(context.Context, string, string) (*tls.Certificate, error) {
	return nil, errors.New("open sealed private key: cipher: message authentication failed")
}

// compile-time: the in-memory CertStore satisfies CertProvider (production adapter).
var _ CertProvider = (*secret.CertStore)(nil)

// trustVaultServer grafts the test CA onto the per-tenant transport for tenantID so
// the client trusts the server's CA-signed cert without weakening verification. It
// forces the tenant transport to be built (transportFor) and sets its RootCAs.
func trustVaultServer(t *testing.T, c *http.Client, tenantID string, ca *certAuthority) {
	t.Helper()
	rt, ok := c.Transport.(*mtlsRoundTripper)
	if !ok {
		t.Fatalf("unexpected transport %T", c.Transport)
	}
	tr := rt.transportFor(tenantID)
	if tr.TLSClientConfig == nil {
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	tr.TLSClientConfig.RootCAs = ca.pool()
}

// mTLSServerRecording is mTLSServer plus a per-request capture of the presented
// client cert's CN into seenCN, so a test can assert which tenant identity actually
// reached the server (tenant-isolation check).
func mTLSServerRecording(t *testing.T, ca *certAuthority, serverCert tls.Certificate, seenCN chan<- string) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cn := ""
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			cn = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		seenCN <- cn
		w.WriteHeader(http.StatusOK)
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

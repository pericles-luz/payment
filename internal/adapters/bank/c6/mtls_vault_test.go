package c6

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
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

// TestVaultMTLSNoRowNeverUsesBootstrapCert: um tenant SEM certificado no cofre não
// apresenta nenhum — nunca o de bootstrap, que é a identidade de outra empresa. O
// handshake falha, e falhar é o desfecho certo.
//
// Isto derrubou o tenant 27 em produção (SIN-69368): entre gravar a credencial e
// gravar o certificado, 40 segundos, a varredura de webhook abriu conexão sob a
// identidade de bootstrap e ela ficou no pool. Como a varredura roda a cada 60s e o
// tempo ocioso é 90s, a conexão errada nunca expirou; o tenant respondeu 500 por mais
// de uma hora, até o reinício. Sem handshake não há conexão para envenenar o pool.
func TestVaultMTLSNoRowNeverUsesBootstrapCert(t *testing.T) {
	t.Parallel()
	ca := newCA(t)
	serverCert, _, _ := ca.issue(t, "127.0.0.1", true)
	srv := mTLSServer(t, ca, serverCert)

	// Certificado de bootstrap em disco (caminho §8); o cofre está VAZIO para este
	// tenant. O de bootstrap é válido para o servidor — se vazasse, a chamada passaria.
	_, bootCertPEM, bootKeyPEM := ca.issue(t, "bootstrap-client", false)
	certPath, keyPath := writePEM(t, bootCertPEM, bootKeyPEM)
	store := secret.NewCertStore()

	c, err := NewVaultMTLSClient(store, ports.BankIDC6, certPath, keyPath, 5*time.Second)
	if err != nil {
		t.Fatalf("NewVaultMTLSClient: %v", err)
	}
	trustVaultServer(t, c, "tenant-without-row", ca)

	resp, err := tenantGet(t, c, srv.URL, "tenant-without-row")
	if err == nil {
		defer resp.Body.Close()
		t.Fatalf("tenant sem certificado próprio conectou (status %d): apresentou a\nidentidade de bootstrap, que pertence a outra empresa", resp.StatusCode)
	}
}

// A contrapartida: uma requisição SEM tenant algum continua usando o certificado de
// bootstrap. É o caminho de infraestrutura (sondagem, registro inicial), e cortá-lo
// junto quebraria a inicialização.
func TestVaultMTLSBootstrapStillServesUntenantedRequests(t *testing.T) {
	t.Parallel()
	ca := newCA(t)
	serverCert, _, _ := ca.issue(t, "127.0.0.1", true)
	srv := mTLSServer(t, ca, serverCert)

	_, bootCertPEM, bootKeyPEM := ca.issue(t, "bootstrap-client", false)
	certPath, keyPath := writePEM(t, bootCertPEM, bootKeyPEM)

	c, err := NewVaultMTLSClient(secret.NewCertStore(), ports.BankIDC6, certPath, keyPath, 5*time.Second)
	if err != nil {
		t.Fatalf("NewVaultMTLSClient: %v", err)
	}
	trustVaultServer(t, c, "", ca)

	resp, err := tenantGet(t, c, srv.URL, "")
	if err != nil {
		t.Fatalf("requisição sem tenant deveria usar o certificado de bootstrap: %v", err)
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

// TestInvalidateTokenDropsPooledTenantConnection: gravar um certificado novo tem de
// alcançar o FIO, não só o cofre.
//
// O certificado do cliente é escolhido no handshake. Uma conexão que já está no pool
// não refaz handshake, então continua apresentando o certificado ANTIGO — e a
// varredura de webhook, de 60 em 60 segundos, mantém essa conexão abaixo do tempo
// ocioso de 90, de modo que ela nunca expira sozinha. Sem descartar o transporte do
// tenant, uma rotação só passa a valer no próximo reinício do processo.
//
// O teste é sobre a fiação inteira: quem chama é Provider.InvalidateToken, que é o
// que os dois caminhos de gravação de certificado (admin e self-serve) já invocam.
func TestInvalidateTokenDropsPooledTenantConnection(t *testing.T) {
	t.Parallel()
	ca := newCA(t)
	serverCert, _, _ := ca.issue(t, "127.0.0.1", true)

	seenCN := make(chan string, 3)
	srv := mTLSServerRecording(t, ca, serverCert, seenCN)

	const tenant = "tenant-rotativo"
	store := secret.NewCertStore()
	_, oldCertPEM, oldKeyPEM := ca.issue(t, "cert-antigo", false)
	seedCertStore(t, store, tenant, ports.BankIDC6, oldCertPEM, oldKeyPEM)

	c, err := NewVaultMTLSClient(store, ports.BankIDC6, "", "", 5*time.Second)
	if err != nil {
		t.Fatalf("NewVaultMTLSClient: %v", err)
	}
	trustVaultServer(t, c, tenant, ca)

	p, err := New(Config{BaseURL: srv.URL, TokenURL: srv.URL + "/oauth/token", HTTPClient: c}, oneTenant(tenant, "cli", "seg"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Primeira chamada: estabelece a conexão e a devolve ao pool (corpo drenado).
	drainTenantGet(t, c, srv.URL, tenant)
	if cn := <-seenCN; cn != "cert-antigo" {
		t.Fatalf("primeira conexão: want cert-antigo, got %q", cn)
	}

	// A empresa envia um certificado novo. O cofre já reflete a troca...
	_, newCertPEM, newKeyPEM := ca.issue(t, "cert-novo", false)
	seedCertStore(t, store, tenant, ports.BankIDC6, newCertPEM, newKeyPEM)

	// ...e a eviction que o caminho de gravação dispara tem de derrubar a conexão
	// antiga junto. Sem isso, a chamada abaixo reaproveita o pool e o servidor
	// continua vendo cert-antigo.
	p.InvalidateToken(tenant)
	trustVaultServer(t, c, tenant, ca) // o transporte é novo: reensina a CA do teste

	drainTenantGet(t, c, srv.URL, tenant)
	if cn := <-seenCN; cn != "cert-novo" {
		t.Fatalf("depois da rotação o C6 ainda vê %q: a conexão antiga continuou no\npool e o certificado novo nunca chegou ao fio", cn)
	}
}

// drainTenantGet faz o GET com tenant e ESVAZIA o corpo antes de fechar, que é a
// condição para a conexão voltar ao pool — sem isso o teste não exercitaria reuso.
func drainTenantGet(t *testing.T, c *http.Client, url, tenantID string) {
	t.Helper()
	resp, err := tenantGet(t, c, url, tenantID)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatalf("drenar corpo: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: want 200, got %d", resp.StatusCode)
	}
}

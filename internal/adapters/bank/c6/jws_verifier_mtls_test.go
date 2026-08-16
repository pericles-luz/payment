package c6

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// SIN-69375: the JWKS fetch is process-wide and stamps no tenant, so on a vault-only
// mTLS transport it would fall back to the (absent) §8 bootstrap cert and fail the
// handshake — breaking every recurrence signature verification. WithMTLSTenant lets an
// operator designate a tenant whose vault certificate is presented on that fetch.

// captureTenantRT records the tenant stamped on the request context and short-circuits
// the round-trip, so the stamping can be asserted without a live TLS handshake.
type captureTenantRT struct {
	seen   string
	called bool
}

func (c *captureTenantRT) RoundTrip(req *http.Request) (*http.Response, error) {
	c.seen = tenantFromContext(req.Context())
	c.called = true
	return nil, errors.New("captured")
}

// TestJWKSFetch_StampsDesignatedMTLSTenant: WithMTLSTenant propagates from the option
// through NewJWSVerifier down to the concrete fetcher, which stamps it on the fetch
// context so a tenant-aware transport can select that tenant's certificate.
func TestJWKSFetch_StampsDesignatedMTLSTenant(t *testing.T) {
	t.Parallel()
	rt := &captureTenantRT{}
	v, err := NewJWSVerifier("https://c6.example/jwks", &http.Client{Transport: rt}, WithMTLSTenant("tenant-jwks"))
	if err != nil {
		t.Fatalf("NewJWSVerifier: %v", err)
	}
	f, ok := v.fetcher.(*httpJWKSFetcher)
	if !ok {
		t.Fatalf("unexpected fetcher %T", v.fetcher)
	}
	if f.mtlsTenant != "tenant-jwks" {
		t.Fatalf("fetcher mtlsTenant = %q, want %q", f.mtlsTenant, "tenant-jwks")
	}
	_, _ = f.fetch(context.Background())
	if !rt.called {
		t.Fatal("transport was never reached")
	}
	if rt.seen != "tenant-jwks" {
		t.Fatalf("fetch stamped tenant %q, want %q", rt.seen, "tenant-jwks")
	}
}

// TestJWKSFetch_NoTenantWhenUnset: without the option the fetch stays tenantless, so
// existing deployments (with a §8 bootstrap cert, or a public JWKS) are unaffected.
func TestJWKSFetch_NoTenantWhenUnset(t *testing.T) {
	t.Parallel()
	rt := &captureTenantRT{}
	v, err := NewJWSVerifier("https://c6.example/jwks", &http.Client{Transport: rt})
	if err != nil {
		t.Fatalf("NewJWSVerifier: %v", err)
	}
	f := v.fetcher.(*httpJWKSFetcher)
	if f.mtlsTenant != "" {
		t.Fatalf("fetcher mtlsTenant = %q, want empty", f.mtlsTenant)
	}
	_, _ = f.fetch(context.Background())
	if rt.seen != "" {
		t.Fatalf("fetch stamped tenant %q, want empty (tenantless)", rt.seen)
	}
}

// TestWithMTLSTenant_EmptyIgnored: an empty designated tenant is a no-op (the fetch
// stays tenantless) rather than pinning the empty-tenant bootstrap slot explicitly.
func TestWithMTLSTenant_EmptyIgnored(t *testing.T) {
	t.Parallel()
	v, err := NewJWSVerifier("https://c6.example/jwks", nil, WithMTLSTenant(""))
	if err != nil {
		t.Fatalf("NewJWSVerifier: %v", err)
	}
	if got := v.fetcher.(*httpJWKSFetcher).mtlsTenant; got != "" {
		t.Fatalf("empty WithMTLSTenant set mtlsTenant = %q, want empty", got)
	}
}

// jwksMTLSServer starts a TLS server that REQUIRES and verifies a client certificate,
// records the presented CN, and serves the JWKS document — the shape of a JWKS
// endpoint sitting behind C6's mTLS.
func jwksMTLSServer(t *testing.T, ca *certAuthority, serverCert tls.Certificate, seenCN chan<- string, key testKey) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cn := ""
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			cn = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		seenCN <- cn
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwkSet(key))
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

// TestJWKSFetch_EndToEndVaultMTLSTenant: on a vault-only transport (NO §8 bootstrap),
// designating the JWKS mTLS tenant makes the fetch present that tenant's vault
// certificate and succeed — the fix's success path.
func TestJWKSFetch_EndToEndVaultMTLSTenant(t *testing.T) {
	t.Parallel()
	ca := newCA(t)
	serverCert, _, _ := ca.issue(t, "127.0.0.1", true)
	key := newES256Key(t, "k-es")
	seenCN := make(chan string, 1)
	srv := jwksMTLSServer(t, ca, serverCert, seenCN, key)

	_, clientCertPEM, clientKeyPEM := ca.issue(t, "jwks-fetch-client", false)
	store := secret.NewCertStore()
	seedCertStore(t, store, "tenant-jwks", ports.BankIDC6, clientCertPEM, clientKeyPEM)

	// Vault-only: neither §8 path set, so the JWKS fetch can only handshake if it
	// presents the designated tenant's vault certificate.
	httpc, err := NewVaultMTLSClient(store, ports.BankIDC6, "", "", 5*time.Second)
	if err != nil {
		t.Fatalf("NewVaultMTLSClient: %v", err)
	}
	trustVaultServer(t, httpc, "tenant-jwks", ca)

	v, err := NewJWSVerifier(srv.URL, httpc, WithMTLSTenant("tenant-jwks"))
	if err != nil {
		t.Fatalf("NewJWSVerifier: %v", err)
	}
	// A verify drives the fetch (unknown kid ⇒ single JWKS fetch, then verify).
	payload, err := v.VerifyJWS(context.Background(), signCompact(t, key, []byte(recPayload)))
	if err != nil {
		t.Fatalf("expected verification to succeed via the designated-tenant JWKS fetch, got: %v", err)
	}
	if string(payload) != recPayload {
		t.Fatalf("payload mismatch: %q", payload)
	}
	if cn := <-seenCN; cn != "jwks-fetch-client" {
		t.Fatalf("JWKS server saw client CN %q, want %q", cn, "jwks-fetch-client")
	}
}

// TestJWKSFetch_VaultOnlyWithoutDesignatedTenantFailsClosed reproduces the SIN-69375
// defect: a vault-only transport with NO designated JWKS tenant stamps none, falls
// back to the absent §8 bootstrap cert, presents no client certificate, and the
// mTLS-requiring JWKS endpoint rejects the handshake — fail-closed, no security hole,
// but recurrence verification cannot proceed. This documents why the option exists.
func TestJWKSFetch_VaultOnlyWithoutDesignatedTenantFailsClosed(t *testing.T) {
	t.Parallel()
	ca := newCA(t)
	serverCert, _, _ := ca.issue(t, "127.0.0.1", true)
	key := newES256Key(t, "k-es")
	seenCN := make(chan string, 1)
	srv := jwksMTLSServer(t, ca, serverCert, seenCN, key)

	store := secret.NewCertStore() // empty vault, no §8 path, no designated tenant
	httpc, err := NewVaultMTLSClient(store, ports.BankIDC6, "", "", 5*time.Second)
	if err != nil {
		t.Fatalf("NewVaultMTLSClient: %v", err)
	}
	trustVaultServer(t, httpc, "", ca) // the tenantless ("") bootstrap slot

	v, err := NewJWSVerifier(srv.URL, httpc) // no WithMTLSTenant
	if err != nil {
		t.Fatalf("NewJWSVerifier: %v", err)
	}
	if _, err := v.VerifyJWS(context.Background(), signCompact(t, key, []byte(recPayload))); err == nil {
		t.Fatal("expected verification to fail closed when the JWKS mTLS handshake presents no client cert")
	}
}

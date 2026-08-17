package outbound

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// allowAllGuard is a permissive SSRFGuard for tests that need to reach an httptest server
// on loopback. The strict publicOnlyGuard is exercised separately (ssrfguard_test.go, and
// the rebind test below); this only removes the loopback block so the transport hardening
// (redirects, timeouts, no-echo) can be tested against a real server.
type allowAllGuard struct{}

func (allowAllGuard) CheckIP(net.IP) error { return nil }

// tlsForwarder builds a test forwarder that trusts srv's self-signed cert, using the given
// guard and allowing the server's random port.
func tlsForwarder(t *testing.T, srv *httptest.Server, guard SSRFGuard) *Forwarder {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return newForwarder(guard, &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, true)
}

// T-SSRF-scheme: non-https schemes and non-443 ports are rejected before any network
// activity, with the opaque blocked-destination error (no oracle).
func TestDeliverRejectsBadSchemeAndPort(t *testing.T) {
	t.Parallel()
	f := NewForwarder() // production: strict guard, 443-only
	ctx := context.Background()
	for _, raw := range []string{
		"http://example.com/hook",
		"file:///etc/passwd",
		"gopher://example.com",
		"ftp://example.com",
		"https://example.com:8080/hook", // non-443 port
		"https:///nohost",
		"://malformed",
	} {
		if _, err := f.Deliver(ctx, raw, nil, []byte("{}")); !errors.Is(err, ErrBlockedDestination) {
			t.Fatalf("Deliver(%q) = %v, want ErrBlockedDestination", raw, err)
		}
	}
}

// Happy path: a public (here: loopback, via the permissive guard) https endpoint returns
// 2xx and the signature/idempotency headers arrive intact.
func TestDeliverSuccess(t *testing.T) {
	t.Parallel()
	var gotSig, gotTS, gotIdem, gotCT string
	var gotBody []byte
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-Webhook-Signature")
		gotTS = r.Header.Get("X-Webhook-Timestamp")
		gotIdem = r.Header.Get("X-Webhook-Idempotency-Key")
		gotCT = r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	f := tlsForwarder(t, srv, allowAllGuard{})
	headers := map[string]string{
		"X-Webhook-Signature":       "sha256=abc",
		"X-Webhook-Timestamp":       "1755440000",
		"X-Webhook-Idempotency-Key": "ek-1",
	}
	status, err := f.Deliver(context.Background(), srv.URL, headers, []byte(`{"hi":1}`))
	if err != nil {
		t.Fatalf("Deliver err = %v", err)
	}
	if status != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", status)
	}
	if gotSig != "sha256=abc" || gotTS != "1755440000" || gotIdem != "ek-1" {
		t.Fatalf("headers not forwarded: sig=%q ts=%q idem=%q", gotSig, gotTS, gotIdem)
	}
	if gotCT != "application/json" {
		t.Fatalf("content-type = %q, want application/json", gotCT)
	}
	if string(gotBody) != `{"hi":1}` {
		t.Fatalf("body = %q, want the exact signed bytes", gotBody)
	}
}

// T-SSRF-rebind: a destination whose IP resolves to a non-public address (here loopback,
// standing in for a rebound 169.254.169.254) is refused AT DIAL by the strict guard —
// proving the enforcement is dial-time, not parse-time. Same server, same URL as the
// happy path; only the guard differs.
func TestDeliverBlocksAtDialTime(t *testing.T) {
	t.Parallel()
	reached := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Strict public-only guard: the loopback IP the URL resolves to is blocked at dial.
	f := tlsForwarder(t, srv, NewPublicOnlyGuard())
	_, err := f.Deliver(context.Background(), srv.URL, nil, []byte("{}"))
	if !errors.Is(err, ErrBlockedDestination) {
		t.Fatalf("Deliver = %v, want ErrBlockedDestination (dial-time block)", err)
	}
	if reached {
		t.Fatal("the endpoint was reached despite a non-public IP — guard did not fire at dial")
	}
}

// T-SSRF-redirect: a 302 to an internal target is NOT followed (v1 zero-redirect); the
// forwarder returns the opaque blocked error without chasing the Location.
func TestDeliverDoesNotFollowRedirect(t *testing.T) {
	t.Parallel()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "https://169.254.169.254/latest/meta-data/")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	f := tlsForwarder(t, srv, allowAllGuard{})
	if _, err := f.Deliver(context.Background(), srv.URL, nil, []byte("{}")); !errors.Is(err, ErrBlockedDestination) {
		t.Fatalf("Deliver = %v, want ErrBlockedDestination (no redirect follow)", err)
	}
}

// T-SSRF-noecho: a large secret response body is neither returned nor surfaced by Deliver
// (it returns only the status int); the read is bounded so a huge body cannot hang or
// balloon memory.
func TestDeliverDoesNotEchoResponseBody(t *testing.T) {
	t.Parallel()
	secret := strings.Repeat("SECRET", 100000) // ~600KB, far past the 4KiB cap
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, secret)
	}))
	defer srv.Close()

	f := tlsForwarder(t, srv, allowAllGuard{})
	status, err := f.Deliver(context.Background(), srv.URL, nil, []byte("{}"))
	if err != nil {
		t.Fatalf("Deliver err = %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	// The API returns only an int status — there is no channel through which the body
	// could be echoed. This test documents/guards that contract.
}

// T-TIMEOUT: a black-holing endpoint does not hang the caller — the context deadline is
// honored and Deliver returns a generic (non-oracle) error, not the server's detail.
func TestDeliverHonorsContextDeadline(t *testing.T) {
	t.Parallel()
	block := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-block // never responds until the test tears down
	}))
	defer srv.Close()
	defer close(block)

	f := tlsForwarder(t, srv, allowAllGuard{})
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	status, err := f.Deliver(ctx, srv.URL, nil, []byte("{}"))
	if err == nil {
		t.Fatal("expected a timeout error, got nil")
	}
	if status != 0 {
		t.Fatalf("status = %d, want 0 on error", status)
	}
	if errors.Is(err, ErrBlockedDestination) {
		t.Fatalf("timeout should be a generic delivery error, not a blocked-destination oracle: %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("Deliver did not honor the short deadline (took %s)", time.Since(start))
	}
}

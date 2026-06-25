package c6

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"
)

// MTLSHTTPClient builds an *http.Client whose transport is identical to the
// adapter's default (TLS >= 1.2, redirects disabled as an anti-SSRF guard, a
// bounded idle-connection pool, and a per-request timeout — see defaultHTTPClient)
// but that additionally presents a client certificate so the connection can
// satisfy C6's mutual-TLS requirement. C6 demands an mTLS client certificate on
// the transport in addition to the OAuth2 bearer; this is the wiring for that
// certificate, kept in the adapter so the domain never imports crypto/tls
// (Hexagonal).
//
// The certificate and its private key are loaded from PEM files at certPath /
// keyPath. The key is a SECRET and lives only in that file — never in code, an
// env value, or a URL (threat C1); only the path is configuration. A load failure
// is returned, not swallowed, so the process fails closed at boot (an explicit
// startup error) rather than silently connecting without the client cert.
func MTLSHTTPClient(certPath, keyPath string, timeout time.Duration) (*http.Client, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		// tls.LoadX509KeyPair wraps the os path error; it does not include private
		// key material in its message, so this is safe to surface and log.
		return nil, fmt.Errorf("c6: load mTLS client certificate: %w", err)
	}
	c := defaultHTTPClient(timeout)
	// defaultHTTPClient always installs an *http.Transport with a non-nil
	// TLSClientConfig (MinVersion TLS 1.2); reuse it and graft the client cert so
	// the TLS-floor and transport hardening stay in exactly one place.
	tr := c.Transport.(*http.Transport)
	tr.TLSClientConfig.Certificates = []tls.Certificate{cert}
	return c, nil
}

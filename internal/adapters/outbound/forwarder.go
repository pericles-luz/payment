package outbound

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// errGenericDelivery is the opaque error returned for any non-guard transport failure
// (timeout, connection refused, TLS error). It carries no host, IP or response detail so
// a forward failure never becomes an oracle about the internal network (SSRF-8).
var errGenericDelivery = errors.New("outbound webhook delivery failed")

// forwarder.go is the SSRF-safe HTTP forwarder (SIN-69492 §1/§4 of the threat model
// SIN-69489). It owns a DEDICATED http.Client — never the C6 client's transport, which
// legitimately talks to one fixed external host — configured so that every property the
// threat model marks bloqueante holds by construction:
//
//   - SSRF-1/5: https-only and port 443 only, checked before the request is built.
//   - SSRF-3 (load-bearing): the net.Dialer.Control runs the injected SSRFGuard on the
//     CONCRETE resolved ip:port immediately before connect, so a hostname that resolved
//     to a public IP at config time but rebinds to 169.254.169.254 at dial time is
//     refused. We validate the exact IP the dialer resolved — no re-resolution window.
//   - SSRF-4: CheckRedirect refuses every redirect (v1 is zero-redirect), so a public
//     endpoint cannot 302 us into the internal network.
//   - SSRF-6: aggressive dial / TLS / response-header / total timeouts bound a slow or
//     black-holing destination (threat D1).
//   - SSRF-7: the response body is read through io.LimitReader and discarded — only the
//     status code is used, nothing from the destination is ever echoed back.
//
// The forwarder performs exactly ONE attempt; retry/backoff, the per-account limiter,
// signing and dead-lettering are the app-layer OutboundProcessor's job (single
// responsibility, and it keeps this adapter a thin, auditable network edge).

const (
	// maxResponseBytes caps how much of the destination's response we read. We only need
	// the status line; the body is irrelevant and reading it unbounded would be a memory
	// DoS and an exfiltration channel (SSRF-7). 4 KiB is ample to drain a small ack.
	maxResponseBytes = 4 << 10

	// defaultDialTimeout / defaultTLSTimeout / defaultResponseHeaderTimeout / defaultTotalTimeout
	// are conservative bounds so a hostile or degraded destination cannot tie up a
	// forward goroutine (SSRF-6 / threat D1). They are deliberately short — a webhook
	// receiver that cannot answer in a few seconds is treated as a failed attempt.
	defaultDialTimeout           = 3 * time.Second
	defaultTLSTimeout            = 3 * time.Second
	defaultResponseHeaderTimeout = 5 * time.Second
	defaultTotalTimeout          = 8 * time.Second
	defaultIdleConnTimeout       = 30 * time.Second
	defaultMaxIdleConnsPerHost   = 2
)

// Forwarder POSTs a signed body to a Conta's outbound endpoint over an SSRF-hardened
// client. It satisfies the app-layer app.OutboundForwarder port.
type Forwarder struct {
	client *http.Client
	// allowAnyPort relaxes the 443-only rule (SSRF-5) — production keeps it false so only
	// :443 is dialled; a test sets it true to reach an httptest server on a random port
	// while the dial-time IP guard (the authoritative control) still runs unchanged.
	allowAnyPort bool
}

// NewForwarder builds the production forwarder: the strict public-only SSRF guard wired
// into a dedicated transport with a zero-redirect policy and aggressive timeouts.
func NewForwarder() *Forwarder {
	return NewForwarderWithGuard(NewPublicOnlyGuard())
}

// NewForwarderWithGuard builds a forwarder with an injected SSRFGuard. Production passes
// the public-only guard; tests pass a permissive guard to reach a loopback httptest
// server, or the strict guard to assert a dial is blocked. Everything else about the
// client (no redirects, timeouts, dedicated transport) is identical either way, so the
// hardening under test is the same code that runs in production.
func NewForwarderWithGuard(guard SSRFGuard) *Forwarder {
	return newForwarder(guard, nil, false)
}

// newForwarder is the injectable constructor. tlsConfig lets a test trust an httptest
// server's self-signed certificate (production passes nil → system roots, real
// verification); allowAnyPort relaxes the 443-only rule for a test's random port. Both
// knobs are test-only — the SSRF dial guard, zero-redirect policy and timeouts are wired
// identically in production and under test, so the hardening exercised is the real thing.
func newForwarder(guard SSRFGuard, tlsConfig *tls.Config, allowAnyPort bool) *Forwarder {
	dialer := &net.Dialer{
		Timeout: defaultDialTimeout,
		// Control runs AFTER name resolution with the concrete ip:port about to be
		// dialled — this is the SSRF-3 enforcement point (validate the resolved IP).
		Control: func(_, address string, _ syscall.RawConn) error {
			return checkDialAddress(guard, address)
		},
	}
	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   defaultTLSTimeout,
		ResponseHeaderTimeout: defaultResponseHeaderTimeout,
		IdleConnTimeout:       defaultIdleConnTimeout,
		MaxIdleConnsPerHost:   defaultMaxIdleConnsPerHost,
		TLSClientConfig:       tlsConfig,
		// No Proxy: a forward must never be laundered through a proxy that could reach
		// the internal network or mask the true destination. ForceAttemptHTTP2 default
		// is fine; TLS verification stays ON (no InsecureSkipVerify — threat T2).
		Proxy: nil,
	}
	return &Forwarder{
		allowAnyPort: allowAnyPort,
		client: &http.Client{
			Transport: transport,
			Timeout:   defaultTotalTimeout,
			// SSRF-4: refuse EVERY redirect. Returning an error here (rather than
			// following) means a public endpoint cannot bounce us into the internal
			// network via a Location header. v1 is zero-redirect by design.
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return fmt.Errorf("%w: redirects are not followed", ErrBlockedDestination)
			},
		},
	}
}

// validateDestinationURL enforces the scheme/port allowlist (SSRF-1, SSRF-5) at request
// build time, BEFORE any network activity, and returns an OPAQUE error (SSRF-8) so the
// caller cannot leak which rule matched. https-only defeats a cleartext downgrade
// (threat T2); port 443-only stops the forwarder being used to probe arbitrary internal
// ports. Note this is the SECOND line of defense — the dial-time guard is authoritative
// against rebinding — but rejecting a bad scheme/port up front avoids even resolving it.
func validateDestinationURL(raw string, allowAnyPort bool) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, ErrBlockedDestination
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return nil, ErrBlockedDestination
	}
	if u.Hostname() == "" {
		return nil, ErrBlockedDestination
	}
	if p := u.Port(); p != "" && p != "443" && !allowAnyPort {
		return nil, ErrBlockedDestination
	}
	return u, nil
}

// Deliver POSTs body to rawURL with the given headers, returning the response status
// code. It is ONE attempt: no retry, no redirect-following. A blocked destination
// (bad scheme/port, or the dial-time guard tripping on a non-public IP) comes back as
// ErrBlockedDestination; a transport error (timeout, refused, TLS failure) comes back
// wrapped but WITHOUT echoing the destination's response (SSRF-7/8). The response body
// is drained through a hard byte cap and discarded — only the status is observed.
//
// The returned status is meaningful only when err is nil; the caller treats a 2xx as
// delivered and anything else as a failed attempt to retry or dead-letter.
func (f *Forwarder) Deliver(ctx context.Context, rawURL string, headers map[string]string, body []byte) (int, error) {
	u, err := validateDestinationURL(rawURL, f.allowAnyPort)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(string(body)))
	if err != nil {
		// A malformed request is our fault, not the destination's; still opaque outward.
		return 0, ErrBlockedDestination
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "sindireceita-webhook/1")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		// Do NOT include the destination's response/host detail in the error — a forward
		// failure must not become an oracle about the internal network (SSRF-8). A
		// guard/redirect refusal surfaces (url.Error-wrapped) as ErrBlockedDestination so
		// the caller still classifies it as blocked; any other transport error (timeout,
		// refused, TLS) collapses to one generic, host-free value.
		if errors.Is(err, ErrBlockedDestination) {
			return 0, ErrBlockedDestination
		}
		return 0, errGenericDelivery
	}
	defer resp.Body.Close()
	// SSRF-7: read at most maxResponseBytes and discard — we never echo the body, and we
	// drain a little so the connection can be reused.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
	return resp.StatusCode, nil
}

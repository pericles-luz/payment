// Package outbound holds the OUT-adapters for the per-Conta outbound webhook forward
// (SIN-69492, F2 of SIN-69486, model (b) ADR-0011): the SSRF-safe HTTP forwarder, its
// dial-time IP guard and the per-account outbound limiter. It is the network edge the
// threat model SIN-69489 is written against — we become a best-effort delivery provider
// for a semi-trusted reseller Conta, and the destination URL is USER-SUPPLIED hostile
// data — so everything here is fail-closed and lives OUTSIDE the domain (hexagonal).
//
// Nothing in this package touches persistence or the domain aggregates directly; it
// speaks only in URLs, headers and bytes. The app-layer OutboundProcessor orchestrates
// it (loads the Conta's config server-side, signs, retries, dead-letters).
package outbound

import (
	"errors"
	"net"
)

// ErrBlockedDestination is the single, OPAQUE error the SSRF guard returns for every
// disallowed destination — a non-public IP, a bad scheme, a bad port. It deliberately
// does NOT say which rule matched or whether the host even exists, so an operator
// pointing the URL at our internal network learns nothing about the topology from the
// error (threat model SIN-69489 §4.2 SSRF-8, anti-oracle). Callers compare with
// errors.Is; they must never surface a more specific reason outward.
var ErrBlockedDestination = errors.New("outbound webhook destination not allowed")

// SSRFGuard decides whether a CONCRETE resolved IP may be dialled. It is the port the
// threat model calls SSRFGuard (SIN-69489 §2/§4.1): injected into the forwarder's
// net.Dialer.Control so it runs on the exact ip:port the dialer resolved, immediately
// before connect (SSRF-3, the load-bearing control). Keeping it an interface lets a
// test wire a permissive guard to exercise the forwarder against a loopback httptest
// server while production always wires publicOnlyGuard.
type SSRFGuard interface {
	// CheckIP returns nil iff ip is a public, globally-routable unicast address safe to
	// dial, and ErrBlockedDestination otherwise. It must be conservative: an address it
	// cannot prove is public is refused (fail-closed).
	CheckIP(ip net.IP) error
}

// publicOnlyGuard enforces the POSITIVE rule of SIN-69489 §4.2 SSRF-2: only a public
// global-unicast IP passes; everything else is refused. A positive ("allow only proven
// public") rule is strictly safer than a denylist because a new reserved range we forgot
// to list still fails the "is it public?" question. The explicit range checks below are
// defense-in-depth on top of that positive rule (SIN-69489 §4.3 residual risk 3).
type publicOnlyGuard struct{}

// NewPublicOnlyGuard returns the production SSRF guard: dial only public unicast IPs.
func NewPublicOnlyGuard() SSRFGuard { return publicOnlyGuard{} }

// nat64Prefix is the well-known NAT64 prefix 64:ff9b::/96 (RFC 6052), which embeds an
// IPv4 address in the low 32 bits. A private IPv4 tunnelled through NAT64 would otherwise
// present as a "public" IPv6, so we block the whole prefix (SIN-69489 §4.2, recommended
// control) as defense-in-depth.
var nat64Prefix = net.IPNet{
	IP:   net.IP{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	Mask: net.CIDRMask(96, 128),
}

// CheckIP implements SSRFGuard. It normalises IPv4-in-IPv6 (`::ffff:a.b.c.d`) to the
// underlying IPv4 BEFORE classifying (else the classic `::ffff:169.254.169.254` bypass
// slips a link-local address past an IPv6-only check), then refuses any non-public
// class: unspecified, loopback, private (RFC1918 / ULA fc00::/7 — IsPrivate covers
// both), link-local unicast (incl. the 169.254.169.254 metadata endpoint) and multicast,
// broadcast, and the NAT64 prefix. Only what survives — a global-unicast public IP — is
// allowed.
func (publicOnlyGuard) CheckIP(ip net.IP) error {
	if ip == nil {
		return ErrBlockedDestination
	}
	// Normalise an IPv4-mapped IPv6 address to its 4-byte form so the IPv4 classifiers
	// below apply (net.IP.To4 also collapses `::ffff:a.b.c.d`).
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	switch {
	case ip.IsUnspecified(): // 0.0.0.0, ::
		return ErrBlockedDestination
	case ip.IsLoopback(): // 127.0.0.0/8, ::1
		return ErrBlockedDestination
	case ip.IsPrivate(): // RFC1918 10/8,172.16/12,192.168/16 and IPv6 ULA fc00::/7
		return ErrBlockedDestination
	case ip.IsLinkLocalUnicast(): // 169.254.0.0/16 (incl. metadata 169.254.169.254), fe80::/10
		return ErrBlockedDestination
	case ip.IsLinkLocalMulticast(): // 224.0.0.0/24, ff02::/16
		return ErrBlockedDestination
	case ip.IsMulticast(): // 224.0.0.0/4, ff00::/8
		return ErrBlockedDestination
	case ip.IsInterfaceLocalMulticast():
		return ErrBlockedDestination
	case ip.Equal(net.IPv4bcast): // 255.255.255.255
		return ErrBlockedDestination
	case nat64Prefix.Contains(ip): // 64:ff9b::/96 (embeds a possibly-private IPv4)
		return ErrBlockedDestination
	case !ip.IsGlobalUnicast(): // positive rule: anything not global-unicast is refused
		return ErrBlockedDestination
	default:
		return nil
	}
}

// checkDialAddress parses the "ip:port" a net.Dialer.Control hands us and validates the
// IP through the guard. It is the glue between Control (which speaks host:port strings)
// and SSRFGuard (which speaks net.IP). A non-numeric host at this point is anomalous —
// the dialer only calls Control with a resolved literal IP — so a parse failure is
// treated as blocked (fail-closed). This is where SSRF-3 actually fires.
func checkDialAddress(guard SSRFGuard, address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return ErrBlockedDestination
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return ErrBlockedDestination
	}
	return guard.CheckIP(ip)
}

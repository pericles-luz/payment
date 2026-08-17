package outbound

import (
	"errors"
	"net"
	"testing"
)

// T-SSRF-ranges (table-driven): every non-public destination class is refused, one case
// per range from threat model SIN-69489 §4.2 SSRF-2. A public address is the only thing
// allowed. This test FAILS against a guard missing any range (it encodes the vuln).
func TestPublicOnlyGuardBlocksNonPublicRanges(t *testing.T) {
	t.Parallel()
	guard := NewPublicOnlyGuard()

	blocked := []struct {
		name string
		ip   string
	}{
		{"loopback v4", "127.0.0.1"},
		{"loopback v4 range", "127.9.9.9"},
		{"private 10/8", "10.0.0.5"},
		{"private 172.16/12", "172.16.0.1"},
		{"private 192.168/16", "192.168.1.1"},
		{"link-local", "169.254.0.1"},
		{"cloud metadata", "169.254.169.254"},
		{"loopback v6", "::1"},
		{"link-local v6", "fe80::1"},
		{"ULA v6 fd00::/8", "fd00::1"},
		{"ULA v6 fc00::/7 low", "fc00::1"},
		{"mapped v4 loopback", "::ffff:127.0.0.1"},
		{"mapped v4 metadata", "::ffff:169.254.169.254"},
		{"mapped v4 private", "::ffff:10.0.0.1"},
		{"unspecified v4", "0.0.0.0"},
		{"unspecified v6", "::"},
		{"broadcast", "255.255.255.255"},
		{"multicast v4", "224.0.0.1"},
		{"multicast v6", "ff02::1"},
		{"nat64 private embed", "64:ff9b::a00:1"}, // 64:ff9b::10.0.0.1
	}
	for _, tc := range blocked {
		t.Run("block/"+tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("bad test ip %q", tc.ip)
			}
			if err := guard.CheckIP(ip); !errors.Is(err, ErrBlockedDestination) {
				t.Fatalf("CheckIP(%s) = %v, want ErrBlockedDestination", tc.ip, err)
			}
		})
	}

	allowed := []struct {
		name string
		ip   string
	}{
		{"public v4", "203.0.113.10"},
		{"public v4 2", "8.8.8.8"},
		{"public v6", "2606:4700:4700::1111"},
	}
	for _, tc := range allowed {
		t.Run("allow/"+tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if err := guard.CheckIP(ip); err != nil {
				t.Fatalf("CheckIP(%s) = %v, want nil (public unicast must pass)", tc.ip, err)
			}
		})
	}
}

// A nil IP is refused (fail-closed).
func TestPublicOnlyGuardNilIP(t *testing.T) {
	t.Parallel()
	if err := NewPublicOnlyGuard().CheckIP(nil); !errors.Is(err, ErrBlockedDestination) {
		t.Fatalf("nil ip = %v, want blocked", err)
	}
}

// checkDialAddress parses the concrete ip:port the dialer resolved and guards it. A bad
// address, a non-literal host, or a blocked IP all fail closed; a public literal passes.
func TestCheckDialAddress(t *testing.T) {
	t.Parallel()
	guard := NewPublicOnlyGuard()
	cases := []struct {
		name    string
		address string
		wantErr bool
	}{
		{"public passes", "203.0.113.10:443", false},
		{"metadata blocked at dial", "169.254.169.254:443", true},
		{"loopback blocked at dial", "127.0.0.1:8080", true},
		{"no port", "203.0.113.10", true},
		{"non-ip host", "example.com:443", true},
		{"garbage", "not-an-address", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkDialAddress(guard, tc.address)
			if tc.wantErr && !errors.Is(err, ErrBlockedDestination) {
				t.Fatalf("checkDialAddress(%q) = %v, want blocked", tc.address, err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("checkDialAddress(%q) = %v, want nil", tc.address, err)
			}
		})
	}
}

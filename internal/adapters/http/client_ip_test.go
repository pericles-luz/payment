package http

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestClientIPSpoofResistance is the white-box regression for GO-2026-5775: the
// spoofable chi middleware.RealIP was replaced by clientIPMiddleware, which
// derives the client IP from the TCP peer (hops=0) or from exactly N trusted
// X-Forwarded-For hops (hops>=1). It proves an attacker-supplied X-Forwarded-For
// can never move the value clientIP returns past the trusted boundary — the value
// keys the rate limiters and IP attribution.
func TestClientIPSpoofResistance(t *testing.T) {
	cases := []struct {
		name       string
		hops       int
		remoteAddr string
		xff        string // X-Forwarded-For header; "" means unset
		want       string
	}{
		{
			// No trusted proxy: forwarding headers are ignored entirely, so a
			// forged X-Forwarded-For cannot displace the real TCP peer.
			name:       "hops0 ignores spoofed XFF, uses TCP peer",
			hops:       0,
			remoteAddr: "203.0.113.7:5555",
			xff:        "1.2.3.4",
			want:       "203.0.113.7",
		},
		{
			name:       "hops0 no XFF still uses TCP peer",
			hops:       0,
			remoteAddr: "203.0.113.7:5555",
			xff:        "",
			want:       "203.0.113.7",
		},
		{
			// One trusted proxy appended the real client IP as the rightmost XFF
			// entry; that is what we trust.
			name:       "hops1 trusts the entry our proxy appended",
			hops:       1,
			remoteAddr: "10.0.0.1:5555",
			xff:        "198.51.100.9",
			want:       "198.51.100.9",
		},
		{
			// Attacker prepends a forged IP; our single trusted proxy still
			// appends the true client on the right. With numTrustedProxies=1 the
			// resolver reads the rightmost entry, so the forged 1.2.3.4 is ignored.
			name:       "hops1 ignores attacker-prepended XFF entry",
			hops:       1,
			remoteAddr: "10.0.0.1:5555",
			xff:        "1.2.3.4, 198.51.100.9",
			want:       "198.51.100.9",
		},
		{
			// XFF shorter than the trusted depth (header missing/architecture
			// changed): no trustworthy hop, so clientIP fails closed to the TCP
			// peer rather than trusting a client-supplied value.
			name:       "hops1 missing XFF falls back to TCP peer",
			hops:       1,
			remoteAddr: "10.0.0.1:5555",
			xff:        "",
			want:       "10.0.0.1",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var got string
			final := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				got = clientIP(r)
			})
			h := clientIPMiddleware(tc.hops)(final)

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tc.remoteAddr
			if tc.xff != "" {
				req.Header.Set("X-Forwarded-For", tc.xff)
			}
			h.ServeHTTP(httptest.NewRecorder(), req)

			if got != tc.want {
				t.Fatalf("clientIP() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestClientIPMiddlewareSelectsVariant asserts hops<1 selects the header-ignoring
// RemoteAddr variant and hops>=1 selects the trusted-XFF variant — the seam that
// keeps the secure default (0) from ever reading a client-controllable header.
func TestClientIPMiddlewareSelectsVariant(t *testing.T) {
	// hops=0 must ignore a present XFF (RemoteAddr variant).
	assertClientIP(t, clientIPMiddleware(0), "203.0.113.7:80", "9.9.9.9", "203.0.113.7")
	// hops=2 must walk two trusted hops from the right.
	assertClientIP(t, clientIPMiddleware(2), "10.0.0.1:80", "203.0.113.5, 10.0.0.2, 10.0.0.1", "10.0.0.2")
}

func assertClientIP(t *testing.T, mw func(http.Handler) http.Handler, remoteAddr, xff, want string) {
	t.Helper()
	var got string
	h := mw(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = clientIP(r)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = remoteAddr
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	h.ServeHTTP(httptest.NewRecorder(), req)
	if got != want {
		t.Fatalf("clientIP() = %q, want %q", got, want)
	}
}

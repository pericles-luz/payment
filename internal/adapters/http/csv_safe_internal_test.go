package http

import "testing"

// TestCSVSafe exercises every branch of the CSV formula-injection neutralizer
// (SIN-69183, CWE-1236): each spreadsheet formula-trigger byte at position 0 gets
// a single-quote prefix; empty and already-safe cells pass through untouched.
func TestCSVSafe(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"plain", "POST /v1/charges", "POST /v1/charges"},
		{"equals", "=1+1", "'=1+1"},
		{"plus", "+1", "'+1"},
		{"minus", "-1", "'-1"},
		{"at", "@SUM(A1)", "'@SUM(A1)"},
		{"tab", "\t=1+1", "'\t=1+1"},
		{"carriage-return", "\r=1+1", "'\r=1+1"},
		{"trigger-not-at-start", "a=1+1", "a=1+1"},
		{"unicode-leading", "ção", "ção"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := csvSafe(tc.in); got != tc.want {
				t.Fatalf("csvSafe(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

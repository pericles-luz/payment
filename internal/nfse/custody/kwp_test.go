package custody

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestKWPWrapRFC5649Vectors pins kwpWrap to the two test vectors in RFC 5649 §6.
func TestKWPWrapRFC5649Vectors(t *testing.T) {
	kek := mustHex(t, "5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8")
	for _, tc := range []struct{ name, key, want string }{
		{"20 octets", "c37b7e6492584340bed12207808941155068f738", "138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a"},
		{"7 octets", "466f7250617369", "afbeb0f07dfbf5419200f2ccb50bb24f"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := kwpWrap(kek, mustHex(t, tc.key))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, mustHex(t, tc.want)) {
				t.Errorf("kwpWrap = %x, want %s", got, tc.want)
			}
		})
	}
}

func TestKWPWrapRejectsBadInput(t *testing.T) {
	if _, err := kwpWrap(make([]byte, 32), nil); err == nil {
		t.Error("empty plaintext should error")
	}
	if _, err := kwpWrap(make([]byte, 5), []byte("x")); err == nil {
		t.Error("invalid AES key size should error")
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

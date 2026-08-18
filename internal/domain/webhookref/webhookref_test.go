package webhookref_test

import (
	"strings"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/domain/webhookref"
)

// TestGenerateShapeAndUniqueness proves a minted ref is exactly RefLen base64url chars,
// passes Valid, and is unique across calls (CSPRNG).
func TestGenerateShapeAndUniqueness(t *testing.T) {
	t.Parallel()
	a, err := webhookref.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	b, err := webhookref.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if a == b {
		t.Fatal("two minted refs must differ")
	}
	if len(a) != webhookref.RefLen {
		t.Fatalf("ref length = %d, want %d", len(a), webhookref.RefLen)
	}
	if !webhookref.Valid(a) {
		t.Fatalf("a minted ref must be structurally valid: %q", a)
	}
}

// TestValid covers the structural gate: exact length AND base64url alphabet only.
func TestValid(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		ref  string
		want bool
	}{
		{"exact 43 A", strings.Repeat("A", 43), true},
		{"exact 43 mixed", strings.Repeat("a1_-", 10) + "abc", true},
		{"too short", strings.Repeat("A", 42), false},
		{"too long", strings.Repeat("A", 44), false},
		{"empty", "", false},
		{"path traversal", "../" + strings.Repeat("A", 40), false},
		{"percent-encoded", strings.Repeat("A", 40) + "%2e", false},
		{"padding equals", strings.Repeat("A", 42) + "=", false},
		{"slash (std b64, not url)", strings.Repeat("A", 42) + "/", false},
		{"plus (std b64, not url)", strings.Repeat("A", 42) + "+", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := webhookref.Valid(c.ref); got != c.want {
				t.Fatalf("Valid(%q) = %v, want %v", c.ref, got, c.want)
			}
		})
	}
}

// TestSumDeterministicAndDistinct proves Sum is a stable hash of the ref and differs
// for different refs.
func TestSumDeterministicAndDistinct(t *testing.T) {
	t.Parallel()
	ref := strings.Repeat("A", 43)
	first, second := webhookref.Sum(ref), webhookref.Sum(ref)
	if first != second {
		t.Fatal("Sum must be deterministic for the same ref")
	}
	if other := webhookref.Sum(strings.Repeat("B", 43)); first == other {
		t.Fatal("Sum must differ for different refs")
	}
}

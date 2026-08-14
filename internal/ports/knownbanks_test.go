package ports_test

import (
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// TestKnownBankIDs pins the read side of the closed allow-list: it returns the
// supported slugs sorted, and every returned slug is itself known (no drift
// between IsKnownBankID and KnownBankIDs).
func TestKnownBankIDs(t *testing.T) {
	t.Parallel()
	got := ports.KnownBankIDs()
	if len(got) == 0 {
		t.Fatal("KnownBankIDs returned empty allow-list")
	}
	// Sorted and self-consistent with IsKnownBankID.
	for i, slug := range got {
		if !ports.IsKnownBankID(slug) {
			t.Errorf("KnownBankIDs[%d]=%q not reported known by IsKnownBankID", i, slug)
		}
		if i > 0 && got[i-1] > slug {
			t.Errorf("KnownBankIDs not sorted: %q before %q", got[i-1], slug)
		}
	}
	// C6 is always present (the integrated default bank).
	found := false
	for _, slug := range got {
		if slug == ports.BankIDC6 {
			found = true
		}
	}
	if !found {
		t.Errorf("KnownBankIDs %v missing %q", got, ports.BankIDC6)
	}
}

// TestKnownBankIDsReturnsCopy asserts a caller cannot mutate the allow-list
// through the returned slice (deny-by-default integrity).
func TestKnownBankIDsReturnsCopy(t *testing.T) {
	t.Parallel()
	a := ports.KnownBankIDs()
	if len(a) == 0 {
		t.Fatal("empty allow-list")
	}
	a[0] = "tampered"
	b := ports.KnownBankIDs()
	for _, slug := range b {
		if slug == "tampered" {
			t.Fatal("KnownBankIDs leaked a mutable reference to the allow-list")
		}
	}
}

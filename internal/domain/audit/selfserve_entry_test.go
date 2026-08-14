package audit_test

import (
	"strings"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
)

// TestDefaultOriginIsAdmin pins the backward-compatible default: every existing
// constructor (which does not opt into an origin) reads back as OriginAdmin, so
// the admin-only world is preserved with no code/test change and matches the DB
// DEFAULT 'admin' of migration 0010.
func TestDefaultOriginIsAdmin(t *testing.T) {
	t.Parallel()
	at := time.Unix(1700000000, 0).UTC()
	e, err := audit.NewCredentialSetEntry("id-1", "op-1", "ten-1", "c6", at)
	if err != nil {
		t.Fatalf("new credential entry: %v", err)
	}
	if e.Origin() != audit.OriginAdmin {
		t.Fatalf("default origin = %q, want %q", e.Origin(), audit.OriginAdmin)
	}
	// A generic entry (NewEntry) is likewise admin by default.
	g, err := audit.NewEntry("id-2", "op-1", audit.ActionCreateTenant, "ten-1", at)
	if err != nil {
		t.Fatalf("new entry: %v", err)
	}
	if g.Origin() != audit.OriginAdmin {
		t.Fatalf("generic entry origin = %q, want %q", g.Origin(), audit.OriginAdmin)
	}
}

// TestSelfServeCredentialSetEntry asserts the self-serve constructor produces an
// entry identical to the admin credential entry EXCEPT the origin, and that it
// still records no secret and carries the same action/bank/tenant.
func TestSelfServeCredentialSetEntry(t *testing.T) {
	t.Parallel()
	at := time.Unix(1700000000, 0).UTC()
	e, err := audit.NewSelfServeCredentialSetEntry("id-1", "op-1", "ten-1", "c6", at)
	if err != nil {
		t.Fatalf("new self-serve entry: %v", err)
	}
	if e.Origin() != audit.OriginSelfServe {
		t.Fatalf("origin = %q, want %q", e.Origin(), audit.OriginSelfServe)
	}
	if e.Action() != audit.ActionSetBankCredential {
		t.Fatalf("action = %q, want %q", e.Action(), audit.ActionSetBankCredential)
	}
	if e.BankID() != "c6" || e.TenantID() != "ten-1" || e.OperatorID() != "op-1" {
		t.Fatalf("unexpected entry fields: %+v", e)
	}
	// No secret-bearing field exists on the entry (it has no secret parameter);
	// render the exported fields and confirm nothing unexpected leaks.
	rendered := strings.Join([]string{e.ID(), e.OperatorID(), string(e.Action()), e.TenantID(), e.BankID(), e.Origin()}, "|")
	if strings.Contains(rendered, "secret") {
		t.Fatalf("entry rendered a secret-like token: %q", rendered)
	}
}

// TestSelfServeCredentialSetEntryValidates pins the shared invariants: the
// self-serve constructor rejects the same empty id/tenant/bank as the admin one.
func TestSelfServeCredentialSetEntryValidates(t *testing.T) {
	t.Parallel()
	at := time.Unix(1700000000, 0).UTC()
	cases := []struct{ id, tenant, bank string }{
		{"", "ten-1", "c6"},
		{"id-1", "", "c6"},
		{"id-1", "ten-1", ""},
	}
	for _, c := range cases {
		if _, err := audit.NewSelfServeCredentialSetEntry(c.id, "op", c.tenant, c.bank, at); err == nil {
			t.Fatalf("want validation error for %+v, got nil", c)
		}
	}
}

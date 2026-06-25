package dda

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

// bc44 returns a syntactically valid 44-digit boleto barcode whose digits vary with the
// seed so distinct items get distinct barcodes.
func bc44(seed byte) string {
	return strings.Repeat(string('0'+seed%10), 44)
}

func TestParseGroupStatus(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in      string
		want    GroupStatus
		wantErr bool
	}{
		{"consultando", StatusConsulting, false},
		{"  aprovado  ", StatusApproved, false},
		{"rascunho", "", true},
		{"", "", true},
	}
	for _, tc := range cases {
		got, err := ParseGroupStatus(tc.in)
		if tc.wantErr {
			if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("ParseGroupStatus(%q): want validation error, got %v", tc.in, err)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Fatalf("ParseGroupStatus(%q) = %q, %v", tc.in, got, err)
		}
	}
}

func TestValidateBarcode(t *testing.T) {
	t.Parallel()
	valid := []string{strings.Repeat("1", 44), strings.Repeat("2", 47), strings.Repeat("3", 48)}
	for _, v := range valid {
		if err := ValidateBarcode(v); err != nil {
			t.Fatalf("ValidateBarcode(len %d): unexpected error %v", len(v), err)
		}
	}
	invalid := []string{"", strings.Repeat("1", 43), strings.Repeat("9", 45), "abcd" + strings.Repeat("1", 40)}
	for _, v := range invalid {
		if err := ValidateBarcode(v); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("ValidateBarcode(%q): want validation error, got %v", v, err)
		}
	}
}

func TestNewDDABoleto(t *testing.T) {
	t.Parallel()
	due := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	b, err := NewDDABoleto("b1", bc44(1), 1500, due, "Acme")
	if err != nil {
		t.Fatalf("NewDDABoleto: %v", err)
	}
	if b.ID() != "b1" || b.AmountCents() != 1500 || b.BeneficiaryName() != "Acme" ||
		b.Barcode() != bc44(1) || !b.DueDate().Equal(due) {
		t.Fatalf("accessors mismatch: %+v", b)
	}

	bad := []struct {
		name                     string
		id, barcode, beneficiary string
		amount                   int64
		due                      time.Time
	}{
		{"empty_id", "", bc44(1), "Acme", 100, due},
		{"bad_barcode", "b1", "xx", "Acme", 100, due},
		{"zero_amount", "b1", bc44(1), "Acme", 0, due},
		{"zero_due", "b1", bc44(1), "Acme", 100, time.Time{}},
		{"empty_beneficiary", "b1", bc44(1), "", 100, due},
	}
	for _, tc := range bad {
		if _, err := NewDDABoleto(tc.id, tc.barcode, tc.amount, tc.due, tc.beneficiary); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("%s: want validation error, got %v", tc.name, err)
		}
	}
}

func TestNewItem(t *testing.T) {
	t.Parallel()
	due := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	it, err := NewItem("i1", bc44(2), 200, due)
	if err != nil {
		t.Fatalf("NewItem: %v", err)
	}
	if it.ID() != "i1" || it.Barcode() != bc44(2) || it.AmountCents() != 200 || !it.DueDate().Equal(due) {
		t.Fatalf("accessors mismatch: %+v", it)
	}
	bad := []struct {
		name, id, barcode string
		amount            int64
		due               time.Time
	}{
		{"empty_id", "", bc44(2), 200, due},
		{"bad_barcode", "i1", "zz", 200, due},
		{"zero_amount", "i1", bc44(2), 0, due},
		{"zero_due", "i1", bc44(2), 200, time.Time{}},
	}
	for _, tc := range bad {
		if _, err := NewItem(tc.id, tc.barcode, tc.amount, tc.due); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("%s: want validation error, got %v", tc.name, err)
		}
	}
}

// mustGroup builds a consulting group with the given item ids for the transition tests.
func mustGroup(t *testing.T, status GroupStatus, itemIDs ...string) *PaymentGroup {
	t.Helper()
	due := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	items := make([]Item, len(itemIDs))
	for i, id := range itemIDs {
		it, err := NewItem(id, bc44(byte(i+1)), int64((i+1)*100), due)
		if err != nil {
			t.Fatalf("seed item: %v", err)
		}
		items[i] = it
	}
	g, err := Reconstruct("g1", "t1", status, items)
	if err != nil {
		t.Fatalf("Reconstruct: %v", err)
	}
	return &g
}

func TestReconstructValidation(t *testing.T) {
	t.Parallel()
	if _, err := Reconstruct("", "t1", StatusConsulting, nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty id: want validation, got %v", err)
	}
	if _, err := Reconstruct("g1", "", StatusConsulting, nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty tenant: want validation, got %v", err)
	}
	if _, err := Reconstruct("g1", "t1", GroupStatus("bogus"), nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("bad status: want validation, got %v", err)
	}
}

func TestItemsIsCopy(t *testing.T) {
	t.Parallel()
	g := mustGroup(t, StatusConsulting, "i1", "i2")
	out := g.Items()
	if len(out) != 2 {
		t.Fatalf("want 2 items, got %d", len(out))
	}
	out[0] = Item{} // mutate the returned slice
	if g.Items()[0].ID() != "i1" {
		t.Fatal("Items() must return a defensive copy")
	}
}

func TestRemoveItems(t *testing.T) {
	t.Parallel()

	t.Run("removes_listed_ids", func(t *testing.T) {
		g := mustGroup(t, StatusConsulting, "i1", "i2", "i3")
		if err := g.RemoveItems("i1", "i3"); err != nil {
			t.Fatalf("RemoveItems: %v", err)
		}
		left := g.Items()
		if len(left) != 1 || left[0].ID() != "i2" {
			t.Fatalf("want only i2 left, got %+v", left)
		}
	})

	t.Run("empty_list_is_validation", func(t *testing.T) {
		g := mustGroup(t, StatusConsulting, "i1")
		if err := g.RemoveItems(); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("want validation, got %v", err)
		}
	})

	t.Run("empty_id_is_validation", func(t *testing.T) {
		g := mustGroup(t, StatusConsulting, "i1")
		if err := g.RemoveItems("  "); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("want validation, got %v", err)
		}
	})

	t.Run("unknown_id_is_not_found_and_all_or_nothing", func(t *testing.T) {
		g := mustGroup(t, StatusConsulting, "i1", "i2")
		if err := g.RemoveItems("i1", "nope"); !errors.Is(err, shared.ErrNotFound) {
			t.Fatalf("want not-found, got %v", err)
		}
		if len(g.Items()) != 2 {
			t.Fatal("removal must be all-or-nothing: nothing should have been removed")
		}
	})

	t.Run("approved_group_is_frozen", func(t *testing.T) {
		g := mustGroup(t, StatusApproved, "i1")
		if err := g.RemoveItems("i1"); !errors.Is(err, shared.ErrInvalidTransition) {
			t.Fatalf("want invalid-transition, got %v", err)
		}
	})
}

func TestSubmitForApproval(t *testing.T) {
	t.Parallel()

	t.Run("consulting_to_approved", func(t *testing.T) {
		g := mustGroup(t, StatusConsulting, "i1")
		if err := g.SubmitForApproval(); err != nil {
			t.Fatalf("SubmitForApproval: %v", err)
		}
		if g.Status() != StatusApproved || !g.IsApproved() {
			t.Fatalf("want approved, got %q", g.Status())
		}
	})

	t.Run("empty_group_rejected", func(t *testing.T) {
		g := mustGroup(t, StatusConsulting)
		if err := g.SubmitForApproval(); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("want validation, got %v", err)
		}
	})

	t.Run("non_consulting_is_invalid_transition", func(t *testing.T) {
		g := mustGroup(t, StatusApproved, "i1")
		if err := g.SubmitForApproval(); !errors.Is(err, shared.ErrInvalidTransition) {
			t.Fatalf("want invalid-transition, got %v", err)
		}
	})
}

func TestAccessors(t *testing.T) {
	t.Parallel()
	g := mustGroup(t, StatusConsulting, "i1")
	if g.ID() != "g1" || g.TenantID() != "t1" || g.Status() != StatusConsulting {
		t.Fatalf("accessors mismatch: %+v", g)
	}
}

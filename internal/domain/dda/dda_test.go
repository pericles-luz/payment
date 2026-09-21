package dda

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

// bc44 returns a syntactically valid 44-digit boleto barcode whose digits vary with the
// seed so distinct items get distinct references.
func bc44(seed byte) string {
	return strings.Repeat(string('0'+seed%10), 44)
}

func TestParseItemStatus(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in      string
		want    ItemStatus
		wantErr bool
	}{
		{"READ_DATA", StatusReadData, false},
		{"  scheduled  ", StatusScheduled, false},
		{"PROCESSED", StatusProcessed, false},
		{"SCHEDULING_CANCELLED", StatusSchedulingCancelled, false},
		// Empty is READ_DATA, not an error: the create response carries no status and
		// rejecting it would make a successful create fail validation.
		{"", StatusReadData, false},
		{"aprovado", "", true},
		{"consultando", "", true},
	}
	for _, tc := range cases {
		got, err := ParseItemStatus(tc.in)
		if tc.wantErr {
			if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("ParseItemStatus(%q): want validation error, got %v", tc.in, err)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Fatalf("ParseItemStatus(%q) = %q, %v", tc.in, got, err)
		}
	}
}

// TestSubmittedStatuses pins WHICH item states mean "the group already went for
// approval". This is the whole basis of the freeze invariant — the bank publishes no
// group status — so a state moving between the two halves must break a test, not
// silently unfreeze a submitted batch.
func TestSubmittedStatuses(t *testing.T) {
	t.Parallel()
	submitted := []ItemStatus{StatusScheduled, StatusProcessing, StatusProcessed, StatusSchedulingCancelled}
	for _, s := range submitted {
		if !s.Submitted() {
			t.Fatalf("%q must count as submitted", s)
		}
	}
	editable := []ItemStatus{StatusReadData, StatusDecodeError, StatusError}
	for _, s := range editable {
		if s.Submitted() {
			t.Fatalf("%q must NOT count as submitted", s)
		}
	}
}

func TestParseProductType(t *testing.T) {
	t.Parallel()
	for _, in := range []string{"BOLETO", "pix", ""} {
		if _, err := ParseProductType(in); err != nil {
			t.Fatalf("ParseProductType(%q): %v", in, err)
		}
	}
	if _, err := ParseProductType("TED"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want validation error, got %v", err)
	}
}

// TestValidateContentAcceptsPix is the regression this refactor exists for: the old
// ValidateBarcode demanded 44/47/48 digits, which refused every PIX payment — and the
// API's own summary is "agendar pagamentos de boletos e pixes".
func TestValidateContentAcceptsPix(t *testing.T) {
	t.Parallel()
	valid := []string{
		strings.Repeat("1", 44),                // código de barras
		strings.Repeat("2", 47),                // linha digitável (cobrança)
		strings.Repeat("3", 48),                // linha digitável (arrecadação)
		"12345678909",                          // CPF
		"05471416000101",                       // CNPJ
		"+5531986058910",                       // telefone
		"pericles@example.com",                 // e-mail
		"123e4567-e12b-12d1-a456-426655440000", // EVP
		"0002010414123456789012342658" + strings.Repeat("0", 40), // BR Code
	}
	for _, v := range valid {
		if err := ValidateContent(v); err != nil {
			t.Fatalf("ValidateContent(%q): unexpected error %v", v, err)
		}
	}
	invalid := []string{
		"",
		strings.Repeat("1", 43),
		strings.Repeat("9", 45),
		"abcd" + strings.Repeat("1", 40),
		"not a key",
		strings.Repeat("7", 40), // long enough for no rule, short of a barcode
	}
	for _, v := range invalid {
		if err := ValidateContent(v); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("ValidateContent(%q): want validation error, got %v", v, err)
		}
	}
}

func TestNewDDABoleto(t *testing.T) {
	t.Parallel()
	due := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	ok := DDABoletoParams{
		Content: bc44(1), AmountCents: 1500, DueDate: due,
		BeneficiaryName: "Acme", PayerName: "Fulano", BankCode: "336", BankName: "Banco C6", Overdue: true,
	}
	b, err := NewDDABoleto(ok)
	if err != nil {
		t.Fatalf("NewDDABoleto: %v", err)
	}
	if b.Content() != bc44(1) || b.AmountCents() != 1500 || b.BeneficiaryName() != "Acme" ||
		b.PayerName() != "Fulano" || b.BankCode() != "336" || b.BankName() != "Banco C6" ||
		!b.Overdue() || !b.DueDate().Equal(due) {
		t.Fatalf("accessors mismatch: %+v", b)
	}

	bad := map[string]func(DDABoletoParams) DDABoletoParams{
		"bad_content":       func(p DDABoletoParams) DDABoletoParams { p.Content = "xx"; return p },
		"zero_amount":       func(p DDABoletoParams) DDABoletoParams { p.AmountCents = 0; return p },
		"zero_due":          func(p DDABoletoParams) DDABoletoParams { p.DueDate = time.Time{}; return p },
		"empty_beneficiary": func(p DDABoletoParams) DDABoletoParams { p.BeneficiaryName = " "; return p },
	}
	for name, mutate := range bad {
		if _, err := NewDDABoleto(mutate(ok)); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("%s: want validation error, got %v", name, err)
		}
	}
}

func TestNewItem(t *testing.T) {
	t.Parallel()
	due := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	ok := ItemParams{
		ID: "i1", Content: bc44(2), AmountCents: 200, DueDate: due,
		Status: "READ_DATA", ProductType: "BOLETO", ErrorMessage: "", Overdue: false,
	}
	it, err := NewItem(ok)
	if err != nil {
		t.Fatalf("NewItem: %v", err)
	}
	if it.ID() != "i1" || it.Content() != bc44(2) || it.AmountCents() != 200 ||
		!it.DueDate().Equal(due) || it.Status() != StatusReadData || it.ProductType() != ProductBoleto {
		t.Fatalf("accessors mismatch: %+v", it)
	}

	// A PIX item has no due date at all, and that must not be an error.
	pix := ItemParams{ID: "i2", Content: "pericles@example.com", AmountCents: 100, Status: "READ_DATA", ProductType: "PIX"}
	got, err := NewItem(pix)
	if err != nil {
		t.Fatalf("NewItem(pix without due date): %v", err)
	}
	if !got.DueDate().IsZero() || got.ProductType() != ProductPix {
		t.Fatalf("pix item mismatch: %+v", got)
	}

	bad := map[string]func(ItemParams) ItemParams{
		"empty_id":     func(p ItemParams) ItemParams { p.ID = " "; return p },
		"bad_content":  func(p ItemParams) ItemParams { p.Content = "zz"; return p },
		"zero_amount":  func(p ItemParams) ItemParams { p.AmountCents = 0; return p },
		"bad_status":   func(p ItemParams) ItemParams { p.Status = "aprovado"; return p },
		"bad_product":  func(p ItemParams) ItemParams { p.ProductType = "TED"; return p },
		"neg_amount":   func(p ItemParams) ItemParams { p.AmountCents = -1; return p },
		"empty_status": func(p ItemParams) ItemParams { p.Status = "nope"; return p },
	}
	for name, mutate := range bad {
		if _, err := NewItem(mutate(ok)); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("%s: want validation error, got %v", name, err)
		}
	}
}

// mustGroup builds a group whose items all carry the given status.
func mustGroup(t *testing.T, status ItemStatus, itemIDs ...string) *PaymentGroup {
	t.Helper()
	due := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	items := make([]Item, len(itemIDs))
	for i, id := range itemIDs {
		it, err := NewItem(ItemParams{
			ID: id, Content: bc44(byte(i + 1)), AmountCents: int64((i + 1) * 100),
			DueDate: due, Status: string(status), ProductType: "BOLETO",
		})
		if err != nil {
			t.Fatalf("seed item: %v", err)
		}
		items[i] = it
	}
	g, err := Reconstruct("g1", "t1", items)
	if err != nil {
		t.Fatalf("Reconstruct: %v", err)
	}
	return &g
}

func TestReconstructValidation(t *testing.T) {
	t.Parallel()
	if _, err := Reconstruct("", "t1", nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty id: want validation, got %v", err)
	}
	if _, err := Reconstruct("g1", "", nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty tenant: want validation, got %v", err)
	}
}

func TestItemsIsCopy(t *testing.T) {
	t.Parallel()
	g := mustGroup(t, StatusReadData, "i1", "i2")
	out := g.Items()
	if len(out) != 2 {
		t.Fatalf("want 2 items, got %d", len(out))
	}
	out[0] = Item{} // mutate the returned slice
	if g.Items()[0].ID() != "i1" {
		t.Fatal("Items() must return a defensive copy")
	}
}

// TestIsSubmittedIsDerived asserts the freeze state comes from the items, and that a
// SINGLE submitted item is enough to freeze a mixed group — the bank schedules the
// batch, not the line.
func TestIsSubmittedIsDerived(t *testing.T) {
	t.Parallel()
	if mustGroup(t, StatusReadData, "i1", "i2").IsSubmitted() {
		t.Fatal("a group of READ_DATA items must not read as submitted")
	}
	if !mustGroup(t, StatusScheduled, "i1").IsSubmitted() {
		t.Fatal("a SCHEDULED item must freeze the group")
	}
	// An empty group has no evidence either way, and must not read as submitted —
	// otherwise SubmitForApproval's empty-group guard becomes unreachable.
	if mustGroup(t, StatusReadData).IsSubmitted() {
		t.Fatal("an empty group must not read as submitted")
	}

	due := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	mixed := []Item{}
	for i, st := range []ItemStatus{StatusReadData, StatusProcessed} {
		it, err := NewItem(ItemParams{
			ID: string(rune('a' + i)), Content: bc44(byte(i + 1)), AmountCents: 100,
			DueDate: due, Status: string(st),
		})
		if err != nil {
			t.Fatalf("seed: %v", err)
		}
		mixed = append(mixed, it)
	}
	g, err := Reconstruct("g1", "t1", mixed)
	if err != nil {
		t.Fatalf("Reconstruct: %v", err)
	}
	if !g.IsSubmitted() {
		t.Fatal("one submitted item must freeze a mixed group")
	}
}

func TestRemoveItems(t *testing.T) {
	t.Parallel()

	t.Run("removes_listed_ids", func(t *testing.T) {
		g := mustGroup(t, StatusReadData, "i1", "i2", "i3")
		if err := g.RemoveItems("i1", "i3"); err != nil {
			t.Fatalf("RemoveItems: %v", err)
		}
		left := g.Items()
		if len(left) != 1 || left[0].ID() != "i2" {
			t.Fatalf("want only i2 left, got %+v", left)
		}
	})

	t.Run("empty_list_is_validation", func(t *testing.T) {
		g := mustGroup(t, StatusReadData, "i1")
		if err := g.RemoveItems(); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("want validation, got %v", err)
		}
	})

	t.Run("empty_id_is_validation", func(t *testing.T) {
		g := mustGroup(t, StatusReadData, "i1")
		if err := g.RemoveItems("  "); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("want validation, got %v", err)
		}
	})

	t.Run("unknown_id_is_not_found_and_all_or_nothing", func(t *testing.T) {
		g := mustGroup(t, StatusReadData, "i1", "i2")
		if err := g.RemoveItems("i1", "nope"); !errors.Is(err, shared.ErrNotFound) {
			t.Fatalf("want not-found, got %v", err)
		}
		if len(g.Items()) != 2 {
			t.Fatal("removal must be all-or-nothing: nothing should have been removed")
		}
	})

	t.Run("submitted_group_is_frozen", func(t *testing.T) {
		g := mustGroup(t, StatusScheduled, "i1")
		if err := g.RemoveItems("i1"); !errors.Is(err, shared.ErrInvalidTransition) {
			t.Fatalf("want invalid-transition, got %v", err)
		}
	})
}

func TestSubmitForApproval(t *testing.T) {
	t.Parallel()

	t.Run("marks_every_item_scheduled", func(t *testing.T) {
		g := mustGroup(t, StatusReadData, "i1", "i2")
		if err := g.SubmitForApproval(); err != nil {
			t.Fatalf("SubmitForApproval: %v", err)
		}
		if !g.IsSubmitted() {
			t.Fatal("want submitted after SubmitForApproval")
		}
		for _, it := range g.Items() {
			if it.Status() != StatusScheduled {
				t.Fatalf("item %s: want SCHEDULED, got %q", it.ID(), it.Status())
			}
		}
	})

	t.Run("empty_group_rejected", func(t *testing.T) {
		g := mustGroup(t, StatusReadData)
		if err := g.SubmitForApproval(); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("want validation, got %v", err)
		}
	})

	t.Run("already_submitted_is_invalid_transition", func(t *testing.T) {
		g := mustGroup(t, StatusProcessing, "i1")
		if err := g.SubmitForApproval(); !errors.Is(err, shared.ErrInvalidTransition) {
			t.Fatalf("want invalid-transition, got %v", err)
		}
	})
}

func TestAccessors(t *testing.T) {
	t.Parallel()
	g := mustGroup(t, StatusReadData, "i1")
	if g.ID() != "g1" || g.TenantID() != "t1" {
		t.Fatalf("accessors mismatch: %+v", g)
	}
}

package invoice_test

import (
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/invoice"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

func mustLine(t *testing.T, endpoint string, calls int, cents int64) invoice.LineItem {
	t.Helper()
	l, err := invoice.NewLineItem(endpoint, calls, cents)
	if err != nil {
		t.Fatalf("NewLineItem(%q): %v", endpoint, err)
	}
	return l
}

func TestNewInvoiceDerivesTotalsAndOrdersLines(t *testing.T) {
	t.Parallel()
	start := time.Unix(1000, 0).UTC()
	end := time.Unix(2000, 0).UTC()
	gen := time.Unix(2500, 0).UTC()
	// Deliberately out of order so we assert the constructor sorts them.
	lines := []invoice.LineItem{
		mustLine(t, "POST /v1/charges", 3, 750),
		mustLine(t, "GET /v1/charges", 1, 10),
	}
	inv, err := invoice.New("inv-1", " t1 ", "acct-t1", start, end, gen, lines)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if inv.ID() != "inv-1" || inv.TenantID() != "t1" || inv.AccountID() != "acct-t1" {
		t.Fatalf("identity = %q/%q/%q", inv.ID(), inv.TenantID(), inv.AccountID())
	}
	if !inv.PeriodStart().Equal(start) || !inv.PeriodEnd().Equal(end) || !inv.GeneratedAt().Equal(gen) {
		t.Fatalf("period/gen mismatch")
	}
	if inv.TotalCalls() != 4 || inv.TotalCents() != 760 {
		t.Fatalf("totals = %d/%d, want 4/760", inv.TotalCalls(), inv.TotalCents())
	}
	got := inv.Lines()
	if len(got) != 2 || got[0].Endpoint() != "GET /v1/charges" || got[1].Endpoint() != "POST /v1/charges" {
		t.Fatalf("lines not sorted by endpoint: %+v", got)
	}
	if got[0].Calls() != 1 || got[0].SubtotalCents() != 10 {
		t.Fatalf("line0 = %+v", got[0])
	}
}

func TestNewInvoiceEmptyLinesIsZeroInvoice(t *testing.T) {
	t.Parallel()
	inv, err := invoice.New("inv-0", "t1", "", time.Unix(1, 0).UTC(), time.Unix(2, 0).UTC(), time.Unix(3, 0).UTC(), nil)
	if err != nil {
		t.Fatalf("New empty: %v", err)
	}
	if inv.TotalCalls() != 0 || inv.TotalCents() != 0 || len(inv.Lines()) != 0 {
		t.Fatalf("zero invoice not zero: %+v", inv)
	}
	if inv.AccountID() != "" {
		t.Fatalf("account should be empty (self-account)")
	}
}

func TestNewInvoiceRejectsBadInput(t *testing.T) {
	t.Parallel()
	s := time.Unix(1000, 0).UTC()
	e := time.Unix(2000, 0).UTC()
	cases := []struct {
		name       string
		id, tenant string
		start, end time.Time
	}{
		{"missing id", "", "t1", s, e},
		{"missing tenant", "inv-1", "  ", s, e},
		{"zero start", "inv-1", "t1", time.Time{}, e},
		{"zero end", "inv-1", "t1", s, time.Time{}},
		{"start == end", "inv-1", "t1", s, s},
		{"start after end", "inv-1", "t1", e, s},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := invoice.New(tc.id, tc.tenant, "", tc.start, tc.end, s, nil); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want validation error, got %v", err)
			}
		})
	}
}

func TestNewLineItemInvariants(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		endpoint string
		calls    int
		cents    int64
	}{
		{"empty endpoint", "  ", 1, 10},
		{"zero calls", "GET /x", 0, 10},
		{"negative calls", "GET /x", -1, 10},
		{"negative subtotal", "GET /x", 1, -5},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := invoice.NewLineItem(tc.endpoint, tc.calls, tc.cents); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want validation error, got %v", err)
			}
		})
	}
	// A zero-cents line is valid (free endpoint that was still called).
	if _, err := invoice.NewLineItem("GET /free", 2, 0); err != nil {
		t.Fatalf("free endpoint line: %v", err)
	}
}

func TestInvoiceLinesReturnsCopy(t *testing.T) {
	t.Parallel()
	src := []invoice.LineItem{mustLine(t, "GET /x", 1, 10)}
	inv, err := invoice.New("inv-1", "t1", "", time.Unix(1, 0).UTC(), time.Unix(2, 0).UTC(), time.Unix(3, 0).UTC(), src)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Mutating the caller's slice must not change the aggregate.
	src[0] = mustLine(t, "GET /y", 9, 900)
	if inv.Lines()[0].Endpoint() != "GET /x" {
		t.Fatalf("aggregate aliased caller slice")
	}
	// Mutating the returned slice must not change the aggregate either.
	out := inv.Lines()
	out[0] = mustLine(t, "GET /z", 5, 50)
	if inv.Lines()[0].Endpoint() != "GET /x" {
		t.Fatalf("returned slice aliases internal state")
	}
}

func TestRehydratePreservesStoredState(t *testing.T) {
	t.Parallel()
	lines := []invoice.LineItem{mustLine(t, "GET /x", 2, 20), mustLine(t, "POST /y", 1, 100)}
	inv := invoice.Rehydrate("inv-9", "t1", "acct-t1",
		time.Unix(1000, 0).UTC(), time.Unix(2000, 0).UTC(), time.Unix(2500, 0).UTC(),
		lines, 3, 120)
	if inv.ID() != "inv-9" || inv.TotalCalls() != 3 || inv.TotalCents() != 120 {
		t.Fatalf("rehydrated = %+v", inv)
	}
	if len(inv.Lines()) != 2 {
		t.Fatalf("lines = %d", len(inv.Lines()))
	}
}

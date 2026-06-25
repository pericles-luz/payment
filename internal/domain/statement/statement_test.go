package statement_test

import (
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/domain/statement"
)

func date(y int, m time.Month, d int) time.Time {
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// TestNewPeriodValid covers the legal windows: a single day (inicio == fim) and a
// full 30-day span (exactly MaxPeriod).
func TestNewPeriodValid(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		start, end time.Time
	}{
		{"single day", date(2026, 6, 1), date(2026, 6, 1)},
		{"thirty day span", date(2026, 6, 1), date(2026, 6, 1).Add(statement.MaxPeriod)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, err := statement.NewPeriod(tc.start, tc.end)
			if err != nil {
				t.Fatalf("NewPeriod: %v", err)
			}
			if !p.Start().Equal(tc.start) || !p.End().Equal(tc.end) {
				t.Fatalf("accessors: got [%v,%v] want [%v,%v]", p.Start(), p.End(), tc.start, tc.end)
			}
		})
	}
}

// TestNewPeriodInvalid covers every rejection path; each must be a validation error.
func TestNewPeriodInvalid(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		start, end time.Time
	}{
		{"missing inicio", time.Time{}, date(2026, 6, 1)},
		{"missing fim", date(2026, 6, 1), time.Time{}},
		{"fim before inicio", date(2026, 6, 2), date(2026, 6, 1)},
		{"window over 30 days", date(2026, 6, 1), date(2026, 6, 1).Add(statement.MaxPeriod + time.Hour)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := statement.NewPeriod(tc.start, tc.end); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want ErrValidation, got %v", err)
			}
		})
	}
}

func TestParseEntryKind(t *testing.T) {
	t.Parallel()
	for _, in := range []string{"credit", " debit "} {
		if _, err := statement.ParseEntryKind(in); err != nil {
			t.Fatalf("ParseEntryKind(%q): %v", in, err)
		}
	}
	if _, err := statement.ParseEntryKind("bogus"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unknown kind: want ErrValidation, got %v", err)
	}
}

func TestNewEntryValid(t *testing.T) {
	t.Parallel()
	e, err := statement.NewEntry("e1", date(2026, 6, 5), 1500, statement.KindCredit, "salary")
	if err != nil {
		t.Fatalf("NewEntry: %v", err)
	}
	if e.ID() != "e1" || e.AmountCents() != 1500 || e.Kind() != statement.KindCredit ||
		e.Description() != "salary" || !e.Date().Equal(date(2026, 6, 5)) {
		t.Fatalf("accessors mismatch: %+v", e)
	}
}

func TestNewEntryInvalid(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		id          string
		date        time.Time
		amount      int64
		kind        statement.EntryKind
		description string
	}{
		{"empty id", " ", date(2026, 6, 5), 100, statement.KindCredit, "x"},
		{"zero date", "e1", time.Time{}, 100, statement.KindCredit, "x"},
		{"zero amount", "e1", date(2026, 6, 5), 0, statement.KindCredit, "x"},
		{"negative amount", "e1", date(2026, 6, 5), -1, statement.KindCredit, "x"},
		{"unknown kind", "e1", date(2026, 6, 5), 100, statement.EntryKind("nope"), "x"},
		{"empty description", "e1", date(2026, 6, 5), 100, statement.KindCredit, "  "},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := statement.NewEntry(tc.id, tc.date, tc.amount, tc.kind, tc.description); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want ErrValidation, got %v", err)
			}
		})
	}
}

func TestNewStatement(t *testing.T) {
	t.Parallel()
	p, _ := statement.NewPeriod(date(2026, 6, 1), date(2026, 6, 30))
	e, _ := statement.NewEntry("e1", date(2026, 6, 5), 1500, statement.KindCredit, "salary")
	entries := []statement.Entry{e}

	st, err := statement.New("tenant-1", p, entries)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if st.TenantID() != "tenant-1" {
		t.Fatalf("tenant: %q", st.TenantID())
	}
	if !st.Period().Start().Equal(date(2026, 6, 1)) {
		t.Fatalf("period start: %v", st.Period().Start())
	}
	if len(st.Entries()) != 1 || st.Entries()[0].ID() != "e1" {
		t.Fatalf("entries: %+v", st.Entries())
	}

	// Defensive copy: mutating the caller's slice or the returned slice must not
	// reach the aggregate.
	entries[0] = statement.Entry{}
	if st.Entries()[0].ID() != "e1" {
		t.Fatal("New must copy the entries slice")
	}
	got := st.Entries()
	got[0] = statement.Entry{}
	if st.Entries()[0].ID() != "e1" {
		t.Fatal("Entries must return a defensive copy")
	}

	// Missing tenant is rejected.
	if _, err := statement.New(" ", p, entries); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty tenant: want ErrValidation, got %v", err)
	}
}

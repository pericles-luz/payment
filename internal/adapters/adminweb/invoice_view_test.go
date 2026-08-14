package adminweb_test

import (
	"strings"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/adminweb"
	"github.com/ia-dev-sindireceita/payment/internal/domain/invoice"
	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
)

func TestToInvoicesView(t *testing.T) {
	t.Parallel()
	line, err := invoice.NewLineItem("POST /v1/charges", 2, 500)
	if err != nil {
		t.Fatalf("line: %v", err)
	}
	// Half-open period [Aug 1, Aug 6): display end is the last billed day (Aug 5).
	inv, err := invoice.New("inv-1", "t1", "acct-t1",
		time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 8, 6, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 8, 6, 9, 0, 0, 0, time.UTC),
		[]invoice.LineItem{line})
	if err != nil {
		t.Fatalf("invoice: %v", err)
	}
	tn := tenant.Rehydrate("t1", "Acme", true, time.Unix(1, 0).UTC())
	view := adminweb.ToInvoicesView(adminweb.ToTenantView(tn), []invoice.Invoice{inv})
	if len(view.Rows) != 1 {
		t.Fatalf("rows = %d", len(view.Rows))
	}
	r := view.Rows[0]
	if r.PeriodFrom != "2026-08-01" || r.PeriodTo != "2026-08-05" || r.Generated != "2026-08-06" {
		t.Fatalf("dates = %q..%q gen %q", r.PeriodFrom, r.PeriodTo, r.Generated)
	}
	if r.TotalCalls != 2 || r.TotalReais() != "R$ 5,00" {
		t.Fatalf("total = %d / %q", r.TotalCalls, r.TotalReais())
	}
	if href := r.CSVHref("t1"); !strings.Contains(href, "/console/tenants/t1/invoices/inv-1.csv") {
		t.Fatalf("csv href = %q", href)
	}

	// Empty list projects zero rows (the template renders its empty state).
	if v := adminweb.ToInvoicesView(adminweb.ToTenantView(tn), nil); len(v.Rows) != 0 {
		t.Fatalf("empty rows = %d", len(v.Rows))
	}
}

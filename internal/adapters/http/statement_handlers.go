package http

import (
	"net/http"
	"strings"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// --- Tenant API: account statement / extrato (roteiro grupo 13) ---
//
// The single handler derives the tenant from the authenticated context
// (tenantFromContext), never from the query or body: the extrato is always the
// authenticated tenant's. The period is parsed and presence/format-checked here
// (400); the window invariants (fim >= inicio, <= 30 dias) are enforced by the domain
// in the use-case and surface as 400 (deny-by-default at both layers).

// stmtDateFormat is the inicio/fim query format accepted at the boundary: a calendar
// date (YYYY-MM-DD). An extrato window is bounded in days, not instants.
const stmtDateFormat = "2006-01-02"

// statementEntryView is the JSON representation of one posted statement entry
// (roteiro 13.a).
type statementEntryView struct {
	ID          string `json:"id"`
	Date        string `json:"date"`
	AmountCents int64  `json:"amount_cents"`
	Kind        string `json:"kind"`
	Description string `json:"description"`
}

// statementView is the JSON page returned by GET /v1/statement.
type statementView struct {
	Entries []statementEntryView `json:"entries"`
}

// handleGetStatement returns the authenticated tenant's account statement for the
// requested period (roteiro 13.a, GET /v1/statement?inicio=&fim= → 200). Missing or
// malformed dates are 400; a period that violates the domain window (fim < inicio or
// > 30 days) is 400 from the use-case.
func (s *Server) handleGetStatement(w http.ResponseWriter, r *http.Request) {
	tenantID := tenantFromContext(r.Context())
	q := r.URL.Query()

	start, ok := parseStmtDate(q.Get("inicio"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid or missing inicio (YYYY-MM-DD)")
		return
	}
	end, ok := parseStmtDate(q.Get("fim"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid or missing fim (YYYY-MM-DD)")
		return
	}

	res, err := s.statement.GetStatement(r.Context(), app.GetStatementInput{
		TenantID: tenantID,
		Start:    start,
		End:      end,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}

	out := make([]statementEntryView, len(res.Entries))
	for i, e := range res.Entries {
		out[i] = toStatementEntryView(e)
	}
	writeJSON(w, http.StatusOK, statementView{Entries: out})
}

// toStatementEntryView maps a port entry onto the tenant-facing view (date as a
// calendar date, consistent with the inicio/fim query format).
func toStatementEntryView(e ports.StatementEntry) statementEntryView {
	return statementEntryView{
		ID:          e.ID,
		Date:        e.Date.UTC().Format(stmtDateFormat),
		AmountCents: e.AmountCents,
		Kind:        e.Kind,
		Description: e.Description,
	}
}

// parseStmtDate parses a required calendar date (YYYY-MM-DD) in UTC, reporting
// ok=false when absent or malformed.
func parseStmtDate(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(stmtDateFormat, s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

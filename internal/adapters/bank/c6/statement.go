package c6

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// Account-statement (extrato) support for the C6 adapter (roteiro grupo 13).
//
// GetStatement reads the entries posted to the tenant's account within a date window
// (inicio/fim, máx. 30 dias). It lives here so the use-case never speaks HTTP/JSON or
// knows the PSP wire shape (Hexagonal).
//
// The JSON shape below is the adapter's clean internal contract (snake_case, explicit
// cents, RFC3339 dates), mirroring the boleto/cobv/DDA adapters: it round-trips
// exactly so Camada A (stub mode) is deterministic. Camada B maps it to the real
// BACEN/C6 extrato wire against the homologação endpoint; that translation does not
// change this port's surface.

// stmtDateFormat is the inicio/fim query format the extrato endpoint expects: a
// calendar date (an extrato window is bounded in days, not instants).
const stmtDateFormat = "2006-01-02"

// compile-time assertion that Provider satisfies the statement port.
var _ ports.StatementProvider = (*Provider)(nil)

// stmtEntryBody is one posted entry of a statement (roteiro 13.a).
type stmtEntryBody struct {
	ID          string    `json:"id"`
	Date        time.Time `json:"date"`
	AmountCents int64     `json:"amount_cents"`
	Kind        string    `json:"kind"`
	Description string    `json:"description"`
}

// stmtResponse wraps the extrato list response.
type stmtResponse struct {
	Entries []stmtEntryBody `json:"entries"`
}

// toStatement maps the wire statement to the port type.
func toStatement(in stmtResponse) ports.Statement {
	entries := make([]ports.StatementEntry, len(in.Entries))
	for i, e := range in.Entries {
		entries[i] = ports.StatementEntry{
			ID:          e.ID,
			Date:        e.Date,
			AmountCents: e.AmountCents,
			Kind:        e.Kind,
			Description: e.Description,
		}
	}
	return ports.Statement{Entries: entries}
}

// GetStatement reads the entries posted to the tenant's account within the requested
// date window (roteiro 13.a). The bearer token is attached per tenant; the read is
// tenant-scoped through it. Complete mediation: an absent inicio or fim is refused at
// the boundary (the use-case already validated the window, but the adapter does not
// trust an empty filter into the PSP).
func (p *Provider) GetStatement(ctx context.Context, tenantID string, filter ports.StatementFilter) (ports.Statement, error) {
	if filter.Start.IsZero() || filter.End.IsZero() {
		return ports.Statement{}, &Error{Op: "get_statement", sentinel: shared.ErrValidation}
	}
	// The C6 statement endpoint expects start_date / end_date (yyyy-MM-dd), NOT the
	// BACEN inicio/fim used by the PIX surface (SIN-65856, live-verified against the
	// sandbox problem+json).
	q := url.Values{}
	q.Set("start_date", filter.Start.UTC().Format(stmtDateFormat))
	q.Set("end_date", filter.End.UTC().Format(stmtDateFormat))
	endpoint := p.baseURL + "/v1/statement?" + q.Encode()
	httpReq, err := p.authedJSONRequest(ctx, tenantID, "get_statement", http.MethodGet, endpoint, nil, "")
	if err != nil {
		return ports.Statement{}, err
	}
	var out stmtResponse
	if err := p.do(httpReq, "get_statement", &out); err != nil {
		return ports.Statement{}, err
	}
	return toStatement(out), nil
}

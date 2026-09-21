package c6

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// Payload locations (BACEN PIX v2 `/loc`, roteiro P_04) for the C6 adapter.
//
// A location is the addressable QR the PSP serves. It exists INDEPENDENTLY of a
// charge, which is what lets a QR be minted — or printed — before the charge that will
// be served through it: the charge is bound to the location afterwards, and can be
// unbound without cancelling it.
//
// Shapes below come from docs/compliance/c6-pix-oas.yaml (PIX v3.0.1), not from
// guesswork. Note especially that `id` is an INTEGER here, unlike every other
// identifier in this adapter: a location is not addressed by a txid.

// pixLocPath is the BACEN payload-location collection under the PIX base.
const pixLocPath = "/v2/pix/loc"

// compile-time assertion that Provider satisfies the location port.
var _ ports.PixLocationProvider = (*Provider)(nil)

// pixLocRequestBody is the POST body: the charge kind is the only required field.
type pixLocRequestBody struct {
	TipoCob string `json:"tipoCob"`
}

// pixLocResponseBody is the location representation. TxID is present only on the
// single read and on the unlink response — the create has no charge to report yet, and
// the unlink answers with the location whose txid it just cleared.
type pixLocResponseBody struct {
	ID       int64  `json:"id"`
	TxID     string `json:"txid"`
	Location string `json:"location"`
	TipoCob  string `json:"tipoCob"`
	Criacao  string `json:"criacao"`
}

// pixLocListResponseBody is the list envelope: pagination plus the `loc` array.
type pixLocListResponseBody struct {
	Parametros pixParametros        `json:"parametros"`
	Loc        []pixLocResponseBody `json:"loc"`
}

// toPixLocation maps the wire location onto the port type. A creation timestamp the
// PSP omits or sends malformed becomes the zero time rather than an error: it is
// informative, and refusing a location over it would lose the id and the URI, which
// are the parts that matter.
func toPixLocation(b pixLocResponseBody) ports.PixLocation {
	var created time.Time
	if b.Criacao != "" {
		if t, err := time.Parse(time.RFC3339, b.Criacao); err == nil {
			created = t
		}
	}
	return ports.PixLocation{
		ID:        b.ID,
		Location:  b.Location,
		TipoCob:   b.TipoCob,
		TxID:      b.TxID,
		CreatedAt: created,
	}
}

// validTipoCob reports whether s is one of the two charge kinds a location may serve.
// It is checked here, at the boundary, because a typo would otherwise come back as an
// opaque 400 and the caller would have no idea which field the PSP disliked.
func validTipoCob(s string) bool {
	return s == "cob" || s == "cobv"
}

// CreateLocation mints a payload location for the given charge kind (roteiro P_04_01).
func (p *Provider) CreateLocation(ctx context.Context, tenantID, tipoCob string) (ports.PixLocation, error) {
	const op = "create_pix_loc"
	tipoCob = strings.TrimSpace(tipoCob)
	if !validTipoCob(tipoCob) {
		return ports.PixLocation{}, &Error{Op: op, sentinel: shared.ErrValidation}
	}
	payload, err := json.Marshal(pixLocRequestBody{TipoCob: tipoCob})
	if err != nil {
		return ports.PixLocation{}, &Error{Op: op, sentinel: shared.ErrValidation}
	}
	httpReq, err := p.authedJSONRequest(ctx, tenantID, op, http.MethodPost, p.baseURL+pixLocPath, payload, "")
	if err != nil {
		return ports.PixLocation{}, err
	}
	var out pixLocResponseBody
	if err := p.do(httpReq, op, &out); err != nil {
		return ports.PixLocation{}, err
	}
	if out.ID == 0 {
		// Without the id nothing can bind a charge to this location, or read it back.
		return ports.PixLocation{}, &Error{Op: op, sentinel: shared.ErrUnavailable}
	}
	return toPixLocation(out), nil
}

// ListLocations returns the payload locations created within the filter's window
// (roteiro P_04_02). The window bounds are mandatory.
func (p *Provider) ListLocations(ctx context.Context, tenantID string, filter ports.PixLocationFilter) (ports.PixLocationList, error) {
	const op = "list_pix_loc"
	if filter.Start.IsZero() || filter.End.IsZero() {
		return ports.PixLocationList{}, &Error{Op: op, sentinel: shared.ErrValidation}
	}
	if filter.TipoCob != "" && !validTipoCob(filter.TipoCob) {
		return ports.PixLocationList{}, &Error{Op: op, sentinel: shared.ErrValidation}
	}
	q := pixWindowQuery(filter.Start, filter.End, filter.Page, filter.PageSize)
	if filter.TipoCob != "" {
		q.Set("tipoCob", filter.TipoCob)
	}
	if filter.TxIDPresent != nil {
		q.Set("txIdPresente", strconv.FormatBool(*filter.TxIDPresent))
	}

	httpReq, err := p.authedJSONRequest(ctx, tenantID, op, http.MethodGet, p.baseURL+pixLocPath+"?"+q.Encode(), nil, "")
	if err != nil {
		return ports.PixLocationList{}, err
	}
	var out pixLocListResponseBody
	if err := p.do(httpReq, op, &out); err != nil {
		return ports.PixLocationList{}, err
	}
	locations := make([]ports.PixLocation, len(out.Loc))
	for i, l := range out.Loc {
		locations[i] = toPixLocation(l)
	}
	return ports.PixLocationList{Locations: locations, PixPage: out.Parametros.toPixPage()}, nil
}

// GetLocation reads one location back, including the charge bound to it (roteiro
// P_04_03). An unknown id within the tenant is shared.ErrNotFound.
func (p *Provider) GetLocation(ctx context.Context, tenantID string, id int64) (ports.PixLocation, error) {
	const op = "get_pix_loc"
	if id <= 0 {
		return ports.PixLocation{}, &Error{Op: op, sentinel: shared.ErrValidation}
	}
	endpoint := p.baseURL + pixLocPath + "/" + strconv.FormatInt(id, 10)
	httpReq, err := p.authedJSONRequest(ctx, tenantID, op, http.MethodGet, endpoint, nil, "")
	if err != nil {
		return ports.PixLocation{}, err
	}
	var out pixLocResponseBody
	if err := p.do(httpReq, op, &out); err != nil {
		return ports.PixLocation{}, err
	}
	return toPixLocation(out), nil
}

// UnlinkLocationTxID detaches the charge from a location (roteiro P_04_04). Afterwards
// the location has no txid and the charge no location; the charge's STATUS is
// untouched, so this must never be used as a way to cancel one.
func (p *Provider) UnlinkLocationTxID(ctx context.Context, tenantID string, id int64) (ports.PixLocation, error) {
	const op = "unlink_pix_loc"
	if id <= 0 {
		return ports.PixLocation{}, &Error{Op: op, sentinel: shared.ErrValidation}
	}
	endpoint := p.baseURL + pixLocPath + "/" + strconv.FormatInt(id, 10) + "/txid"
	httpReq, err := p.authedJSONRequest(ctx, tenantID, op, http.MethodDelete, endpoint, nil, "")
	if err != nil {
		return ports.PixLocation{}, err
	}
	// The unlink answers 200 with the location, not 204 — so it decodes like a read.
	var out pixLocResponseBody
	if err := p.do(httpReq, op, &out); err != nil {
		return ports.PixLocation{}, err
	}
	return toPixLocation(out), nil
}

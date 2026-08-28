package c6

import (
	"context"
	"net/http"
	"strconv"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// PIX Automático — payload locations (locrec), the artifact the QR journeys are built
// on. A location is the URL the payer's PSP fetches the mandate parameters from when
// it reads a composite QR; the recebedor mints one, then binds it to a mandate by
// passing its id on CreateRec (ports.CreateRecRequest.LocID).
//
// Two shape notes from the C6/BACEN contract, both load-bearing:
//
//   - POST /v2/pix/locrec takes NO request body. The location is minted from the
//     authenticated recebedor alone, so there is nothing a caller could inject here —
//     the confused-deputy surface of ADR-0004 does not exist on this endpoint.
//   - the location id is an int64, not a string. It is rendered into the URL with
//     strconv, never string-concatenated from caller input, so no path-injection seam
//     is opened by a location read.
//
// Writes are plain JSON ({"data":{...}} envelope), and so are the reads — like every
// other Recorrência surface (see recurrenceRead).

type locRecResponseBody struct {
	ID       int64  `json:"id"`
	Location string `json:"location"`
	Criacao  string `json:"criacao"`
	IDRec    string `json:"idRec"`
}

func (b locRecResponseBody) toResult() ports.LocRecResult {
	return ports.LocRecResult{
		ID:       b.ID,
		Location: b.Location,
		Criacao:  parseInstant(b.Criacao),
		IDRec:    b.IDRec,
	}
}

// CreateLocRec mints a payload location (POST /v2/pix/locrec). The BACEN contract
// takes no body, so the request is sent bodyless; idempotencyKey, when supplied,
// collapses a retried mint into one location instead of leaking a fresh one per retry.
func (p *Provider) CreateLocRec(ctx context.Context, tenantID, idempotencyKey string) (ports.LocRecResult, error) {
	req, err := p.authedJSONRequest(ctx, tenantID, "create_locrec", http.MethodPost, p.baseURL+locRecPath, nil, idempotencyKey)
	if err != nil {
		return ports.LocRecResult{}, err
	}
	var out struct {
		Data locRecResponseBody `json:"data"`
	}
	if err := p.do(req, "create_locrec", &out); err != nil {
		return ports.LocRecResult{}, err
	}
	return out.Data.toResult(), nil
}

// GetLocRec reads one location back (GET /v2/pix/locrec/{id}), including the mandate
// currently bound to it.
func (p *Provider) GetLocRec(ctx context.Context, tenantID string, id int64) (ports.LocRecResult, error) {
	if id <= 0 {
		return ports.LocRecResult{}, &Error{Op: "get_locrec", sentinel: shared.ErrValidation}
	}
	req, err := p.authedJSONRequest(ctx, tenantID, "get_locrec", http.MethodGet, p.baseURL+locRecPath+"/"+strconv.FormatInt(id, 10), nil, "")
	if err != nil {
		return ports.LocRecResult{}, err
	}
	var out struct {
		Data locRecResponseBody `json:"data"`
	}
	if err := p.do(req, "get_locrec", &out); err != nil {
		return ports.LocRecResult{}, err
	}
	return out.Data.toResult(), nil
}

// UnlinkLocRec detaches the mandate from a location (DELETE /v2/pix/locrec/{id}/idRec)
// so the location can be rebound to another mandate. The location id is forwarded as
// the Idempotency-Key: unlinking twice is the same effect, not two.
func (p *Provider) UnlinkLocRec(ctx context.Context, tenantID string, id int64) (ports.LocRecResult, error) {
	if id <= 0 {
		return ports.LocRecResult{}, &Error{Op: "unlink_locrec", sentinel: shared.ErrValidation}
	}
	idStr := strconv.FormatInt(id, 10)
	req, err := p.authedJSONRequest(ctx, tenantID, "unlink_locrec", http.MethodDelete, p.baseURL+locRecPath+"/"+idStr+"/idRec", nil, idStr)
	if err != nil {
		return ports.LocRecResult{}, err
	}
	var out struct {
		Data locRecResponseBody `json:"data"`
	}
	if err := p.do(req, "unlink_locrec", &out); err != nil {
		return ports.LocRecResult{}, err
	}
	return out.Data.toResult(), nil
}

package c6

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// Batches of due-date charges (BACEN PIX v2 `/lotecobv`, roteiro P_03) for the C6
// adapter.
//
// # O 202 não quer dizer que as cobranças existem
//
// Criar e alterar um lote respondem **202 Accepted**, não 201: o PSP ACEITA o lote e o
// processa depois. O contrato é explícito sobre a consequência — cobranças em
// `EM_PROCESSAMENTO` ou `NEGADA` "não existem de fato e não aparecem em consultas".
// Tratar o 202 como "as cobranças estão criadas" é a forma de errar aqui, e é por isso
// que os verbos de escrita não devolvem lote nenhum: o resultado por cobrança só
// aparece em GetBatch.
//
// # O que a alteração pode e não pode
//
// Alterar um lote só mantém o CONJUNTO original: não dá para acrescentar nem remover
// cobranças. Cobrança criada individualmente não entra num lote depois, e cobrança de
// lote não muda de lote.

// pixLoteCobvPath is the BACEN batch collection under the PIX base.
const pixLoteCobvPath = "/v2/pix/lotecobv"

// compile-time assertion that Provider satisfies the batch port.
var _ ports.PixDueChargeBatchProvider = (*Provider)(nil)

// loteID tolerates an id the contract declares as an INTEGER on the read and as a
// STRING on the path. The spec disagrees with itself; refusing either form would make
// a real response unparseable, and a batch we cannot read back is a batch we cannot
// reconcile.
type loteID string

// UnmarshalJSON accepts both `"abc"` and `123`, and maps null to empty.
func (l *loteID) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if s == "null" {
		*l = ""
		return nil
	}
	*l = loteID(strings.Trim(s, `"`))
	return nil
}

// loteCobvCharge is one charge inside the batch REQUEST: the caller's txid plus the
// ordinary cobv body, flattened into the same object the way the contract's allOf
// composes them.
type loteCobvCharge struct {
	TxID string `json:"txid"`
	cobvRequestBody
}

// loteCobvRequestBody is the PUT/PATCH body: a description plus the charges.
type loteCobvRequestBody struct {
	Descricao string           `json:"descricao"`
	CobsV     []loteCobvCharge `json:"cobsv"`
}

// loteCobvProblem is the RFC7807 body the PSP attaches to a NEGADA charge. It is the
// only place the reason for ONE rejected line survives, so it is read rather than
// discarded — and flattened to a single string, because the adapter never surfaces a
// raw PSP body.
type loteCobvProblem struct {
	Title  string `json:"title"`
	Detail string `json:"detail"`
}

// loteCobvChargeView is one charge's outcome in the batch READ.
type loteCobvChargeView struct {
	TxID     string           `json:"txid"`
	Status   string           `json:"status"`
	Problema *loteCobvProblem `json:"problema"`
	Criacao  string           `json:"criacao"`
}

// loteCobvResponseBody is a batch's representation.
type loteCobvResponseBody struct {
	ID        loteID               `json:"id"`
	Descricao string               `json:"descricao"`
	Criacao   string               `json:"criacao"`
	CobsV     []loteCobvChargeView `json:"cobsv"`
}

// loteCobvListResponseBody is the list envelope: pagination plus the `lotes` array.
type loteCobvListResponseBody struct {
	Parametros pixParametros          `json:"parametros"`
	Lotes      []loteCobvResponseBody `json:"lotes"`
}

// describeProblem flattens an RFC7807 problem into one line, or "" when absent.
func describeProblem(p *loteCobvProblem) string {
	if p == nil {
		return ""
	}
	switch {
	case p.Title != "" && p.Detail != "":
		return p.Title + ": " + p.Detail
	case p.Detail != "":
		return p.Detail
	default:
		return p.Title
	}
}

// toPixDueChargeBatch maps a batch onto the port type. The id falls back to the one
// the caller addressed when the PSP echoes none.
func toPixDueChargeBatch(batchID string, b loteCobvResponseBody) ports.PixDueChargeBatch {
	id := string(b.ID)
	if id == "" {
		id = batchID
	}
	var created time.Time
	if t, err := time.Parse(time.RFC3339, b.Criacao); err == nil {
		created = t
	}
	items := make([]ports.PixDueChargeBatchItem, len(b.CobsV))
	for i, c := range b.CobsV {
		var itemCreated time.Time
		if t, err := time.Parse(time.RFC3339, c.Criacao); err == nil {
			itemCreated = t
		}
		items[i] = ports.PixDueChargeBatchItem{
			TxID:      c.TxID,
			Status:    c.Status,
			Problem:   describeProblem(c.Problema),
			CreatedAt: itemCreated,
		}
	}
	return ports.PixDueChargeBatch{ID: id, Description: b.Descricao, CreatedAt: created, Items: items}
}

// buildLoteBody validates and assembles the batch payload shared by create and revise.
// Every charge must carry its own txid: the batch addresses its charges by txid, and a
// blank one would silently drop a charge from a lot the caller believes it sent.
func (p *Provider) buildLoteBody(ctx context.Context, tenantID, op, batchID, description string, charges []ports.PixDueChargeRequest) ([]byte, error) {
	if strings.TrimSpace(batchID) == "" || strings.TrimSpace(description) == "" || len(charges) == 0 {
		return nil, &Error{Op: op, sentinel: shared.ErrValidation}
	}
	items := make([]loteCobvCharge, len(charges))
	for i, c := range charges {
		txid := strings.TrimSpace(c.TxID)
		if txid == "" || c.AmountCents <= 0 || c.DueDate.IsZero() {
			return nil, &Error{Op: op, sentinel: shared.ErrValidation}
		}
		chave, err := p.resolveCreditorKey(ctx, tenantID, c.CreditorKey)
		if err != nil {
			return nil, err
		}
		items[i] = loteCobvCharge{TxID: txid, cobvRequestBody: toCobvRequestBody(chave, c)}
	}
	payload, err := json.Marshal(loteCobvRequestBody{Descricao: strings.TrimSpace(description), CobsV: items})
	if err != nil {
		return nil, &Error{Op: op, sentinel: shared.ErrValidation}
	}
	return payload, nil
}

// CreateBatch registers or amends a batch of due-date charges under the caller's batch
// id via PUT /v2/pix/lotecobv/{id} (roteiro P_03_01).
//
// It returns no batch on purpose: the 202 says the PSP took the request, not that the
// charges exist. Read it back with GetBatch.
func (p *Provider) CreateBatch(ctx context.Context, tenantID, batchID, description string, charges []ports.PixDueChargeRequest) error {
	const op = "create_lotecobv"
	payload, err := p.buildLoteBody(ctx, tenantID, op, batchID, description, charges)
	if err != nil {
		return err
	}
	endpoint := p.baseURL + pixLoteCobvPath + "/" + url.PathEscape(strings.TrimSpace(batchID))
	// The batch id IS the idempotency anchor: PUTting the same id twice addresses the
	// same batch, so it is forwarded as the Idempotency-Key too.
	httpReq, err := p.authedJSONRequest(ctx, tenantID, op, http.MethodPut, endpoint, payload, strings.TrimSpace(batchID))
	if err != nil {
		return err
	}
	return p.doNoContent(httpReq, op)
}

// ReviseBatch revises specific charges inside an existing batch via PATCH
// /v2/pix/lotecobv/{id} (roteiro P_03_02). The revision may only keep the batch's
// original set of charges — adding or removing one is not a revision, and the PSP
// rejects it.
func (p *Provider) ReviseBatch(ctx context.Context, tenantID, batchID, description string, charges []ports.PixDueChargeRequest) error {
	const op = "revise_lotecobv"
	payload, err := p.buildLoteBody(ctx, tenantID, op, batchID, description, charges)
	if err != nil {
		return err
	}
	endpoint := p.baseURL + pixLoteCobvPath + "/" + url.PathEscape(strings.TrimSpace(batchID))
	httpReq, err := p.authedJSONRequest(ctx, tenantID, op, http.MethodPatch, endpoint, payload, "")
	if err != nil {
		return err
	}
	return p.doNoContent(httpReq, op)
}

// GetBatch reads a batch's authoritative state, per charge (roteiro P_03_03). This is
// the only place the outcome of a batched registration shows up.
func (p *Provider) GetBatch(ctx context.Context, tenantID, batchID string) (ports.PixDueChargeBatch, error) {
	const op = "get_lotecobv"
	batchID = strings.TrimSpace(batchID)
	if batchID == "" {
		return ports.PixDueChargeBatch{}, &Error{Op: op, sentinel: shared.ErrValidation}
	}
	endpoint := p.baseURL + pixLoteCobvPath + "/" + url.PathEscape(batchID)
	httpReq, err := p.authedJSONRequest(ctx, tenantID, op, http.MethodGet, endpoint, nil, "")
	if err != nil {
		return ports.PixDueChargeBatch{}, err
	}
	var out loteCobvResponseBody
	if err := p.do(httpReq, op, &out); err != nil {
		return ports.PixDueChargeBatch{}, err
	}
	return toPixDueChargeBatch(batchID, out), nil
}

// ListBatches returns the batches created within the filter's window (roteiro
// P_03_04). The window bounds are mandatory.
func (p *Provider) ListBatches(ctx context.Context, tenantID string, filter ports.PixDueChargeBatchFilter) (ports.PixDueChargeBatchList, error) {
	const op = "list_lotecobv"
	if filter.Start.IsZero() || filter.End.IsZero() {
		return ports.PixDueChargeBatchList{}, &Error{Op: op, sentinel: shared.ErrValidation}
	}
	q := pixWindowQuery(filter.Start, filter.End, filter.Page, filter.PageSize)
	httpReq, err := p.authedJSONRequest(ctx, tenantID, op, http.MethodGet, p.baseURL+pixLoteCobvPath+"?"+q.Encode(), nil, "")
	if err != nil {
		return ports.PixDueChargeBatchList{}, err
	}
	var out loteCobvListResponseBody
	if err := p.do(httpReq, op, &out); err != nil {
		return ports.PixDueChargeBatchList{}, err
	}
	batches := make([]ports.PixDueChargeBatch, len(out.Lotes))
	for i, l := range out.Lotes {
		batches[i] = toPixDueChargeBatch("", l)
	}
	return ports.PixDueChargeBatchList{Batches: batches, PixPage: out.Parametros.toPixPage()}, nil
}

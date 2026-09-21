package ports

import (
	"context"
	"time"
)

// This file holds the BACEN PIX v2 surfaces beyond cob/cobv: payload locations
// (`/loc`), received PIX and their refunds (`/pix`, `/devolucao`), batches of
// due-date charges (`/lotecobv`), and the revision verbs the charge ports lacked.
//
// # Por que estão em portas próprias, e por que não há caso de uso
//
// Cada uma é uma interface ESTREITA e separada (ISP), pelo mesmo motivo que
// PixDueChargeProvider não foi enfiado dentro de PixProvider: quem cria uma cobrança
// imediata não deve passar a depender de semântica de devolução, e quem devolve um
// PIX não deve depender de QR code.
//
// Elas nasceram sem caso de uso nem rota, só para o adapter falar o que o roteiro de
// homologação do C6 cobra. Hoje todas têm rota (`PixLocationService`,
// `PixReceivedService`, `PixBatchService`, e os verbos de revisão dentro de
// `PixService`/`PixDueChargeService`), e o roteador de banco responde 503 para o banco
// que não as implementa.
//
// Uma coisa NÃO subiu junto, de propósito: `CreateImmediateChargeAutoTxID`. O txid das
// nossas cobranças nasce da âncora de idempotência, e é essa derivação que faz um
// reenvio acertar a mesma cobrança em vez de cobrar o comprador duas vezes. Deixar o
// PSP escolher o txid jogaria isso fora — ela existe porque o roteiro cobra o verbo.
//
// Todo método carrega tenantID explicitamente, como as outras portas de banco, para
// que o isolamento por tenant que o adapter aplica nunca seja contornado (ameaça
// H1/P1). Um id de outro tenant é shared.ErrNotFound, nunca um erro distinto.

// PixLocation is a payload location: the addressable QR the PSP serves for a charge.
// ID is the PSP-assigned numeric id, Location the URI a payer's app fetches, TipoCob
// which kind of charge it may carry ("cob" or "cobv"), and TxID the charge currently
// bound to it (empty when none, and emptied by an unlink).
type PixLocation struct {
	ID        int64
	Location  string
	TipoCob   string
	TxID      string
	CreatedAt time.Time
}

// PixLocationFilter is the date window and optional filters of a location query. Start
// and End are mandatory (the contract requires inicio/fim). TipoCob narrows to one
// charge kind; TxIDPresent, when non-nil, filters by whether a charge is bound.
type PixLocationFilter struct {
	Start       time.Time
	End         time.Time
	TipoCob     string
	TxIDPresent *bool
	Page        int
	PageSize    int
}

// PixPage is the pagination block every BACEN PIX list echoes back.
type PixPage struct {
	Page       int
	PageSize   int
	TotalItems int
	TotalPages int
}

// PixLocationList is a page of payload locations.
type PixLocationList struct {
	Locations []PixLocation
	PixPage
}

// PixLocationProvider is the output port for payload-location management (roteiro
// P_04). A location is minted independently of a charge, which is what lets a QR be
// printed before the charge that will be served through it exists.
type PixLocationProvider interface {
	// CreateLocation mints a payload location for the given charge kind ("cob" or
	// "cobv"), roteiro P_04_01. The kind is the only required field.
	CreateLocation(ctx context.Context, tenantID, tipoCob string) (PixLocation, error)
	// ListLocations returns the locations created within the filter's window
	// (roteiro P_04_02). Pure read.
	ListLocations(ctx context.Context, tenantID string, filter PixLocationFilter) (PixLocationList, error)
	// GetLocation reads one location back, including the charge bound to it
	// (roteiro P_04_03). An unknown id within the tenant is shared.ErrNotFound.
	GetLocation(ctx context.Context, tenantID string, id int64) (PixLocation, error)
	// UnlinkLocationTxID detaches the charge from a location (roteiro P_04_04).
	// Afterwards the location has no txid and the charge no location — the charge's
	// STATUS does not change, which is why this is not a cancellation.
	UnlinkLocationTxID(ctx context.Context, tenantID string, id int64) (PixLocation, error)
}

// ReceivedPix is one PIX credited to the account. EndToEndID is the settlement
// identifier that travels in the PACS messages; TxID links it to the charge that
// originated it, and is EMPTY for a PIX paid against a static key — reconciliation
// must handle that rather than assume a charge.
type ReceivedPix struct {
	EndToEndID  string
	TxID        string
	AmountCents int64
	CreditorKey string
	ReceivedAt  time.Time
	PayerInfo   string
	Refunds     []PixRefund
}

// ReceivedPixFilter is the window and optional filters of a received-PIX query. Start
// and End are mandatory. TxID narrows to one charge; TxIDPresent and RefundPresent,
// when non-nil, filter by the existence of a charge link or of a refund.
//
// PayerTaxID filters by the payer's CPF or CNPJ. The contract forbids sending both,
// and the adapter places the value by length rather than asking the caller to pick.
type ReceivedPixFilter struct {
	Start         time.Time
	End           time.Time
	TxID          string
	TxIDPresent   *bool
	RefundPresent *bool
	PayerTaxID    string
	Page          int
	PageSize      int
}

// ReceivedPixList is a page of received PIX.
type ReceivedPixList struct {
	Received []ReceivedPix
	PixPage
}

// PixRefundNature is why a refund is being made. Empty means ORIGINAL, which is what
// the contract assumes when the field is omitted.
type PixRefundNature string

const (
	// RefundOriginal is the ordinary refund of a common PIX.
	RefundOriginal PixRefundNature = "ORIGINAL"
	// RefundWithdrawal refunds the withdrawal leg of a Pix Saque / Pix Troco.
	RefundWithdrawal PixRefundNature = "RETIRADA"
	// RefundMEDOperational is a refund for an operational failure, under the BACEN
	// Mecanismo Especial de Devolução.
	RefundMEDOperational PixRefundNature = "MED_OPERACIONAL"
	// RefundMEDFraud is a refund for suspected fraud, under the MED.
	RefundMEDFraud PixRefundNature = "MED_FRAUDE"
)

// PixRefundRequest asks the PSP to refund part or all of a received PIX. AmountCents
// is required and the sum of all refunds may not exceed the PIX. Description, when
// present, is shown to the payer (140 characters at the PACS level).
type PixRefundRequest struct {
	AmountCents int64
	Nature      PixRefundNature
	Description string
}

// PixRefund is a refund's state at the PSP. Status is the contract's vocabulary
// verbatim — EM_PROCESSAMENTO, DEVOLVIDO, NAO_REALIZADO — and Reason carries the PSP's
// explanation, which is the only place a NAO_REALIZADO says why.
type PixRefund struct {
	ID          string
	ReturnID    string
	AmountCents int64
	Nature      PixRefundNature
	Description string
	Status      string
	Reason      string
	RequestedAt time.Time
	SettledAt   time.Time
}

// PixReceivedProvider is the output port for reading received PIX and refunding them
// (roteiro P_05). Refunding is the one MONEY-MOVING operation among the surfaces in
// this file, which is why its request carries an explicit amount instead of defaulting
// to the whole PIX.
type PixReceivedProvider interface {
	// GetReceivedPix reads one received PIX by its end-to-end id (roteiro P_05_01).
	GetReceivedPix(ctx context.Context, tenantID, endToEndID string) (ReceivedPix, error)
	// ListReceivedPix returns the PIX credited within the filter's window (roteiro
	// P_05_02). Pure read.
	ListReceivedPix(ctx context.Context, tenantID string, filter ReceivedPixFilter) (ReceivedPixList, error)
	// RequestRefund asks for a refund of a received PIX (roteiro P_05_03). refundID is
	// the CALLER's identifier for this refund, which makes the operation idempotent at
	// the PSP: the same (endToEndID, refundID) always addresses the same refund and can
	// never pay twice.
	RequestRefund(ctx context.Context, tenantID, endToEndID, refundID string, req PixRefundRequest) (PixRefund, error)
	// GetRefund reconciles a refund's authoritative state (roteiro P_05_04).
	GetRefund(ctx context.Context, tenantID, endToEndID, refundID string) (PixRefund, error)
}

// PixBatchChargeStatus is the state of ONE charge inside a batch, which is about the
// batch REQUEST and not about payment: CRIADA means the PSP accepted the registration,
// not that anybody paid.
type PixBatchChargeStatus string

const (
	// BatchChargeProcessing — a solicitação ainda está sendo processada.
	BatchChargeProcessing PixBatchChargeStatus = "EM_PROCESSAMENTO"
	// BatchChargeCreated — a cobrança foi criada/alterada com sucesso.
	BatchChargeCreated PixBatchChargeStatus = "CRIADA"
	// BatchChargeDenied — a solicitação foi negada; Problem diz por quê.
	BatchChargeDenied PixBatchChargeStatus = "NEGADA"
)

// PixDueChargeBatchItem is one charge inside a batch, with the outcome of its
// registration. Problem carries the PSP's RFC7807 title/detail for a NEGADA item — it
// is the only place the reason for a single rejected line survives.
type PixDueChargeBatchItem struct {
	TxID      string
	Status    string
	Problem   string
	CreatedAt time.Time
}

// PixDueChargeBatch is a batch of due-date charges: its id, the description shown
// with it, and the per-charge outcomes.
//
// ID is a STRING because the contract disagrees with itself: the path parameter of
// PUT /lotecobv/{id} is a string the CALLER chooses, while the read declares `id` as
// an int64. Carrying a string accepts both, and never loses a caller id that happens
// not to be numeric.
type PixDueChargeBatch struct {
	ID          string
	Description string
	CreatedAt   time.Time
	Items       []PixDueChargeBatchItem
}

// PixDueChargeBatchFilter is the mandatory date window of a batch query.
type PixDueChargeBatchFilter struct {
	Start    time.Time
	End      time.Time
	Page     int
	PageSize int
}

// PixDueChargeBatchList is a page of batches.
type PixDueChargeBatchList struct {
	Batches []PixDueChargeBatch
	PixPage
}

// PixDueChargeBatchProvider is the output port for batches of due-date charges
// (lotecobv, roteiro P_03).
//
// The write verbs answer 202 Accepted, not 201: the PSP takes the batch and processes
// it asynchronously. A caller that treats the 202 as "the charges exist" is wrong —
// the outcome per charge only shows up in GetBatch, which is why it is a separate read
// rather than a return value.
type PixDueChargeBatchProvider interface {
	// CreateBatch registers or amends a batch of due-date charges under the caller's
	// batch id (roteiro P_03_01). Accepted, not completed: read it back.
	CreateBatch(ctx context.Context, tenantID, batchID, description string, charges []PixDueChargeRequest) error
	// ReviseBatch revises specific charges inside an existing batch (roteiro P_03_02).
	// Same asynchronous semantics as CreateBatch.
	ReviseBatch(ctx context.Context, tenantID, batchID, description string, charges []PixDueChargeRequest) error
	// GetBatch reads a batch's authoritative state, per charge (roteiro P_03_03).
	GetBatch(ctx context.Context, tenantID, batchID string) (PixDueChargeBatch, error)
	// ListBatches returns the batches created within the filter's window (roteiro
	// P_03_04). Pure read.
	ListBatches(ctx context.Context, tenantID string, filter PixDueChargeBatchFilter) (PixDueChargeBatchList, error)
}

// PixChargeReviser adds the two immediate-charge verbs PixProvider does not carry:
// creating without choosing a txid, and revising an existing charge.
//
// They are HERE rather than on PixProvider because the product never wants either.
// Our charges are addressed by a txid derived from the payment's idempotency anchor —
// that derivation is what makes a re-submit hit the same charge instead of billing
// twice — so letting the PSP pick the txid would throw away the idempotency, and
// revising an amount after the payer already has the QR is a money-changing operation
// no flow here asks for. The roteiro cobra as duas; o produto não.
type PixChargeReviser interface {
	// CreateImmediateChargeAutoTxID creates a charge letting the PSP assign the txid
	// (roteiro P_01_02). See the interface comment before reaching for this.
	CreateImmediateChargeAutoTxID(ctx context.Context, tenantID string, req ChargeRequest, expiresIn time.Duration) (PixChargeResult, error)
	// ReviseImmediateCharge amends an existing charge (roteiro P_01_03). Only the
	// fields present in req are sent.
	ReviseImmediateCharge(ctx context.Context, tenantID, txID string, req ChargeRequest, expiresIn time.Duration) (PixChargeResult, error)
}

// PixDueChargeReviser revises a due-date charge with PATCH (roteiro P_02_02).
//
// It is separate from PixDueChargeProvider.UpdateDueCharge, which sends the FULL
// parameter set with PUT. The two are not interchangeable: PUT replaces, PATCH amends,
// and sending a partial body to the PUT would clear the fields it omits.
type PixDueChargeReviser interface {
	ReviseDueCharge(ctx context.Context, tenantID, txID string, req PixDueChargeRequest) (PixDueChargeResult, error)
}

// PixDueChargeLister lists due-date charges by interval (roteiro P_02_04).
type PixDueChargeLister interface {
	ListDueCharges(ctx context.Context, tenantID string, filter PixListFilter) (PixDueChargeList, error)
}

// PixDueChargeList is a page of due-date charges.
type PixDueChargeList struct {
	Charges []PixDueChargeResult
	PixPage
}

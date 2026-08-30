// Package recurrence holds the PIX Automático (recorrência) persistence domain:
// the durable record of a recurring-debit mandate (Rec) and of each scheduled
// charge instance in its cycle (CobR), plus the rules that decide which status
// transitions are legal. These rules are PURE domain — they never touch the
// network, the PSP or storage. The C6 adapter (internal/adapters/bank/c6) speaks
// the BACEN wire contract via ports.RecResult/CobRResult; this package is the
// authoritative in-house model that survives a restart and whose status changes
// are the events the audit trail records.
//
// Why a separate domain type from the ports DTOs: a ports.RecResult is the bank's
// view at one instant (as reconciled from it). A recurrence.Rec is OUR durable
// aggregate — it owns the legal state machine (a mandate cannot go APROVADA →
// CRIADA, a terminal mandate cannot move at all) so an out-of-order or replayed
// webhook can never corrupt the lifecycle (threat W3). The string values of the
// status/periodicidade enums are kept identical to the wire vocabulary so the
// future use-case (F4) translates losslessly with a plain cast.
//
// Pure domain: this package MUST NOT import database/sql, net/http, vendor SDKs or
// the ports package. Persistence lives behind ports.RecRepository /
// ports.CobRRepository, implemented by the sqlite and inmemory adapters.
package recurrence

import (
	"strings"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

// RecPeriodicidade is how often a recurring mandate may be charged. The closed
// vocabulary mirrors BACEN/C6 so persistence and the wire agree by value.
type RecPeriodicidade string

const (
	RecSemanal    RecPeriodicidade = "SEMANAL"
	RecMensal     RecPeriodicidade = "MENSAL"
	RecTrimestral RecPeriodicidade = "TRIMESTRAL"
	RecSemestral  RecPeriodicidade = "SEMESTRAL"
	RecAnual      RecPeriodicidade = "ANUAL"
)

func (p RecPeriodicidade) valid() bool {
	switch p {
	case RecSemanal, RecMensal, RecTrimestral, RecSemestral, RecAnual:
		return true
	default:
		return false
	}
}

// RecStatus is the lifecycle state of a recurring mandate (Rec). The closed set
// matches the audit vocabulary of transitions the trail records
// (criada/aprovada/rejeitada/expirada/cancelada).
type RecStatus string

const (
	// RecCriada is the initial state: the mandate is registered but not yet
	// confirmed by the payer at their bank. No CobR is chargeable until APROVADA.
	RecCriada RecStatus = "CRIADA"
	// RecAprovada means the payer confirmed the mandate; CobR instances may be
	// originated against it.
	RecAprovada RecStatus = "APROVADA"
	// RecRejeitada means the payer (or their bank) declined the mandate. Terminal.
	RecRejeitada RecStatus = "REJEITADA"
	// RecExpirada means the activation window lapsed before approval, or an approved
	// mandate reached its end. Terminal.
	RecExpirada RecStatus = "EXPIRADA"
	// RecCancelada means the mandate was revoked (by the recebedor or the payer) so
	// no further debits can be originated. Terminal.
	RecCancelada RecStatus = "CANCELADA"
)

func (s RecStatus) valid() bool {
	switch s {
	case RecCriada, RecAprovada, RecRejeitada, RecExpirada, RecCancelada:
		return true
	default:
		return false
	}
}

// terminal reports whether no further transition is legal from s.
func (s RecStatus) terminal() bool {
	switch s {
	case RecRejeitada, RecExpirada, RecCancelada:
		return true
	default:
		return false
	}
}

// recTransitions is the legal mandate state machine: from → allowed set. A
// transition not listed here is rejected (deny-by-default), so a replayed or
// out-of-order event can never drive an illegal lifecycle change.
var recTransitions = map[RecStatus]map[RecStatus]bool{
	RecCriada: {
		RecAprovada:  true,
		RecRejeitada: true,
		RecExpirada:  true,
		RecCancelada: true,
	},
	RecAprovada: {
		RecCancelada: true,
		RecExpirada:  true,
	},
}

// Devedor identifies the payer bound to a mandate. Exactly one of CPF/CNPJ is
// populated (BACEN oneOf), alongside the name. The document is never logged.
type Devedor struct {
	doc  string // CPF (11) or CNPJ (14) digits
	nome string
}

// Doc returns the payer document digits (CPF or CNPJ).
func (d Devedor) Doc() string { return d.doc }

// Nome returns the payer name.
func (d Devedor) Nome() string { return d.nome }

// NewDevedor validates and builds a payer. The document must be 11 (CPF) or 14
// (CNPJ) digits and the name is required.
func NewDevedor(doc, nome string) (Devedor, error) {
	doc = strings.TrimSpace(doc)
	if len(doc) != 11 && len(doc) != 14 {
		return Devedor{}, shared.NewValidationError("devedor_doc", "must be an 11-digit CPF or 14-digit CNPJ")
	}
	for _, r := range doc {
		if r < '0' || r > '9' {
			return Devedor{}, shared.NewValidationError("devedor_doc", "must contain only digits")
		}
	}
	nome = strings.TrimSpace(nome)
	if nome == "" {
		return Devedor{}, shared.NewValidationError("devedor_nome", "is required")
	}
	return Devedor{doc: doc, nome: nome}, nil
}

// Rec is the durable recurring-debit mandate aggregate. It is constructed CRIADA
// and only moves through legal transitions (Transition). Fields are unexported and
// exposed via accessors so the status can change only through the state machine.
type Rec struct {
	idRec         string
	tenantID      string
	bankID        string
	contrato      string
	devedor       Devedor
	dataInicial   string // yyyy-MM-dd, first eligible charge date
	periodicidade RecPeriodicidade
	valorCents    int64 // mandate amount in centavos; 0 = unspecified/variable
	status        RecStatus
	// locID is the bank-side payload location the composite QR renders this mandate
	// from (0 = none). jornadaTxID is the txid of the immediate charge the Jornada 3
	// QR settles alongside the authorization ("" = not a Jornada 3 mandate).
	//
	// Both are registration facts, not lifecycle state: they are decided once, when the
	// mandate is created, and never move. They are kept here so re-composing the QR does
	// not force every caller to remember which charge a mandate was bound to — a fact
	// that, if lost, cannot be recovered from the mandate alone.
	locID       int64
	jornadaTxID string
	createdAt   time.Time
	updatedAt   time.Time
}

// NewRecParams is the validated input to register a mandate durably.
type NewRecParams struct {
	IDRec         string
	TenantID      string
	BankID        string
	Contrato      string
	Devedor       Devedor
	DataInicial   string
	Periodicidade RecPeriodicidade
	ValorCents    int64
	// LocID / JornadaTxID are the QR-journey binding (see the Rec fields). Both are
	// optional: a mandate activated through solicrec (Jornada 1) has neither.
	LocID       int64
	JornadaTxID string
}

// dateLayout is the BACEN calendar date format (no time component).
const dateLayout = "2006-01-02"

func validDate(s string) bool {
	_, err := time.Parse(dateLayout, s)
	return err == nil
}

// NewRec builds a mandate in the initial CRIADA state, enforcing invariants:
// non-empty idRec/tenant/bank/contrato, a valid devedor, a well-formed dataInicial,
// a known periodicidade and a non-negative value. at stamps both timestamps.
func NewRec(p NewRecParams, at time.Time) (*Rec, error) {
	idRec := strings.TrimSpace(p.IDRec)
	if idRec == "" {
		return nil, shared.NewValidationError("id_rec", "is required")
	}
	tenantID := strings.TrimSpace(p.TenantID)
	if tenantID == "" {
		return nil, shared.NewValidationError("tenant_id", "is required")
	}
	bankID := strings.TrimSpace(p.BankID)
	if bankID == "" {
		return nil, shared.NewValidationError("bank_id", "is required")
	}
	contrato := strings.TrimSpace(p.Contrato)
	if contrato == "" {
		return nil, shared.NewValidationError("contrato", "is required")
	}
	if p.Devedor == (Devedor{}) {
		return nil, shared.NewValidationError("devedor", "is required")
	}
	if !validDate(p.DataInicial) {
		return nil, shared.NewValidationError("data_inicial", "must be a yyyy-MM-dd date")
	}
	if !p.Periodicidade.valid() {
		return nil, shared.NewValidationError("periodicidade", "unknown periodicidade")
	}
	if p.ValorCents < 0 {
		return nil, shared.NewValidationError("valor_cents", "must not be negative")
	}
	return &Rec{
		idRec:         idRec,
		tenantID:      tenantID,
		bankID:        bankID,
		contrato:      contrato,
		devedor:       p.Devedor,
		dataInicial:   p.DataInicial,
		periodicidade: p.Periodicidade,
		valorCents:    p.ValorCents,
		status:        RecCriada,
		locID:         p.LocID,
		jornadaTxID:   strings.TrimSpace(p.JornadaTxID),
		createdAt:     at,
		updatedAt:     at,
	}, nil
}

// Transition moves the mandate to a new status if the change is legal, stamping
// updatedAt. It returns shared.ErrInvalidTransition for an illegal transition (a
// terminal mandate, or an unmodeled edge) so a replayed/out-of-order event cannot
// corrupt the lifecycle. A transition to the SAME status is a no-op (idempotent
// re-delivery) and returns nil without advancing updatedAt.
func (r *Rec) Transition(to RecStatus, at time.Time) error {
	if !to.valid() {
		return shared.NewValidationError("status", "unknown rec status")
	}
	if to == r.status {
		return nil
	}
	if r.status.terminal() || !recTransitions[r.status][to] {
		return shared.ErrInvalidTransition
	}
	r.status = to
	r.updatedAt = at
	return nil
}

// RehydrateRec reconstructs a mandate from persisted columns without re-running
// construction validation (the row was valid when written). It is the storage
// adapter's inverse of the accessors.
func RehydrateRec(idRec, tenantID, bankID, contrato string, devedor Devedor, dataInicial string, periodicidade RecPeriodicidade, valorCents int64, status RecStatus, createdAt, updatedAt time.Time, opts ...RehydrateRecOption) *Rec {
	rec := &Rec{
		idRec:         idRec,
		tenantID:      tenantID,
		bankID:        bankID,
		contrato:      contrato,
		devedor:       devedor,
		dataInicial:   dataInicial,
		periodicidade: periodicidade,
		valorCents:    valorCents,
		status:        status,
		createdAt:     createdAt,
		updatedAt:     updatedAt,
	}
	for _, o := range opts {
		o(rec)
	}
	return rec
}

// RehydrateRecOption restores a column that a row written before the QR-journey
// columns existed simply does not have. Optional rather than positional so the
// adapters keep compiling — and so a NULL column rehydrates as the zero value, which
// is exactly "this mandate has no QR binding".
type RehydrateRecOption func(*Rec)

// WithRecJourney restores the QR-journey binding (payload location + Jornada 3 txid).
func WithRecJourney(locID int64, jornadaTxID string) RehydrateRecOption {
	return func(r *Rec) {
		r.locID = locID
		r.jornadaTxID = jornadaTxID
	}
}

// IDRec returns the mandate identifier (the bank's idRec).
func (r *Rec) IDRec() string { return r.idRec }

// TenantID returns the owning tenant.
func (r *Rec) TenantID() string { return r.tenantID }

// BankID returns the non-secret bank slug (ADR-0007).
func (r *Rec) BankID() string { return r.bankID }

// Contrato returns the contract reference binding the mandate to its purpose.
func (r *Rec) Contrato() string { return r.contrato }

// Devedor returns the payer bound to the mandate.
func (r *Rec) Devedor() Devedor { return r.devedor }

// DataInicial returns the first eligible charge date (yyyy-MM-dd).
func (r *Rec) DataInicial() string { return r.dataInicial }

// Periodicidade returns how often the mandate may be charged.
func (r *Rec) Periodicidade() RecPeriodicidade { return r.periodicidade }

// ValorCents returns the mandate amount in centavos (0 = unspecified/variable).
func (r *Rec) ValorCents() int64 { return r.valorCents }

// LocID returns the payload location bound to the mandate (0 = none).
func (r *Rec) LocID() int64 { return r.locID }

// JornadaTxID returns the immediate-charge txid the Jornada 3 composite QR settles
// ("" when the mandate was not created for that journey).
func (r *Rec) JornadaTxID() string { return r.jornadaTxID }

// Status returns the current lifecycle state.
func (r *Rec) Status() RecStatus { return r.status }

// CreatedAt returns when the mandate was first registered.
func (r *Rec) CreatedAt() time.Time { return r.createdAt }

// UpdatedAt returns when the mandate last changed status.
func (r *Rec) UpdatedAt() time.Time { return r.updatedAt }

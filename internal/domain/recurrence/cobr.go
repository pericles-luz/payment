package recurrence

import (
	"strings"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

// CobRStatus is the lifecycle state of one scheduled charge instance (CobR) in a
// mandate's cycle. The closed vocabulary mirrors the PIX cobrança statuses already
// modelled for cob/cobv so the cycle reads consistently across products.
type CobRStatus string

const (
	// CobRCriada is a scheduled charge awaiting its due date / settlement.
	CobRCriada CobRStatus = "CRIADA"
	// CobRAtrasada is a charge past its due date and not yet settled.
	CobRAtrasada CobRStatus = "ATRASADA"
	// CobRLiquidada is a settled (paid) charge. Terminal.
	CobRLiquidada CobRStatus = "LIQUIDADA"
	// CobRRemovida is a charge removed before settlement (by the recebedor or the
	// PSP). Terminal.
	CobRRemovida CobRStatus = "REMOVIDA"
)

func (s CobRStatus) valid() bool {
	switch s {
	case CobRCriada, CobRAtrasada, CobRLiquidada, CobRRemovida:
		return true
	default:
		return false
	}
}

func (s CobRStatus) terminal() bool {
	switch s {
	case CobRLiquidada, CobRRemovida:
		return true
	default:
		return false
	}
}

// cobrTransitions is the legal charge state machine. Deny-by-default: a transition
// not listed is rejected, so a replayed settlement webhook cannot un-settle a
// charge (threat W3).
var cobrTransitions = map[CobRStatus]map[CobRStatus]bool{
	CobRCriada: {
		CobRAtrasada:  true,
		CobRLiquidada: true,
		CobRRemovida:  true,
	},
	CobRAtrasada: {
		CobRLiquidada: true,
		CobRRemovida:  true,
	},
}

// CobR is one durable scheduled charge instance anchored to a mandate. The TxID is
// the anti-double-bill invariant: a CobR is addressed by it, so a retried create
// targets the same instance (never a second charge). Fields are unexported and
// the status moves only through Transition.
type CobR struct {
	txID       string
	idRec      string
	tenantID   string
	vencimento string // yyyy-MM-dd due date
	valorCents int64  // charge amount in centavos (always > 0)
	status     CobRStatus
	createdAt  time.Time
	updatedAt  time.Time
}

// NewCobRParams is the validated input to register one charge instance durably.
type NewCobRParams struct {
	TxID       string
	IDRec      string
	TenantID   string
	Vencimento string
	ValorCents int64
}

// NewCobR builds a charge instance in the initial CRIADA state, enforcing
// invariants: non-empty txid/idRec/tenant, a well-formed vencimento and a strictly
// positive amount (a charge with no value is meaningless). at stamps both
// timestamps.
func NewCobR(p NewCobRParams, at time.Time) (*CobR, error) {
	txID := strings.TrimSpace(p.TxID)
	if txID == "" {
		return nil, shared.NewValidationError("tx_id", "is required")
	}
	idRec := strings.TrimSpace(p.IDRec)
	if idRec == "" {
		return nil, shared.NewValidationError("id_rec", "is required")
	}
	tenantID := strings.TrimSpace(p.TenantID)
	if tenantID == "" {
		return nil, shared.NewValidationError("tenant_id", "is required")
	}
	if !validDate(p.Vencimento) {
		return nil, shared.NewValidationError("vencimento", "must be a yyyy-MM-dd date")
	}
	if p.ValorCents <= 0 {
		return nil, shared.NewValidationError("valor_cents", "must be greater than zero")
	}
	return &CobR{
		txID:       txID,
		idRec:      idRec,
		tenantID:   tenantID,
		vencimento: p.Vencimento,
		valorCents: p.ValorCents,
		status:     CobRCriada,
		createdAt:  at,
		updatedAt:  at,
	}, nil
}

// Transition moves the charge to a new status if legal, stamping updatedAt. Same
// semantics as Rec.Transition: same-status is an idempotent no-op (nil); an
// illegal move returns shared.ErrInvalidTransition; an unknown status is a
// validation error.
func (c *CobR) Transition(to CobRStatus, at time.Time) error {
	if !to.valid() {
		return shared.NewValidationError("status", "unknown cobr status")
	}
	if to == c.status {
		return nil
	}
	if c.status.terminal() || !cobrTransitions[c.status][to] {
		return shared.ErrInvalidTransition
	}
	c.status = to
	c.updatedAt = at
	return nil
}

// RehydrateCobR reconstructs a charge instance from persisted columns.
func RehydrateCobR(txID, idRec, tenantID, vencimento string, valorCents int64, status CobRStatus, createdAt, updatedAt time.Time) *CobR {
	return &CobR{
		txID:       txID,
		idRec:      idRec,
		tenantID:   tenantID,
		vencimento: vencimento,
		valorCents: valorCents,
		status:     status,
		createdAt:  createdAt,
		updatedAt:  updatedAt,
	}
}

// TxID returns the charge's anti-double-bill anchor.
func (c *CobR) TxID() string { return c.txID }

// IDRec returns the mandate this charge belongs to.
func (c *CobR) IDRec() string { return c.idRec }

// TenantID returns the owning tenant.
func (c *CobR) TenantID() string { return c.tenantID }

// Vencimento returns the due date (yyyy-MM-dd).
func (c *CobR) Vencimento() string { return c.vencimento }

// ValorCents returns the charge amount in centavos.
func (c *CobR) ValorCents() int64 { return c.valorCents }

// Status returns the current charge state.
func (c *CobR) Status() CobRStatus { return c.status }

// CreatedAt returns when the charge was registered.
func (c *CobR) CreatedAt() time.Time { return c.createdAt }

// UpdatedAt returns when the charge last changed status.
func (c *CobR) UpdatedAt() time.Time { return c.updatedAt }

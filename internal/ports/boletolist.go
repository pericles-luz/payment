package ports

import (
	"context"
	"time"
)

// BoletoListFilter is the query of a BolePix charge listing (roteiro BP_06).
//
// AT LEAST ONE date range is required — payment, due or credit — and none may span
// more than 60 days. The three are different questions ("o que foi pago", "o que vence",
// "o que cai na conta") and the acquirer answers them separately, so they are three
// ranges rather than one with a mode flag.
type BoletoListFilter struct {
	PaymentDateFrom time.Time
	PaymentDateTo   time.Time
	DueDateFrom     time.Time
	DueDateTo       time.Time
	CreditDateFrom  time.Time
	CreditDateTo    time.Time
	// Status narrows to one lifecycle state (CREATED, PAID, CANCELED,
	// WAITING_CONFIRMATION). Empty means all.
	Status string
	// ExternalReferenceID narrows to a single charge by OUR reference.
	ExternalReferenceID string
	// Page is zero-based here, unlike the BACEN PIX lists which start at 1.
	Page     int
	PageSize int
}

// BoletoList is a page of BolePix charges.
type BoletoList struct {
	Boletos    []BoletoResult
	Page       int
	PageSize   int
	TotalItems int
	TotalPages int
}

// BoletoLister lists the BolePix charges a tenant has issued (roteiro BP_06). It is
// kept separate from BoletoProvider (ISP): the settlement path reconciles ONE charge
// and must not be handed a listing it has no use for.
type BoletoLister interface {
	ListBoletos(ctx context.Context, tenantID string, filter BoletoListFilter) (BoletoList, error)
}

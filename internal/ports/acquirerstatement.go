package ports

import (
	"context"
	"time"
)

// Acquirer statement: the card-acquiring extract (C6 Pay's "Transações e Recebíveis",
// roteiro grupo TR). Two reads over the same window: the TRANSACTIONS the terminal or
// the checkout authorised, and the RECEIVABLES those transactions settle into.
//
// They are not the same money and must not be confused. A transaction is what the
// buyer authorised — gross, at once. A receivable is one instalment of what the
// acquirer will actually pay the merchant, net of the MDR and the per-sale fee, on a
// future date. Our own ledger settles on GROSS; the merchant's account receives NET.
// That gap is real (R$ 30,00 authorised lands as R$ 28,39, per
// docs/compliance/c6pay-recebiveis-notas.md) and this port is where it becomes
// visible instead of being discovered in a reconciliation.

// Receivable is one instalment the acquirer owes the merchant for a card sale.
//
// The money fields are in CENTS. FeeCents and DiscountCents arrive NEGATIVE on the
// wire (they are deductions) and are carried with their sign intact: flipping them
// here would hide which direction the money moved.
type Receivable struct {
	ReceivableID  string
	TransactionID string
	LocalRef      string
	BrandName     string
	PaymentType   string
	Type          string
	Status        string
	Origin        string
	// Installment is which instalment this is, of Installments total.
	Installment  int
	Installments int
	InterestType string

	GrossAmountCents int64
	FeeCents         int64
	DiscountCents    int64
	NetAmountCents   int64
	// MDR is the merchant discount rate as the acquirer reports it, scaled by 100 —
	// so a wire value of 2 arrives as 200.
	//
	// The contract does NOT say whether it is a percentage or an amount, and its
	// example (2) reads as either. Nothing here interprets it: it is transported so a
	// reconciliation can look at it, and the tariff actually agreed with the acquirer
	// is recorded in docs/compliance/c6pay-recebiveis-notas.md, not inferred from this
	// field.
	MDR int64

	ExpectedDate    time.Time
	PaymentDate     time.Time
	TransactionTime time.Time
}

// CardTransaction is one authorisation (or cancellation) on the acquirer.
//
// The cardholder's name and the masked PAN are deliberately NOT carried. They are in
// the response; not modelling them is how they never reach a log, an error or a
// stored row (ADR-0008, and the same discipline the received-PIX payer gets). Brand,
// instalment count and the authorisation code are enough to reconcile a sale.
type CardTransaction struct {
	ID            string
	LocalRef      string
	AuthCode      string
	AuthorizerRef string
	BrandName     string
	PaymentType   string
	Status        string
	Origin        string
	EntryMode     string
	Installments  int
	InterestType  string
	CurrencyCode  string
	TerminalID    string
	FraudAnalysis string
	AmountCents   int64
	OccurredAt    time.Time
}

// AcquirerStatementFilter is the query window of an acquirer extract. Start is
// required; an absent End means "the same day as Start", which is the acquirer's own
// default. The window may not exceed 60 days.
type AcquirerStatementFilter struct {
	Start    time.Time
	End      time.Time
	Page     int
	PageSize int
}

// AcquirerPage is the pagination the acquirer echoes. LastPage is the number of pages
// in the result and Items the count in THIS page — it is not a grand total, and
// reading it as one would under-report a paginated extract.
type AcquirerPage struct {
	Page     int
	LastPage int
	Items    int
}

// ReceivableList is a page of receivables.
type ReceivableList struct {
	Receivables []Receivable
	AcquirerPage
}

// CardTransactionList is a page of card transactions.
type CardTransactionList struct {
	Transactions []CardTransaction
	AcquirerPage
}

// AcquirerStatementProvider is the output port for the card-acquiring extract
// (roteiro TR_01/TR_02). Both methods are pure reads.
//
// In production this surface answers 403 unless the acquiring product is separately
// enabled for the account — a token carrying statement.read is NOT enough, because
// C6 Pay is a different product from the bank statement. That 403 is an entitlement
// answer, not a bug, and it is why the adapter maps it through unchanged.
type AcquirerStatementProvider interface {
	// ListReceivables returns the receivables scheduled or settled within the
	// filter's window (roteiro TR_01).
	ListReceivables(ctx context.Context, tenantID string, filter AcquirerStatementFilter) (ReceivableList, error)
	// ListCardTransactions returns the transactions and cancellations within the
	// filter's window (roteiro TR_02).
	ListCardTransactions(ctx context.Context, tenantID string, filter AcquirerStatementFilter) (CardTransactionList, error)
}

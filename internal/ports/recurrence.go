package ports

import (
	"context"
	"time"
)

// PIX Automático (Recorrência) output ports — the REAL BACEN/C6 recurring-debit
// contract captured live in SIN-66034 (F0). These supersede the chutado
// ConsentProvider: the recurring mandate is a Rec, the request that asks a payer's
// participant to confirm it is a SolicRec, and each scheduled charge instance is a
// CobR (cobrança recorrente).
//
// Money crosses the port as integer centavos; rendering it as the BACEN decimal
// string on the wire is the adapter's concern (padrão brlDecimal, SIN-65953) so a
// payment amount can never drift through a float. idRec and txid are the
// anti-double-bill invariants: a CobR is anchored to a single txid so a retried
// create targets the same charge.
//
// Reads (GetRec/GetSolicRec/GetCobR) reconcile authoritative state from the bank —
// never trust a raw webhook (threat W3). C6 returns those reads as JWS-signed
// documents (Accept: application/jose; non-repúdio do mandato BACEN); verifying
// that signature before the body is trusted is the adapter's responsibility.
//
// The bank dimension is fixed in the adapter's identity ("c6"), never carried on a
// business request: resolution stays on the (tenantID, bankID) credential seam
// (ADR-0007), with no parallel selection path.

// RecPeriodicidade is how often a recurring mandate may be charged.
type RecPeriodicidade string

const (
	RecSemanal    RecPeriodicidade = "SEMANAL"
	RecMensal     RecPeriodicidade = "MENSAL"
	RecTrimestral RecPeriodicidade = "TRIMESTRAL"
	RecSemestral  RecPeriodicidade = "SEMESTRAL"
	RecAnual      RecPeriodicidade = "ANUAL"
)

// RetryPolicy is the BACEN política de retentativa applied to a failed debit.
type RetryPolicy string

const (
	RetryNaoPermite RetryPolicy = "NAO_PERMITE"
	Retry3R7D       RetryPolicy = "PERMITE_3R_7D"
)

// RecStatus is the lifecycle state of a recurring mandate (Rec).
type RecStatus string

const (
	RecCriada    RecStatus = "CRIADA"
	RecAprovada  RecStatus = "APROVADA"
	RecRejeitada RecStatus = "REJEITADA"
	RecCancelada RecStatus = "CANCELADA"
	RecExpirada  RecStatus = "EXPIRADA"
)

// RecDevedor identifies the payer bound to a recurring mandate. Exactly one of
// CPF/CNPJ is populated (BACEN oneOf), alongside Nome.
type RecDevedor struct {
	CPF  string
	CNPJ string
	Nome string
}

// RecVinculo is the contract binding the mandate to its payer and purpose.
type RecVinculo struct {
	Contrato string
	Devedor  RecDevedor
	Objeto   string // optional free-text purpose of the recurrence
}

// RecCalendario is the recurring schedule: the first eligible date and how often.
type RecCalendario struct {
	DataInicial   string // yyyy-MM-dd
	Periodicidade RecPeriodicidade
}

// Recebedor is the credited account. It is auto-filled by the bank from the
// authenticated tenant's account and is NEVER sent on a create — funds cannot be
// rerouted to an arbitrary account (confused-deputy defense, ADR-0004).
type Recebedor struct {
	ISPB string
	CNPJ string
	CPF  string
	Nome string
}

// CreateRecRequest registers a recurring-debit mandate at the bank.
type CreateRecRequest struct {
	Vinculo             RecVinculo
	Calendario          RecCalendario
	PoliticaRetentativa RetryPolicy
	// IdempotencyKey collapses retried/concurrent registrations into one mandate.
	IdempotencyKey string
}

// RecResult is the bank's representation of a recurring mandate.
type RecResult struct {
	IDRec               string
	Status              RecStatus
	Vinculo             RecVinculo
	Calendario          RecCalendario
	Recebedor           Recebedor
	PoliticaRetentativa RetryPolicy
	// TipoJornada is the activation-journey state, e.g. AGUARDANDO_DEFINICAO until
	// the payer approves the mandate at their bank.
	TipoJornada string
}

// RecProvider is the output port for recurring-debit mandates (rec).
type RecProvider interface {
	// CreateRec registers a recurring-debit mandate. The mandate starts CRIADA and
	// must be APROVADA (out-of-band, via the payer's bank) before any CobR is
	// chargeable.
	CreateRec(ctx context.Context, tenantID string, req CreateRecRequest) (RecResult, error)
	// GetRec reconciles the authoritative mandate state from the bank (JWS-verified).
	GetRec(ctx context.Context, tenantID, idRec string) (RecResult, error)
	// CancelRec revokes a mandate (PATCH status=CANCELADA) so no further debits can
	// be originated. Idempotent on idRec.
	CancelRec(ctx context.Context, tenantID, idRec string) (RecResult, error)
}

// SolicRecDestinatario is the participant/account a recurrence-activation request
// is addressed to. Exactly one of CPF/CNPJ is populated, plus the routing fields.
type SolicRecDestinatario struct {
	CPF              string
	CNPJ             string
	Agencia          string
	Conta            string
	ISPBParticipante string
}

// CreateSolicRecRequest asks the payer's participant to confirm a mandate (idRec).
type CreateSolicRecRequest struct {
	IDRec        string
	Destinatario SolicRecDestinatario
	// ExpiraEm is when the activation request expires. BACEN rule CMT-APR-SOLI-016
	// requires it to be less than 30 days in the future.
	ExpiraEm       time.Time
	IdempotencyKey string
}

// SolicRecResult is the bank's representation of a recurrence-activation request.
type SolicRecResult struct {
	IDSolicRec   string
	IDRec        string
	Status       string
	Destinatario SolicRecDestinatario
	ExpiraEm     time.Time
}

// SolicRecProvider is the output port for recurrence-activation requests (solicrec).
type SolicRecProvider interface {
	CreateSolicRec(ctx context.Context, tenantID string, req CreateSolicRecRequest) (SolicRecResult, error)
	// GetSolicRec reconciles the authoritative activation-request state (JWS-verified).
	GetSolicRec(ctx context.Context, tenantID, idSolicRec string) (SolicRecResult, error)
}

// TipoConta is the credited account type for a recurring charge.
type TipoConta string

const (
	ContaCorrente  TipoConta = "CORRENTE"
	ContaPoupanca  TipoConta = "POUPANCA"
	ContaPagamento TipoConta = "PAGAMENTO"
)

// CobRRecebedor is the credited account of a recurring charge instance.
type CobRRecebedor struct {
	Conta     string
	TipoConta TipoConta
}

// CreateCobRRequest is one scheduled charge instance against an APROVADA mandate.
// The devedor is inherited from the mandate's vínculo and is therefore not carried
// here (the wire sends an empty object).
type CreateCobRRequest struct {
	IDRec string
	// TxID is the anti-double-bill anchor: the charge is addressed by it and a
	// retried create with the same TxID targets the same instance. Required.
	TxID string
	// DataVencimento is the due date (yyyy-MM-dd).
	DataVencimento string
	AjusteDiaUtil  bool
	// ValorCents is the charge amount in centavos (decimal on the wire, brlDecimal).
	ValorCents     int64
	Recebedor      CobRRecebedor
	IdempotencyKey string
}

// CobRResult is the bank's representation of a recurring charge instance.
type CobRResult struct {
	TxID       string
	IDRec      string
	Status     string
	ValorCents int64
}

// CobRProvider is the output port for recurring charge instances (cobr).
type CobRProvider interface {
	CreateCobR(ctx context.Context, tenantID string, req CreateCobRRequest) (CobRResult, error)
	// GetCobR reconciles the authoritative charge state from the bank (JWS-verified).
	GetCobR(ctx context.Context, tenantID, txID string) (CobRResult, error)
	// ReviseCobR updates a not-yet-settled charge instance (PUT /cobr/{txid}).
	ReviseCobR(ctx context.Context, tenantID string, req CreateCobRRequest) (CobRResult, error)
	// RetryCobR schedules a retry of a failed charge per the mandate's política de
	// retentativa, on the given date (yyyy-MM-dd).
	RetryCobR(ctx context.Context, tenantID, txID, dataRetentativa string) (CobRResult, error)
}

// RecurrenceWebhookRegistrar is the output port for registering and reading the
// PSP-side recurrence notification callbacks (PIX Automático, SIN-66036). Unlike
// the immediate-PIX webhook (keyed per chave do recebedor, PixWebhookRegistrar),
// the recurrence callbacks are SINGLETONS per recebedor: BACEN exposes them at
// PUT|GET|DELETE /webhookrec (mandate-status callback) and /webhookcobr (recurring
// charge callback) with NO path key, so a tenant has exactly one of each. The URL
// crosses as a single {"webhookUrl": "https://…"} body; HTTPS is mandatory (a
// plaintext callback would leak the secret per-tenant ref the URL embeds). Both
// register operations are idempotent (a re-PUT replaces the registered URL).
type RecurrenceWebhookRegistrar interface {
	// RegisterRecWebhook idempotently registers (PUTs /webhookrec) the HTTPS
	// webhookURL the PSP notifies on every mandate (Rec) status transition for the
	// tenant. A non-HTTPS url or empty tenant is refused at the boundary.
	RegisterRecWebhook(ctx context.Context, tenantID, webhookURL string) error
	// GetRecWebhook reads back the registered Rec callback (GET /webhookrec) so a
	// caller can confirm the registration idempotently.
	GetRecWebhook(ctx context.Context, tenantID string) (WebhookRegistration, error)
	// RegisterCobRWebhook idempotently registers (PUTs /webhookcobr) the HTTPS
	// webhookURL the PSP notifies on every recurring charge (CobR) event.
	RegisterCobRWebhook(ctx context.Context, tenantID, webhookURL string) error
	// GetCobRWebhook reads back the registered CobR callback (GET /webhookcobr).
	GetCobRWebhook(ctx context.Context, tenantID string) (WebhookRegistration, error)
}

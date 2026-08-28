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
// never trust a raw webhook (threat W3). They are plain application/json, and their
// authenticity comes from the CHANNEL: OAuth2 client_credentials over the per-tenant
// mTLS, exactly as for cob/cobv/boleto/checkout.
//
// There is deliberately NO signature check on this path, and that is a correction, not
// an omission. An earlier design had the adapter demand `Accept: application/jose` and
// verify a JWS against a C6 JWKS; probed against the sandbox on 28/08/2026 C6 answers
// that header with 400 — it serves only application/json — so every recurrence read was
// failing and no JWKS value could have helped. The Pix Automático JWS is real but it is
// someone else's document: it lives on GET /rec/{recUrlAccessToken}, a public endpoint
// on another host, fetched and validated by the PAYER's PSP when it reads the QR. We are
// the recebedor and never request it. Residual, stated plainly: there is no cryptographic
// non-repudiation of the mandate document on our side. See SIN-66034 and
// docs/ops/c6-recurrence-jws-obsoleto.md.
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
	// LocID is the payload location (locrec) the composite QR renders the mandate
	// parameters from. Zero means "no location" — legal for the solicrec journey
	// (Jornada 1), which has no QR at all; required for the QR journeys 2/3/4.
	LocID int64
	// JornadaTxID is the txid of the ALREADY-CREATED immediate charge the composite
	// QR settles alongside the authorization (ativacao.dadosJornada.txid). BACEN makes
	// it mandatory for Jornada 3 and forbids it on 1/2/4, so it is sent only when set.
	JornadaTxID string
	// ValorRecCents is the fixed amount every cycle debits, in centavos (valor.valorRec
	// on the wire, rendered as the BACEN decimal string). Zero = variable-value mandate,
	// whose amount is decided per cycle. A non-zero value is the ceiling the payer
	// authorized: recurrence.RequireWithinAuthorizedValue caps every CobR at it.
	ValorRecCents int64
	// IdempotencyKey collapses retried/concurrent registrations into one mandate.
	IdempotencyKey string
}

// RecDadosQR is the composite QR (QR composto) the bank renders for a mandate. It is
// populated only on a read that carries every parameter the QR needs — see
// RecProvider.GetRecForQR. Jornada names which QR was composed: JORNADA_2 (mandate
// only), JORNADA_3 (mandate + immediate charge) or JORNADA_4 (mandate + due charge).
type RecDadosQR struct {
	Jornada       string
	PixCopiaECola string
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
	// LocID / Location are the payload location bound to the mandate (zero/empty when
	// none is bound). Location is the URL the payer's PSP reads the parameters from.
	LocID    int64
	Location string
	// ValorRecCents is the fixed authorized amount in centavos (0 = variable-value).
	ValorRecCents int64
	// DadosQR carries the composite QR when the read asked for one and the bank had
	// everything it needed to compose it. Zero value means "not composed".
	DadosQR RecDadosQR
}

// RecProvider is the output port for recurring-debit mandates (rec).
type RecProvider interface {
	// CreateRec registers a recurring-debit mandate. The mandate starts CRIADA and
	// must be APROVADA (out-of-band, via the payer's bank) before any CobR is
	// chargeable.
	CreateRec(ctx context.Context, tenantID string, req CreateRecRequest) (RecResult, error)
	// GetRec reconciles the authoritative mandate state from the bank.
	GetRec(ctx context.Context, tenantID, idRec string) (RecResult, error)
	// GetRecForQR reads the mandate asking the bank to compose the QR for a journey.
	// It is a separate method rather than a parameter on GetRec because the two have
	// different reasons to exist: GetRec is the reconcile-before-settle read the
	// webhook path depends on (never trust the body — threat W3), while this one is a
	// presentation read that produces the artifact the shop displays. A txID selects
	// the journey: the txid of an immediate charge composes JORNADA_3, the txid of a
	// due charge composes JORNADA_4, and an empty txID composes JORNADA_2.
	GetRecForQR(ctx context.Context, tenantID, idRec, txID string) (RecResult, error)
	// CancelRec revokes a mandate (PATCH status=CANCELADA) so no further debits can
	// be originated. Idempotent on idRec.
	CancelRec(ctx context.Context, tenantID, idRec string) (RecResult, error)
}

// LocRecResult is a payload location for recurrence (locrec): the URL the payer's
// PSP fetches the mandate parameters from when it reads a composite QR. The bank
// mints it; the recebedor then binds it to a mandate by passing the id on
// CreateRecRequest.LocID.
type LocRecResult struct {
	// ID is the bank-assigned location identifier (int64 on the wire, not a string).
	ID int64
	// Location is the URL embedded in the composite QR.
	Location string
	// Criacao is when the bank minted the location.
	Criacao time.Time
	// IDRec is the mandate currently bound to this location, empty when unbound.
	IDRec string
}

// LocRecProvider is the output port for recurrence payload locations (locrec). It is
// its own port rather than a method on RecProvider because a deployment can speak the
// mandate surface without the QR journeys (Jornada 1 needs no location at all), and
// the hexagonal seam should let that be a wiring decision.
type LocRecProvider interface {
	// CreateLocRec mints a payload location. The BACEN contract takes NO request body
	// — the location is minted from the authenticated recebedor's context alone — so
	// there is nothing to validate at this boundary beyond the tenant.
	CreateLocRec(ctx context.Context, tenantID, idempotencyKey string) (LocRecResult, error)
	// GetLocRec reads one location back, including the mandate bound to it.
	GetLocRec(ctx context.Context, tenantID string, id int64) (LocRecResult, error)
	// UnlinkLocRec detaches the mandate from a location (DELETE /locrec/{id}/idRec) so
	// the location can be rebound. Idempotent: unlinking an already-free location is a
	// no-op that returns the location.
	UnlinkLocRec(ctx context.Context, tenantID string, id int64) (LocRecResult, error)
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
	// GetSolicRec reconciles the authoritative activation-request state.
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
	// GetCobR reconciles the authoritative charge state from the bank.
	GetCobR(ctx context.Context, tenantID, txID string) (CobRResult, error)
	// CancelCobR cancels ONE scheduled charge instance (PATCH /cobr/{txid} with
	// status=CANCELADA) without touching the mandate: the payer's authorization stays
	// standing and later cycles still charge. It is the only amendment the BACEN
	// contract admits on a cobr — `status: CANCELADA` is the sole revisable field and
	// the sole allowed value, so there is no way to change an instalment's amount or
	// due date. To charge a different amount, cancel this instance and originate a new
	// one; that keeps every debit traceable to the instance that authorized it instead
	// of letting one txid quietly mean two different amounts.
	//
	// Idempotent on txid: cancelling an already-cancelled charge is the same effect.
	CancelCobR(ctx context.Context, tenantID, txID string) (CobRResult, error)
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

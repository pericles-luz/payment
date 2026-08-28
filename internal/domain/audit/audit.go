// Package audit holds the immutable, append-only audit trail of privileged
// admin-plane actions. An Entry captures who (the server-derived operator id),
// what (the action), the target tenant and when — it is the forensic/compliance
// record for cross-tenant privileged operations (credential writes, tenant
// provisioning, pricing changes, and future activation/suspension).
//
// An Entry NEVER carries a secret value or any credential material: it records
// only the fact that an action occurred and by whom (threat C1/C4). Pure domain:
// this package MUST NOT import database/sql, net/http or vendor SDKs.
package audit

import (
	"strings"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/account"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

// Action is the privileged operation an audit Entry records. Actions are a
// closed vocabulary so the trail stays queryable and tamper-evident.
type Action string

const (
	// ActionCreateTenant records provisioning of a new tenant.
	ActionCreateTenant Action = "tenant.create"
	// ActionSetEndpointPrice records an upsert of a tenant's endpoint pricing.
	ActionSetEndpointPrice Action = "pricing.set"
	// ActionSetBankCredential records a write of a tenant's bank (PSP) credential.
	// The audit entry names the tenant and operator only — never the secret.
	ActionSetBankCredential Action = "credential.set"
	// ActionSetCreditorKey records a write of a tenant's registered PIX creditor key
	// (chave do recebedor). It is a fund-routing change and so MUST be attributable
	// (OWASP A09); the entry names who/which-tenant/which-bank only — never the key
	// value (the key is routing-sensitive; threat C1/C4).
	ActionSetCreditorKey Action = "credential.creditor_key.set"
	// ActionSuspendTenant records suspension (soft-delete / deactivation) of a
	// tenant (ADR-0012 §4). It names the operator and the target tenant; no secret
	// is involved.
	ActionSuspendTenant Action = "tenant.suspend"
	// ActionActivateTenant records (re)activation of a suspended tenant (ADR-0012 §4).
	ActionActivateTenant Action = "tenant.activate"
	// ActionRenameTenant records an edit of a tenant's display name (ADR-0012 §1).
	// It records who/which-tenant/when only — never the old or new name value (a
	// name is not a secret, but the trail records the fact of the change, OWASP A09).
	ActionRenameTenant Action = "tenant.rename"
	// ActionRenameAccount records an edit of an Account's display name (ADR-0012 §1).
	// Account-scoped: the entry's AccountID names the target and its tenant_id is
	// empty (an account is not a tenant).
	ActionRenameAccount Action = "account.rename"
	// ActionSuspendAccount records suspension (soft-delete / deactivation) of an
	// Account (ADR-0012 §3). Account-scoped like ActionRenameAccount.
	ActionSuspendAccount Action = "account.suspend"
	// ActionActivateAccount records (re)activation of a suspended Account (ADR-0012 §3).
	ActionActivateAccount Action = "account.activate"
	// ActionRemoveBankConfig records the hard-delete of a tenant's per-bank
	// configuration — the credential AND certificate for a (tenant, bankID) pair
	// (ADR-0012 §5). It carries the non-secret bankID so the trail records WHICH
	// bank's configuration was removed; it NEVER records the deleted secret or key
	// material by construction (threat C1/C4).
	ActionRemoveBankConfig Action = "bank_config.remove"
	// ActionSettlementAmountMismatch records a money-movement divergence: a charge
	// the PSP marked paid whose received amount did not match the expected
	// (original) amount, so settlement was refused (reconcile-before-settle, threat
	// W3). Unlike the other actions this is a system-actor event (no human
	// operator) and carries the expected/received cents and the txid.
	ActionSettlementAmountMismatch Action = "settlement.amount_mismatch"

	// ActionRecCreated..ActionRecCancelled record the lifecycle transitions of a PIX
	// Automático recurring mandate (Rec, SIN-66037). They reuse the durable
	// audit_log mechanism (SIN-66016/66025) rather than a parallel trail: the action
	// names WHICH transition occurred and the entry's TxID() carries the subject
	// idRec (see NewRecurrenceTransitionEntry). Append-only ordering over a tenant's
	// entries reconstructs the full mandate history. No secret is involved — a Rec
	// transition records only who/what/which-mandate/tenant/when.
	ActionRecCreated   Action = "recurrence.created"
	ActionRecApproved  Action = "recurrence.approved"
	ActionRecRejected  Action = "recurrence.rejected"
	ActionRecExpired   Action = "recurrence.expired"
	ActionRecCancelled Action = "recurrence.cancelled"

	// ActionCobRCreated records the origination of one recurring charge instance
	// (CobR) against an approved mandate (PIX Automático F4, SIN-66039). Like the
	// Rec transitions it reuses the durable audit_log: the entry's TxID() carries
	// the charge txid (its anti-double-bill anchor) and, paired with the SaveCobR in
	// the same unit of work, makes the charge and its forensic record commit
	// atomically. No secret is involved — it records only who/what/which-charge/
	// tenant/when.
	ActionCobRCreated Action = "recurrence.cobr.created"

	// ActionCobRCancelled records the cancellation of ONE scheduled recurring charge
	// (PATCH /cobr/{txid} status=CANCELADA). It is deliberately distinct from
	// ActionRecCancelled: revoking the MANDATE stops every future debit, while this
	// stops a single instalment and leaves the authorization standing. Reading a trail
	// that conflated the two would make it impossible to answer "was this payer's
	// authorization revoked, or did we just skip one month?" — the exact question a
	// disputed debit turns on. The entry's TxID() carries the charge txid.
	ActionCobRCancelled Action = "recurrence.cobr.cancelled"

	// ActionSetBankCertificate records a write of a tenant's per-bank mTLS client
	// certificate (SIN-66087). Like ActionSetBankCredential it names the tenant, the
	// operator and the non-secret bankID; additionally it carries the certificate's
	// SHA-256 fingerprint (a PUBLIC identifier) in the tx_id column so the trail
	// records WHICH certificate was provisioned and distinguishes a cert rotation
	// from an OAuth secret write. It NEVER records the private key (threat C1/C4).
	ActionSetBankCertificate Action = "certificate.set"

	// ActionInvoiceGenerated records the generation of a Fatura (invoice) for a
	// tenant over a billing period (SIN-69121). It names the operator and the
	// tenant; the invoice is append-only billing evidence, so the trail records WHO
	// generated a statement for WHICH empresa-cliente and WHEN. It carries no
	// secret and no PII — an invoice is ids + endpoints + money only.
	ActionInvoiceGenerated Action = "invoice.generated"

	// ActionMintAccountKey records the emission (create==rotate) of an Account's
	// rotatable bearer key — the model (b) chave-de-Conta (ADR-0011 §3, SIN-69386).
	// Key emission is a privileged credential-issuance action, so it MUST leave an
	// attributable trail (OWASP A09): the entry names who (operator), which Conta
	// (accountID) and when. Account-scoped like the other account.* actions — the
	// target is an Account, so accountID is explicit and tenant_id is empty. It
	// NEVER records the minted secret by construction (the constructor has no secret
	// parameter; display-once, ADR-0010). A single entry covers BOTH write surfaces
	// (JSON admin bootstrap + HTML console) because it is emitted from the shared
	// mint path; an idempotent replay (409) mints nothing and so emits no entry.
	ActionMintAccountKey Action = "account.key_mint"

	// ActionSetOutboundWebhook / ActionRotateOutboundWebhookSecret /
	// ActionRemoveOutboundWebhook record the config lifecycle of a Conta's OUTBOUND
	// webhook endpoint (SIN-69490, F0 of SIN-69486). They are ACCOUNT-scoped (the
	// target is an Account, so accountID is explicit and tenant_id is empty, like the
	// other account.* actions) and record the mutation as a FACT only — never the
	// signing secret nor the URL by construction (the constructor has no such
	// parameter; threat C1/C4). set covers both create and update of the endpoint;
	// rotate_secret is the display-once secret rotation; remove is the hard-delete.
	ActionSetOutboundWebhook          Action = "account.webhook.set"
	ActionRotateOutboundWebhookSecret Action = "account.webhook.rotate_secret"
	ActionRemoveOutboundWebhook       Action = "account.webhook.remove"

	// ActionOutboundWebhookDelivered / ActionOutboundWebhookDeadLettered record the
	// per-attempt RESULT of forwarding a Conta's event to its outbound endpoint
	// (SIN-69492, F2 of SIN-69486; threat model SIN-69489 §3 R1 — non-repudiation). They
	// are account-scoped and name which Conta and which inbound event_key (as the subject
	// txID) the attempt concerned, plus its terminal outcome — delivered (2xx) or
	// dead-lettered (endpoint inactive / retries exhausted). Like every audit action they
	// record a FACT only: never the payload, never the signing secret, never the
	// destination response body (the constructor has no such parameter).
	ActionOutboundWebhookDelivered    Action = "account.webhook.delivered"
	ActionOutboundWebhookDeadLettered Action = "account.webhook.dead_letter"
)

// recurrenceActionByStatus maps a recurrence.RecStatus string to the audit Action
// that records reaching it. The keys are the (closed) status vocabulary the
// recurrence domain transitions through; they are kept as plain strings so the
// audit package stays decoupled from the recurrence domain (no import cycle, and
// audit owns its own action vocabulary). A status with no recordable transition
// (none today) is reported as not-ok.
var recurrenceActionByStatus = map[string]Action{
	"CRIADA":    ActionRecCreated,
	"APROVADA":  ActionRecApproved,
	"REJEITADA": ActionRecRejected,
	"EXPIRADA":  ActionRecExpired,
	"CANCELADA": ActionRecCancelled,
}

// valid reports whether a is a known action (deny-by-default: unknown actions
// are rejected so a typo can never produce an unclassifiable audit record).
func (a Action) valid() bool {
	switch a {
	case ActionCreateTenant, ActionSetEndpointPrice, ActionSetBankCredential,
		ActionSetCreditorKey, ActionSuspendTenant, ActionActivateTenant,
		ActionRenameTenant, ActionRenameAccount, ActionSuspendAccount,
		ActionActivateAccount, ActionRemoveBankConfig,
		ActionSettlementAmountMismatch, ActionRecCreated, ActionRecApproved,
		ActionRecRejected, ActionRecExpired, ActionRecCancelled, ActionCobRCreated,
		ActionCobRCancelled,
		ActionSetBankCertificate, ActionInvoiceGenerated, ActionMintAccountKey,
		ActionSetOutboundWebhook, ActionRotateOutboundWebhookSecret, ActionRemoveOutboundWebhook,
		ActionOutboundWebhookDelivered, ActionOutboundWebhookDeadLettered:
		return true
	default:
		return false
	}
}

// Entry is an immutable record of one privileged admin-plane or system action.
// Fields are unexported and exposed via accessors so an entry cannot be mutated
// after construction (append-only at the type level, mirroring
// billing.LedgerEntry).
//
// txID is the subject resource id: the charge txid for a money-movement event
// (ActionSettlementAmountMismatch) or the mandate idRec for a recurrence
// transition (ActionRec*). expectedCents/receivedCents are populated only for a
// settlement mismatch. bankID is populated only for a credential write
// (ActionSetBankCredential). They are zero-valued for the other actions. No field
// ever carries a secret — bankID is a non-secret routing slug (ADR-0007).
type Entry struct {
	id            string
	operatorID    string
	action        Action
	tenantID      string
	at            time.Time
	txID          string
	expectedCents int64
	receivedCents int64
	bankID        string
	// accountID is set ONLY for an account-scoped action (ActionRenameAccount /
	// ActionSuspendAccount / ActionActivateAccount, ADR-0012 §1/§3), where the
	// target is an Account and there is no tenant. When set it is the value AccountID()
	// returns; when empty (every tenant-scoped action) AccountID() derives from the
	// tenant, so existing constructors keep their prior meaning unchanged. It carries
	// NO secret — an account id is a public attribution id.
	accountID string
	// origin labels WHICH surface performed the action: OriginAdmin (an admin
	// operator on the admin plane / console) or OriginSelfServe (an empresa-cliente
	// rotating its own credential via the tenant-plane self-serve intake, SIN-69196).
	// It is a closed, non-secret label. The zero value ("") is read back as
	// OriginAdmin by Origin(), so every existing constructor keeps its prior meaning
	// without a code or test change (matches the DB DEFAULT 'admin' of migration 0010).
	origin string
}

const (
	// OriginAdmin marks an action performed by an admin operator (the admin JSON
	// plane or the HTML console). It is the default surface and the value the audit
	// column defaults to (migration 0010), so pre-existing entries and every code
	// path that does not opt into another origin read back as admin.
	OriginAdmin = "admin"
	// OriginSelfServe marks an action a tenant performed on itself through the
	// self-serve intake (SIN-69196): the credential.set on PUT /v1/bank-credential,
	// authenticated by the tenant's own token (never an admin operator). It lets the
	// forensic trail separate a tenant self-rotation from an admin-driven write.
	OriginSelfServe = "self-serve"
)

// NewEntry builds an audit entry, enforcing invariants: a non-empty id, a known
// action and a target tenant. The operator id is intentionally allowed to be
// empty: it denotes a non-attributed internal caller (the HTTP admin middleware
// always populates it server-side for real requests). NewEntry rejects any
// attempt to smuggle a secret by construction — it has no secret parameter.
func NewEntry(id, operatorID string, action Action, tenantID string, at time.Time) (Entry, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return Entry{}, shared.NewValidationError("id", "audit entry id is required")
	}
	if !action.valid() {
		return Entry{}, shared.NewValidationError("action", "unknown audit action")
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return Entry{}, shared.NewValidationError("tenant_id", "tenant id is required")
	}
	return Entry{
		id:         id,
		operatorID: strings.TrimSpace(operatorID),
		action:     action,
		tenantID:   tenantID,
		at:         at,
	}, nil
}

// accountActionValid reports whether action is one of the account-scoped
// lifecycle actions NewAccountActionEntry accepts (deny-by-default so a
// tenant-scoped or money-movement action can never be smuggled through the
// account constructor and land with an empty tenant_id).
func accountActionValid(action Action) bool {
	switch action {
	case ActionRenameAccount, ActionSuspendAccount, ActionActivateAccount:
		return true
	default:
		return false
	}
}

// NewAccountActionEntry builds an account-scoped audit record (rename / suspend /
// activate of an Account, ADR-0012 §1/§3). Unlike the tenant-scoped constructors
// the target is an Account, so it carries the account id explicitly (AccountID()
// returns it) and leaves the tenant id empty — an account is not a tenant. It
// NEVER records a name or any secret by construction (it has no such parameter).
// Invariants: a non-empty id, a known account action and a non-empty accountID.
func NewAccountActionEntry(id, operatorID string, action Action, accountID string, at time.Time) (Entry, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return Entry{}, shared.NewValidationError("id", "audit entry id is required")
	}
	if !accountActionValid(action) {
		return Entry{}, shared.NewValidationError("action", "unknown account audit action")
	}
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		return Entry{}, shared.NewValidationError("account_id", "account id is required")
	}
	return Entry{
		id:         id,
		operatorID: strings.TrimSpace(operatorID),
		action:     action,
		at:         at,
		accountID:  accountID,
	}, nil
}

// NewAccountKeyMintEntry builds the audit record for minting/rotating an Account's
// rotatable bearer key (ActionMintAccountKey, ADR-0011 §3 / SIN-69386). Account-key
// emission is a privileged credential-issuance action, so it MUST be attributable
// (OWASP A09): the entry names who (operatorID), which Conta (accountID) and when.
// Like the other account-scoped constructors the target is an Account, so it carries
// the account id explicitly (AccountID() returns it) and leaves the tenant id empty
// — an Account is not a tenant (ADR-0012 pattern). It records the mint as a FACT
// only and NEVER the minted secret by construction — it has no secret parameter
// (threat C1/C4; display-once, ADR-0010, so the plaintext leaves the mint service
// exactly once and never reaches the trail). It is emitted from the shared mint path
// so BOTH write surfaces (JSON admin bootstrap + HTML console) are covered
// uniformly. Invariants: a non-empty id and accountID; operatorID may be empty (a
// non-attributed internal caller).
func NewAccountKeyMintEntry(id, operatorID, accountID string, at time.Time) (Entry, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return Entry{}, shared.NewValidationError("id", "audit entry id is required")
	}
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		return Entry{}, shared.NewValidationError("account_id", "account id is required")
	}
	return Entry{
		id:         id,
		operatorID: strings.TrimSpace(operatorID),
		action:     ActionMintAccountKey,
		at:         at,
		accountID:  accountID,
	}, nil
}

// outboundWebhookActionValid reports whether action is one of the account-scoped
// outbound-webhook config actions NewOutboundWebhookEntry accepts (deny-by-default so
// a tenant-scoped or money-movement action can never be smuggled through the
// outbound-webhook constructor and land with an empty tenant_id).
func outboundWebhookActionValid(action Action) bool {
	switch action {
	case ActionSetOutboundWebhook, ActionRotateOutboundWebhookSecret, ActionRemoveOutboundWebhook:
		return true
	default:
		return false
	}
}

// NewOutboundWebhookEntry builds the audit record for a Conta's outbound-webhook
// config mutation (set / rotate_secret / remove; SIN-69490, F0 of SIN-69486).
// Configuring an outbound delivery endpoint and rotating its signing secret are
// privileged, security-relevant actions, so each MUST be attributable (OWASP A09):
// the entry names who (operatorID), which Conta (accountID) and when. Like the other
// account-scoped constructors the target is an Account, so it carries the account id
// explicitly (AccountID() returns it) and leaves the tenant id empty — an Account is
// not a tenant (ADR-0012 pattern). It records the mutation as a FACT only and NEVER
// the signing secret nor the URL by construction — it has no such parameter (threat
// C1/C4). Invariants: a non-empty id, a known outbound-webhook action and a non-empty
// accountID; operatorID may be empty (a non-attributed internal caller).
func NewOutboundWebhookEntry(id, operatorID string, action Action, accountID string, at time.Time) (Entry, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return Entry{}, shared.NewValidationError("id", "audit entry id is required")
	}
	if !outboundWebhookActionValid(action) {
		return Entry{}, shared.NewValidationError("action", "unknown outbound webhook audit action")
	}
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		return Entry{}, shared.NewValidationError("account_id", "account id is required")
	}
	return Entry{
		id:         id,
		operatorID: strings.TrimSpace(operatorID),
		action:     action,
		at:         at,
		accountID:  accountID,
	}, nil
}

// outboundDeliveryActionValid reports whether action is one of the F2 per-attempt
// delivery-result actions NewOutboundDeliveryEntry accepts (deny-by-default so a config
// action or a foreign action can never be smuggled through the delivery constructor).
func outboundDeliveryActionValid(action Action) bool {
	switch action {
	case ActionOutboundWebhookDelivered, ActionOutboundWebhookDeadLettered:
		return true
	default:
		return false
	}
}

// NewOutboundDeliveryEntry builds the per-attempt audit record for forwarding a Conta's
// event to its outbound endpoint (SIN-69492, F2 of SIN-69486; threat model SIN-69489 §3
// R1). It is account-scoped — the target is the owning Conta (accountID explicit,
// tenant_id empty, like the other account.* actions) — and carries the inbound event_key
// as the subject txID so the trail can be joined to the outbox/dead-letter and the
// inbound processed-events barrier. It records the FACT and its RESULT (delivered /
// dead-lettered) only, NEVER the payload, the signing secret or the destination's
// response, by construction (no such parameter — threat R1/I3). operatorID is the system
// actor (a forward has no human operator). Invariants: a non-empty id, a known delivery
// action and a non-empty accountID; eventKey may be empty (an event that carried none).
func NewOutboundDeliveryEntry(id, operatorID string, action Action, accountID, eventKey string, at time.Time) (Entry, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return Entry{}, shared.NewValidationError("id", "audit entry id is required")
	}
	if !outboundDeliveryActionValid(action) {
		return Entry{}, shared.NewValidationError("action", "unknown outbound delivery audit action")
	}
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		return Entry{}, shared.NewValidationError("account_id", "account id is required")
	}
	return Entry{
		id:         id,
		operatorID: strings.TrimSpace(operatorID),
		action:     action,
		at:         at,
		accountID:  accountID,
		txID:       strings.TrimSpace(eventKey),
	}, nil
}

// NewBankConfigRemovedEntry builds the audit record for the hard-delete of a
// tenant's per-bank configuration — the credential AND certificate for a
// (tenant, bankID) pair (ActionRemoveBankConfig, ADR-0012 §5). Like
// NewCredentialSetEntry it carries the non-secret bankID so the trail records
// WHICH bank's configuration was removed for the tenant; it NEVER records the
// deleted secret or private key by construction (it has no such parameter, threat
// C1/C4). Invariants: a non-empty id, tenant and bankID (the console normalises an
// empty selector to the default bank before calling).
func NewBankConfigRemovedEntry(id, operatorID, tenantID, bankID string, at time.Time) (Entry, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return Entry{}, shared.NewValidationError("id", "audit entry id is required")
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return Entry{}, shared.NewValidationError("tenant_id", "tenant id is required")
	}
	bankID = strings.TrimSpace(bankID)
	if bankID == "" {
		return Entry{}, shared.NewValidationError("bank_id", "bank id is required")
	}
	return Entry{
		id:         id,
		operatorID: strings.TrimSpace(operatorID),
		action:     ActionRemoveBankConfig,
		tenantID:   tenantID,
		at:         at,
		bankID:     bankID,
	}, nil
}

// NewCredentialSetEntry builds the audit record for a bank credential write
// (ActionSetBankCredential). Beyond who/what/tenant/when it carries the non-secret
// bankID, so the trail records WHICH bank's credential was (re)written for the
// tenant. It NEVER records the secret or the client id by construction — it has
// no such parameter (threat C1/C4). Invariants: a non-empty id, tenant and bankID;
// the admin service normalizes an empty selector to the default bank before
// calling, so a blank bankID here is a programming error.
func NewCredentialSetEntry(id, operatorID, tenantID, bankID string, at time.Time) (Entry, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return Entry{}, shared.NewValidationError("id", "audit entry id is required")
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return Entry{}, shared.NewValidationError("tenant_id", "tenant id is required")
	}
	bankID = strings.TrimSpace(bankID)
	if bankID == "" {
		return Entry{}, shared.NewValidationError("bank_id", "bank id is required")
	}
	return Entry{
		id:         id,
		operatorID: strings.TrimSpace(operatorID),
		action:     ActionSetBankCredential,
		tenantID:   tenantID,
		at:         at,
		bankID:     bankID,
	}, nil
}

// NewSelfServeCredentialSetEntry builds the audit record for a bank credential
// write a tenant performed on ITSELF through the self-serve intake (SIN-69196):
// the credential.set on PUT /v1/bank-credential, authenticated by the tenant's own
// token. It is identical to NewCredentialSetEntry — same ActionSetBankCredential,
// same invariants, same never-records-the-secret guarantee (it has no secret
// parameter, threat C1/C4) — EXCEPT it stamps OriginSelfServe, so the forensic
// trail distinguishes a tenant self-rotation from an admin-driven write. Keeping
// NewCredentialSetEntry untouched means the admin path (and its tests) are
// unchanged; only this new surface opts into the self-serve origin.
func NewSelfServeCredentialSetEntry(id, operatorID, tenantID, bankID string, at time.Time) (Entry, error) {
	e, err := NewCredentialSetEntry(id, operatorID, tenantID, bankID, at)
	if err != nil {
		return Entry{}, err
	}
	e.origin = OriginSelfServe
	return e, nil
}

// NewCreditorKeySetEntry builds the audit record for a PIX creditor-key write
// (ActionSetCreditorKey). It is the sibling of NewCredentialSetEntry: beyond
// who/what/tenant/when it carries the non-secret bankID so the trail records WHICH
// bank's creditor key the tenant pointed its funds at. It NEVER records the key
// value by construction — it has no such parameter (the key is routing-sensitive;
// threat C1/C4). Invariants: a non-empty id, tenant and bankID (the console
// resolves the default bank before calling, so a blank bankID is a programming
// error).
func NewCreditorKeySetEntry(id, operatorID, tenantID, bankID string, at time.Time) (Entry, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return Entry{}, shared.NewValidationError("id", "audit entry id is required")
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return Entry{}, shared.NewValidationError("tenant_id", "tenant id is required")
	}
	bankID = strings.TrimSpace(bankID)
	if bankID == "" {
		return Entry{}, shared.NewValidationError("bank_id", "bank id is required")
	}
	return Entry{
		id:         id,
		operatorID: strings.TrimSpace(operatorID),
		action:     ActionSetCreditorKey,
		tenantID:   tenantID,
		at:         at,
		bankID:     bankID,
	}, nil
}

// NewCertificateSetEntry builds the audit record for a per-bank mTLS certificate
// write (ActionSetBankCertificate, SIN-66087). Beyond who/what/tenant/when it
// carries the non-secret bankID and the certificate's SHA-256 fingerprint (a
// public identifier) in the tx_id column, so the trail records WHICH certificate
// was provisioned for the (tenant, bank) pair. It NEVER records the private key by
// construction — it has no such parameter (threat C1/C4). Invariants: a non-empty
// id, tenant, bankID and fingerprint; the admin service normalizes an empty
// selector to the default bank before calling, so a blank bankID is a programming
// error.
func NewCertificateSetEntry(id, operatorID, tenantID, bankID, fingerprint string, at time.Time) (Entry, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return Entry{}, shared.NewValidationError("id", "audit entry id is required")
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return Entry{}, shared.NewValidationError("tenant_id", "tenant id is required")
	}
	bankID = strings.TrimSpace(bankID)
	if bankID == "" {
		return Entry{}, shared.NewValidationError("bank_id", "bank id is required")
	}
	fingerprint = strings.TrimSpace(fingerprint)
	if fingerprint == "" {
		return Entry{}, shared.NewValidationError("fingerprint", "certificate fingerprint is required")
	}
	return Entry{
		id:         id,
		operatorID: strings.TrimSpace(operatorID),
		action:     ActionSetBankCertificate,
		tenantID:   tenantID,
		at:         at,
		txID:       fingerprint,
		bankID:     bankID,
	}, nil
}

// NewSelfServeCertificateSetEntry builds the audit record for a per-bank mTLS
// certificate write a tenant performed on ITSELF through the self-serve intake
// (SIN-69346): the certificate.set on PUT /v1/bank-certificate, authenticated by
// the tenant's own token. It is identical to NewCertificateSetEntry — same
// ActionSetBankCertificate, same invariants, the fingerprint (a public
// identifier) in tx_id, and the same never-records-the-private-key guarantee (it
// has no key parameter, threat C1/C4) — EXCEPT it stamps OriginSelfServe, so the
// forensic trail distinguishes a tenant self-provisioned certificate from an
// admin-driven write. Keeping NewCertificateSetEntry untouched means the admin
// path (and its tests) are unchanged; only this new surface opts into the
// self-serve origin, mirroring NewSelfServeCredentialSetEntry.
func NewSelfServeCertificateSetEntry(id, operatorID, tenantID, bankID, fingerprint string, at time.Time) (Entry, error) {
	e, err := NewCertificateSetEntry(id, operatorID, tenantID, bankID, fingerprint, at)
	if err != nil {
		return Entry{}, err
	}
	e.origin = OriginSelfServe
	return e, nil
}

// NewSettlementMismatchEntry builds the audit record for a refused settlement: a
// charge the PSP marked paid whose received amount did not match the expected
// amount (reconcile-before-settle, threat W3). It is a system-actor event — the
// operatorID is a reserved synthetic id (e.g. "system:c6-webhook"), since a PSP
// webhook has no human operator. It records who/what/tenant/when plus the txid
// and the expected/received cents so the divergence is durably queryable; it
// carries no secret by construction (it has no secret parameter).
//
// Invariants: a non-empty id, tenant and txid. The amounts are recorded verbatim
// (including a zero received) — the whole point is to capture what diverged.
func NewSettlementMismatchEntry(id, operatorID, tenantID, txID string, expectedCents, receivedCents int64, at time.Time) (Entry, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return Entry{}, shared.NewValidationError("id", "audit entry id is required")
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return Entry{}, shared.NewValidationError("tenant_id", "tenant id is required")
	}
	txID = strings.TrimSpace(txID)
	if txID == "" {
		return Entry{}, shared.NewValidationError("tx_id", "tx id is required")
	}
	return Entry{
		id:            id,
		operatorID:    strings.TrimSpace(operatorID),
		action:        ActionSettlementAmountMismatch,
		tenantID:      tenantID,
		at:            at,
		txID:          txID,
		expectedCents: expectedCents,
		receivedCents: receivedCents,
	}, nil
}

// NewRecurrenceTransitionEntry builds the audit record for a PIX Automático
// mandate (Rec) status transition (SIN-66037). toStatus is the recurrence status
// the mandate moved to (the closed CRIADA/APROVADA/REJEITADA/EXPIRADA/CANCELADA
// vocabulary, passed as a plain string so audit stays decoupled from the
// recurrence domain); it maps to the matching recurrence.* Action. The subject
// idRec is carried in the existing tx_id column — the audit_log row's "subject
// resource id" — so no schema change is needed (it reuses the durable mechanism
// from SIN-66016/66025 rather than introducing a parallel trail). It records only
// who/what/which-mandate/tenant/when and carries no secret by construction.
//
// Invariants: a non-empty id, tenant and idRec, plus a recognised toStatus. When
// emitted inside the unit of work that performed the transition, the audit append
// and the Rec save commit atomically (the bundled ports.Repository), closing the
// forensic-gap window.
func NewRecurrenceTransitionEntry(id, operatorID, tenantID, idRec, toStatus string, at time.Time) (Entry, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return Entry{}, shared.NewValidationError("id", "audit entry id is required")
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return Entry{}, shared.NewValidationError("tenant_id", "tenant id is required")
	}
	idRec = strings.TrimSpace(idRec)
	if idRec == "" {
		return Entry{}, shared.NewValidationError("id_rec", "id rec is required")
	}
	action, ok := recurrenceActionByStatus[strings.TrimSpace(toStatus)]
	if !ok {
		return Entry{}, shared.NewValidationError("status", "unknown recurrence transition status")
	}
	return Entry{
		id:         id,
		operatorID: strings.TrimSpace(operatorID),
		action:     action,
		tenantID:   tenantID,
		at:         at,
		txID:       idRec,
	}, nil
}

// NewCobROriginationEntry builds the audit record for originating one recurring
// charge instance (CobR) against an approved mandate (PIX Automático F4,
// SIN-66039). The subject txID is the charge's anti-double-bill anchor, carried in
// the existing tx_id column (no schema change — it reuses the durable mechanism
// from SIN-66016/66025). It records only who/what/which-charge/tenant/when and
// carries no secret by construction. Invariants: a non-empty id, tenant and txID.
// When emitted inside the unit of work that persisted the charge (the bundled
// ports.Repository), the audit append and the SaveCobR commit atomically.
func NewCobROriginationEntry(id, operatorID, tenantID, txID string, at time.Time) (Entry, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return Entry{}, shared.NewValidationError("id", "audit entry id is required")
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return Entry{}, shared.NewValidationError("tenant_id", "tenant id is required")
	}
	txID = strings.TrimSpace(txID)
	if txID == "" {
		return Entry{}, shared.NewValidationError("tx_id", "tx id is required")
	}
	return Entry{
		id:         id,
		operatorID: strings.TrimSpace(operatorID),
		action:     ActionCobRCreated,
		tenantID:   tenantID,
		at:         at,
		txID:       txID,
	}, nil
}

// NewCobRCancellationEntry builds the audit record for cancelling ONE scheduled
// recurring charge (PIX Automático, PATCH /cobr/{txid} status=CANCELADA). It mirrors
// NewCobROriginationEntry — same durable mechanism, same tx_id column carrying the
// charge txid — so origination and cancellation of the same instalment read as one
// ordered story in the trail. Invariants: a non-empty id, tenant and txID. Emitted
// inside the unit of work that persisted the transition, so the charge's new state and
// its forensic record commit atomically.
func NewCobRCancellationEntry(id, operatorID, tenantID, txID string, at time.Time) (Entry, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return Entry{}, shared.NewValidationError("id", "audit entry id is required")
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return Entry{}, shared.NewValidationError("tenant_id", "tenant id is required")
	}
	txID = strings.TrimSpace(txID)
	if txID == "" {
		return Entry{}, shared.NewValidationError("tx_id", "tx id is required")
	}
	return Entry{
		id:         id,
		operatorID: strings.TrimSpace(operatorID),
		action:     ActionCobRCancelled,
		tenantID:   tenantID,
		at:         at,
		txID:       txID,
	}, nil
}

// ID returns the audit entry identifier.
func (e Entry) ID() string { return e.id }

// OperatorID returns the server-derived id of the operator who performed the
// action, or "" for a non-attributed internal caller.
func (e Entry) OperatorID() string { return e.operatorID }

// Action returns the recorded privileged action.
func (e Entry) Action() Action { return e.action }

// TenantID returns the tenant the action targeted.
func (e Entry) TenantID() string { return e.tenantID }

// AccountID returns the owning API-user/reseller account of the audited entity —
// the forensic completeness of the account→tenant rollup (design §4, SIN-69127).
// For an ACCOUNT-scoped action (rename/suspend/activate of an Account, ADR-0012)
// the account is the target itself, carried in the explicit accountID field. For a
// TENANT-scoped action it is DERIVED from the tenant through the single source of
// truth (account.SelfAccountID), matching migration 0007/0009's backfill
// ('acct-'||tenant_id) and the F1 auth-side derivation exactly. When explicit
// (non-self) tenant→account bindings become stored the derivation branch will read
// the binding; until then deriving here can never diverge from the tenant's owner.
func (e Entry) AccountID() string {
	if e.accountID != "" {
		return e.accountID
	}
	return account.SelfAccountID(e.tenantID)
}

// At returns the time the action occurred.
func (e Entry) At() time.Time { return e.at }

// TxID returns the subject resource id: the charge txid for a money-movement
// event, the mandate idRec for a recurrence transition, or "" for an admin-plane
// action.
func (e Entry) TxID() string { return e.txID }

// ExpectedCents returns the expected (original) charge amount in cents for a
// money-movement event, or 0 for an admin-plane action.
func (e Entry) ExpectedCents() int64 { return e.expectedCents }

// ReceivedCents returns the received amount in cents for a money-movement event,
// or 0 for an admin-plane action.
func (e Entry) ReceivedCents() int64 { return e.receivedCents }

// BankID returns the non-secret bank slug for a credential.set event, or "" for
// any other action.
func (e Entry) BankID() string { return e.bankID }

// Origin returns the surface that performed the action: OriginSelfServe for a
// tenant self-rotation via the self-serve intake (SIN-69196), else OriginAdmin.
// The zero value ("") reads back as OriginAdmin, so every constructor that does
// not opt into another origin — i.e. all of them except
// NewSelfServeCredentialSetEntry — reports admin, matching the DB DEFAULT 'admin'
// of migration 0010 and preserving the prior admin-only semantics.
func (e Entry) Origin() string {
	if e.origin == "" {
		return OriginAdmin
	}
	return e.origin
}

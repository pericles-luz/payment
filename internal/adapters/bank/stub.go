// Package bank provides a stub BankProvider for the foundation. The real C6
// adapter (mTLS + OAuth2 client_credentials, webhook authenticity) is a later
// workstream and re-passes the threat model. This stub lets the wiring, use-cases
// and tests run end-to-end without an external dependency.
package bank

import (
	"context"
	"sync"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// StubProvider implements ports.BankProvider deterministically in-memory. It
// derives a txid from the payment id and tracks charge state so reconciliation
// (GetCharge) can be driven in tests.
type StubProvider struct {
	creds ports.CredentialStore
	// bankID is the slug this stub instance is bound to ("c6"), mirroring how the
	// real C6 adapter fixes its bank in its identity (ADR-0007 §3): every credential
	// lookup resolves the (tenant, "c6") pair, never carrying the bank on a business
	// request.
	bankID string
	// now is the clock for PIX QR-expiry computation. Defaults to time.Now;
	// overridable (SetClock) so tests can pin the immediate-charge window/listing.
	now func() time.Time

	mu         sync.Mutex
	charges    map[string]ports.ChargeResult   // keyed by tenantID+"\x00"+txID
	byIdem     map[string]ports.ChargeResult   // keyed by tenantID+"\x00"+idempotencyKey
	pixCharges map[string]stubPixCharge        // keyed by tenantID+"\x00"+txID (PIX cobrança imediata)
	pixByIdem  map[string]string               // keyed by tenantID+"\x00"+idempotencyKey -> txID
	boletos    map[string]ports.BoletoResult   // keyed by tenantID+"\x00"+boletoID (BolePix)
	checkouts  map[string]ports.CheckoutResult // keyed by tenantID+"\x00"+sessionID (unified checkout)
	// cobvCharges holds PIX cobrança-com-vencimento (cobv) charges keyed by
	// tenantID+"\x00"+txID; cobvDueByIdem maps the idempotency anchor to its txID so a
	// re-submit resolves to the same charge (roteiro 7.5–7.7).
	cobvCharges   map[string]ports.PixDueChargeResult
	cobvDueByIdem map[string]string // keyed by tenantID+"\x00"+anchor -> txID
	// ddaBoletos holds the boletos open in a tenant's DDA (roteiro 8.1), keyed by
	// tenantID. ddaGroups holds DDA payment groups keyed by tenantID+"\x00"+groupID;
	// ddaGroupByIdem maps the idempotency anchor to its groupID so a re-submitted
	// consult resolves to the same group (roteiro 8.2–8.6).
	ddaBoletos     map[string][]ports.DDABoleto
	ddaGroups      map[string]*stubDDAGroup
	ddaGroupByIdem map[string]string // keyed by tenantID+"\x00"+anchor -> groupID
	// stmtEntries holds the statement entries (extrato, roteiro 13.a) posted to a
	// tenant's account, keyed by tenantID. GetStatement filters them by the requested
	// date window.
	stmtEntries map[string][]ports.StatementEntry
	// PIX Automático (Recorrência) in-memory state (SIN-66035): recs keyed by
	// tenantID+"\x00"+idRec, solicRecs by tenantID+"\x00"+idSolicRec, cobrs by
	// tenantID+"\x00"+txid. Lets wiring and use-cases run end-to-end without C6.
	recs      map[string]ports.RecResult
	solicRecs map[string]ports.SolicRecResult
	cobrs     map[string]ports.CobRResult
	// recJornadaTxID remembers the immediate-charge txid a mandate was created against
	// (ativacao.dadosJornada.txid, Jornada 3), keyed like recs. The bank composes the
	// QR only when the mandate and the referenced charge agree on that txid, so the
	// stub keeps it to reproduce that rule instead of composing a QR for any txid.
	recJornadaTxID map[string]string
	// recWebhooks / cobrWebhooks hold the singleton recurrence callback URLs
	// registered per tenant (PIX Automático, SIN-66036), keyed by tenantID. Unlike
	// the immediate-PIX webhook (per chave), these are one-per-recebedor.
	recWebhooks  map[string]ports.WebhookRegistration
	cobrWebhooks map[string]ports.WebhookRegistration
	// locRecs holds the PIX Automático payload locations (locrec) minted per tenant,
	// keyed by tenantID+"\x00"+id. locRecSeq is the per-provider id counter: the real
	// C6 ids are int64s assigned by the bank, so the stub hands out 1, 2, 3… under the
	// same mutex, and locRecByIdem collapses a retried mint onto the location it
	// already produced (a retry must not leak a fresh location every attempt).
	locRecs      map[string]ports.LocRecResult
	locRecByIdem map[string]int64
	locRecSeq    int64
}

// stubPixCharge is the in-memory record for an immediate PIX charge: the port
// result plus the creation instant so ListImmediateCharges can filter by date.
type stubPixCharge struct {
	result    ports.PixChargeResult
	createdAt time.Time
}

// NewStubProvider builds a StubProvider. creds is used to demonstrate per-tenant
// credential isolation at charge time (the secret is never logged).
func NewStubProvider(creds ports.CredentialStore) *StubProvider {
	return &StubProvider{
		creds:          creds,
		bankID:         ports.BankIDC6,
		now:            time.Now,
		charges:        make(map[string]ports.ChargeResult),
		byIdem:         make(map[string]ports.ChargeResult),
		pixCharges:     make(map[string]stubPixCharge),
		pixByIdem:      make(map[string]string),
		boletos:        make(map[string]ports.BoletoResult),
		checkouts:      make(map[string]ports.CheckoutResult),
		cobvCharges:    make(map[string]ports.PixDueChargeResult),
		cobvDueByIdem:  make(map[string]string),
		ddaBoletos:     make(map[string][]ports.DDABoleto),
		ddaGroups:      make(map[string]*stubDDAGroup),
		ddaGroupByIdem: make(map[string]string),
		stmtEntries:    make(map[string][]ports.StatementEntry),
		recs:           make(map[string]ports.RecResult),
		recJornadaTxID: make(map[string]string),
		solicRecs:      make(map[string]ports.SolicRecResult),
		cobrs:          make(map[string]ports.CobRResult),
		recWebhooks:    make(map[string]ports.WebhookRegistration),
		cobrWebhooks:   make(map[string]ports.WebhookRegistration),
		locRecs:        make(map[string]ports.LocRecResult),
		locRecByIdem:   make(map[string]int64),
	}
}

// SetClock overrides the stub's clock (PIX QR expiry / list-window filtering) so a
// test can pin time deterministically. Passing nil restores time.Now.
func (s *StubProvider) SetClock(now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if now == nil {
		now = time.Now
	}
	s.now = now
}

func key(tenantID, txID string) string { return tenantID + "\x00" + txID }

// CreateCharge resolves the tenant's credential (proving isolation) and returns
// a pending charge with a deterministic txid derived from the payment id.
//
// It models PSP-side idempotency (F3b): when the request carries an idempotency
// key, a repeat call with the same (tenant, key) returns the original charge
// without creating a new one — even if the PaymentID differs. This is the
// defense-in-depth the real C6 adapter must inherit by forwarding the key to the
// bank, so a retry that races the local reservation cannot double-charge. The key
// is tenant-scoped, so one tenant's key can never collide with another's.
func (s *StubProvider) CreateCharge(ctx context.Context, tenantID string, req ports.ChargeRequest) (ports.ChargeResult, error) {
	if _, err := s.creds.GetBankCredential(ctx, tenantID, s.bankID); err != nil {
		return ports.ChargeResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if req.IdempotencyKey != "" {
		if prev, ok := s.byIdem[key(tenantID, req.IdempotencyKey)]; ok {
			return prev, nil // PSP dedupe: same key => same charge, no new effect
		}
	}
	txID := "tx_" + req.PaymentID
	// Record the expected amount so reconciliation (GetCharge) can prove the money
	// adds up, not only the status (threat W3). Received stays zero until the charge
	// settles (MarkSettled / MarkSettledWithReceived).
	res := ports.ChargeResult{TxID: txID, Status: "pending", ExpectedAmountCents: req.AmountCents}
	s.charges[key(tenantID, txID)] = res
	if req.IdempotencyKey != "" {
		s.byIdem[key(tenantID, req.IdempotencyKey)] = res
	}
	return res, nil
}

// GetCharge returns the authoritative state of a charge for reconciliation.
func (s *StubProvider) GetCharge(ctx context.Context, tenantID, txID string) (ports.ChargeResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, ok := s.charges[key(tenantID, txID)]
	if !ok {
		return ports.ChargeResult{}, shared.ErrNotFound
	}
	return res, nil
}

// ChargeCount returns the number of distinct charges held by the stub. Because a
// charge's txid is derived deterministically from the payment id, charging the
// same payment id more than once collapses to a single entry — so this counts
// distinct charges (test/dev hook for asserting no double-charge).
func (s *StubProvider) ChargeCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.charges)
}

// MarkSettled flips a charge to paid and reconciles the full expected amount
// (test/dev hook simulating the bank settling a correctly-paid charge): the
// received amount equals the expected amount, so AmountReconciled holds.
func (s *StubProvider) MarkSettled(tenantID, txID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if res, ok := s.charges[key(tenantID, txID)]; ok {
		res.Status = "paid"
		res.ReceivedAmountCents = res.ExpectedAmountCents
		s.charges[key(tenantID, txID)] = res
	}
}

// MarkSettledWithReceived flips a charge to paid with a specific received amount
// (test/dev hook simulating a divergent settlement: partial payment, an
// adjustable charge paid to a different value, or overpayment). When received !=
// expected, AmountReconciled is false and settlement must be refused.
func (s *StubProvider) MarkSettledWithReceived(tenantID, txID string, receivedCents int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if res, ok := s.charges[key(tenantID, txID)]; ok {
		res.Status = "paid"
		res.ReceivedAmountCents = receivedCents
		s.charges[key(tenantID, txID)] = res
	}
}

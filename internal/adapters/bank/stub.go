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
	// now is the clock for PIX QR-expiry computation. Defaults to time.Now;
	// overridable (SetClock) so tests can pin the immediate-charge window/listing.
	now func() time.Time

	mu         sync.Mutex
	charges    map[string]ports.ChargeResult  // keyed by tenantID+"\x00"+txID
	byIdem     map[string]ports.ChargeResult  // keyed by tenantID+"\x00"+idempotencyKey
	consents   map[string]ports.ConsentResult // keyed by tenantID+"\x00"+consentID (C6-C)
	pixCharges map[string]stubPixCharge       // keyed by tenantID+"\x00"+txID (PIX cobrança imediata)
	pixByIdem  map[string]string              // keyed by tenantID+"\x00"+idempotencyKey -> txID
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
		creds:      creds,
		now:        time.Now,
		charges:    make(map[string]ports.ChargeResult),
		byIdem:     make(map[string]ports.ChargeResult),
		consents:   make(map[string]ports.ConsentResult),
		pixCharges: make(map[string]stubPixCharge),
		pixByIdem:  make(map[string]string),
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
	if _, err := s.creds.GetBankCredential(ctx, tenantID); err != nil {
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

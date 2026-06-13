// Package bank provides a stub BankProvider for the foundation. The real C6
// adapter (mTLS + OAuth2 client_credentials, webhook authenticity) is a later
// workstream and re-passes the threat model. This stub lets the wiring, use-cases
// and tests run end-to-end without an external dependency.
package bank

import (
	"context"
	"sync"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// StubProvider implements ports.BankProvider deterministically in-memory. It
// derives a txid from the payment id and tracks charge state so reconciliation
// (GetCharge) can be driven in tests.
type StubProvider struct {
	creds ports.CredentialStore

	mu      sync.Mutex
	charges map[string]ports.ChargeResult // keyed by tenantID+"\x00"+txID
}

// NewStubProvider builds a StubProvider. creds is used to demonstrate per-tenant
// credential isolation at charge time (the secret is never logged).
func NewStubProvider(creds ports.CredentialStore) *StubProvider {
	return &StubProvider{creds: creds, charges: make(map[string]ports.ChargeResult)}
}

func key(tenantID, txID string) string { return tenantID + "\x00" + txID }

// CreateCharge resolves the tenant's credential (proving isolation) and returns
// a pending charge with a deterministic txid derived from the payment id.
func (s *StubProvider) CreateCharge(ctx context.Context, tenantID string, req ports.ChargeRequest) (ports.ChargeResult, error) {
	if _, err := s.creds.GetBankCredential(ctx, tenantID); err != nil {
		return ports.ChargeResult{}, err
	}
	txID := "tx_" + req.PaymentID
	res := ports.ChargeResult{TxID: txID, Status: "pending"}
	s.mu.Lock()
	s.charges[key(tenantID, txID)] = res
	s.mu.Unlock()
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

// MarkSettled flips a charge to paid (test/dev hook simulating the bank settling).
func (s *StubProvider) MarkSettled(tenantID, txID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if res, ok := s.charges[key(tenantID, txID)]; ok {
		res.Status = "paid"
		s.charges[key(tenantID, txID)] = res
	}
}

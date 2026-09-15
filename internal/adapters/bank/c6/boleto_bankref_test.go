package c6

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

// The settlement path knows a bank reference, not a local id, so this read must address the
// reference VERBATIM. Deriving from it — as GetBoleto does — would address a charge that
// was never registered.
func TestGetBoletoByBankRefUsesReferenceVerbatim(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	p := ps.provider(t, oneTenant("t1", "client-1", "secret-1"))

	const ref = "1Z5AE1TZJB92GBBHPQX3WT1CE2"
	res, err := p.GetBoletoByBankRef(context.Background(), "t1", ref)
	if err != nil {
		t.Fatalf("GetBoletoByBankRef: %v", err)
	}
	if want := "/v2/bank_slips/" + ref; ps.path() != want {
		t.Fatalf("path = %q, want %q — the reference must not be re-derived", ps.path(), want)
	}
	// This reference IS one of ours, so the bijection recovers the local boleto id for
	// free — no lookup table needed.
	if res.BoletoID != "3f2a9c1d7e4b48a0b5c6d7e8f9a0b1c2" {
		t.Fatalf("local id should be recovered from the reference, got %q", res.BoletoID)
	}
}

// A reference that does not match the contract's shape is refused locally, before a round
// trip the bank would reject anyway.
func TestGetBoletoByBankRefRejectsMalformed(t *testing.T) {
	t.Parallel()
	for _, ref := range []string{"", "short", "1z5ae1tzjb92gbbhpqx3wt1ce2", "1Z5AE1TZJB92GBBHPQX3WT1CE2X"} {
		ps := newProductServer(t)
		p := ps.provider(t, oneTenant("t1", "client-1", "secret-1"))

		_, err := p.GetBoletoByBankRef(context.Background(), "t1", ref)
		if !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("ref %q: want ErrValidation, got %v", ref, err)
		}
		if len(ps.body()) != 0 || ps.path() != "" {
			t.Fatalf("ref %q must not reach the bank", ref)
		}
	}
}

// An unknown reference is a not-found, so the settlement path can tell "this is not our
// charge" from "the bank is down".
func TestGetBoletoByBankRefNotFound(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	ps.boletoGet = func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) }
	p := ps.provider(t, oneTenant("t1", "client-1", "secret-1"))

	_, err := p.GetBoletoByBankRef(context.Background(), "t1", "1Z5AE1TZJB92GBBHPQX3WT1CE2")
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

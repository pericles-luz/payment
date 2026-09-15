package c6

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// Amendment DOES exist at the bank. The adapter used to refuse it outright, on the premise
// that the published contract had no such endpoint; the Bolepix contract (v1.1.0) has
// PATCH /v2/bank_slips/{external_reference_id}. What the earlier code actually got wrong
// was the verb and the path, not the existence of the operation.
func TestUpdateBoletoPatchesTheCharge(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	p := ps.provider(t, oneTenant("t1", "client-1", "secret-1"))

	amount := int64(7000)
	res, err := p.UpdateBoleto(context.Background(), "t1", "3f2a9c1d7e4b48a0b5c6d7e8f9a0b1c2",
		ports.BoletoPatch{AmountCents: &amount})
	if err != nil {
		t.Fatalf("UpdateBoleto: %v", err)
	}
	if res.BoletoID != "3f2a9c1d7e4b48a0b5c6d7e8f9a0b1c2" {
		t.Fatalf("BoletoID must stay the local id, got %q", res.BoletoID)
	}
	if res.TxID != "01HBANKSLIP0000000000000001" {
		t.Fatalf("the bank's id must map to TxID, got %q", res.TxID)
	}
	if res.AmountCents != 7000 {
		t.Fatalf("amended amount not mapped: %+v", res)
	}
}

// A partial amendment sends ONLY what changed. Sending a zero for an untouched field would
// ask the bank to make the charge free, or to drop a fine the payer already agreed to —
// and this contract's schema rejects zero-valued keys besides.
func TestUpdateBoletoOmitsUntouchedFields(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	p := ps.provider(t, oneTenant("t1", "client-1", "secret-1"))

	amount := int64(7000)
	if _, err := p.UpdateBoleto(context.Background(), "t1", "3f2a9c1d7e4b48a0b5c6d7e8f9a0b1c2",
		ports.BoletoPatch{AmountCents: &amount}); err != nil {
		t.Fatalf("UpdateBoleto: %v", err)
	}

	var sent map[string]json.RawMessage
	if err := json.Unmarshal(ps.body(), &sent); err != nil {
		t.Fatalf("decode body: %v (%s)", err, ps.body())
	}
	if _, ok := sent["amount"]; !ok {
		t.Fatalf("the amended field must be sent: %s", ps.body())
	}
	for _, absent := range []string{"due_date", "description", "fees", "days_after_due_date"} {
		if _, present := sent[absent]; present {
			t.Fatalf("%q must be omitted from a partial patch, got %s", absent, ps.body())
		}
	}
}

// An amendment that changes nothing is refused locally rather than sent as an empty body.
func TestUpdateBoletoRejectsEmptyPatch(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	p := ps.provider(t, oneTenant("t1", "client-1", "secret-1"))

	_, err := p.UpdateBoleto(context.Background(), "t1", "3f2a9c1d7e4b48a0b5c6d7e8f9a0b1c2", ports.BoletoPatch{})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation, got %v", err)
	}
	if len(ps.body()) != 0 {
		t.Fatalf("an empty patch must not reach the bank, sent %s", ps.body())
	}
}

// valid_until is expressed to the bank as a count of days AFTER the due date, so amending
// it without stating the due date has no anchor to count from. Refusing is better than
// silently counting from a due date we did not re-read.
func TestUpdateBoletoValidUntilRequiresDueDate(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	p := ps.provider(t, oneTenant("t1", "client-1", "secret-1"))

	vu := time.Date(2027, 2, 10, 0, 0, 0, 0, time.UTC)
	_, err := p.UpdateBoleto(context.Background(), "t1", "3f2a9c1d7e4b48a0b5c6d7e8f9a0b1c2",
		ports.BoletoPatch{ValidUntil: &vu})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation, got %v", err)
	}
	if len(ps.body()) != 0 {
		t.Fatalf("nothing must reach the bank, sent %s", ps.body())
	}

	// With both, it maps to days_after_due_date.
	due := time.Date(2027, 2, 1, 0, 0, 0, 0, time.UTC)
	if _, err := p.UpdateBoleto(context.Background(), "t1", "3f2a9c1d7e4b48a0b5c6d7e8f9a0b1c2",
		ports.BoletoPatch{DueDate: &due, ValidUntil: &vu}); err != nil {
		t.Fatalf("UpdateBoleto: %v", err)
	}
	var sent struct {
		DueDate          string `json:"due_date"`
		DaysAfterDueDate *int   `json:"days_after_due_date"`
	}
	if err := json.Unmarshal(ps.body(), &sent); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if sent.DueDate != "2027-02-01" {
		t.Fatalf("due_date must be yyyy-MM-dd, got %q", sent.DueDate)
	}
	if sent.DaysAfterDueDate == nil || *sent.DaysAfterDueDate != 9 {
		t.Fatalf("valid_until must become days_after_due_date=9, got %v", sent.DaysAfterDueDate)
	}
}

// The amendment goes to the reference-addressed path, with PATCH — not a speculative PUT
// on an id-addressed path the bank does not serve.
func TestUpdateBoletoUsesPatchOnReferencePath(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	p := ps.provider(t, oneTenant("t1", "client-1", "secret-1"))

	const id = "3f2a9c1d7e4b48a0b5c6d7e8f9a0b1c2"
	amount := int64(7000)
	if _, err := p.UpdateBoleto(context.Background(), "t1", id, ports.BoletoPatch{AmountCents: &amount}); err != nil {
		t.Fatalf("UpdateBoleto: %v", err)
	}
	wantPath := "/v2/bank_slips/" + externalReferenceID(id)
	if ps.path() != wantPath {
		t.Fatalf("path = %q, want %q", ps.path(), wantPath)
	}
	if ps.method() != "PATCH" {
		t.Fatalf("method = %q, want PATCH", ps.method())
	}
}

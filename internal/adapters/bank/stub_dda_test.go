package bank_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/bank"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

func newDDAStub(t *testing.T) *bank.StubProvider {
	t.Helper()
	creds := secret.NewStore(map[string]ports.BankCredential{
		"t1": {ClientID: "c", Secret: "s"},
		"t2": {ClientID: "c2", Secret: "s2"},
	})
	return bank.NewStubProvider(creds)
}

func ddaBC(seed byte) string { return strings.Repeat(string('0'+seed%10), 44) }

func ddaReq(key string, contents ...string) ports.DDAGroupRequest {
	payments := make([]ports.DDAPayment, len(contents))
	for i, c := range contents {
		payments[i] = ports.DDAPayment{Content: c, AmountCents: int64(i+1) * 100}
	}
	return ports.DDAGroupRequest{TenantID: "t1", Payments: payments, IdempotencyKey: key}
}

func TestStubDDAListOpenBoletos(t *testing.T) {
	t.Parallel()
	p := newDDAStub(t)
	ctx := context.Background()

	// Empty by default.
	got, err := p.ListOpenBoletos(ctx, "t1")
	if err != nil || len(got) != 0 {
		t.Fatalf("empty list: %v %v", got, err)
	}

	seed := []ports.DDABoleto{
		{Content: ddaBC(1), AmountCents: 1000, DueDate: time.Now(), BeneficiaryName: "Acme"},
		{Content: ddaBC(2), AmountCents: 2000, DueDate: time.Now(), BeneficiaryName: "Beta"},
	}
	p.SeedDDABoletos("t1", seed)
	got, err = p.ListOpenBoletos(ctx, "t1")
	if err != nil || len(got) != 2 {
		t.Fatalf("seeded list: %v %v", got, err)
	}
	// A returned slice mutation must not affect the stub's stored state.
	got[0].Content = "mutated"
	again, _ := p.ListOpenBoletos(ctx, "t1")
	if again[0].Content != ddaBC(1) {
		t.Fatal("ListOpenBoletos must return a defensive copy")
	}
	// Another tenant sees nothing.
	if other, _ := p.ListOpenBoletos(ctx, "t2"); len(other) != 0 {
		t.Fatalf("tenant isolation: t2 should see no boletos, got %d", len(other))
	}
}

func TestStubDDAListUnknownTenantCredential(t *testing.T) {
	t.Parallel()
	p := newDDAStub(t)
	if _, err := p.ListOpenBoletos(context.Background(), "nope"); err == nil {
		t.Fatal("missing credential must error (isolation)")
	}
}

func TestStubDDACreateAndGet(t *testing.T) {
	t.Parallel()
	p := newDDAStub(t)
	ctx := context.Background()

	g, err := p.CreatePaymentGroup(ctx, "t1", ddaReq("k1", ddaBC(1), ddaBC(2)))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Like the bank, the create answers with the id ALONE — a caller that skips the
	// read-back must break here too, not only against C6.
	if g.ID == "" || len(g.Items) != 0 {
		t.Fatalf("unexpected group: %+v", g)
	}

	// Get reconciles the group, and only then are there items.
	got, err := p.GetPaymentGroup(ctx, "t1", g.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ID != g.ID || len(got.Items) != 2 {
		t.Fatalf("get mismatch: %+v", got)
	}
	for _, it := range got.Items {
		if it.ID == "" || it.AmountCents <= 0 || it.Status != "READ_DATA" || it.ProductType != "BOLETO" {
			t.Fatalf("malformed item: %+v", it)
		}
	}
}

func TestStubDDACreateIdempotent(t *testing.T) {
	t.Parallel()
	p := newDDAStub(t)
	ctx := context.Background()

	g1, err := p.CreatePaymentGroup(ctx, "t1", ddaReq("same", ddaBC(1)))
	if err != nil {
		t.Fatalf("create 1: %v", err)
	}
	g2, err := p.CreatePaymentGroup(ctx, "t1", ddaReq("same", ddaBC(1)))
	if err != nil {
		t.Fatalf("create 2: %v", err)
	}
	if g1.ID != g2.ID {
		t.Fatalf("idempotent re-submit must resolve to the same group: %s vs %s", g1.ID, g2.ID)
	}
}

func TestStubDDACreateValidation(t *testing.T) {
	t.Parallel()
	p := newDDAStub(t)
	ctx := context.Background()
	if _, err := p.CreatePaymentGroup(ctx, "t1", ddaReq("", ddaBC(1))); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty anchor: want validation, got %v", err)
	}
	if _, err := p.CreatePaymentGroup(ctx, "t1", ddaReq("k")); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty payments: want validation, got %v", err)
	}
	zero := ports.DDAGroupRequest{
		TenantID: "t1", IdempotencyKey: "k",
		Payments: []ports.DDAPayment{{Content: ddaBC(1)}},
	}
	if _, err := p.CreatePaymentGroup(ctx, "t1", zero); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("zero amount: want validation, got %v", err)
	}
}

func TestStubDDAGetCrossTenantNotFound(t *testing.T) {
	t.Parallel()
	p := newDDAStub(t)
	ctx := context.Background()
	g, err := p.CreatePaymentGroup(ctx, "t1", ddaReq("k1", ddaBC(1)))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// t2 cannot see t1's group — no cross-tenant existence oracle.
	if _, err := p.GetPaymentGroup(ctx, "t2", g.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant get: want not-found, got %v", err)
	}
	if _, err := p.GetPaymentGroup(ctx, "t1", "ddag_missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("unknown group: want not-found, got %v", err)
	}
}

func TestStubDDARemoveItems(t *testing.T) {
	t.Parallel()
	p := newDDAStub(t)
	ctx := context.Background()
	g, err := p.CreatePaymentGroup(ctx, "t1", ddaReq("k1", ddaBC(1), ddaBC(2), ddaBC(3)))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	seeded, _ := p.GetPaymentGroup(ctx, "t1", g.ID)
	rm := []string{seeded.Items[0].ID, seeded.Items[2].ID}
	if err := p.RemovePaymentGroupItems(ctx, "t1", g.ID, rm); err != nil {
		t.Fatalf("remove list: %v", err)
	}
	got, _ := p.GetPaymentGroup(ctx, "t1", g.ID)
	if len(got.Items) != 1 || got.Items[0].ID != seeded.Items[1].ID {
		t.Fatalf("after list removal want 1 item left, got %+v", got.Items)
	}
	// Remove the single remaining item (AP_05).
	if err := p.RemovePaymentGroupItem(ctx, "t1", g.ID, got.Items[0].ID); err != nil {
		t.Fatalf("remove single: %v", err)
	}
	got, _ = p.GetPaymentGroup(ctx, "t1", g.ID)
	if len(got.Items) != 0 {
		t.Fatalf("after single removal want 0 items, got %+v", got.Items)
	}
}

func TestStubDDARemoveUnknownGroupNotFound(t *testing.T) {
	t.Parallel()
	p := newDDAStub(t)
	ctx := context.Background()
	if err := p.RemovePaymentGroupItems(ctx, "t1", "missing", []string{"x"}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("remove list unknown group: want not-found, got %v", err)
	}
	if err := p.RemovePaymentGroupItem(ctx, "t1", "missing", "x"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("remove single unknown group: want not-found, got %v", err)
	}
}

func TestStubDDASubmit(t *testing.T) {
	t.Parallel()
	p := newDDAStub(t)
	ctx := context.Background()
	g, err := p.CreatePaymentGroup(ctx, "t1", ddaReq("k1", ddaBC(1)))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := p.SubmitPaymentGroup(ctx, "t1", g.ID, "Zé da Silva", "idem-1"); err != nil {
		t.Fatalf("submit: %v", err)
	}
	// There is no group status: a submitted group is one whose ITEMS moved on.
	got, _ := p.GetPaymentGroup(ctx, "t1", g.ID)
	for _, it := range got.Items {
		if it.Status != "SCHEDULED" {
			t.Fatalf("want SCHEDULED after submit, got %q", it.Status)
		}
	}
	// Idempotent: re-submitting an already-submitted group succeeds.
	if err := p.SubmitPaymentGroup(ctx, "t1", g.ID, "Zé da Silva", "idem-1"); err != nil {
		t.Fatalf("re-submit: %v", err)
	}
	// uploader_name is required by the contract.
	if err := p.SubmitPaymentGroup(ctx, "t1", g.ID, " ", "idem-1"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty uploader: want validation, got %v", err)
	}
	// Unknown group → not found.
	if err := p.SubmitPaymentGroup(ctx, "t1", "missing", "Zé", "idem-2"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("submit unknown: want not-found, got %v", err)
	}
}

package app_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// newDDAHarness wires a DDAService with the stub as the DDA provider plus a seeded,
// credentialed tenant. DDA is not a billable surface, so no pricing is required.
func newDDAHarness(t *testing.T) (*app.DDAService, *harness, string) {
	t.Helper()
	h := newHarness(t)
	h.deps.DDA = h.bank
	admin := app.NewAdminService(h.deps)
	tn, err := admin.CreateTenant(context.Background(), "Acme")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	h.deps.Credentials.(*secret.Store).Set(tn.ID(), ports.BankCredential{ClientID: "cid", Secret: "shh"})
	return app.NewDDAService(h.deps), h, tn.ID()
}

func ddaBarcode(seed byte) string { return strings.Repeat(string('0'+seed%10), 44) }

func ddaCreateInput(tenantID, key string, contents ...string) app.CreateGroupInput {
	payments := make([]ports.DDAPayment, len(contents))
	for i, c := range contents {
		payments[i] = ports.DDAPayment{Content: c, AmountCents: int64(i+1) * 100}
	}
	return app.CreateGroupInput{TenantID: tenantID, Payments: payments, IdempotencyKey: key}
}

// ddaItemIDs reads a group's item ids back from the provider. The create answers with
// the id alone — like the bank — so nothing else knows them.
func ddaItemIDs(t *testing.T, svc *app.DDAService, tenantID, groupID string) []string {
	t.Helper()
	items, err := svc.GetPaymentGroupItems(context.Background(), tenantID, groupID)
	if err != nil {
		t.Fatalf("GetPaymentGroupItems: %v", err)
	}
	ids := make([]string, len(items))
	for i, it := range items {
		ids[i] = it.ID
	}
	return ids
}

func TestDDAListOpenBoletos(t *testing.T) {
	t.Parallel()
	svc, h, tenantID := newDDAHarness(t)
	h.bank.SeedDDABoletos(tenantID, []ports.DDABoleto{
		{Content: ddaBarcode(1), AmountCents: 1000, DueDate: time.Now().Add(48 * time.Hour), BeneficiaryName: "Acme"},
	})
	got, err := svc.ListOpenBoletos(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("ListOpenBoletos: %v", err)
	}
	if len(got) != 1 || got[0].Content != ddaBarcode(1) {
		t.Fatalf("unexpected boletos: %+v", got)
	}
	// Unknown tenant → error (resolve tenant fails).
	if _, err := svc.ListOpenBoletos(context.Background(), "missing"); err == nil {
		t.Fatal("unknown tenant must error")
	}
}

func TestDDACreatePaymentGroup(t *testing.T) {
	t.Parallel()
	svc, _, tenantID := newDDAHarness(t)

	g, err := svc.CreatePaymentGroup(context.Background(), ddaCreateInput(tenantID, "k1", ddaBarcode(1), ddaBarcode(2)))
	if err != nil {
		t.Fatalf("CreatePaymentGroup: %v", err)
	}
	// The create answers with the id alone: no items, no status.
	if g.ID == "" || len(g.Items) != 0 {
		t.Fatalf("unexpected group: %+v", g)
	}

	// A PIX key is a legitimate payment reference — the API schedules "boletos e
	// pixes" — and the old barcode-only validation refused every one of them.
	if _, err := svc.CreatePaymentGroup(context.Background(), ddaCreateInput(tenantID, "kpix", "pericles@example.com")); err != nil {
		t.Fatalf("PIX key must be accepted as content: %v", err)
	}

	tooLong := app.CreateGroupInput{
		TenantID: tenantID, IdempotencyKey: "k",
		Payments: []ports.DDAPayment{{Content: ddaBarcode(1), AmountCents: 100, Description: strings.Repeat("x", 101)}},
	}
	bad := []struct {
		name string
		in   app.CreateGroupInput
	}{
		{"empty_idem", ddaCreateInput(tenantID, "", ddaBarcode(1))},
		{"empty_payments", ddaCreateInput(tenantID, "k")},
		{"invalid_content", ddaCreateInput(tenantID, "k", "not-a-barcode")},
		{"zero_amount", app.CreateGroupInput{TenantID: tenantID, IdempotencyKey: "k", Payments: []ports.DDAPayment{{Content: ddaBarcode(1)}}}},
		{"description_too_long", tooLong},
	}
	for _, tc := range bad {
		if _, err := svc.CreatePaymentGroup(context.Background(), tc.in); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("%s: want validation, got %v", tc.name, err)
		}
	}

	// Too many payments → validation.
	many := make([]string, 201)
	for i := range many {
		many[i] = ddaBarcode(byte(i))
	}
	if _, err := svc.CreatePaymentGroup(context.Background(), ddaCreateInput(tenantID, "k", many...)); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("too many payments: want validation, got %v", err)
	}
}

func TestDDAGetPaymentGroupItems(t *testing.T) {
	t.Parallel()
	svc, _, tenantID := newDDAHarness(t)
	g, err := svc.CreatePaymentGroup(context.Background(), ddaCreateInput(tenantID, "k1", ddaBarcode(1), ddaBarcode(2)))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	items, err := svc.GetPaymentGroupItems(context.Background(), tenantID, g.ID)
	if err != nil {
		t.Fatalf("GetPaymentGroupItems: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("want 2 items, got %d", len(items))
	}
	if _, err := svc.GetPaymentGroupItems(context.Background(), tenantID, "  "); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty id: want validation, got %v", err)
	}
	if _, err := svc.GetPaymentGroupItems(context.Background(), tenantID, "missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("unknown group: want not-found, got %v", err)
	}
}

func TestDDARemovePaymentGroupItems(t *testing.T) {
	t.Parallel()
	svc, _, tenantID := newDDAHarness(t)
	g, err := svc.CreatePaymentGroup(context.Background(), ddaCreateInput(tenantID, "k1", ddaBarcode(1), ddaBarcode(2), ddaBarcode(3)))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	all := ddaItemIDs(t, svc, tenantID, g.ID)
	ids := []string{all[0], all[1]}
	if err := svc.RemovePaymentGroupItems(context.Background(), tenantID, g.ID, ids); err != nil {
		t.Fatalf("RemovePaymentGroupItems: %v", err)
	}
	left, _ := svc.GetPaymentGroupItems(context.Background(), tenantID, g.ID)
	if len(left) != 1 {
		t.Fatalf("want 1 item left, got %d", len(left))
	}
	// Empty list → validation.
	if err := svc.RemovePaymentGroupItems(context.Background(), tenantID, g.ID, nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty list: want validation, got %v", err)
	}
	// Unknown group → not found.
	if err := svc.RemovePaymentGroupItems(context.Background(), tenantID, "missing", []string{"x"}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("unknown group: want not-found, got %v", err)
	}
}

func TestDDARemovePaymentGroupItem(t *testing.T) {
	t.Parallel()
	svc, _, tenantID := newDDAHarness(t)
	g, err := svc.CreatePaymentGroup(context.Background(), ddaCreateInput(tenantID, "k1", ddaBarcode(1), ddaBarcode(2)))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := svc.RemovePaymentGroupItem(context.Background(), tenantID, g.ID, ddaItemIDs(t, svc, tenantID, g.ID)[0]); err != nil {
		t.Fatalf("RemovePaymentGroupItem: %v", err)
	}
	if err := svc.RemovePaymentGroupItem(context.Background(), tenantID, g.ID, "  "); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty item id: want validation, got %v", err)
	}
	// Removing an unknown item id is rejected by the domain as not-found.
	if err := svc.RemovePaymentGroupItem(context.Background(), tenantID, g.ID, "nope"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("unknown item: want not-found, got %v", err)
	}
}

func TestDDASubmitPaymentGroup(t *testing.T) {
	t.Parallel()
	svc, _, tenantID := newDDAHarness(t)
	g, err := svc.CreatePaymentGroup(context.Background(), ddaCreateInput(tenantID, "k1", ddaBarcode(1)))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	ids := ddaItemIDs(t, svc, tenantID, g.ID)
	// Missing idempotency key → validation, before any state read.
	if err := svc.SubmitPaymentGroup(context.Background(), tenantID, g.ID, "Zé", ""); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty idem: want validation, got %v", err)
	}
	// uploader_name is required by the contract, and checked before any state read.
	if err := svc.SubmitPaymentGroup(context.Background(), tenantID, g.ID, " ", "s1"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty uploader: want validation, got %v", err)
	}
	if err := svc.SubmitPaymentGroup(context.Background(), tenantID, g.ID, "Zé", "s1"); err != nil {
		t.Fatalf("submit: %v", err)
	}
	// Re-submitting an already-submitted group is an idempotent no-op (success).
	if err := svc.SubmitPaymentGroup(context.Background(), tenantID, g.ID, "Zé", "s1"); err != nil {
		t.Fatalf("idempotent re-submit: %v", err)
	}
	// Once submitted the group is frozen: trimming → invalid transition.
	if err := svc.RemovePaymentGroupItems(context.Background(), tenantID, g.ID, ids); !errors.Is(err, shared.ErrInvalidTransition) {
		t.Fatalf("trim after submit: want invalid-transition, got %v", err)
	}
	// Unknown group → not found.
	if err := svc.SubmitPaymentGroup(context.Background(), tenantID, "missing", "Zé", "s2"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("unknown group: want not-found, got %v", err)
	}
}

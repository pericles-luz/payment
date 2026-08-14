package bank

import (
	"context"
	"errors"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

const stubRecWebhookURL = "https://payment.lmhost.com.br/webhooks/c6/ref-123"

// Register then read back both singleton recurrence callbacks; a re-register
// replaces (idempotent) rather than erroring.
func TestStubRecurrenceWebhookLifecycle(t *testing.T) {
	t.Parallel()
	s := newStub(t)
	ctx := context.Background()

	if err := s.RegisterRecWebhook(ctx, "t1", stubRecWebhookURL); err != nil {
		t.Fatalf("RegisterRecWebhook: %v", err)
	}
	reg, err := s.GetRecWebhook(ctx, "t1")
	if err != nil || reg.WebhookURL != stubRecWebhookURL || reg.CreatedAt.IsZero() {
		t.Fatalf("GetRecWebhook: %+v / %v", reg, err)
	}
	// Idempotent replace.
	const updated = "https://payment.lmhost.com.br/webhooks/c6/ref-456"
	if err := s.RegisterRecWebhook(ctx, "t1", updated); err != nil {
		t.Fatalf("re-register: %v", err)
	}
	if reg, _ := s.GetRecWebhook(ctx, "t1"); reg.WebhookURL != updated {
		t.Fatalf("re-register did not replace: %s", reg.WebhookURL)
	}

	if err := s.RegisterCobRWebhook(ctx, "t1", stubRecWebhookURL); err != nil {
		t.Fatalf("RegisterCobRWebhook: %v", err)
	}
	if reg, err := s.GetCobRWebhook(ctx, "t1"); err != nil || reg.WebhookURL != stubRecWebhookURL {
		t.Fatalf("GetCobRWebhook: %+v / %v", reg, err)
	}
}

// A non-HTTPS callback and an empty tenant are refused; the streams are isolated
// (registering rec does not register cobr) and an unregistered read is NotFound.
func TestStubRecurrenceWebhookErrors(t *testing.T) {
	t.Parallel()
	s := newStub(t)
	ctx := context.Background()

	if err := s.RegisterRecWebhook(ctx, "t1", "http://nope"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("non-https rec: want validation, got %v", err)
	}
	if err := s.RegisterCobRWebhook(ctx, "t1", ""); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty url cobr: want validation, got %v", err)
	}
	// Unknown tenant has no credential → the credential lookup fails.
	if err := s.RegisterRecWebhook(ctx, "ghost", stubRecWebhookURL); err == nil {
		t.Fatal("unknown tenant should fail credential lookup")
	}
	// cobr unregistered while only rec is set → NotFound (streams isolated).
	if err := s.RegisterRecWebhook(ctx, "t1", stubRecWebhookURL); err != nil {
		t.Fatalf("register rec: %v", err)
	}
	if _, err := s.GetCobRWebhook(ctx, "t1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cobr should be unregistered: %v", err)
	}
}

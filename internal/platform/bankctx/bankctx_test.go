package bankctx_test

import (
	"context"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/platform/bankctx"
)

func TestWithBankIDRoundTrips(t *testing.T) {
	ctx := bankctx.WithBankID(context.Background(), "itau")
	if got := bankctx.FromContext(ctx); got != "itau" {
		t.Fatalf("want itau, got %q", got)
	}
}

func TestFromContextEmptyWhenAbsent(t *testing.T) {
	if got := bankctx.FromContext(context.Background()); got != "" {
		t.Fatalf("want empty for a bare context, got %q", got)
	}
}

func TestWithBankIDEmptyReportsEmpty(t *testing.T) {
	// An empty stamp must read back as "" so the router applies its default rather
	// than routing to a bank named "".
	ctx := bankctx.WithBankID(context.Background(), "")
	if got := bankctx.FromContext(ctx); got != "" {
		t.Fatalf("want empty, got %q", got)
	}
}

func TestWithBankIDOverwrites(t *testing.T) {
	ctx := bankctx.WithBankID(context.Background(), "c6")
	ctx = bankctx.WithBankID(ctx, "itau")
	if got := bankctx.FromContext(ctx); got != "itau" {
		t.Fatalf("want the most recent stamp itau, got %q", got)
	}
}

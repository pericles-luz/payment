// Package bankctx carries the resolved bank id (the multi-bank routing selector)
// on a request context. It is a tiny, dependency-free seam so the HTTP driving
// adapter can stamp the bank a request was routed to and the bank-router output
// adapter can read it back — without either importing the other and without
// widening any port method with a bankID parameter (the routing decision is made
// once, at the request boundary, and travels on the context; SIN-66022 / ADR-0007).
//
// The bank id stamped here is ALWAYS resolved server-side from the authenticated
// tenant's configured banks (see the HTTP bank selector) — never trusted raw from
// client input — so reading it back during dispatch cannot escalate beyond the
// tenant's own banks (confused-deputy defense, OWASP A01).
package bankctx

import "context"

// ctxKey is an unexported context key type so the bank-id value can never collide
// with another package's context entries.
type ctxKey int

const bankIDKey ctxKey = iota

// WithBankID returns a child context carrying the resolved bank id. An empty
// bankID is stored verbatim; FromContext then reports "" so the router applies its
// retro-compatible default (ports.BankIDC6).
func WithBankID(ctx context.Context, bankID string) context.Context {
	return context.WithValue(ctx, bankIDKey, bankID)
}

// FromContext returns the resolved bank id stamped by the request boundary, or ""
// when none is present (legacy/internal call paths, or a context that never passed
// through the selector). Callers treat "" as "apply the default bank".
func FromContext(ctx context.Context) string {
	if v, ok := ctx.Value(bankIDKey).(string); ok {
		return v
	}
	return ""
}

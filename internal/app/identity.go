package app

import "context"

// operatorIDKey is the unexported context key carrying the authenticated admin
// operator id. Using a private zero-size type avoids collisions with any other
// package's context values.
type operatorIDKey struct{}

// WithOperatorID returns a context carrying the server-derived operator id of an
// authenticated admin caller. The HTTP admin middleware sets it from the admin
// principal (never from client input); AdminService reads it to attribute audit
// entries. Keeping the key in the app layer lets the use-cases read the operator
// without importing the transport adapter (preserving the dependency direction).
func WithOperatorID(ctx context.Context, operatorID string) context.Context {
	return context.WithValue(ctx, operatorIDKey{}, operatorID)
}

// OperatorIDFromContext returns the operator id set by the transport, or "" when
// none is present (e.g. an internal caller or a non-admin path). An empty result
// is recorded as a non-attributed action rather than failing the operation.
func OperatorIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(operatorIDKey{}).(string); ok {
		return v
	}
	return ""
}

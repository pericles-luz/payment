// Package http is the driving adapter exposing the application over HTTP: the
// tenant API, the admin plane and the bank webhook. Security posture is
// deny-by-default: every route is behind authentication; the tenant is derived
// from the credential server-side and never from client input (threat H1).
package http

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"
)

type ctxKey int

const (
	ctxTenantID ctxKey = iota
	ctxRole
	ctxCSRFToken
)

// Role is an admin-plane authorization role. It is derived server-side from the
// authenticated credential — never from client input — and drives requireRole
// guards. The model is least-privilege: RoleOperator is read-only, RoleAdmin is
// full. Unknown/empty roles are denied (deny-by-default).
type Role string

const (
	// RoleAdmin has full admin-plane access (reads and writes).
	RoleAdmin Role = "admin"
	// RoleOperator is read-only: it may view admin resources but not mutate them.
	RoleOperator Role = "operator"
)

// TenantAuthenticator resolves an opaque API token to a tenant id. A failed
// lookup denies the request (threat H2).
type TenantAuthenticator interface {
	AuthenticateTenant(token string) (tenantID string, ok bool)
}

// AdminAuthenticator authenticates an admin token and resolves its role (admin
// plane, TB6). The role is derived server-side from the token; a failed lookup
// denies the request (deny-by-default).
type AdminAuthenticator interface {
	AuthenticateAdmin(token string) (role Role, ok bool)
}

// WebhookAuthenticator authenticates an inbound bank webhook. In production this
// is mTLS client-cert validation; the scaffold verifies a shared secret in
// constant time. Either way the posture is failure-closed (threat W1).
type WebhookAuthenticator interface {
	AuthenticateWebhook(secret string) bool
}

// StaticTokenAuth is a config-driven authenticator: opaque tokens map to tenant
// ids; admin tokens map to roles; a webhook secret. Tokens/secrets come from
// config, not code. Suitable for the foundation; replace with a real IdP/mTLS
// adapter later.
type StaticTokenAuth struct {
	tenantTokens  map[string]string // token -> tenantID
	adminRoles    map[string]Role   // admin token -> role
	webhookSecret string
}

// NewStaticTokenAuth builds a StaticTokenAuth where every admin token has the
// full RoleAdmin role. It is a thin wrapper over NewStaticTokenAuthWithRoles for
// the common single-role case.
func NewStaticTokenAuth(tenantTokens map[string]string, adminTokens []string, webhookSecret string) *StaticTokenAuth {
	roles := make(map[string]Role, len(adminTokens))
	for _, t := range adminTokens {
		roles[t] = RoleAdmin
	}
	return NewStaticTokenAuthWithRoles(tenantTokens, roles, webhookSecret)
}

// NewStaticTokenAuthWithRoles builds a StaticTokenAuth from explicit token→role
// assignments. Empty tokens and empty/unknown roles are dropped so a
// misconfigured entry can never silently grant access (deny-by-default).
func NewStaticTokenAuthWithRoles(tenantTokens map[string]string, adminRoles map[string]Role, webhookSecret string) *StaticTokenAuth {
	tt := make(map[string]string, len(tenantTokens))
	for k, v := range tenantTokens {
		tt[k] = v
	}
	ar := make(map[string]Role, len(adminRoles))
	for tok, role := range adminRoles {
		if tok == "" || !role.valid() {
			continue
		}
		ar[tok] = role
	}
	return &StaticTokenAuth{tenantTokens: tt, adminRoles: ar, webhookSecret: webhookSecret}
}

// valid reports whether r is a known role.
func (r Role) valid() bool {
	switch r {
	case RoleAdmin, RoleOperator:
		return true
	default:
		return false
	}
}

// AuthenticateTenant resolves a token to a tenant id.
func (a *StaticTokenAuth) AuthenticateTenant(token string) (string, bool) {
	if token == "" {
		return "", false
	}
	tenantID, ok := a.tenantTokens[token]
	return tenantID, ok
}

// AuthenticateAdmin resolves an admin token to its role. The comparison is
// constant-time (crypto/subtle) and scans every registered token without an
// early return, so timing does not reveal which token (if any) matched (mirrors
// the webhook secret check). An empty or unknown token is denied.
func (a *StaticTokenAuth) AuthenticateAdmin(token string) (Role, bool) {
	if token == "" {
		return "", false
	}
	tb := []byte(token)
	var matched Role
	var found int
	for tok, role := range a.adminRoles {
		if subtle.ConstantTimeCompare([]byte(tok), tb) == 1 {
			matched = role
			found = 1
		}
	}
	if found == 1 {
		return matched, true
	}
	return "", false
}

// AuthenticateWebhook compares the provided secret in constant time.
func (a *StaticTokenAuth) AuthenticateWebhook(secret string) bool {
	if a.webhookSecret == "" || secret == "" {
		return false // failure-closed: no secret configured => deny
	}
	return subtle.ConstantTimeCompare([]byte(secret), []byte(a.webhookSecret)) == 1
}

// bearerToken extracts the token from an "Authorization: Bearer <token>" header.
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	return ""
}

// tenantAuthMiddleware enforces tenant authentication and injects the tenant id.
func tenantAuthMiddleware(auth TenantAuthenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenantID, ok := auth.AuthenticateTenant(bearerToken(r))
			if !ok {
				writeError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			ctx := context.WithValue(r.Context(), ctxTenantID, tenantID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// adminAuthMiddleware enforces admin authentication and injects the resolved
// role into the request context for requireRole to consume. Deny-by-default: an
// unauthenticated request is rejected before any handler runs.
func adminAuthMiddleware(auth AdminAuthenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			role, ok := auth.AuthenticateAdmin(bearerToken(r))
			if !ok {
				writeError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			ctx := context.WithValue(r.Context(), ctxRole, role)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// requireRole is a reusable authorization guard: it admits the request only if
// the context role (set by adminAuthMiddleware) is in the allowed set. A missing
// role yields 401 (deny-by-default — the guard must sit behind authentication);
// an authenticated-but-insufficient role yields 403. It is consumed by the admin
// handlers here and by the admin-UI handlers in the child issue.
func requireRole(allowed ...Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			role, ok := roleFromContext(r.Context())
			if !ok {
				writeError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			for _, a := range allowed {
				if role == a {
					next.ServeHTTP(w, r)
					return
				}
			}
			writeError(w, http.StatusForbidden, "forbidden")
		})
	}
}

// tenantFromContext returns the authenticated tenant id, or "" if absent.
func tenantFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ctxTenantID).(string); ok {
		return v
	}
	return ""
}

// roleFromContext returns the admin role set by adminAuthMiddleware, or false if
// none is present (e.g. an unauthenticated request).
func roleFromContext(ctx context.Context) (Role, bool) {
	v, ok := ctx.Value(ctxRole).(Role)
	return v, ok
}

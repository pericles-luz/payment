// Package http is the driving adapter exposing the application over HTTP: the
// tenant API, the admin plane and the bank webhook. Security posture is
// deny-by-default: every route is behind authentication; the tenant is derived
// from the credential server-side and never from client input (threat H1).
package http

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/ia-dev-sindireceita/payment/internal/app"
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

// AdminPrincipal is the server-side identity of an authenticated admin caller:
// the authorization role plus a stable operator id used to attribute audit-trail
// entries. Both are derived from the token server-side — never from client input
// — so the "who" in the audit trail cannot be forged by the caller.
type AdminPrincipal struct {
	// OperatorID is a stable, non-reversible pseudonym for the admin token. It is
	// safe to record in the audit trail and logs (it never exposes the token).
	OperatorID string
	Role       Role
}

// AdminPrincipalAuthenticator authenticates an admin token and resolves its full
// principal (role + operator id). It is the identity source the admin middleware
// uses so privileged actions can be attributed in the audit trail.
type AdminPrincipalAuthenticator interface {
	AuthenticateAdminPrincipal(token string) (AdminPrincipal, bool)
}

// WebhookIdentity is the server-side identity that a valid per-tenant callback
// reference resolves to. TenantID is authoritative: it scopes the anti-replay
// namespace (processed_events) and the reconcile (GetCharge). ClientID is the
// tenant's C6 client_id, used ONLY to cross-check the untrusted webhook body
// (defense-in-depth, ADR-0002 item 3). Both are bound to the tenantRef at
// registration; the caller never supplies them.
type WebhookIdentity struct {
	TenantID string
	ClientID string
}

// WebhookAuthenticator resolves an inbound C6 webhook's opaque per-tenant callback
// reference (tenantRef, carried in the URL path) to the tenant it was minted for.
//
// The C6 webhook contract carries NO message authenticity — no HMAC, signature or
// key-id (notificações.yaml, anexo SIN-64704) — so the unguessable per-tenant URL
// itself IS the credential (capability URL): holding a valid tenantRef
// authenticates the channel and binds it to exactly one tenant (ADR-0002 / F4,
// SIN-64720). The body's client_id is never the source of truth for the tenant.
//
// Resolution is failure-closed and must not be an enumeration oracle: an unknown
// ref returns the same (zero, false) as a wrong one, so the handler answers a
// uniform 401 and the response never reveals whether a tenant exists for a ref.
type WebhookAuthenticator interface {
	AuthenticateWebhook(tenantRef string) (WebhookIdentity, bool)
}

// StaticTokenAuth is a config-driven authenticator: opaque tokens map to tenant
// ids; admin tokens map to roles; opaque per-tenant webhook refs map to a tenant
// identity. Tokens/secrets come from config, not code. Suitable for the
// foundation; replace with a real IdP adapter later.
type StaticTokenAuth struct {
	tenantTokens map[string]string          // token -> tenantID
	adminRoles   map[string]Role            // admin token -> role
	webhookRefs  map[string]WebhookIdentity // sha256(tenantRef) -> identity
}

// NewStaticTokenAuth builds a StaticTokenAuth where every admin token has the
// full RoleAdmin role. It is a thin wrapper over NewStaticTokenAuthWithRoles for
// the common single-role case.
func NewStaticTokenAuth(tenantTokens map[string]string, adminTokens []string, webhookRefs map[string]WebhookIdentity) *StaticTokenAuth {
	roles := make(map[string]Role, len(adminTokens))
	for _, t := range adminTokens {
		roles[t] = RoleAdmin
	}
	return NewStaticTokenAuthWithRoles(tenantTokens, roles, webhookRefs)
}

// NewStaticTokenAuthWithRoles builds a StaticTokenAuth from explicit token→role
// assignments. Empty tokens and empty/unknown roles are dropped so a
// misconfigured entry can never silently grant access (deny-by-default).
//
// Webhook refs are stored hashed (sha256), so the raw capability secret is not
// held in memory, and indexed by hash for O(1) lookup. A ref whose format is
// invalid (see validTenantRef) or whose tenant id is empty is dropped: a
// misconfigured ref disables that tenant's webhook (failure-closed) rather than
// registering a weak credential.
func NewStaticTokenAuthWithRoles(tenantTokens map[string]string, adminRoles map[string]Role, webhookRefs map[string]WebhookIdentity) *StaticTokenAuth {
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
	wr := make(map[string]WebhookIdentity, len(webhookRefs))
	for ref, id := range webhookRefs {
		if !validTenantRef(ref) || id.TenantID == "" {
			continue
		}
		wr[hashTenantRef(ref)] = id
	}
	return &StaticTokenAuth{tenantTokens: tt, adminRoles: ar, webhookRefs: wr}
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
	p, ok := a.AuthenticateAdminPrincipal(token)
	return p.Role, ok
}

// AuthenticateAdminPrincipal resolves an admin token to its full principal (role
// + operator id). Like AuthenticateAdmin it scans every registered token in
// constant time without early return so timing leaks nothing about which token
// matched. The operator id is derived from the matched token via a one-way hash
// (deriveOperatorID): it is stable per token and safe to record, and it never
// reveals the token itself. An empty or unknown token is denied.
func (a *StaticTokenAuth) AuthenticateAdminPrincipal(token string) (AdminPrincipal, bool) {
	if token == "" {
		return AdminPrincipal{}, false
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
		return AdminPrincipal{OperatorID: deriveOperatorID(token), Role: matched}, true
	}
	return AdminPrincipal{}, false
}

// deriveOperatorID maps an admin token to a stable, non-reversible operator id
// for audit attribution. It is a SHA-256 of the token, truncated and prefixed —
// recording it never exposes the underlying token while still uniquely (for
// audit purposes) identifying the operator.
func deriveOperatorID(token string) string {
	sum := sha256.Sum256([]byte(token))
	return "op-" + hex.EncodeToString(sum[:8])
}

// AuthenticateWebhook resolves an opaque per-tenant callback ref to its tenant
// identity. The ref is the credential (the C6 webhook is unsigned); a malformed or
// unregistered ref denies with the same (zero, false), so the caller cannot tell
// "no such tenant" from "wrong ref" (no enumeration oracle). The lookup is an O(1)
// map keyed by the ref's sha256 — the raw ref is never compared or stored, and the
// uniform deny makes lookup timing irrelevant to existence.
func (a *StaticTokenAuth) AuthenticateWebhook(tenantRef string) (WebhookIdentity, bool) {
	if !validTenantRef(tenantRef) {
		return WebhookIdentity{}, false // failure-closed
	}
	id, ok := a.webhookRefs[hashTenantRef(tenantRef)]
	if !ok {
		return WebhookIdentity{}, false
	}
	return id, true
}

// tenantRefBytes is the entropy of a minted tenantRef: 32 bytes (256 bits) makes
// the capability URL infeasible to guess.
const tenantRefBytes = 32

// tenantRefLen is the fixed length of a tenantRef once base64url-encoded (no
// padding): ceil(32*8/6) = 43 characters.
const tenantRefLen = 43

// GenerateTenantRef mints a fresh, unguessable per-tenant callback reference: 32
// random bytes (256 bits) encoded base64url without padding (43 chars). It is the
// secret embedded in a tenant's webhook URL (/webhooks/c6/{tenantRef}); register
// the returned value and hand the full URL to C6. Returns an error only if the
// system CSPRNG fails.
func GenerateTenantRef() (string, error) {
	b := make([]byte, tenantRefBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// validTenantRef reports whether ref is structurally a tenantRef: exactly
// tenantRefLen base64url characters ([A-Za-z0-9_-], no padding). Enforcing a fixed
// shape before any lookup rejects path-traversal/percent-encoded inputs uniformly
// (same 401) and keeps a malformed ref from ever reaching the credential map.
func validTenantRef(ref string) bool {
	if len(ref) != tenantRefLen {
		return false
	}
	for i := 0; i < len(ref); i++ {
		c := ref[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// hashTenantRef maps a tenantRef to the hex sha256 used as the credential-map key,
// so the raw capability secret is never stored in memory.
func hashTenantRef(ref string) string {
	sum := sha256.Sum256([]byte(ref))
	return hex.EncodeToString(sum[:])
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
// principal: the role (for requireRole) and the operator id (for audit
// attribution, via the app-layer context key). Deny-by-default: an
// unauthenticated request is rejected before any handler runs. The operator id
// is derived server-side from the token, so the audit "who" cannot be forged by
// the client.
func adminAuthMiddleware(auth AdminPrincipalAuthenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := auth.AuthenticateAdminPrincipal(bearerToken(r))
			if !ok {
				writeError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			ctx := context.WithValue(r.Context(), ctxRole, p.Role)
			ctx = app.WithOperatorID(ctx, p.OperatorID)
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

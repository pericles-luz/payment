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
	"github.com/ia-dev-sindireceita/payment/internal/domain/account"
	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
)

type ctxKey int

const (
	ctxTenantID ctxKey = iota
	ctxRole
	ctxCSRFToken
	// ctxAccountID carries the owning Account id resolved at the auth choke-point
	// alongside ctxTenantID (two-level tenancy, ADR-0009 / SIN-69126). It is
	// derived server-side from the authenticated token — never from client input —
	// and read by the metering/billing rollup (F2+). Downstream handlers keep
	// reading only ctxTenantID; the tenant isolation boundary is unchanged.
	ctxAccountID
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

// Principal is the server-side identity of an authenticated tenant caller in the
// two-level tenancy model (ADR-0009 / SIN-69126): the empresa-cliente (TenantID)
// plus the owning API-user/reseller account (AccountID). BOTH are resolved from
// the token server-side at the single auth choke-point — never from client input
// (there is no client selector, so the whole broken-access-control class A01 is
// designed out). TenantID stays authoritative for the isolation boundary exactly
// as before; AccountID is attribution-only (billing/metering rollup) and never
// widens or weakens the tenant scope.
type Principal struct {
	AccountID string
	TenantID  string
}

// TenantPrincipalAuthenticator resolves an opaque API token to the full tenant
// principal (owning account + tenant). It is the identity source the tenant
// middleware uses so the account dimension is carried from the same choke-point
// that already resolves the tenant. A failed lookup denies the request (threat
// H2), identically to AuthenticateTenant.
type TenantPrincipalAuthenticator interface {
	AuthenticateTenantPrincipal(token string) (Principal, bool)
}

// AccountResolver resolves an already-authenticated tenant to its owning Account
// id at the auth choke-point (two-level tenancy, ADR-0009 / SIN-69222). It is a
// READ-ONLY port and never participates in access control: the tenant id it
// receives is already authoritative (resolved from the credential, never from
// client input), and it only reads which Account the tenant was grouped under in
// the admin plane (tenants.account_id) so the account dimension stamped on the
// ledger reflects that grouping — the input to "Uso por Conta".
//
// Contract: return the tenant's REAL owning account id, or "" for a tenant with
// no explicitly-assigned account (a legacy self-account, NULL account_id). A ""
// return leaves the choke-point's derived self-account default in place, so the
// backfill 1:1 case (migration 0007) is unchanged (retrocompat). It MUST NEVER
// return a tenant id and MUST NEVER widen the tenant isolation scope — the
// isolation boundary stays keyed on the tenant id.
type AccountResolver interface {
	ResolveAccountID(ctx context.Context, tenantID string) string
}

// tenantAccountFinder is the narrow slice of the tenant read store the account
// resolver depends on: look up one tenant to read its owning account. Declared
// here (accept-narrow) so StoreAccountResolver depends on an interface, not the
// whole repository; satisfied by ports.TenantRepository and both persistence
// adapters.
type tenantAccountFinder interface {
	FindTenantByID(ctx context.Context, id string) (*tenant.Tenant, error)
}

// StoreAccountResolver backs AccountResolver by reading the owning Account from
// the tenant store. This is the piece the static token authenticator cannot do
// on its own: PAYMENT_TENANT_TOKENS maps token→tenant with no store access, so
// the choke-point defaulted every tenant to its self-account (acct-<tid>) and the
// "Uso por Conta" rollup on ledger.account_id found nothing for multi-empresa
// accounts. Resolving the parent here — behind a read port, no SQL in the
// middleware (hexagonal) — makes the stamped account_id match the admin grouping.
type StoreAccountResolver struct {
	tenants tenantAccountFinder
}

// NewStoreAccountResolver builds a StoreAccountResolver over the tenant read
// store. Passing a nil finder yields a resolver that always returns "" (the
// choke-point then keeps the self-account default), so wiring it is safe even in
// stripped-down deployments.
func NewStoreAccountResolver(finder tenantAccountFinder) *StoreAccountResolver {
	return &StoreAccountResolver{tenants: finder}
}

// ResolveAccountID reads the tenant's owning account from the store. It is
// fail-safe: an empty tenant id, a missing finder, or ANY store error returns ""
// so the choke-point falls back to the derived self-account and never widens the
// scope on a transient read failure. A found tenant returns its AccountID(),
// which is "" for a legacy self-account (unassigned) and the real parent Account
// id once the admin plane has grouped it.
func (r *StoreAccountResolver) ResolveAccountID(ctx context.Context, tenantID string) string {
	if r == nil || r.tenants == nil {
		return ""
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return ""
	}
	t, err := r.tenants.FindTenantByID(ctx, tenantID)
	if err != nil {
		return "" // fail-safe: keep the self-account default, never widen scope
	}
	return t.AccountID()
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

// AuthenticateTenantPrincipal resolves a token to its full principal (owning
// account + tenant). The tenant is resolved exactly as AuthenticateTenant; the
// owning account is DERIVED server-side as the tenant's self-account
// (account.SelfAccountID, the "acct-<tenantID>" convention from migration 0007's
// backfill). This is the dark-ship default: a legacy token maps to its own
// self-account, so the account dimension is present and correct with no config or
// admin-plane change (explicit account assignment arrives in a later phase and
// will layer on top here). A failed tenant lookup denies with the same
// (zero, false) as AuthenticateTenant — no new oracle.
func (a *StaticTokenAuth) AuthenticateTenantPrincipal(token string) (Principal, bool) {
	tenantID, ok := a.AuthenticateTenant(token)
	if !ok {
		return Principal{}, false
	}
	return Principal{TenantID: tenantID, AccountID: account.SelfAccountID(tenantID)}, true
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

// tenantAuthMiddleware enforces tenant authentication and injects the resolved
// principal: the tenant id (ctxTenantID, unchanged — still authoritative for the
// isolation boundary) AND the owning account id (ctxAccountID — attribution for
// the metering/billing rollup). Both come from the same single choke-point,
// derived server-side from the token and never from client input. Deny-by-default:
// an unresolved token is rejected before any handler runs.
//
// The account id defaults to what the authenticator resolves — the tenant's
// self-account (acct-<tid>), the dark-ship default. An optional AccountResolver
// (zero or one; variadic keeps the single-arg call sites and tests unchanged)
// upgrades that to the tenant's REAL owning Account read from the store, so a
// tenant grouped under a multi-empresa Account in the admin plane stamps
// ledger.account_id = <that Account> and "Uso por Conta" sees the rollup
// (SIN-69222). The resolver runs with the REQUEST context (cancellation /
// deadline propagate to the store read) and only overrides when it returns a
// non-empty real parent — an unassigned (self-account) tenant or a transient read
// failure keeps the self-account default (retrocompat, fail-safe). The tenant id
// is never sourced from the resolver, so the isolation boundary is unchanged.
func tenantAuthMiddleware(auth TenantPrincipalAuthenticator, resolver ...AccountResolver) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := auth.AuthenticateTenantPrincipal(bearerToken(r))
			if !ok {
				writeError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			accountID := p.AccountID
			for _, res := range resolver {
				if res == nil {
					continue
				}
				if parent := res.ResolveAccountID(r.Context(), p.TenantID); parent != "" {
					accountID = parent
					break
				}
			}
			ctx := context.WithValue(r.Context(), ctxTenantID, p.TenantID)
			ctx = context.WithValue(ctx, ctxAccountID, accountID)
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

// accountFromContext returns the owning account id resolved at the auth
// choke-point (two-level tenancy, ADR-0009 / SIN-69126), or "" if absent. It is
// attribution-only: consumers use it for the metering/billing rollup and MUST
// keep scoping isolation on the tenant id.
func accountFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ctxAccountID).(string); ok {
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

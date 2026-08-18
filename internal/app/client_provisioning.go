package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// ErrClientProvisioningUnavailable is returned when the tenant store is not wired.
// It mirrors the other "store not configured" sentinels so a stripped-down
// deployment fails closed with a clear error instead of a nil-pointer panic.
var ErrClientProvisioningUnavailable = errors.New("client provisioning store not configured")

// defaultClientName labels an empresa-cliente provisioned without a name. The
// request body's name is optional (ADR-0011 §4 / SIN-69281), but the Tenant
// aggregate requires a non-empty name; this keeps the API convenient without
// weakening the domain invariant.
const defaultClientName = "empresa-cliente"

// clientProvisionIdempotencyTTL bounds how long a used Idempotency-Key is
// remembered for client provisioning. Provisioning is a rare, deliberate action;
// a double-submit (buggy client retry or a lost-response retry) is inherently
// same-process/same-minute, so a short window collapses the realistic
// duplicate-tenant race while keeping the guard tiny. It is process-local (see
// clientProvisionIdempotencyGuard): a cross-instance/cross-restart replay is not
// collapsed, but the WORST case there is a second empresa-cliente the Account can
// see and delete — never a cross-account write (account_id always comes from the
// key). It mirrors the account-key rotation guard (SIN-69280).
const clientProvisionIdempotencyTTL = 15 * time.Minute

// tenantProvisioner is the narrow slice of ports.TenantRepository the provisioning
// use-case needs: persist a new tenant and read one back (for an idempotent
// replay). Declared here (accept-narrow) so the service depends on an interface,
// not the whole repository; satisfied by the in-memory and sqlite adapters.
type tenantProvisioner interface {
	SaveTenant(ctx context.Context, t *tenant.Tenant) error
	FindTenantByID(ctx context.Context, id string) (*tenant.Tenant, error)
}

// ClientProvisioningService is the use-case behind self-serve empresa-cliente
// provisioning by an Account (model (b), ADR-0011 §4 / SIN-69281). A reseller
// Conta (e.g. Verz), authenticated by its rotatable account-key, creates a new
// empresa-cliente (tenant) already bound to the CALLER's Account and gets back the
// tenant id to use in the X-Client-Tenant selector.
//
// Security invariant (A01/T6): the owning Account is taken from the authenticated
// caller and passed to ProvisionClient by the HTTP adapter from the account-key
// context — NEVER from the request body. There is no code path by which a body
// field can steer the binding to a different Account, so a Conta can only ever
// provision empresas-clientes under itself (broken-access-control designed out).
type ClientProvisioningService struct {
	tenants     tenantProvisioner
	ids         ports.IDProvider
	clock       ports.Clock
	guard       *clientProvisionIdempotencyGuard
	webhookRefs webhookRefMinter
}

// webhookRefMinter mints a durable per-tenant C6 webhook callback ref and returns the
// plaintext ONCE (SIN-69559 / F1). It is the narrow slice of WebhookRefMintService the
// provisioning use-case needs (accept-narrow); a nil minter means the webhook feature
// is not wired and ProvisionClientWithWebhook returns an empty ref (retrocompat — the
// legacy ProvisionClient path never mints).
type webhookRefMinter interface {
	MintWebhookRef(ctx context.Context, tenantID string) (plaintext string, err error)
}

// NewClientProvisioningService wires the service over the tenant repository, an id
// provider and a clock. The repository is required (a nil one yields a service that
// fails closed rather than panicking). The clock drives the idempotency-guard TTL
// (production wires the system clock; tests inject a deterministic one).
func NewClientProvisioningService(tenants ports.TenantRepository, ids ports.IDProvider, clock ports.Clock) *ClientProvisioningService {
	return &ClientProvisioningService{
		tenants: tenants,
		ids:     ids,
		clock:   clock,
		guard:   newClientProvisionIdempotencyGuard(clientProvisionIdempotencyTTL),
	}
}

// WithWebhookRefMinter wires the durable webhook-ref minter (SIN-69559 / F1) so that
// ProvisionClientWithWebhook mints a per-tenant C6 callback ref on a genuine create.
// It returns the receiver for a fluent wiring call. Passing a nil minter leaves the
// feature off (the webhook variant then returns an empty ref) — the legacy
// ProvisionClient path never mints, wired minter or not.
func (s *ClientProvisioningService) WithWebhookRefMinter(m webhookRefMinter) *ClientProvisioningService {
	s.webhookRefs = m
	return s
}

// ProvisionClient creates a new empresa-cliente owned by accountID and returns it.
// The caller (the HTTP adapter) has already authenticated the account-key and
// resolved the authoritative accountID server-side, so this method never derives
// identity from client input — name is the ONLY client-supplied field and it is
// optional (defaults to defaultClientName).
//
// idemKey is MANDATORY (the route rejects an empty one at the boundary; the service
// also rejects it, defense-in-depth). It dedups retries: the FIRST call under a
// given (account, idemKey) creates and returns the empresa-cliente; a REPEAT within
// the TTL returns the SAME empresa-cliente (re-read from the store) rather than
// creating a duplicate. Unlike the display-once account key, a tenant id is not a
// secret, so returning it again is the correct idempotent outcome.
//
// The guard is held across the create so two concurrent double-submits cannot both
// miss the cache and both create. A create FAILURE is not remembered, so a
// transient store error does not poison the idempotency key — a retry can succeed.
func (s *ClientProvisioningService) ProvisionClient(ctx context.Context, accountID, name, idemKey string) (*tenant.Tenant, error) {
	t, _, err := s.provision(ctx, accountID, name, idemKey, false)
	return t, err
}

// ProvisionClientWithWebhook provisions like ProvisionClient AND, on a genuine first
// create, mints a durable per-tenant C6 webhook callback ref (SIN-69559 / F1),
// returning the plaintext ref display-once alongside the empresa-cliente. This closes
// the self-serve gap (SIN-69557): a client created here can receive C6 webhooks with
// NO operator edit and NO restart.
//
// Display-once semantics: the ref is a capability secret returned exactly once. An
// idempotent REPLAY (a retry within the guard window) returns the SAME empresa-cliente
// but an EMPTY ref — the first response already carried it, and only the hash is
// stored, so it cannot be re-shown (mirroring the account-key/credential display-once
// contract). A caller that lost the first response rotates the ref (a later phase) or
// re-provisions under a fresh Idempotency-Key. With no minter wired the ref is empty.
func (s *ClientProvisioningService) ProvisionClientWithWebhook(ctx context.Context, accountID, name, idemKey string) (*tenant.Tenant, string, error) {
	return s.provision(ctx, accountID, name, idemKey, true)
}

// provision is the shared core of both entrypoints. mintWebhook selects whether a
// durable webhook ref is minted on the CREATE path; the ref is returned only to the
// webhook variant. The idempotency guard is held across the whole create (save + mint)
// so two concurrent double-submits cannot both create, and a mint FAILURE is not
// remembered — the idempotency key is left un-poisoned so a retry can complete the
// provision rather than replaying a client that has no durable ref.
func (s *ClientProvisioningService) provision(ctx context.Context, accountID, name, idemKey string, mintWebhook bool) (*tenant.Tenant, string, error) {
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		return nil, "", shared.NewValidationError("account_id", "account id is required")
	}
	idemKey = strings.TrimSpace(idemKey)
	if idemKey == "" {
		return nil, "", shared.NewValidationError("idempotency_key", "idempotency key is required")
	}
	if s.tenants == nil {
		return nil, "", ErrClientProvisioningUnavailable
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = defaultClientName
	}

	gkey := accountID + "\x00" + idemKey
	s.guard.mu.Lock()
	defer s.guard.mu.Unlock()
	now := s.clock.Now()
	s.guard.pruneLocked(now)
	if res, seen := s.guard.seen[gkey]; seen {
		// Idempotent replay: return the SAME empresa-cliente the first call created.
		// Re-read from the store so the response reflects persisted state. The webhook
		// ref is display-once — the first response carried it — so a replay returns "".
		t, err := s.tenants.FindTenantByID(ctx, res.tenantID)
		if err != nil {
			return nil, "", fmt.Errorf("resolve provisioned client: %w", err)
		}
		return t, "", nil
	}

	t, err := tenant.New(s.ids.NewID(), name, now)
	if err != nil {
		return nil, "", err
	}
	// Bind the new empresa-cliente to the Account taken from the authenticated key.
	// AssignAccount is the set-once binding FROM empty (ADR-0009 §2), NOT the
	// CTO-gated re-parenting — a fresh tenant starts as a self-account and is bound
	// exactly once here.
	if err := t.AssignAccount(accountID); err != nil {
		return nil, "", err
	}
	if err := s.tenants.SaveTenant(ctx, t); err != nil {
		return nil, "", fmt.Errorf("save tenant: %w", err)
	}
	// Mint the durable webhook ref AFTER the tenant exists (the store's FK binds the ref
	// to a real tenant). Only the hash is persisted; the plaintext is returned once. A
	// mint failure returns BEFORE recording the idempotency key, so a retry re-provisions
	// (worst case a second empresa-cliente the Account can see and delete) rather than
	// replaying a ref-less client.
	var ref string
	if mintWebhook && s.webhookRefs != nil {
		ref, err = s.webhookRefs.MintWebhookRef(ctx, t.ID())
		if err != nil {
			return nil, "", fmt.Errorf("mint webhook ref: %w", err)
		}
	}
	// Record ONLY the created tenant id (not a secret) so the next replay collapses
	// to the same empresa-cliente without a second create.
	s.guard.seen[gkey] = provisionResult{tenantID: t.ID(), at: s.clock.Now()}
	return t, ref, nil
}

// provisionResult is the guard's remembered outcome of a first provisioning call:
// the created tenant id and when it happened (for TTL pruning). It never holds a
// secret.
type provisionResult struct {
	tenantID string
	at       time.Time
}

// clientProvisionIdempotencyGuard is the process-local, TTL-bounded dedup store for
// empresa-cliente provisioning (SIN-69281), keyed by "<accountID>\x00<idemKey>". It
// remembers the created tenant id so a replay returns the SAME empresa-cliente
// rather than creating a duplicate. The mutex is held across the guarded create
// (see ProvisionClient), so no separate reservation state is needed. It mirrors the
// account-key idempotency guard (SIN-69280) / invoiceBatchGuard (SIN-69184).
type clientProvisionIdempotencyGuard struct {
	mu   sync.Mutex
	ttl  time.Duration
	seen map[string]provisionResult
}

func newClientProvisionIdempotencyGuard(ttl time.Duration) *clientProvisionIdempotencyGuard {
	return &clientProvisionIdempotencyGuard{ttl: ttl, seen: make(map[string]provisionResult)}
}

// pruneLocked drops entries older than the TTL. The caller MUST hold g.mu.
func (g *clientProvisionIdempotencyGuard) pruneLocked(now time.Time) {
	for k, r := range g.seen {
		if now.Sub(r.at) > g.ttl {
			delete(g.seen, k)
		}
	}
}

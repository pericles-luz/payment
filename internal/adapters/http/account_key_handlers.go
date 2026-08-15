package http

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/accountkey"
)

// AccountKeyMinter mints/rotates an Account's rotatable bearer key and returns the
// plaintext ONCE (model (b), ADR-0011 §3 / SIN-69280). It is the app-layer port the
// account-key routes depend on (accept-narrow: the adapter needs only the mint, not
// the authenticate surface). Satisfied by app.AccountKeyService.
//
// Idempotency contract: idemKey is mandatory; a replay under an already-used key
// returns app.ErrAccountKeyAlreadyRotated and NO plaintext (display-once — the
// secret is never returned twice), which the handler surfaces as 409 Conflict.
type AccountKeyMinter interface {
	RotateAccountKey(ctx context.Context, accountID, idemKey string) (secret string, err error)
}

// accountKeyMintView is the response body for a successful mint/rotation. It is the
// ONLY view that ever carries the secret, and only at the instant of emission
// (display-once, ADR-0010): there is deliberately no read endpoint and no other
// response shape that echoes it, so the plaintext leaves the service exactly once
// and is never logged (the handler never logs the body). Status is a fixed,
// non-oracle string — a create and a rotate are byte-identical (nothing reveals
// whether the Account already had a key).
type accountKeyMintView struct {
	AccountID string `json:"account_id"`
	Secret    string `json:"secret"`
	Status    string `json:"status"`
}

// accountKeyAuthMiddleware authenticates an Account by its own rotatable bearer key
// (model (b), ADR-0011 §3 / SIN-69280) for the account-plane self-service route.
// UNLIKE the tenant choke-point (tenantAuthMiddlewareWithSelector) it takes NO
// X-Client-Tenant selector and resolves NO tenant: the Account is acting on ITSELF
// (its own credential), so only the authenticated account id is placed on the
// context — there is no tenant-scoped resource here, hence no selector and no
// isolation widening to reason about.
//
// Deny-by-default and no enumeration oracle: a bearer that is absent, lacks the
// account-key shape, or is unknown/superseded is rejected with the SAME uniform 401
// (mirrors AuthenticateWebhook / the choke-point) — nothing distinguishes "no such
// key" from "wrong key". The route is registered ONLY when model (b) is enabled, so
// with the flag off this middleware and its route do not exist at all.
func accountKeyAuthMiddleware(auth AccountKeyAuthenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bearer := bearerToken(r)
			if !accountkey.HasSecretShape(bearer) {
				writeError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			accountID, ok := auth.AuthenticateAccountKey(r.Context(), bearer)
			if !ok {
				writeError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			ctx := context.WithValue(r.Context(), ctxAccountID, accountID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// handleRotateAccountKey is the self-serve rotation (POST /v1/account-key): the
// Account rotates its OWN key using its EXISTING key (accountKeyAuthMiddleware put
// the authenticated account id on the context). The account id is taken from the
// authenticated context, NEVER from the path/body — an Account can only ever rotate
// its own key (A01 designed out, mirroring the self-serve credential intake).
func (s *Server) handleRotateAccountKey(w http.ResponseWriter, r *http.Request) {
	accountID := accountFromContext(r.Context())
	if accountID == "" {
		// Only reachable via a wiring bug (route not behind accountKeyAuthMiddleware);
		// fail closed rather than mint for an unauthenticated caller.
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	s.mintAccountKey(w, r, accountID)
}

// handleAdminMintAccountKey is the admin-plane bootstrap (POST
// /admin/accounts/{accountID}/account-key): an admin mints the FIRST key for a named
// Account — how the board provisions Verz's initial key, which is then handed over a
// secure channel (never a public comment, same discipline as
// PAYMENT_CONSOLE_BOOTSTRAP_TOKEN). It uses the same create==rotate path, so calling
// it on an Account that already has a key rotates it (an intentional admin override).
// The route is behind adminAuthMiddleware + requireRole(RoleAdmin), so only a full
// admin reaches it; the account id comes from the path (an admin legitimately names
// which Account to provision), unlike the self-serve route.
func (s *Server) handleAdminMintAccountKey(w http.ResponseWriter, r *http.Request) {
	accountID := strings.TrimSpace(chi.URLParam(r, "accountID"))
	if accountID == "" {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	s.mintAccountKey(w, r, accountID)
}

// mintAccountKey is the shared body for both write surfaces: enforce the mandatory
// Idempotency-Key, mint (create==rotate) and return the plaintext exactly once. The
// secret is written straight into the response and never logged. A replayed
// Idempotency-Key yields 409 with NO secret (display-once, never returned twice);
// any validation/store error is mapped by writeDomainError without echoing input.
func (s *Server) mintAccountKey(w http.ResponseWriter, r *http.Request, accountID string) {
	if s.accountKeyMint == nil {
		writeError(w, http.StatusServiceUnavailable, "account key issuance unavailable")
		return
	}
	idemKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if idemKey == "" {
		writeError(w, http.StatusBadRequest, "missing Idempotency-Key header")
		return
	}
	secret, err := s.accountKeyMint.RotateAccountKey(r.Context(), accountID, idemKey)
	if errors.Is(err, app.ErrAccountKeyAlreadyRotated) {
		// Idempotent replay: the key was already minted under this Idempotency-Key and
		// the secret was delivered on the original response. It is never shown again
		// (display-once); rotate with a fresh Idempotency-Key for a new secret.
		writeError(w, http.StatusConflict, "idempotency key already used; the secret is shown only once — rotate with a fresh Idempotency-Key for a new secret")
		return
	}
	if err != nil {
		writeDomainError(w, err)
		return
	}
	// 201 Created + the plaintext, ONCE. No read endpoint, no second response shape
	// carries it; the handler never logs the body.
	writeJSON(w, http.StatusCreated, accountKeyMintView{AccountID: accountID, Secret: secret, Status: "created"})
}

package app

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/ia-dev-sindireceita/payment/internal/domain/account"
	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
	"github.com/ia-dev-sindireceita/payment/internal/domain/outboundwebhook"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

// outbound_webhook.go holds the console use-cases for a Conta's OUTBOUND webhook
// configuration (SIN-69490, F0 of SIN-69486, model (b) ADR-0011): the durable,
// encrypted, account-scoped CRUD that lets an operator point a Conta's events at an
// https receiver and manage its HMAC signing secret. It is DARK — there is no
// forwarding here (that is F2), and the whole surface is gated at the HTTP boundary
// by the PAYMENT_ACCOUNT_OUTBOUND_WEBHOOK flag (default-off), so wiring the store has
// zero effect on the current flow until the flag turns the console routes on.
//
// It sits on ConsoleService (like the account CRUD) so it reuses the same account
// store, audit trail, clock and id provider. Nothing here crosses a domain boundary:
// the aggregate is pure (outboundwebhook.Config) and the secret is sealed by the
// persistence adapter, never by this layer.

// ErrOutboundWebhookUnavailable is returned by the outbound-webhook use-cases when
// the console was wired without an OutboundWebhookStore (no vault cipher, or the dark
// feature not provisioned). The HTTP adapter maps it to 503, mirroring
// ErrAccountsUnavailable / ErrInvoicesUnavailable.
var ErrOutboundWebhookUnavailable = errors.New("outbound webhook store not configured")

// OutboundWebhookStore is the durable persistence the console needs for a Conta's
// single outbound webhook config: the account-scoped get/upsert/delete triple. The
// concrete sqlite vault (encrypted-at-rest) and the in-memory adapter satisfy it. It
// is a narrow app-level port (like ConsoleCredentialStore) — one config per Account,
// keyed by accountID. Get returns shared.ErrNotFound when the Conta has none.
type OutboundWebhookStore interface {
	GetOutboundWebhook(ctx context.Context, accountID string) (*outboundwebhook.Config, error)
	UpsertOutboundWebhook(ctx context.Context, cfg *outboundwebhook.Config) error
	DeleteOutboundWebhook(ctx context.Context, accountID string) error
}

// resolveWebhookAccount validates that outbound-webhook use-cases can run for acctID:
// the store must be wired, the account must exist (clean 404 — no enumeration oracle,
// OWASP A01), and it must be a REAL Conta. A derived self-account (the legacy 1:1
// backfill) has no outbound webhook — model (b) endpoints are for real reseller
// Contas — so it is refused with shared.ErrNotFound (defense-in-depth: the console
// also hides the card and the flag gates the routes). Returns the trimmed account id.
func (s *ConsoleService) resolveWebhookAccount(ctx context.Context, acctID string) (string, error) {
	if s.webhooks == nil {
		return "", ErrOutboundWebhookUnavailable
	}
	if s.accounts == nil {
		return "", ErrAccountsUnavailable
	}
	acctID = strings.TrimSpace(acctID)
	a, err := s.accounts.FindAccountByID(ctx, acctID)
	if err != nil {
		return "", fmt.Errorf("resolve account: %w", err)
	}
	if account.IsSelfAccountID(a.ID()) {
		return "", fmt.Errorf("self-account has no outbound webhook: %w", shared.ErrNotFound)
	}
	return a.ID(), nil
}

// GetOutboundWebhook returns a Conta's outbound webhook config and whether one is
// configured. A missing config (shared.ErrNotFound) is the empty state, not an error:
// it returns (nil, false, nil). The account must exist and be a real Conta.
func (s *ConsoleService) GetOutboundWebhook(ctx context.Context, acctID string) (*outboundwebhook.Config, bool, error) {
	id, err := s.resolveWebhookAccount(ctx, acctID)
	if err != nil {
		return nil, false, err
	}
	cfg, err := s.webhooks.GetOutboundWebhook(ctx, id)
	switch {
	case err == nil:
		return cfg, true, nil
	case errors.Is(err, shared.ErrNotFound):
		return nil, false, nil
	default:
		return nil, false, fmt.Errorf("get outbound webhook: %w", err)
	}
}

// SetOutboundWebhook creates or updates a Conta's outbound webhook endpoint (URL +
// enabled toggle), account-scoped. On FIRST provisioning it mints a fresh signing
// secret and returns the plaintext EXACTLY once (display-once) so the operator can
// configure their receiver; on an update it PRESERVES the existing secret and returns
// "" (the secret is never re-derivable, never rendered — write-only). The URL is
// validated https-only in the domain. Every mutation is audited (account.webhook.set)
// with who/which-Conta/when — never the secret or the URL.
//
// It returns the resulting config and the freshly-minted plaintext secret (empty on
// an update). A validation error (bad URL) surfaces unchanged for inline rendering.
func (s *ConsoleService) SetOutboundWebhook(ctx context.Context, acctID, rawURL string, enabled bool) (*outboundwebhook.Config, string, error) {
	id, err := s.resolveWebhookAccount(ctx, acctID)
	if err != nil {
		return nil, "", err
	}
	existing, err := s.webhooks.GetOutboundWebhook(ctx, id)
	switch {
	case err == nil:
		// Update: keep the secret, re-validate the URL, toggle enabled.
		if err := existing.SetURL(rawURL, s.clock.Now()); err != nil {
			return nil, "", err
		}
		existing.SetEnabled(enabled, s.clock.Now())
		if err := s.webhooks.UpsertOutboundWebhook(ctx, existing); err != nil {
			return nil, "", fmt.Errorf("upsert outbound webhook: %w", err)
		}
		if err := s.auditWebhook(ctx, audit.ActionSetOutboundWebhook, id); err != nil {
			return nil, "", err
		}
		return existing, "", nil
	case errors.Is(err, shared.ErrNotFound):
		// First provisioning: mint a signing secret and return it display-once.
		secret, gErr := outboundwebhook.GenerateSigningSecret()
		if gErr != nil {
			return nil, "", fmt.Errorf("generate signing secret: %w", gErr)
		}
		cfg, nErr := outboundwebhook.New(id, rawURL, secret, enabled, s.clock.Now())
		if nErr != nil {
			return nil, "", nErr
		}
		if err := s.webhooks.UpsertOutboundWebhook(ctx, cfg); err != nil {
			return nil, "", fmt.Errorf("upsert outbound webhook: %w", err)
		}
		if err := s.auditWebhook(ctx, audit.ActionSetOutboundWebhook, id); err != nil {
			return nil, "", err
		}
		return cfg, secret, nil
	default:
		return nil, "", fmt.Errorf("get outbound webhook: %w", err)
	}
}

// RotateOutboundWebhookSecret mints a NEW signing secret for an already-configured
// Conta, invalidating the previous one immediately (the safer default), and returns
// the plaintext EXACTLY once. The config must already exist (shared.ErrNotFound
// otherwise — a rotation presupposes an endpoint). Audited (account.webhook.rotate_secret)
// with who/which-Conta/when — never the secret.
func (s *ConsoleService) RotateOutboundWebhookSecret(ctx context.Context, acctID string) (*outboundwebhook.Config, string, error) {
	id, err := s.resolveWebhookAccount(ctx, acctID)
	if err != nil {
		return nil, "", err
	}
	cfg, err := s.webhooks.GetOutboundWebhook(ctx, id)
	if err != nil {
		// ErrNotFound flows through: no endpoint to rotate a secret for (404 at boundary).
		return nil, "", fmt.Errorf("get outbound webhook: %w", err)
	}
	secret, err := cfg.RotateSecret(s.clock.Now())
	if err != nil {
		return nil, "", fmt.Errorf("rotate signing secret: %w", err)
	}
	if err := s.webhooks.UpsertOutboundWebhook(ctx, cfg); err != nil {
		return nil, "", fmt.Errorf("upsert outbound webhook: %w", err)
	}
	if err := s.auditWebhook(ctx, audit.ActionRotateOutboundWebhookSecret, id); err != nil {
		return nil, "", err
	}
	return cfg, secret, nil
}

// RemoveOutboundWebhook hard-deletes a Conta's outbound webhook config (idempotent —
// removing an absent config is a no-op that still returns success), account-scoped.
// Audited (account.webhook.remove) with who/which-Conta/when — never the deleted
// secret. The account must exist and be a real Conta.
func (s *ConsoleService) RemoveOutboundWebhook(ctx context.Context, acctID string) error {
	id, err := s.resolveWebhookAccount(ctx, acctID)
	if err != nil {
		return err
	}
	if err := s.webhooks.DeleteOutboundWebhook(ctx, id); err != nil {
		return fmt.Errorf("delete outbound webhook: %w", err)
	}
	if err := s.auditWebhook(ctx, audit.ActionRemoveOutboundWebhook, id); err != nil {
		return err
	}
	return nil
}

// auditWebhook appends the account-scoped audit entry for an outbound-webhook
// mutation. Fail-closed: an audit-append error surfaces rather than silently dropping
// the forensic trail, matching the console's other privileged single-store mutations.
// The entry records who/which-Conta/when only — never the secret or the URL.
func (s *ConsoleService) auditWebhook(ctx context.Context, action audit.Action, accountID string) error {
	e, err := audit.NewOutboundWebhookEntry(s.ids.NewID(), OperatorIDFromContext(ctx), action, accountID, s.clock.Now())
	if err != nil {
		return fmt.Errorf("build audit entry: %w", err)
	}
	if err := s.audit.Append(ctx, e); err != nil {
		return fmt.Errorf("append audit entry: %w", err)
	}
	return nil
}

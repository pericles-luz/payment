package http_test

import (
	"context"
	"errors"
	"testing"

	httpadapter "github.com/ia-dev-sindireceita/payment/internal/adapters/http"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// TestBankResolverNoOracleMatrix is the SIN-66040 defense-in-depth matrix: it drives
// BankResolver.Resolve through the full enumerated set of selectors and asserts the
// fail-closed, no-oracle contract end to end.
//
//   - A slug carrying NUL or any other control char is rejected BEFORE it can become a
//     fragment of the secret store's composite key (tenant + "\x00" + bank), so it can
//     never forge or collide another tenant's credential key.
//   - A well-formed but unregistered (unwired) slug is rejected the same way.
//   - Every rejection returns the IDENTICAL shared.ErrNotFound — indistinguishable
//     from a genuine not-found — so a caller cannot use the error to tell a malformed
//     slug from an unknown one, an unknown one from an unconfigured one, or enumerate
//     which banks exist (no oracle, AC #4).
//   - The one valid, wired, configured slug (c6) resolves cleanly.
//
// It complements the white-box normalizeBankID sweep in bankselect_normalize_test.go:
// this proves the guard holds through Resolve, the path the HTTP boundary actually
// calls, with the real in-memory credential store (no DB mock).
func TestBankResolverNoOracleMatrix(t *testing.T) {
	creds := secret.NewStore(nil)
	// Tenant t-a is configured (wired + credentialed) only for c6.
	if err := creds.SetBankCredential(context.Background(), "t-a", "c6", "client", "secret"); err != nil {
		t.Fatalf("seed c6 credential: %v", err)
	}
	// itau is wired but t-a holds no credential for it (configured-for-tenant gate).
	r := httpadapter.NewBankResolver([]string{"c6", "itau"}, creds)

	cases := []struct {
		name      string
		requested string
		want      string // expected resolved bank when wantErr is false
		wantErr   bool
	}{
		{"valid registered c6", "c6", "c6", false},
		{"nul embedded", "c6\x00evil", "", true},
		{"nul prefix forge attempt", "\x00c6", "", true},
		{"newline control", "c6\nx", "", true},
		{"tab control", "c6\tx", "", true},
		{"del 0x7f control", "c6\x7f", "", true},
		{"unit separator 0x1f", "c6\x1f", "", true},
		{"unregistered slug", "bradesco", "", true},
		{"wired but unconfigured for tenant", "itau", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := r.Resolve(context.Background(), "t-a", c.requested)
			if c.wantErr {
				if err == nil {
					t.Fatalf("requested=%q: want error, got resolved bank %q", c.requested, got)
				}
				// No oracle: every rejection is the same not-found sentinel.
				if !errors.Is(err, shared.ErrNotFound) {
					t.Fatalf("requested=%q: want shared.ErrNotFound (no oracle), got %v", c.requested, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("requested=%q: unexpected error %v", c.requested, err)
			}
			if got != c.want {
				t.Fatalf("requested=%q: resolved %q, want %q", c.requested, got, c.want)
			}
		})
	}
}

// TestBankResolverControlCharNeverHitsStore proves the rejection is fail-closed at the
// validation layer: a control-char slug never reaches credential resolution, so it
// cannot be used as a timing/error oracle against the store nor mint a token. The
// resolver is built with a credential store that PANICS if queried, so any read for a
// malformed slug would crash the test rather than pass silently.
func TestBankResolverControlCharNeverHitsStore(t *testing.T) {
	r := httpadapter.NewBankResolver([]string{"c6"}, panicStore{})

	// NOTE: each slug is rejected by normalizeBankID — either NUL/non-whitespace
	// control bytes, or a control byte placed INTERIOR so strings.TrimSpace cannot
	// strip it. A trailing whitespace-class byte (\t,\n) would be trimmed to a valid
	// slug and legitimately reach the store, so it is deliberately not used here.
	for _, slug := range []string{"c6\x00x", "c6\nx", "c6\tx", "\x00", "c6\x7f"} {
		got, err := r.Resolve(context.Background(), "t-a", slug)
		if err == nil {
			t.Fatalf("slug=%q: want rejection, got %q", slug, got)
		}
		if !errors.Is(err, shared.ErrNotFound) {
			t.Fatalf("slug=%q: want shared.ErrNotFound, got %v", slug, err)
		}
	}
}

// panicStore is a CredentialStore that fails the test if any method is called, used to
// assert that a malformed slug short-circuits before any credential lookup.
type panicStore struct{}

func (panicStore) GetBankCredential(_ context.Context, tenantID, bankID string) (ports.BankCredential, error) {
	panic("credential store must not be queried for a control-char slug: tenant=" + tenantID + " bank=" + bankID)
}

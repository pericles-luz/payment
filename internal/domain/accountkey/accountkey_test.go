package accountkey_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/accountkey"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

func epoch() time.Time { return time.Unix(0, 0).UTC() }

func TestNewValidation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, accountID, secret string
		wantErr                 bool
	}{
		{name: "valid", accountID: "a1", secret: "ak_deadbeef", wantErr: false},
		{name: "trims account", accountID: "  a1 ", secret: "ak_x", wantErr: false},
		{name: "missing account", accountID: "", secret: "ak_x", wantErr: true},
		{name: "blank account", accountID: "   ", secret: "ak_x", wantErr: true},
		{name: "missing secret", accountID: "a1", secret: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			k, err := accountkey.New(tt.accountID, tt.secret, epoch())
			if tt.wantErr {
				if !errors.Is(err, shared.ErrValidation) {
					t.Fatalf("want ErrValidation, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected: %v", err)
			}
			if k.AccountID() != strings.TrimSpace(tt.accountID) {
				t.Fatalf("account id = %q", k.AccountID())
			}
			if !k.Active() {
				t.Fatal("new key must be active")
			}
			if !k.CreatedAt().Equal(epoch()) {
				t.Fatal("createdAt mismatch")
			}
			if !k.RotatedAt().IsZero() {
				t.Fatal("new key must have zero rotatedAt")
			}
		})
	}
}

// TestHashNeverStoresPlaintext proves the invariant: the hash is the sha256 of the
// secret, is never equal to the plaintext, and does not contain it.
func TestHashNeverStoresPlaintext(t *testing.T) {
	t.Parallel()
	const secret = "ak_super-secret-value-1234567890"
	k, err := accountkey.New("a1", secret, epoch())
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if k.Hash() == secret {
		t.Fatal("hash must not equal the plaintext")
	}
	if strings.Contains(k.Hash(), secret) || strings.Contains(k.Hash(), "super-secret") {
		t.Fatal("hash must not contain the plaintext")
	}
	if k.Hash() != accountkey.HashSecret(secret) {
		t.Fatal("hash must be the sha256 of the secret")
	}
	if len(k.Hash()) != 64 { // hex sha256 is 32 bytes = 64 hex chars
		t.Fatalf("hash length = %d, want 64", len(k.Hash()))
	}
}

// TestGenerateSecretEntropyAndShape proves the secret is prefixed, high-entropy,
// and unique across mints.
func TestGenerateSecretEntropyAndShape(t *testing.T) {
	t.Parallel()
	seen := make(map[string]struct{})
	for i := 0; i < 1000; i++ {
		s, err := accountkey.GenerateSecret()
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		if !accountkey.HasSecretShape(s) {
			t.Fatalf("secret %q lacks the account-key prefix", s)
		}
		// 32 bytes base64url (no padding) = 43 chars, plus the "ak_" prefix.
		if want := len("ak_") + 43; len(s) != want {
			t.Fatalf("secret length = %d, want %d", len(s), want)
		}
		if _, dup := seen[s]; dup {
			t.Fatalf("duplicate secret minted: %q", s)
		}
		seen[s] = struct{}{}
	}
}

func TestHasSecretShape(t *testing.T) {
	t.Parallel()
	if !accountkey.HasSecretShape("ak_anything") {
		t.Fatal("ak_-prefixed value should have the shape")
	}
	if accountkey.HasSecretShape("tenant-token-without-prefix") {
		t.Fatal("a non-prefixed value must not have the shape")
	}
}

// TestVerifyMatchMismatchAndInactive covers constant-time verification: the right
// secret verifies while active, the wrong secret never does, and a superseded key
// stops verifying even with the right secret.
func TestVerifyMatchMismatchAndInactive(t *testing.T) {
	t.Parallel()
	k, _, err := accountkey.Mint("a1", epoch())
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	// Re-mint to obtain a known plaintext to verify against.
	secret, err := accountkey.GenerateSecret()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	k2, err := accountkey.New("a1", secret, epoch())
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if !k2.Verify(secret) {
		t.Fatal("correct secret should verify")
	}
	if k2.Verify(secret + "x") {
		t.Fatal("wrong secret must not verify")
	}
	if k2.Verify("") {
		t.Fatal("empty secret must not verify")
	}
	// Cross-key: k's secret is unknown here, but a random other secret must not verify.
	if k.Verify(secret) {
		t.Fatal("a different key must not verify this secret")
	}
	// Supersede invalidates immediately.
	k2.Supersede(epoch().Add(time.Hour))
	if k2.Verify(secret) {
		t.Fatal("superseded key must not verify even the correct secret")
	}
	if k2.Active() {
		t.Fatal("superseded key must be inactive")
	}
	if !k2.RotatedAt().Equal(epoch().Add(time.Hour)) {
		t.Fatal("supersede must record rotatedAt")
	}
}

// TestMintReturnsVerifiablePlaintext proves Mint's returned plaintext verifies
// against the key it also returns, and that two mints yield distinct secrets.
func TestMintReturnsVerifiablePlaintext(t *testing.T) {
	t.Parallel()
	k, plaintext, err := accountkey.Mint("a1", epoch())
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if !k.Verify(plaintext) {
		t.Fatal("minted plaintext should verify against its key")
	}
	if !accountkey.HasSecretShape(plaintext) {
		t.Fatal("minted plaintext should carry the prefix")
	}
	_, p2, err := accountkey.Mint("a1", epoch())
	if err != nil {
		t.Fatalf("mint2: %v", err)
	}
	if plaintext == p2 {
		t.Fatal("two mints must yield distinct plaintexts")
	}
}

func TestRehydrate(t *testing.T) {
	t.Parallel()
	created := time.Unix(10, 0).UTC()
	rotated := time.Unix(20, 0).UTC()
	k := accountkey.Rehydrate("a1", "abc123", false, created, rotated)
	if k.AccountID() != "a1" || k.Hash() != "abc123" || k.Active() {
		t.Fatal("rehydrate field mismatch")
	}
	if !k.CreatedAt().Equal(created) || !k.RotatedAt().Equal(rotated) {
		t.Fatal("rehydrate timestamp mismatch")
	}
}

// TestLogValueRedactsHash proves the hash never reaches a structured log line.
func TestLogValueRedactsHash(t *testing.T) {
	t.Parallel()
	k, err := accountkey.New("a1", "ak_top-secret-plaintext-value", epoch())
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	logger.LogAttrs(context.Background(), slog.LevelInfo, "account key", slog.Any("key", k))
	out := buf.String()
	if strings.Contains(out, k.Hash()) {
		t.Fatalf("log leaked the hash: %s", out)
	}
	if strings.Contains(out, "top-secret") {
		t.Fatalf("log leaked the plaintext: %s", out)
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Fatalf("log should mark the hash redacted: %s", out)
	}
	if !strings.Contains(out, "a1") {
		t.Fatalf("log should still carry the non-secret account id: %s", out)
	}
}

package account_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/account"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

func TestNewAccount(t *testing.T) {
	t.Parallel()
	now := time.Unix(0, 0).UTC()
	tests := []struct {
		name, id, aname string
		wantErr         bool
	}{
		{name: "valid", id: "a1", aname: "Verz", wantErr: false},
		{name: "trims", id: " a1 ", aname: " Verz ", wantErr: false},
		{name: "missing id", id: "", aname: "Verz", wantErr: true},
		{name: "blank id", id: "   ", aname: "Verz", wantErr: true},
		{name: "missing name", id: "a1", aname: "  ", wantErr: true},
		{name: "name too long", id: "a1", aname: strings.Repeat("x", 201), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := account.New(tt.id, tt.aname, now)
			if tt.wantErr {
				if !errors.Is(err, shared.ErrValidation) {
					t.Fatalf("want ErrValidation, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected: %v", err)
			}
			if got.ID() != strings.TrimSpace(tt.id) || got.Name() != strings.TrimSpace(tt.aname) {
				t.Fatalf("field mismatch: id=%q name=%q", got.ID(), got.Name())
			}
			if !got.Active() {
				t.Fatal("new account should be active")
			}
			if !got.CreatedAt().Equal(now) {
				t.Fatal("createdAt mismatch")
			}
		})
	}
}

func TestAccountRehydrateAndToggle(t *testing.T) {
	t.Parallel()
	now := time.Unix(7, 0).UTC()
	a := account.Rehydrate("a1", "Verz", true, now)
	if !a.Active() || a.ID() != "a1" || a.Name() != "Verz" || !a.CreatedAt().Equal(now) {
		t.Fatal("rehydrate mismatch")
	}
	a.Deactivate()
	if a.Active() {
		t.Fatal("should be inactive after Deactivate")
	}
	a.Activate()
	if !a.Active() {
		t.Fatal("should be active after Activate")
	}
}

func TestSelfAccountID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, tenantID, want string
	}{
		{name: "derives acct- prefix", tenantID: "t1", want: "acct-t1"},
		{name: "trims whitespace", tenantID: "  t1  ", want: "acct-t1"},
		{name: "empty tenant has no self-account", tenantID: "", want: ""},
		{name: "blank tenant has no self-account", tenantID: "   ", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := account.SelfAccountID(tt.tenantID); got != tt.want {
				t.Fatalf("SelfAccountID(%q) = %q, want %q", tt.tenantID, got, tt.want)
			}
		})
	}
}

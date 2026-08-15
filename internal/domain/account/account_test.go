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

func TestAccountRename(t *testing.T) {
	t.Parallel()
	now := time.Unix(0, 0).UTC()
	tests := []struct {
		name, in, want string
		wantErr        bool
	}{
		{name: "ok", in: "Verz Novo", want: "Verz Novo", wantErr: false},
		{name: "trims", in: "  Verz  ", want: "Verz", wantErr: false},
		{name: "blank", in: "   ", wantErr: true},
		{name: "empty", in: "", wantErr: true},
		{name: "too long", in: strings.Repeat("x", 201), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			a, err := account.New("a1", "Original", now)
			if err != nil {
				t.Fatalf("setup: %v", err)
			}
			err = a.Rename(tt.in)
			if tt.wantErr {
				if !errors.Is(err, shared.ErrValidation) {
					t.Fatalf("want ErrValidation, got %v", err)
				}
				if a.Name() != "Original" {
					t.Fatalf("name must be unchanged on error, got %q", a.Name())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected: %v", err)
			}
			if a.Name() != tt.want {
				t.Fatalf("Name() = %q, want %q", a.Name(), tt.want)
			}
		})
	}
}

func TestAccountRenameSelfAccountRejected(t *testing.T) {
	t.Parallel()
	now := time.Unix(0, 0).UTC()
	// A derived self-account carries the acct-<tenantID> id; rehydrate one and
	// confirm a direct rename is refused and the name is left untouched (ADR-0012 §1).
	self := account.Rehydrate(account.SelfAccountID("t-123"), "Self", true, now)
	if !account.IsSelfAccountID(self.ID()) {
		t.Fatalf("setup: %q is not a self-account id", self.ID())
	}
	err := self.Rename("New Name")
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation renaming self-account, got %v", err)
	}
	if self.Name() != "Self" {
		t.Fatalf("name must be unchanged, got %q", self.Name())
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

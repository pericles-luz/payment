package tenant_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
)

func TestNewTenant(t *testing.T) {
	t.Parallel()
	now := time.Unix(0, 0).UTC()
	tests := []struct {
		name, id, tname string
		wantErr         bool
	}{
		{name: "valid", id: "t1", tname: "Acme", wantErr: false},
		{name: "trims", id: " t1 ", tname: " Acme ", wantErr: false},
		{name: "missing id", id: "", tname: "Acme", wantErr: true},
		{name: "missing name", id: "t1", tname: "  ", wantErr: true},
		{name: "name too long", id: "t1", tname: strings.Repeat("x", 201), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := tenant.New(tt.id, tt.tname, now)
			if tt.wantErr {
				if !errors.Is(err, shared.ErrValidation) {
					t.Fatalf("want ErrValidation, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected: %v", err)
			}
			if !got.Active() {
				t.Fatal("new tenant should be active")
			}
			if !got.CreatedAt().Equal(now) {
				t.Fatal("createdAt mismatch")
			}
		})
	}
}

func TestTenantDeactivateAndRehydrate(t *testing.T) {
	t.Parallel()
	now := time.Unix(5, 0).UTC()
	tt := tenant.Rehydrate("t1", "Acme", true, now)
	if !tt.Active() || tt.ID() != "t1" || tt.Name() != "Acme" {
		t.Fatal("rehydrate mismatch")
	}
	tt.Deactivate()
	if tt.Active() {
		t.Fatal("should be inactive after Deactivate")
	}
}

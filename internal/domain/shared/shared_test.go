package shared_test

import (
	"errors"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

func TestNewMoney(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		cents    int64
		currency string
		wantErr  bool
	}{
		{"valid", 1500, "BRL", false},
		{"zero amount", 0, "BRL", true},
		{"negative amount", -10, "BRL", true},
		{"bad currency lower", 10, "brl", true},
		{"bad currency length", 10, "REAL", true},
		{"empty currency", 10, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m, err := shared.NewMoney(tt.cents, tt.currency)
			if tt.wantErr {
				if !errors.Is(err, shared.ErrValidation) {
					t.Fatalf("want ErrValidation, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if m.Cents() != tt.cents || m.Currency() != tt.currency {
				t.Fatalf("got %d %s", m.Cents(), m.Currency())
			}
			if m.IsZero() {
				t.Fatal("valid money reported zero")
			}
		})
	}
}

func TestMoneyZeroValue(t *testing.T) {
	t.Parallel()
	var m shared.Money
	if !m.IsZero() {
		t.Fatal("zero value should be zero")
	}
}

func TestValidationError(t *testing.T) {
	t.Parallel()
	err := shared.NewValidationError("field", "msg")
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatal("should match ErrValidation")
	}
	var ve *shared.ValidationError
	if !errors.As(err, &ve) {
		t.Fatal("should be a *ValidationError")
	}
	if ve.Field != "field" || ve.Msg != "msg" {
		t.Fatalf("unexpected fields: %+v", ve)
	}
	if got := err.Error(); got == "" {
		t.Fatal("empty error string")
	}
}

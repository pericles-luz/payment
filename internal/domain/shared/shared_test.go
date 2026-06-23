package shared_test

import (
	"errors"
	"math"
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

func TestAddCents(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		a, b    int64
		want    int64
		wantErr bool
	}{
		{"zero", 0, 0, 0, false},
		{"small", 1000, 250, 1250, false},
		{"max boundary ok", math.MaxInt64 - 1, 1, math.MaxInt64, false},
		{"positive overflow", math.MaxInt64, 1, 0, true},
		{"positive overflow large", math.MaxInt64, math.MaxInt64, 0, true},
		{"min boundary ok", math.MinInt64 + 1, -1, math.MinInt64, false},
		{"negative overflow", math.MinInt64, -1, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := shared.AddCents(tt.a, tt.b)
			if tt.wantErr {
				if !errors.Is(err, shared.ErrValidation) {
					t.Fatalf("want ErrValidation, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("AddCents(%d,%d) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestSumCents(t *testing.T) {
	t.Parallel()
	t.Run("empty is zero", func(t *testing.T) {
		t.Parallel()
		got, err := shared.SumCents()
		if err != nil || got != 0 {
			t.Fatalf("SumCents() = %d, %v; want 0, nil", got, err)
		}
	})
	t.Run("sums positives", func(t *testing.T) {
		t.Parallel()
		got, err := shared.SumCents(1000, 250, 50)
		if err != nil || got != 1300 {
			t.Fatalf("SumCents() = %d, %v; want 1300, nil", got, err)
		}
	})
	t.Run("rejects mid-fold overflow that would wrap positive", func(t *testing.T) {
		t.Parallel()
		// Each item is a valid positive amount, but the running sum wraps past
		// math.MaxInt64 — without a checked add it would land on a small
		// positive value (here 3) and pass NewMoney's `<= 0` guard.
		_, err := shared.SumCents(math.MaxInt64, math.MaxInt64, 5)
		if !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("want ErrValidation, got %v", err)
		}
	})
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

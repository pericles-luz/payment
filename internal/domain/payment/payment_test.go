package payment_test

import (
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/payment"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

func mustMoney(t *testing.T) shared.Money {
	t.Helper()
	m, err := shared.NewMoney(1000, "BRL")
	if err != nil {
		t.Fatalf("money: %v", err)
	}
	return m
}

func TestNewPaymentValidation(t *testing.T) {
	t.Parallel()
	now := time.Unix(0, 0).UTC()
	money := mustMoney(t)
	tests := []struct {
		name, id, tenant, endpoint, idem string
		zeroMoney                        bool
		wantErr                          bool
	}{
		{name: "valid", id: "p1", tenant: "t1", endpoint: "pix.create", idem: "k1"},
		{name: "missing id", tenant: "t1", endpoint: "pix.create", idem: "k1", wantErr: true},
		{name: "missing tenant", id: "p1", endpoint: "pix.create", idem: "k1", wantErr: true},
		{name: "missing endpoint", id: "p1", tenant: "t1", idem: "k1", wantErr: true},
		{name: "missing idem", id: "p1", tenant: "t1", endpoint: "pix.create", wantErr: true},
		{name: "zero money", id: "p1", tenant: "t1", endpoint: "pix.create", idem: "k1", zeroMoney: true, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := money
			if tt.zeroMoney {
				m = shared.Money{}
			}
			p, err := payment.New(tt.id, tt.tenant, tt.endpoint, tt.idem, m, now)
			if tt.wantErr {
				if !errors.Is(err, shared.ErrValidation) {
					t.Fatalf("want ErrValidation, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if p.Status() != payment.StatusPending {
				t.Fatalf("new payment should be pending, got %s", p.Status())
			}
			if p.TenantID() != tt.tenant || p.Endpoint() != tt.endpoint || p.IdempotencyKey() != tt.idem {
				t.Fatal("field mismatch")
			}
		})
	}
}

func TestPaymentLifecycle(t *testing.T) {
	t.Parallel()
	now := time.Unix(0, 0).UTC()
	later := now.Add(time.Hour)
	build := func() *payment.Payment {
		p, err := payment.New("p1", "t1", "pix.create", "k1", mustMoney(t), now)
		if err != nil {
			t.Fatalf("new: %v", err)
		}
		return p
	}

	t.Run("mark paid", func(t *testing.T) {
		t.Parallel()
		p := build()
		if err := p.MarkPaid("tx1", later); err != nil {
			t.Fatalf("mark paid: %v", err)
		}
		if p.Status() != payment.StatusPaid || p.TxID() != "tx1" {
			t.Fatal("not settled")
		}
		if !p.UpdatedAt().Equal(later) {
			t.Fatal("updatedAt not bumped")
		}
	})

	t.Run("mark paid requires tx", func(t *testing.T) {
		t.Parallel()
		p := build()
		if err := p.MarkPaid("  ", later); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("want validation, got %v", err)
		}
	})

	t.Run("idempotent re-settle same tx", func(t *testing.T) {
		t.Parallel()
		p := build()
		_ = p.MarkPaid("tx1", later)
		if err := p.MarkPaid("tx1", later); err != nil {
			t.Fatalf("idempotent replay should succeed: %v", err)
		}
	})

	t.Run("conflict re-settle different tx", func(t *testing.T) {
		t.Parallel()
		p := build()
		_ = p.MarkPaid("tx1", later)
		if err := p.MarkPaid("tx2", later); !errors.Is(err, shared.ErrConflict) {
			t.Fatalf("want conflict, got %v", err)
		}
	})

	t.Run("cannot pay canceled", func(t *testing.T) {
		t.Parallel()
		p := build()
		if err := p.Cancel(later); err != nil {
			t.Fatalf("cancel: %v", err)
		}
		if p.Status() != payment.StatusCanceled {
			t.Fatal("not canceled")
		}
		if err := p.MarkPaid("tx1", later); !errors.Is(err, shared.ErrInvalidTransition) {
			t.Fatalf("want invalid transition, got %v", err)
		}
	})

	t.Run("cannot cancel paid", func(t *testing.T) {
		t.Parallel()
		p := build()
		_ = p.MarkPaid("tx1", later)
		if err := p.Cancel(later); !errors.Is(err, shared.ErrInvalidTransition) {
			t.Fatalf("want invalid transition, got %v", err)
		}
	})
}

func TestPaymentRehydrateAndSetTxID(t *testing.T) {
	t.Parallel()
	now := time.Unix(10, 0).UTC()
	p := payment.Rehydrate("p1", "t1", "pix.create", "k1", "tx1", mustMoney(t), payment.StatusPaid, now, now)
	if p.ID() != "p1" || p.TxID() != "tx1" || p.Status() != payment.StatusPaid {
		t.Fatal("rehydrate mismatch")
	}
	if !p.CreatedAt().Equal(now) {
		t.Fatal("createdAt mismatch")
	}
	p.SetTxID(" tx9 ")
	if p.TxID() != "tx9" {
		t.Fatalf("SetTxID did not trim: %q", p.TxID())
	}
}

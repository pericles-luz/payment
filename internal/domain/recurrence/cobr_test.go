package recurrence_test

import (
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/recurrence"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

func validCobRParams() recurrence.NewCobRParams {
	return recurrence.NewCobRParams{
		TxID:       "TX-1",
		IDRec:      "RR123",
		TenantID:   "tenant-1",
		Vencimento: "2026-07-10",
		ValorCents: 5000,
	}
}

func TestNewCobRValidation(t *testing.T) {
	base := validCobRParams()
	tests := []struct {
		name   string
		mutate func(p *recurrence.NewCobRParams)
	}{
		{"empty txid", func(p *recurrence.NewCobRParams) { p.TxID = "  " }},
		{"empty id_rec", func(p *recurrence.NewCobRParams) { p.IDRec = "" }},
		{"empty tenant", func(p *recurrence.NewCobRParams) { p.TenantID = "" }},
		{"bad vencimento", func(p *recurrence.NewCobRParams) { p.Vencimento = "10/07/2026" }},
		{"zero valor", func(p *recurrence.NewCobRParams) { p.ValorCents = 0 }},
		{"negative valor", func(p *recurrence.NewCobRParams) { p.ValorCents = -1 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := base
			tc.mutate(&p)
			if _, err := recurrence.NewCobR(p, at0); err == nil {
				t.Fatalf("want validation error, got nil")
			}
		})
	}
}

func TestNewCobROK(t *testing.T) {
	c, err := recurrence.NewCobR(validCobRParams(), at0)
	if err != nil {
		t.Fatalf("NewCobR: %v", err)
	}
	if c.Status() != recurrence.CobRCriada {
		t.Fatalf("status = %q, want CRIADA", c.Status())
	}
	if c.TxID() != "TX-1" || c.IDRec() != "RR123" || c.TenantID() != "tenant-1" {
		t.Fatalf("unexpected identity: %+v", c)
	}
	if c.Vencimento() != "2026-07-10" || c.ValorCents() != 5000 {
		t.Fatalf("unexpected fields: %+v", c)
	}
	if !c.CreatedAt().Equal(at0) || !c.UpdatedAt().Equal(at0) {
		t.Fatalf("timestamps not stamped")
	}
}

func TestCobRTransitions(t *testing.T) {
	at1 := at0.Add(time.Hour)
	tests := []struct {
		name      string
		from, to  recurrence.CobRStatus
		wantErr   error
		wantNoOp  bool
		wantState recurrence.CobRStatus
	}{
		{name: "criada→ativa", from: recurrence.CobRCriada, to: recurrence.CobRAtiva, wantState: recurrence.CobRAtiva},
		{name: "criada→concluida", from: recurrence.CobRCriada, to: recurrence.CobRConcluida, wantState: recurrence.CobRConcluida},
		{name: "criada→cancelada", from: recurrence.CobRCriada, to: recurrence.CobRCancelada, wantState: recurrence.CobRCancelada},
		{name: "ativa→concluida", from: recurrence.CobRAtiva, to: recurrence.CobRConcluida, wantState: recurrence.CobRConcluida},
		{name: "ativa→cancelada", from: recurrence.CobRAtiva, to: recurrence.CobRCancelada, wantState: recurrence.CobRCancelada},
		{name: "ativa→expirada", from: recurrence.CobRAtiva, to: recurrence.CobRExpirada, wantState: recurrence.CobRExpirada},
		{name: "ativa→rejeitada", from: recurrence.CobRAtiva, to: recurrence.CobRRejeitada, wantState: recurrence.CobRRejeitada},
		// A settled charge can never be un-settled, and a refused one can never be
		// quietly reclassified as cancelled — a replayed webhook must not rewrite either
		// (threat W3).
		{name: "concluida terminal", from: recurrence.CobRConcluida, to: recurrence.CobRCancelada, wantErr: shared.ErrInvalidTransition, wantState: recurrence.CobRConcluida},
		{name: "cancelada terminal", from: recurrence.CobRCancelada, to: recurrence.CobRConcluida, wantErr: shared.ErrInvalidTransition, wantState: recurrence.CobRCancelada},
		{name: "rejeitada terminal", from: recurrence.CobRRejeitada, to: recurrence.CobRCancelada, wantErr: shared.ErrInvalidTransition, wantState: recurrence.CobRRejeitada},
		{name: "expirada terminal", from: recurrence.CobRExpirada, to: recurrence.CobRConcluida, wantErr: shared.ErrInvalidTransition, wantState: recurrence.CobRExpirada},
		{name: "ativa→criada illegal", from: recurrence.CobRAtiva, to: recurrence.CobRCriada, wantErr: shared.ErrInvalidTransition, wantState: recurrence.CobRAtiva},
		{name: "same-status no-op", from: recurrence.CobRCriada, to: recurrence.CobRCriada, wantNoOp: true, wantState: recurrence.CobRCriada},
		{name: "unknown status", from: recurrence.CobRCriada, to: recurrence.CobRStatus("BOGUS"), wantErr: errSentinelValidation, wantState: recurrence.CobRCriada},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := chargeInState(t, tc.from)
			before := c.UpdatedAt()
			err := c.Transition(tc.to, at1)
			switch {
			case tc.wantErr == errSentinelValidation:
				var ve *shared.ValidationError
				if !errors.As(err, &ve) {
					t.Fatalf("want validation error, got %v", err)
				}
			case tc.wantErr != nil:
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("want %v, got %v", tc.wantErr, err)
				}
			default:
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
			if c.Status() != tc.wantState {
				t.Fatalf("state = %q, want %q", c.Status(), tc.wantState)
			}
			advanced := tc.wantErr == nil && !tc.wantNoOp
			if advanced && !c.UpdatedAt().Equal(at1) {
				t.Fatalf("updatedAt not advanced on legal transition")
			}
			if !advanced && !c.UpdatedAt().Equal(before) {
				t.Fatalf("updatedAt changed on no-op/illegal transition")
			}
		})
	}
}

func chargeInState(t *testing.T, s recurrence.CobRStatus) *recurrence.CobR {
	t.Helper()
	if s == recurrence.CobRCriada {
		c, err := recurrence.NewCobR(validCobRParams(), at0)
		if err != nil {
			t.Fatalf("NewCobR: %v", err)
		}
		return c
	}
	return recurrence.RehydrateCobR("TX-1", "RR123", "tenant-1", "2026-07-10", 5000, s, at0, at0)
}

package recurrence_test

import (
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/recurrence"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

var at0 = time.Date(2026, 6, 26, 12, 0, 0, 0, time.UTC)

func validDevedor(t *testing.T) recurrence.Devedor {
	t.Helper()
	d, err := recurrence.NewDevedor("12345678901", "Maria Pagadora")
	if err != nil {
		t.Fatalf("NewDevedor: %v", err)
	}
	return d
}

func validRecParams(t *testing.T) recurrence.NewRecParams {
	t.Helper()
	return recurrence.NewRecParams{
		IDRec:         "RR123",
		TenantID:      "tenant-1",
		BankID:        "c6",
		Contrato:      "contract-9",
		Devedor:       validDevedor(t),
		DataInicial:   "2026-07-01",
		Periodicidade: recurrence.RecMensal,
		ValorCents:    12345,
	}
}

func TestNewDevedor(t *testing.T) {
	tests := []struct {
		name, doc, nome string
		wantErr         bool
	}{
		{"valid CPF", "12345678901", "Ana", false},
		{"valid CNPJ", "12345678000199", "Empresa", false},
		{"short doc", "123", "Ana", true},
		{"non-digit doc", "1234567890a", "Ana", true},
		{"empty name", "12345678901", "  ", true},
		{"trims name", "12345678901", "  Ana  ", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, err := recurrence.NewDevedor(tc.doc, tc.nome)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if d.Doc() == "" || d.Nome() == "" {
				t.Fatalf("expected populated devedor, got %+v", d)
			}
		})
	}
}

func TestNewRecValidation(t *testing.T) {
	base := validRecParams(t)
	tests := []struct {
		name   string
		mutate func(p *recurrence.NewRecParams)
	}{
		{"empty id_rec", func(p *recurrence.NewRecParams) { p.IDRec = " " }},
		{"empty tenant", func(p *recurrence.NewRecParams) { p.TenantID = "" }},
		{"empty bank", func(p *recurrence.NewRecParams) { p.BankID = "" }},
		{"empty contrato", func(p *recurrence.NewRecParams) { p.Contrato = "" }},
		{"zero devedor", func(p *recurrence.NewRecParams) { p.Devedor = recurrence.Devedor{} }},
		{"bad data_inicial", func(p *recurrence.NewRecParams) { p.DataInicial = "2026-13-99" }},
		{"unknown periodicidade", func(p *recurrence.NewRecParams) { p.Periodicidade = "DAILY" }},
		{"negative valor", func(p *recurrence.NewRecParams) { p.ValorCents = -1 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := base
			tc.mutate(&p)
			if _, err := recurrence.NewRec(p, at0); err == nil {
				t.Fatalf("want validation error, got nil")
			}
		})
	}
}

func TestNewRecOK(t *testing.T) {
	r, err := recurrence.NewRec(validRecParams(t), at0)
	if err != nil {
		t.Fatalf("NewRec: %v", err)
	}
	if r.Status() != recurrence.RecCriada {
		t.Fatalf("status = %q, want CRIADA", r.Status())
	}
	if r.IDRec() != "RR123" || r.TenantID() != "tenant-1" || r.BankID() != "c6" {
		t.Fatalf("unexpected identity fields: %+v", r)
	}
	if r.Contrato() != "contract-9" || r.DataInicial() != "2026-07-01" {
		t.Fatalf("unexpected fields: %+v", r)
	}
	if r.Periodicidade() != recurrence.RecMensal || r.ValorCents() != 12345 {
		t.Fatalf("unexpected schedule/value: %+v", r)
	}
	if r.Devedor().Doc() != "12345678901" {
		t.Fatalf("unexpected devedor: %+v", r.Devedor())
	}
	if !r.CreatedAt().Equal(at0) || !r.UpdatedAt().Equal(at0) {
		t.Fatalf("timestamps not stamped: %v / %v", r.CreatedAt(), r.UpdatedAt())
	}
	// ValorCents == 0 is allowed (unspecified/variable mandate).
	p := validRecParams(t)
	p.ValorCents = 0
	if _, err := recurrence.NewRec(p, at0); err != nil {
		t.Fatalf("zero valor should be allowed: %v", err)
	}
}

func TestRecTransitions(t *testing.T) {
	at1 := at0.Add(time.Hour)
	tests := []struct {
		name      string
		from      recurrence.RecStatus
		to        recurrence.RecStatus
		wantErr   error // nil = legal advance; sentinel otherwise
		wantNoOp  bool  // same-status idempotent
		wantState recurrence.RecStatus
	}{
		{name: "criada→aprovada", from: recurrence.RecCriada, to: recurrence.RecAprovada, wantState: recurrence.RecAprovada},
		{name: "criada→rejeitada", from: recurrence.RecCriada, to: recurrence.RecRejeitada, wantState: recurrence.RecRejeitada},
		{name: "criada→expirada", from: recurrence.RecCriada, to: recurrence.RecExpirada, wantState: recurrence.RecExpirada},
		{name: "criada→cancelada", from: recurrence.RecCriada, to: recurrence.RecCancelada, wantState: recurrence.RecCancelada},
		{name: "aprovada→cancelada", from: recurrence.RecAprovada, to: recurrence.RecCancelada, wantState: recurrence.RecCancelada},
		{name: "aprovada→expirada", from: recurrence.RecAprovada, to: recurrence.RecExpirada, wantState: recurrence.RecExpirada},
		{name: "aprovada→criada illegal", from: recurrence.RecAprovada, to: recurrence.RecCriada, wantErr: shared.ErrInvalidTransition, wantState: recurrence.RecAprovada},
		{name: "aprovada→rejeitada illegal", from: recurrence.RecAprovada, to: recurrence.RecRejeitada, wantErr: shared.ErrInvalidTransition, wantState: recurrence.RecAprovada},
		{name: "cancelada terminal", from: recurrence.RecCancelada, to: recurrence.RecAprovada, wantErr: shared.ErrInvalidTransition, wantState: recurrence.RecCancelada},
		{name: "rejeitada terminal", from: recurrence.RecRejeitada, to: recurrence.RecAprovada, wantErr: shared.ErrInvalidTransition, wantState: recurrence.RecRejeitada},
		{name: "expirada terminal", from: recurrence.RecExpirada, to: recurrence.RecCancelada, wantErr: shared.ErrInvalidTransition, wantState: recurrence.RecExpirada},
		{name: "same-status no-op", from: recurrence.RecAprovada, to: recurrence.RecAprovada, wantNoOp: true, wantState: recurrence.RecAprovada},
		{name: "unknown status", from: recurrence.RecCriada, to: recurrence.RecStatus("BOGUS"), wantErr: errSentinelValidation, wantState: recurrence.RecCriada},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := mandateInState(t, tc.from)
			before := r.UpdatedAt()
			err := r.Transition(tc.to, at1)
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
			if r.Status() != tc.wantState {
				t.Fatalf("state = %q, want %q", r.Status(), tc.wantState)
			}
			advanced := tc.wantErr == nil && !tc.wantNoOp
			if advanced && !r.UpdatedAt().Equal(at1) {
				t.Fatalf("updatedAt not advanced on legal transition")
			}
			if !advanced && !r.UpdatedAt().Equal(before) {
				t.Fatalf("updatedAt changed on no-op/illegal transition")
			}
		})
	}
}

// errSentinelValidation is a marker telling the table the case expects a
// *shared.ValidationError (vs a sentinel matched by errors.Is).
var errSentinelValidation = errors.New("expect validation error")

// mandateInState builds a Rec and drives it to the requested status through legal
// transitions, so tests start from a real (not rehydrated) aggregate where
// possible. Terminal/aprovada states are reached via Rehydrate to avoid coupling
// the setup to the very transitions under test.
func mandateInState(t *testing.T, s recurrence.RecStatus) *recurrence.Rec {
	t.Helper()
	if s == recurrence.RecCriada {
		r, err := recurrence.NewRec(validRecParams(t), at0)
		if err != nil {
			t.Fatalf("NewRec: %v", err)
		}
		return r
	}
	return recurrence.RehydrateRec("RR123", "tenant-1", "c6", "contract-9",
		validDevedor(t), "2026-07-01", recurrence.RecMensal, 12345, s, at0, at0)
}

func TestRehydrateRecRoundTrip(t *testing.T) {
	d := validDevedor(t)
	updated := at0.Add(2 * time.Hour)
	r := recurrence.RehydrateRec("RRx", "tenant-9", "c6", "c-1", d,
		"2026-08-01", recurrence.RecAnual, 999, recurrence.RecAprovada, at0, updated)
	if r.IDRec() != "RRx" || r.TenantID() != "tenant-9" || r.Status() != recurrence.RecAprovada {
		t.Fatalf("rehydrate mismatch: %+v", r)
	}
	if r.Periodicidade() != recurrence.RecAnual || r.ValorCents() != 999 {
		t.Fatalf("rehydrate schedule/value mismatch: %+v", r)
	}
	if !r.UpdatedAt().Equal(updated) {
		t.Fatalf("rehydrate updatedAt mismatch")
	}
}

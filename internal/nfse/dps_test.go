package nfse

import (
	"errors"
	"testing"
	"time"
)

var testNow = time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)

func validParams() NewDPSParams {
	return NewDPSParams{
		EmitterCNPJ:       "47.064.135/0001-84",
		Series:            "1",
		Number:            "42",
		Competencia:       Competencia{Year: 2026, Month: 6},
		MunicipalityCode:  "3550308",
		Description:       "Serviços de consultoria",
		ServiceValueCents: 15000,
		Environment:       EnvHomologacao,
		Now:               testNow,
		ServiceCode:       "010501",
	}
}

func TestNewDPS(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*NewDPSParams)
		wantErr error
	}{
		{"valid", func(*NewDPSParams) {}, nil},
		{"strips cnpj formatting", func(p *NewDPSParams) { p.EmitterCNPJ = "47.064.135/0001-84" }, nil},
		{"empty emitter", func(p *NewDPSParams) { p.EmitterCNPJ = "" }, ErrEmptyEmitter},
		{"emitter no digits", func(p *NewDPSParams) { p.EmitterCNPJ = "abc" }, ErrEmptyEmitter},
		{"month zero", func(p *NewDPSParams) { p.Competencia.Month = 0 }, ErrInvalidCompetencia},
		{"month 13", func(p *NewDPSParams) { p.Competencia.Month = 13 }, ErrInvalidCompetencia},
		{"year too old", func(p *NewDPSParams) { p.Competencia.Year = 2022 }, ErrInvalidCompetencia},
		{"year future", func(p *NewDPSParams) { p.Competencia.Year = 2027 }, ErrInvalidCompetencia},
		{"zero value", func(p *NewDPSParams) { p.ServiceValueCents = 0 }, ErrNonPositiveValue},
		{"negative value", func(p *NewDPSParams) { p.ServiceValueCents = -1 }, ErrNonPositiveValue},
		{"blank description", func(p *NewDPSParams) { p.Description = "   " }, ErrEmptyDescription},
		{"short municipality", func(p *NewDPSParams) { p.MunicipalityCode = "35503" }, ErrInvalidMunicipality},
		{"long municipality", func(p *NewDPSParams) { p.MunicipalityCode = "355030899" }, ErrInvalidMunicipality},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := validParams()
			tc.mutate(&p)
			dps, err := NewDPS(p)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if dps.EmitterCNPJ != "47064135000184" {
				t.Errorf("emitter not normalised: %q", dps.EmitterCNPJ)
			}
			if dps.Environment != EnvHomologacao {
				t.Errorf("env = %d", dps.Environment)
			}
		})
	}
}

func TestNewDPSDefaultsEnvironmentAndClock(t *testing.T) {
	p := validParams()
	p.Environment = 0 // unset
	p.Now = time.Time{}
	// A current-year competência must still validate against the real clock.
	p.Competencia = Competencia{Year: time.Now().Year(), Month: 1}
	dps, err := NewDPS(p)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if dps.Environment != EnvHomologacao {
		t.Errorf("default env = %d, want homologação", dps.Environment)
	}
	if dps.EmittedAt.IsZero() {
		t.Error("EmittedAt should default to now")
	}
}

func TestFormatValor(t *testing.T) {
	tests := []struct {
		cents int64
		want  string
	}{
		{0, "0.00"},
		{1, "0.01"},
		{99, "0.99"},
		{100, "1.00"},
		{15000, "150.00"},
		{123456, "1234.56"},
		{-250, "-2.50"},
	}
	for _, tc := range tests {
		if got := formatValor(tc.cents); got != tc.want {
			t.Errorf("formatValor(%d) = %q, want %q", tc.cents, got, tc.want)
		}
	}
}

func TestCompetenciaFirstDay(t *testing.T) {
	c := Competencia{Year: 2026, Month: 6}
	if got := c.date().Format("2006-01-02"); got != "2026-06-01" {
		t.Errorf("date = %s", got)
	}
}

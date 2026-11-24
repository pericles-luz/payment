package nfse

import (
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"
)

func regimeParams(regime SimplesNacional, rateBps int) NewDPSParams {
	return NewDPSParams{
		EmitterCNPJ:       "47.064.135/0001-84",
		Series:            "1",
		Number:            "42",
		Competencia:       Competencia{Year: 2026, Month: 6},
		MunicipalityCode:  "2507507",
		Description:       "Licenciamento de software",
		ServiceValueCents: 15000,
		ServiceCode:       "010501",
		Regime:            regime,
		SimplesTaxRateBps: rateBps,
		Now:               time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC),
	}
}

func TestNewDPSRegimes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		regime  SimplesNacional
		rateBps int
		want    error
	}{
		{"MEI is the default", 0, 0, nil},
		{"MEI", SimplesMEI, 0, nil},
		{"MEI with a Simples rate (E0710)", SimplesMEI, 600, ErrInvalidSimplesTaxRate},
		{"ME/EPP with rate", SimplesMEEPP, 600, nil},
		{"ME/EPP without rate (E0712)", SimplesMEEPP, 0, ErrInvalidSimplesTaxRate},
		{"ME/EPP rate out of TSDec2V2", SimplesMEEPP, 10000, ErrInvalidSimplesTaxRate},
		{"não optante is out of scope", 1, 0, ErrInvalidRegime},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := NewDPS(regimeParams(tc.regime, tc.rateBps))
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if err == nil && tc.regime == 0 && d.Regime != SimplesMEI {
				t.Errorf("default regime = %d, want MEI", d.Regime)
			}
		})
	}
}

func TestNewDPSSchemaFields(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(*NewDPSParams)
		want error
	}{
		{"service code with 5 digits", func(p *NewDPSParams) { p.ServiceCode = "01050" }, ErrInvalidServiceCode},
		{"service code missing", func(p *NewDPSParams) { p.ServiceCode = "" }, ErrInvalidServiceCode},
		{"service code formatted is fine", func(p *NewDPSParams) { p.ServiceCode = "01.05.01" }, nil},
		{"number with leading zero", func(p *NewDPSParams) { p.Number = "042" }, ErrInvalidSeriesNumber},
		{"number too long", func(p *NewDPSParams) { p.Number = "1234567890123456" }, ErrInvalidSeriesNumber},
		{"series too long", func(p *NewDPSParams) { p.Series = "123456" }, ErrInvalidSeriesNumber},
		{"series with letters", func(p *NewDPSParams) { p.Series = "A1" }, ErrInvalidSeriesNumber},
		{"emitter municipality malformed", func(p *NewDPSParams) { p.EmitterMunicipalityCode = "123" }, ErrInvalidMunicipality},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := regimeParams(SimplesMEI, 0)
			tc.mut(&p)
			if _, err := NewDPS(p); !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestDPSIDLayout pins TSIdDPS: "DPS" + cLocEmi(7) + 2(CNPJ) + CNPJ(14) +
// série(5) + nDPS(15), zero-padded.
func TestDPSIDLayout(t *testing.T) {
	p := regimeParams(SimplesMEI, 0)
	p.EmitterMunicipalityCode = "3550308"
	d, err := NewDPS(p)
	if err != nil {
		t.Fatal(err)
	}
	id := dpsID(d)
	want := "DPS" + "3550308" + "2" + "47064135000184" + "00001" + "000000000000042"
	if id != want {
		t.Errorf("id = %s\nwant %s", id, want)
	}
	if !regexp.MustCompile(`^DPS[0-9]{42}$`).MatchString(id) {
		t.Errorf("id %q does not match TSIdDPS", id)
	}
}

func TestMarshalInfDPSByRegime(t *testing.T) {
	mei, _ := NewDPS(regimeParams(SimplesMEI, 0))
	meepp, _ := NewDPS(regimeParams(SimplesMEEPP, 600))
	meiXML, _ := marshalInfDPS(mei)
	meeppXML, _ := marshalInfDPS(meepp)

	for _, c := range []struct {
		name    string
		xml     string
		want    []string
		notWant []string
	}{
		{"MEI", string(meiXML),
			[]string{"<opSimpNac>2</opSimpNac><regEspTrib>0</regEspTrib>", "<totTrib><indTotTrib>0</indTotTrib></totTrib>", "<tpRetISSQN>1</tpRetISSQN>"},
			[]string{"regApTribSN", "pTotTribSN", "pAliq", "tribFed"}},
		{"ME/EPP", string(meeppXML),
			[]string{"<opSimpNac>3</opSimpNac><regApTribSN>1</regApTribSN><regEspTrib>0</regEspTrib>", "<totTrib><pTotTribSN>6.00</pTotTribSN></totTrib>"},
			[]string{"indTotTrib", "pAliq"}},
	} {
		for _, w := range c.want {
			if !strings.Contains(c.xml, w) {
				t.Errorf("%s: missing %s", c.name, w)
			}
		}
		for _, n := range c.notWant {
			if strings.Contains(c.xml, n) {
				t.Errorf("%s: must not contain %s", c.name, n)
			}
		}
	}
}

// TestInfDPSCanonicalCarriesNamespace: the Reference digest is computed over
// the Exclusive C14N of infDPS, which renders the visibly-utilized default
// namespace on the element itself.
func TestInfDPSCanonicalCarriesNamespace(t *testing.T) {
	d, _ := NewDPS(regimeParams(SimplesMEI, 0))
	inf, id := marshalInfDPS(d)
	want := `<infDPS xmlns="http://www.sped.fazenda.gov.br/nfse" Id="` + id + `">`
	if !strings.HasPrefix(string(inf), want) {
		t.Errorf("canonical infDPS starts %q, want %q", string(inf)[:80], want)
	}
}

// TestDhEmiBackdated: dhEmi is rendered in Brasília time and backdated so a
// clock slightly ahead of the Sefin's is not rejected with E0008.
func TestDhEmiBackdated(t *testing.T) {
	d, _ := NewDPS(regimeParams(SimplesMEI, 0))
	inf, _ := marshalInfDPS(d)
	if !strings.Contains(string(inf), "<dhEmi>2026-10-05T08:59:00-03:00</dhEmi>") {
		t.Errorf("dhEmi not backdated to Brasília time: %s", inf)
	}
}

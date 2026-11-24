package nfse

import (
	"regexp"
	"strings"
	"time"
)

// minCompetenciaYear is the earliest competência the ADN accepts. The NFS-e
// Nacional went live in 2023; anything before that is a client input error.
const minCompetenciaYear = 2023

// Competencia is the date a DPS refers to (dCompet). Day zero means "the
// month" and renders as its first day; a non-zero Day is an exact date — e.g.
// the emission date, which is how the portal nacional fills it in.
type Competencia struct {
	Year  int
	Month int
	Day   int
}

func (c Competencia) valid(now time.Time) bool {
	if c.Month < 1 || c.Month > 12 {
		return false
	}
	// A competência in a future calendar year cannot exist; the current year is
	// the upper bound (a MEI may declare an earlier month of the current year).
	if c.Year < minCompetenciaYear || c.Year > now.Year() {
		return false
	}
	if c.Day == 0 {
		return true
	}
	d := c.date()
	if d.Day() != c.Day || d.Month() != time.Month(c.Month) {
		return false // 31/02 and the like
	}
	// dCompet after the emission date is rejected by the Sefin.
	today := now.In(brt)
	return !d.After(time.Date(today.Year(), today.Month(), today.Day(), 0, 0, 0, 0, time.UTC))
}

// date returns dCompet: the exact day, or the first day of the month.
func (c Competencia) date() time.Time {
	day := c.Day
	if day == 0 {
		day = 1
	}
	return time.Date(c.Year, time.Month(c.Month), day, 0, 0, 0, 0, time.UTC)
}

// CompetenciaOn is the competência of the calendar day of t in Brasília time —
// the emission date, the portal nacional's default.
func CompetenciaOn(t time.Time) Competencia {
	b := t.In(brt)
	return Competencia{Year: b.Year(), Month: int(b.Month()), Day: b.Day()}
}

// DPS is the Declaração de Prestação de Serviços aggregate — the fiscal
// document a MEI emits per service. It is validated on construction so an
// invalid DPS can never be marshalled or signed. It is pure data: no transport,
// storage, or crypto concerns leak in here.
type DPS struct {
	// EmitterCNPJ is the 14-digit CNPJ of the MEI providing the service. Modelo
	// B requires it to equal the custodied certificate's holder (enforced by
	// the Emitter service, not here — the aggregate only knows its own value).
	EmitterCNPJ string
	// Series / Number identify the DPS within the emitter's sequence.
	Series string
	Number string
	// EmittedAt is the DPS emission instant (dhEmi).
	EmittedAt time.Time
	// Competencia is the service month (dCompet).
	Competencia Competencia
	// MunicipalityCode is the 7-digit IBGE code of the place of provision
	// (cLocPrestacao).
	MunicipalityCode string
	// Description is the discriminação do serviço (xDescServ).
	Description string
	// ServiceValueCents is the service value in cents (vServ), strictly
	// positive.
	ServiceValueCents int64
	// Environment is the ADN environment tag (tpAmb): 2 = homologação (this
	// round), 1 = produção (GA only).
	Environment Environment
	// EmitterMunicipalityCode is the 7-digit IBGE code of the emitting
	// establishment (cLocEmi); it also forms the DPS Id.
	EmitterMunicipalityCode string
	// ServiceCode is the national taxation code of the service (cTribNac,
	// 6 digits: LC 116 item + subitem + desdobro, e.g. 010501).
	ServiceCode string
	// Regime is the emitter's Simples Nacional situation (opSimpNac).
	Regime SimplesNacional
	// SimplesTaxRateBps is pTotTribSN — the approximate total tax rate of the
	// company's Simples Nacional bracket, in basis points (600 = 6,00%).
	// Required for ME/EPP (E0712 forbids indTotTrib), forbidden for MEI
	// (E0710).
	SimplesTaxRateBps int
	// Tomador is the service taker (toma); nil omits the group.
	Tomador *Tomador
	// MunicipalServiceCode is cTribMun (3 digits), the município's own
	// subdivision of the national code; empty omits it.
	MunicipalServiceCode string
	// NBSCode is cNBS (9 digits, Nomenclatura Brasileira de Serviços); empty
	// omits it.
	NBSCode string
}

// Tomador is the service taker (DPS toma). Document is a CPF (11 digits) or a
// CNPJ (14 digits); Name is the razão social / nome (xNome); Email is optional.
type Tomador struct {
	Document string
	Name     string
	Email    string
}

const (
	maxTomadorName  = 300 // TSRazaoSocial
	maxTomadorEmail = 80  // TSEmail
)

// normalize validates t and returns a copy with the document reduced to
// digits and the text fields trimmed.
func (t Tomador) normalize() (Tomador, error) {
	doc := onlyDigits(t.Document)
	name := strings.TrimSpace(t.Name)
	email := strings.TrimSpace(t.Email)
	if (len(doc) != 11 && len(doc) != 14) || name == "" || len([]rune(name)) > maxTomadorName ||
		len(email) > maxTomadorEmail || (email != "" && !strings.Contains(email, "@")) {
		return Tomador{}, ErrInvalidTomador
	}
	return Tomador{Document: doc, Name: name, Email: email}, nil
}

// SimplesNacional is the emitter's situation in the Simples Nacional
// (DPS prest/regTrib/opSimpNac). The product emits for the two Simples
// regimes; a não optante (opSimpNac=1) is out of scope and rejected.
type SimplesNacional int

const (
	// SimplesMEI is opSimpNac=2, the default.
	SimplesMEI SimplesNacional = 2
	// SimplesMEEPP is opSimpNac=3, micro or small company in the Simples,
	// with taxes collected through the Simples (regApTribSN=1).
	SimplesMEEPP SimplesNacional = 3
)

// maxSimplesTaxRateBps keeps pTotTribSN inside TSDec2V2 (< 100,00%).
const maxSimplesTaxRateBps = 9999

// dhEmiSkew backdates dhEmi: the Sefin rejects a DPS whose emission instant is
// after its own processing instant (E0008), so a clock a few seconds ahead of
// the government's would refuse every emission.
const dhEmiSkew = time.Minute

var (
	seriesRe      = regexp.MustCompile(`^0{0,4}\d{1,5}$`)
	numberRe      = regexp.MustCompile(`^[1-9][0-9]{0,14}$`)
	serviceCodeRe = regexp.MustCompile(`^[0-9]{6}$`)
	tribMunRe     = regexp.MustCompile(`^[0-9]{3}$`)
	nbsRe         = regexp.MustCompile(`^[0-9]{9}$`)
)

// Environment is the ADN tpAmb tag.
type Environment int

const (
	// EnvHomologacao is tpAmb=2 — the only environment this round targets.
	EnvHomologacao Environment = 2
	// EnvProducao is tpAmb=1 — GA only, gated on the KMS work.
	EnvProducao Environment = 1
)

// NewDPSParams carries the inputs for NewDPS. now is injectable for
// deterministic tests; when zero, EmittedAt/validation use the given clock.
type NewDPSParams struct {
	EmitterCNPJ       string
	Series            string
	Number            string
	Competencia       Competencia
	MunicipalityCode  string
	Description       string
	ServiceValueCents int64
	Environment       Environment
	Now               time.Time
	// EmitterMunicipalityCode defaults to MunicipalityCode.
	EmitterMunicipalityCode string
	ServiceCode             string
	// Regime defaults to SimplesMEI.
	Regime SimplesNacional
	// SimplesTaxRateBps is required for ME/EPP and must be zero for MEI.
	SimplesTaxRateBps int
	// Tomador is optional.
	Tomador *Tomador
	// MunicipalServiceCode (cTribMun, 3 digits) and NBSCode (cNBS, 9 digits)
	// are optional; punctuation is ignored.
	MunicipalServiceCode string
	NBSCode              string
}

// NewDPS builds and validates a DPS aggregate. It enforces the aggregate
// invariants (competência range, positive value, non-empty description, valid
// municipality) and returns a typed error on the first violation. The
// emitter-equals-certificate-holder invariant is enforced one layer up, in the
// Emitter service, where the certificate metadata is available.
func NewDPS(p NewDPSParams) (*DPS, error) {
	now := p.Now
	if now.IsZero() {
		now = time.Now()
	}
	emitter := onlyDigits(p.EmitterCNPJ)
	if emitter == "" {
		return nil, ErrEmptyEmitter
	}
	if !p.Competencia.valid(now) {
		return nil, ErrInvalidCompetencia
	}
	if p.ServiceValueCents <= 0 {
		return nil, ErrNonPositiveValue
	}
	if strings.TrimSpace(p.Description) == "" {
		return nil, ErrEmptyDescription
	}
	if len(onlyDigits(p.MunicipalityCode)) != 7 {
		return nil, ErrInvalidMunicipality
	}
	emitMun := onlyDigits(p.EmitterMunicipalityCode)
	if emitMun == "" {
		emitMun = onlyDigits(p.MunicipalityCode)
	}
	if len(emitMun) != 7 {
		return nil, ErrInvalidMunicipality
	}
	if !seriesRe.MatchString(p.Series) || !numberRe.MatchString(p.Number) {
		return nil, ErrInvalidSeriesNumber
	}
	service := onlyDigits(p.ServiceCode)
	if !serviceCodeRe.MatchString(service) {
		return nil, ErrInvalidServiceCode
	}
	regime := p.Regime
	if regime == 0 {
		regime = SimplesMEI
	}
	switch regime {
	case SimplesMEI:
		if p.SimplesTaxRateBps != 0 {
			return nil, ErrInvalidSimplesTaxRate
		}
	case SimplesMEEPP:
		if p.SimplesTaxRateBps <= 0 || p.SimplesTaxRateBps > maxSimplesTaxRateBps {
			return nil, ErrInvalidSimplesTaxRate
		}
	default:
		return nil, ErrInvalidRegime
	}
	tribMun := onlyDigits(p.MunicipalServiceCode)
	if tribMun != "" && !tribMunRe.MatchString(tribMun) {
		return nil, ErrInvalidServiceCode
	}
	nbs := onlyDigits(p.NBSCode)
	if nbs != "" && !nbsRe.MatchString(nbs) {
		return nil, ErrInvalidNBS
	}
	var toma *Tomador
	if p.Tomador != nil {
		t, err := p.Tomador.normalize()
		if err != nil {
			return nil, err
		}
		toma = &t
	}
	env := p.Environment
	if env == 0 {
		env = EnvHomologacao
	}
	return &DPS{
		EmitterCNPJ:       emitter,
		Series:            p.Series,
		Number:            p.Number,
		EmittedAt:         now.UTC().Add(-dhEmiSkew),
		Competencia:       p.Competencia,
		MunicipalityCode:  onlyDigits(p.MunicipalityCode),
		Description:       strings.TrimSpace(p.Description),
		ServiceValueCents: p.ServiceValueCents,
		Environment:       env,

		EmitterMunicipalityCode: emitMun,
		ServiceCode:             service,
		Regime:                  regime,
		SimplesTaxRateBps:       p.SimplesTaxRateBps,
		Tomador:                 toma,
		MunicipalServiceCode:    tribMun,
		NBSCode:                 nbs,
	}, nil
}

// onlyDigits strips every non-digit rune from s.
func onlyDigits(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

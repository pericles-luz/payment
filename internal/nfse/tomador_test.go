package nfse

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestTomadorInDPSXML(t *testing.T) {
	cases := []struct {
		name    string
		toma    Tomador
		want    []string
		wantNot []string
	}{
		{
			name: "cnpj with email",
			toma: Tomador{Document: "57.151.944/0001-87", Name: " Syndeotech & Cia ", Email: "fin@x.com"},
			want: []string{`<toma><CNPJ>57151944000187</CNPJ><xNome>Syndeotech &amp; Cia</xNome><email>fin@x.com</email></toma>`},
		},
		{
			name:    "cpf without email",
			toma:    Tomador{Document: "529.982.247-25", Name: "Fulano"},
			want:    []string{`<toma><CPF>52998224725</CPF><xNome>Fulano</xNome></toma>`},
			wantNot: []string{"<email>"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := validParams()
			toma := tc.toma
			p.Tomador = &toma
			dps, err := NewDPS(p)
			if err != nil {
				t.Fatalf("NewDPS: %v", err)
			}
			got, _ := marshalInfDPS(dps)
			s := string(got)
			for _, w := range tc.want {
				if !strings.Contains(s, w) {
					t.Errorf("missing %q in %s", w, s)
				}
			}
			for _, w := range tc.wantNot {
				if strings.Contains(s, w) {
					t.Errorf("unexpected %q in %s", w, s)
				}
			}
			if strings.Index(s, "</prest>") > strings.Index(s, "<toma>") || strings.Index(s, "</toma>") > strings.Index(s, "<serv>") {
				t.Errorf("toma out of schema order: %s", s)
			}
		})
	}
}

func TestDPSWithoutTomadorOmitsGroup(t *testing.T) {
	got, _ := marshalInfDPS(mustDPS(t))
	if strings.Contains(string(got), "<toma>") {
		t.Fatal("toma emitted without a tomador")
	}
}

func TestTomadorValidation(t *testing.T) {
	bad := []Tomador{
		{Document: "123", Name: "X"},
		{Document: "57151944000187", Name: "  "},
		{Document: "57151944000187", Name: strings.Repeat("a", maxTomadorName+1)},
		{Document: "57151944000187", Name: "X", Email: "sem-arroba"},
		{Document: "57151944000187", Name: "X", Email: strings.Repeat("a", maxTomadorEmail) + "@x"},
	}
	for i, toma := range bad {
		p := validParams()
		tt := toma
		p.Tomador = &tt
		if _, err := NewDPS(p); !errors.Is(err, ErrInvalidTomador) {
			t.Errorf("case %d: err = %v, want ErrInvalidTomador", i, err)
		}
	}
}

// memSequencer is a concurrency-safe Sequencer for the tests.
type memSequencer struct {
	mu    sync.Mutex
	next  map[string]int64
	err   error
	calls int
}

func (m *memSequencer) NextDPSNumber(_ context.Context, cnpj, series string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	if m.err != nil {
		return 0, m.err
	}
	if m.next == nil {
		m.next = map[string]int64{}
	}
	m.next[cnpj+"/"+series]++
	return m.next[cnpj+"/"+series], nil
}

func TestEmitAssignsNumberFromSequencer(t *testing.T) {
	tx := &fakeTransmitter{receipt: Receipt{ChaveAcesso: "k", NFSeNumber: "7", XML: []byte("<NFSe/>")}}
	seq := &memSequencer{}
	e, _ := provisionEmitter(t, testCNPJ, 24*time.Hour, tx, WithSequencer(seq))

	for want := 1; want <= 2; want++ {
		cmd := validCommand()
		cmd.Number = ""
		cmd.IdempotencyKey = "k" + string(rune('0'+want))
		cmd.Tomador = &Tomador{Document: "57151944000187", Name: "Syndeotech"}
		em, err := e.Emit(context.Background(), cmd)
		if err != nil {
			t.Fatalf("Emit: %v", err)
		}
		if em.Number != string(rune('0'+want)) || em.Series != "1" {
			t.Errorf("number = %q series = %q, want %d/1", em.Number, em.Series, want)
		}
		if em.TomadorDocument != "57151944000187" || em.TomadorName != "Syndeotech" {
			t.Errorf("tomador not recorded: %+v", em)
		}
		if string(em.XML) != "<NFSe/>" {
			t.Errorf("XML not kept: %q", em.XML)
		}
		if !strings.Contains(string(tx.lastXML), "<nDPS>"+em.Number+"</nDPS>") {
			t.Errorf("transmitted DPS lacks nDPS %s", em.Number)
		}
	}
}

func TestEmitNoNumberWithoutSequencer(t *testing.T) {
	e, _ := provisionEmitter(t, testCNPJ, 24*time.Hour, &fakeTransmitter{})
	cmd := validCommand()
	cmd.Number = ""
	if _, err := e.Emit(context.Background(), cmd); !errors.Is(err, ErrNoNumber) {
		t.Fatalf("err = %v, want ErrNoNumber", err)
	}
}

func TestEmitDoesNotConsumeNumberOnInvalidCommand(t *testing.T) {
	seq := &memSequencer{}
	e, _ := provisionEmitter(t, testCNPJ, 24*time.Hour, &fakeTransmitter{}, WithSequencer(seq))
	cmd := validCommand()
	cmd.Number = ""
	cmd.Description = ""
	if _, err := e.Emit(context.Background(), cmd); !errors.Is(err, ErrEmptyDescription) {
		t.Fatalf("err = %v", err)
	}
	if seq.calls != 0 {
		t.Errorf("sequencer consumed %d numbers on an invalid command", seq.calls)
	}
}

func TestEmitSequencerError(t *testing.T) {
	boom := errors.New("seq down")
	e, _ := provisionEmitter(t, testCNPJ, 24*time.Hour, &fakeTransmitter{}, WithSequencer(&memSequencer{err: boom}))
	cmd := validCommand()
	cmd.Number = ""
	cmd.IdempotencyKey = "seqfail"
	if _, err := e.Emit(context.Background(), cmd); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	// The reservation was released: a retry is not "in flight".
	e.seq = &memSequencer{}
	if _, err := e.Emit(context.Background(), cmd); err != nil {
		t.Fatalf("retry after release: %v", err)
	}
}

func TestEmitTakeoverReusesPinnedNumber(t *testing.T) {
	tx := &fakeTransmitter{receipt: Receipt{ChaveAcesso: "abc"}}
	seq := &memSequencer{}
	clock := testNow
	e, _ := provisionEmitter(t, testCNPJ, 24*time.Hour, tx, WithSequencer(seq), WithClock(func() time.Time { return clock }))
	cmd := validCommand()
	cmd.Number = ""
	cmd.IdempotencyKey = "idem-crash"
	// A crashed attempt that already pinned nDPS 99.
	if _, ok, err := e.store.Reserve(context.Background(), Emission{
		ID: "nfse_crashed", TenantID: cmd.TenantID, IdempotencyKey: cmd.IdempotencyKey,
		EmitterCNPJ: testCNPJ, Series: "1", Number: "99", Status: StatusPending, CreatedAt: clock,
	}, clock.Add(-reservationTTL)); err != nil || !ok {
		t.Fatalf("seed: ok=%v err=%v", ok, err)
	}
	clock = clock.Add(reservationTTL + time.Second)
	em, err := e.Emit(context.Background(), cmd)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if em.Number != "99" || seq.calls != 0 {
		t.Errorf("number = %s (seq calls %d), want the pinned 99 reused", em.Number, seq.calls)
	}
}

func TestCServOptionalCodes(t *testing.T) {
	p := validParams()
	p.MunicipalServiceCode = "001"
	p.NBSCode = "1.1106.20.00"
	dps, err := NewDPS(p)
	if err != nil {
		t.Fatalf("NewDPS: %v", err)
	}
	got, _ := marshalInfDPS(dps)
	want := `<cServ><cTribNac>` + dps.ServiceCode + `</cTribNac><cTribMun>001</cTribMun><xDescServ>`
	if !strings.Contains(string(got), want) || !strings.Contains(string(got), `</xDescServ><cNBS>111062000</cNBS></cServ>`) {
		t.Fatalf("cServ = %s", got)
	}
	plain, _ := marshalInfDPS(mustDPS(t))
	if strings.Contains(string(plain), "cTribMun") || strings.Contains(string(plain), "cNBS") {
		t.Fatalf("optional codes emitted when empty: %s", plain)
	}
	p = validParams()
	p.MunicipalServiceCode = "01"
	if _, err := NewDPS(p); !errors.Is(err, ErrInvalidServiceCode) {
		t.Errorf("bad cTribMun: %v", err)
	}
	p = validParams()
	p.NBSCode = "123"
	if _, err := NewDPS(p); !errors.Is(err, ErrInvalidNBS) {
		t.Errorf("bad cNBS: %v", err)
	}
}

func TestCompetenciaDay(t *testing.T) {
	// testNow is the clock of validParams; the emission day in BRT is valid,
	// the next day is not.
	today := CompetenciaOn(testNow)
	cases := []struct {
		name string
		c    Competencia
		ok   bool
		want string
	}{
		{"emission day", today, true, today.date().Format("2006-01-02")},
		{"month only", Competencia{Year: 2026, Month: 6}, true, "2026-06-01"},
		{"tomorrow", CompetenciaOn(testNow.Add(24 * time.Hour)), false, ""},
		{"31 feb", Competencia{Year: 2026, Month: 2, Day: 31}, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := validParams()
			p.Competencia = tc.c
			dps, err := NewDPS(p)
			if !tc.ok {
				if !errors.Is(err, ErrInvalidCompetencia) {
					t.Fatalf("err = %v, want ErrInvalidCompetencia", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewDPS: %v", err)
			}
			got, _ := marshalInfDPS(dps)
			if !strings.Contains(string(got), "<dCompet>"+tc.want+"</dCompet>") {
				t.Fatalf("dCompet missing %s: %s", tc.want, got)
			}
		})
	}
	late := time.Date(2026, 11, 5, 23, 30, 0, 0, brt) // 02:30 UTC of the 6th
	if c := CompetenciaOn(late); c.Day != 5 {
		t.Errorf("CompetenciaOn uses UTC day: %+v", c)
	}
}

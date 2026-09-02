package c6

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// stmtTestServer is a C6 + OAuth2 double exposing the extrato endpoint
// (GET /v1/statement with start_date/end_date) so the statement read path can be exercised.
type stmtTestServer struct {
	*httptest.Server
	lastQuery      url.Values
	lastAuthHeader string
	statusCode     int
	body           string
}

func newStmtTestServer(t *testing.T) *stmtTestServer {
	t.Helper()
	ts := &stmtTestServer{statusCode: http.StatusOK}
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		user, _, _ := r.BasicAuth()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok-` + user + `","token_type":"Bearer","expires_in":3600}`))
	})
	mux.HandleFunc("/v1/statement", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		ts.lastQuery = r.URL.Query()
		ts.lastAuthHeader = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(ts.statusCode)
		_, _ = w.Write([]byte(ts.body))
	})
	ts.Server = httptest.NewTLSServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

func (ts *stmtTestServer) provider(t *testing.T, creds ports.CredentialStore) *Provider {
	t.Helper()
	p, err := New(Config{
		BaseURL:    ts.URL,
		TokenURL:   ts.URL + "/oauth/token",
		HTTPClient: ts.Client(),
	}, creds)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

// O corpo abaixo é a resposta REAL do C6 em produção, capturada no fio em 02/09/2026 —
// o crédito das vendas no cartão caindo na conta. A entrada de débito foi acrescentada
// no mesmo formato para cobrir o outro sentido.
//
// Este teste existe porque o adaptador lia uma forma que o banco nunca mandou: `id`,
// `date`, `amount_cents`, `kind`. Nenhum desses nomes existe no fio, então TODO campo
// caía zerado, o `kind` vazio reprovava na revalidação de domínio, e a rota devolvia
// 400 em qualquer janela de datas. Fixar a forma inventada era pior do que não ter
// teste: dava confiança num caminho que nunca funcionou.
const extratoRealDoC6 = `{"entries":[
	{"external_id":"225614624409401844848161597951885097716","created_at":"2026-09-02T06:43:05Z",
	 "entry_date":"2026-09-02","amount":"37.29","title":"CRED LOJ C CREDITO",
	 "description":"CART. CREDIT - PAYGO ADMINISTR - Elo Cré","receipt":null,
	 "reference":"202609010000499095671","operation_type":"INCOMING","transaction_type":"OTHER"},
	{"external_id":"99","created_at":"2026-09-02T09:00:00Z","entry_date":"2026-09-02",
	 "amount":"1234.05","title":"TARIFA","description":"PACOTE MENSAL","receipt":null,
	 "reference":"2026090100004990000","operation_type":"OUTGOING","transaction_type":"OTHER"}
]}`

func TestGetStatementLeOFioRealDoC6(t *testing.T) {
	t.Parallel()
	ts := newStmtTestServer(t)
	ts.body = extratoRealDoC6
	p := ts.provider(t, oneTenant("t1", "client-1", "s"))

	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)
	st, err := p.GetStatement(context.Background(), "t1", ports.StatementFilter{Start: start, End: end})
	if err != nil {
		t.Fatalf("GetStatement: %v", err)
	}
	if ts.lastQuery.Get("start_date") != "2026-09-01" || ts.lastQuery.Get("end_date") != "2026-09-02" {
		t.Fatalf("janela não foi enviada como start_date/end_date: %v", ts.lastQuery)
	}
	if ts.lastAuthHeader != "Bearer tok-client-1" {
		t.Fatalf("bearer por tenant não foi anexado: %q", ts.lastAuthHeader)
	}
	if len(st.Entries) != 2 {
		t.Fatalf("entradas = %d, want 2: %+v", len(st.Entries), st.Entries)
	}

	credito := st.Entries[0]
	if credito.ID != "225614624409401844848161597951885097716" {
		t.Errorf("id veio de external_id? got %q", credito.ID)
	}
	// 37,29 em texto tem de virar 3729 centavos. Passar por float aqui é como se perde
	// um centavo que ninguém consegue explicar depois.
	if credito.AmountCents != 3729 {
		t.Errorf("amount = %d centavos, want 3729 (de \"37.29\")", credito.AmountCents)
	}
	if credito.Kind != "credit" {
		t.Errorf("INCOMING deveria virar credit, got %q", credito.Kind)
	}
	if credito.Date.Format("2006-01-02") != "2026-09-02" {
		t.Errorf("data veio de entry_date? got %s", credito.Date)
	}
	// As duas metades do histórico: quem concilia precisa da natureza E da origem.
	if !strings.Contains(credito.Description, "CRED LOJ C CREDITO") ||
		!strings.Contains(credito.Description, "PAYGO") {
		t.Errorf("histórico perdeu uma das metades: %q", credito.Description)
	}

	debito := st.Entries[1]
	if debito.Kind != "debit" {
		t.Errorf("OUTGOING deveria virar debit, got %q", debito.Kind)
	}
	if debito.AmountCents != 123405 {
		t.Errorf("amount = %d centavos, want 123405 (de \"1234.05\")", debito.AmountCents)
	}
}

// Tipo de operação desconhecido NÃO é chutado para crédito. Num extrato, errar o sinal
// é errar o saldo — melhor a leitura falhar visivelmente na revalidação de domínio do
// que classificar como entrada algo que talvez seja saída.
func TestGetStatementTipoDesconhecidoNaoViraCredito(t *testing.T) {
	t.Parallel()
	ts := newStmtTestServer(t)
	ts.body = `{"entries":[{"external_id":"x","entry_date":"2026-09-02","amount":"1.00",
		"title":"?","description":"?","operation_type":"ALGO_NOVO"}]}`
	p := ts.provider(t, oneTenant("t1", "c", "s"))

	st, err := p.GetStatement(context.Background(), "t1", ports.StatementFilter{
		Start: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
		End:   time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("GetStatement: %v", err)
	}
	if st.Entries[0].Kind != "" {
		t.Fatalf("tipo desconhecido virou %q em vez de vazio: o domínio precisa poder recusar", st.Entries[0].Kind)
	}
}

// Uma das metades do histórico ausente não pode deixar separador órfão.
func TestGetStatementHistoricoComUmaMetadeSo(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ nome, title, desc, quer string }{
		{"só título", "TARIFA", "", "TARIFA"},
		{"só descrição", "", "PACOTE", "PACOTE"},
		{"as duas", "TARIFA", "PACOTE", "TARIFA — PACOTE"},
	} {
		if got := stmtHistory(tc.title, tc.desc); got != tc.quer {
			t.Errorf("%s: got %q, want %q", tc.nome, got, tc.quer)
		}
	}
}

func TestGetStatementMissingWindow(t *testing.T) {
	t.Parallel()
	ts := newStmtTestServer(t)
	p := ts.provider(t, oneTenant("t1", "c", "s"))

	if _, err := p.GetStatement(context.Background(), "t1", ports.StatementFilter{End: time.Now()}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation for missing inicio, got %v", err)
	}
	if _, err := p.GetStatement(context.Background(), "t1", ports.StatementFilter{Start: time.Now()}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation for missing fim, got %v", err)
	}
}

func TestGetStatementUpstreamError(t *testing.T) {
	t.Parallel()
	ts := newStmtTestServer(t)
	ts.statusCode = http.StatusInternalServerError
	ts.body = `{}`
	p := ts.provider(t, oneTenant("t1", "c", "s"))

	_, err := p.GetStatement(context.Background(), "t1", ports.StatementFilter{
		Start: time.Now().Add(-time.Hour), End: time.Now(),
	})
	if !errors.Is(err, shared.ErrUnavailable) {
		t.Fatalf("want ErrUnavailable on 5xx, got %v", err)
	}
}

func TestGetStatementMalformedBody(t *testing.T) {
	t.Parallel()
	ts := newStmtTestServer(t)
	ts.body = `not-json`
	p := ts.provider(t, oneTenant("t1", "c", "s"))

	_, err := p.GetStatement(context.Background(), "t1", ports.StatementFilter{
		Start: time.Now().Add(-time.Hour), End: time.Now(),
	})
	if !errors.Is(err, shared.ErrUnavailable) {
		t.Fatalf("want ErrUnavailable on malformed body, got %v", err)
	}
}

func TestGetStatementUnknownTenantCredential(t *testing.T) {
	t.Parallel()
	ts := newStmtTestServer(t)
	ts.body = `{"entries":[]}`
	p := ts.provider(t, oneTenant("t1", "c", "s"))

	// A tenant with no credential cannot obtain a token → not-found from the store.
	if _, err := p.GetStatement(context.Background(), "other", ports.StatementFilter{
		Start: time.Now().Add(-time.Hour), End: time.Now(),
	}); err == nil {
		t.Fatal("missing credential must error (isolation)")
	}
}

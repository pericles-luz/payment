package http

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

// Um 500 sem log é indistinguível, de fora, de "a integração nunca foi chamada".
//
// Foi o que aconteceu: o gateway devolveu 500 dez vezes seguidas para um tenant e o
// journal não tinha uma única linha. A causa era um handshake mTLS com a identidade
// errada — que o log teria nomeado na primeira requisição. Custou uma hora.
//
// Estes testes fixam os dois lados do contrato: o erro não mapeado TEM de deixar
// rastro, e o rastro NÃO pode carregar a ref de capacidade que mora no caminho.

func captureSlog(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	fn()
	return buf.String()
}

// requestOnRoute builds a request already carrying a chi route context, as it would
// inside a handler the router dispatched to.
func requestOnRoute(method, pattern, path string) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	rc := chi.NewRouteContext()
	rc.RoutePatterns = []string{pattern}
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rc))
}

func TestUnmappedErrorIsLogged(t *testing.T) {
	const marker = "mtls handshake: certificate identity mismatch"
	rec := httptest.NewRecorder()
	req := requestOnRoute(http.MethodPost, "/v1/pix", "/v1/pix")

	logs := captureSlog(t, func() {
		writeDomainError(rec, req, errors.New(marker))
	})

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if !strings.Contains(logs, marker) {
		t.Fatalf("o 500 não deixou rastro: de fora isso é indistinguível de a integração\nnunca ter sido chamada; logs: %s", logs)
	}
	if !strings.Contains(logs, "/v1/pix") {
		t.Fatalf("a rota não aparece no log, então não dá para saber o que falhou; logs: %s", logs)
	}
	// O corpo continua genérico: quem diagnostica é o operador, não o cliente.
	if strings.Contains(rec.Body.String(), marker) {
		t.Fatalf("detalhe interno vazou na resposta: %s", rec.Body.String())
	}
}

// A ref no caminho do webhook É a credencial do tenant (ADR-0002/F4). Registrar
// r.URL.Path trocaria a cegueira por um vazamento — por isso o log usa o PADRÃO da rota.
func TestUnmappedErrorLogNeverLeaksTheWebhookRef(t *testing.T) {
	const ref = "SEGREDOsegredoSEGREDOsegredoSEGREDOsegredoXY"
	rec := httptest.NewRecorder()
	req := requestOnRoute(http.MethodPost, "/webhooks/c6/{tenantRef}", "/webhooks/c6/"+ref)

	logs := captureSlog(t, func() {
		writeDomainError(rec, req, errors.New("boom"))
	})

	if strings.Contains(logs, ref) {
		t.Fatalf("a ref de capacidade foi parar no log — é a credencial do tenant, e um\njournal não é lugar para ela; logs: %s", logs)
	}
	if !strings.Contains(logs, "/webhooks/c6/{tenantRef}") {
		t.Fatalf("sem o padrão da rota o log não diz o que falhou; logs: %s", logs)
	}
}

// Os desfechos ESPERADOS não registram: são de alto volume e já dizem ao cliente o que
// houve. Registrá-los seria ruído escondendo justamente o que importa.
func TestMappedErrorsAreNotLogged(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want int
	}{
		{"validação", shared.NewValidationError("campo", "obrigatório"), http.StatusBadRequest},
		{"não encontrado", shared.ErrNotFound, http.StatusNotFound},
		{"conflito", shared.ErrConflict, http.StatusConflict},
		{"escopo de tenant", shared.ErrTenantScope, http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := requestOnRoute(http.MethodGet, "/v1/charges/{id}", "/v1/charges/abc")

			logs := captureSlog(t, func() {
				writeDomainError(rec, req, tc.err)
			})

			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
			if strings.TrimSpace(logs) != "" {
				t.Fatalf("desfecho esperado virou linha de log; isso é o ruído que esconde o\n500 de verdade: %s", logs)
			}
		})
	}
}

package http

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

// errorBody is the generic error envelope. It never leaks internal detail
// (stack/SQL/secret) to the client (threat H5).
type errorBody struct {
	Error string `json:"error"`
}

// writeJSON encodes v as JSON with the given status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError writes a generic error envelope.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorBody{Error: msg})
}

// writeDomainError maps a domain error to a safe HTTP status + generic message, and
// LOGS the ones nobody mapped.
//
// O corpo da resposta continua genérico de propósito (ameaça H5) — o cliente não recebe
// pilha, SQL nem segredo. O problema era o outro lado: um erro que não casa com nenhum
// caso conhecido virava 500 e NÃO deixava rastro nenhum no servidor.
//
// Isso custou uma hora de diagnóstico em produção (SIN-69368). O gateway devolveu 500
// dez vezes seguidas para um tenant e o journal não tinha uma única linha; do lado de
// fora era indistinguível de "a integração não foi chamada". A causa era um handshake
// mTLS com a identidade errada, que o log teria nomeado na primeira requisição.
//
// Só o ramo default registra. Validação, não-encontrado e conflito são desfechos
// ESPERADOS, de alto volume, e já dizem ao cliente o que houve — registrá-los seria
// ruído que esconde justamente o que importa. O default é, por definição, o que
// ninguém previu.
func writeDomainError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, shared.ErrValidation):
		writeError(w, http.StatusBadRequest, "invalid request")
	case errors.Is(err, shared.ErrNotFound):
		writeError(w, http.StatusNotFound, "not found")
	case errors.Is(err, shared.ErrConflict):
		writeError(w, http.StatusConflict, "conflict")
	case errors.Is(err, shared.ErrTenantScope):
		// Surface as not-found to avoid confirming existence cross-tenant.
		writeError(w, http.StatusNotFound, "not found")
	default:
		slog.ErrorContext(r.Context(), "unmapped error, answering 500",
			slog.String("method", r.Method),
			slog.String("route", routePattern(r)),
			slog.String("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "internal error")
	}
}

// routePattern returns the chi ROUTE PATTERN ("/webhooks/c6/{tenantRef}"), never the
// raw path.
//
// A distinção é obrigatória, não estética: o caminho do webhook carrega a ref de
// capacidade do tenant no último segmento, e essa ref É a credencial (ADR-0002/F4).
// Registrar r.URL.Path colocaria um segredo vivo no journal — trocaria uma cegueira por
// um vazamento. O padrão nomeia a rota sem revelar nada.
func routePattern(r *http.Request) string {
	if rc := chi.RouteContext(r.Context()); rc != nil {
		if p := rc.RoutePattern(); p != "" {
			return p
		}
	}
	return "unknown"
}

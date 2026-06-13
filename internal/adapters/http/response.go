package http

import (
	"encoding/json"
	"errors"
	"net/http"

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

// writeDomainError maps a domain error to a safe HTTP status + generic message.
func writeDomainError(w http.ResponseWriter, err error) {
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
		writeError(w, http.StatusInternalServerError, "internal error")
	}
}

package nfse

import (
	"errors"
	"fmt"
	"strings"
)

// Domain sentinels. All are fail-closed and match with errors.Is so callers
// (the HTTP boundary) can branch without string matching.
var (
	// ErrEmptyEmitter is returned when the emitter CNPJ is missing.
	ErrEmptyEmitter = errors.New("nfse: emitter cnpj required")
	// ErrEmitterMismatch is the core Modelo B invariant: the DPS emitter must be
	// the holder of the custodied certificate. Signing a DPS whose emitter is
	// not the cert holder is denied before any signature is produced.
	ErrEmitterMismatch = errors.New("nfse: emitter cnpj does not match certificate holder")
	// ErrInvalidCompetencia is returned for an out-of-range competência (month
	// not in 1..12, or a year outside the accepted window).
	ErrInvalidCompetencia = errors.New("nfse: invalid competência")
	// ErrNonPositiveValue is returned when the service value is not strictly
	// positive.
	ErrNonPositiveValue = errors.New("nfse: service value must be positive")
	// ErrEmptyDescription is returned when the service description
	// (discriminação) is empty.
	ErrEmptyDescription = errors.New("nfse: service description required")
	// ErrInvalidMunicipality is returned when the IBGE municipality code is not
	// the expected 7 digits.
	ErrInvalidMunicipality = errors.New("nfse: municipality code must be 7 digits")
	// ErrInvalidSeriesNumber is returned when the DPS série (up to 5 digits)
	// or número (1-15 digits, no leading zero) is malformed.
	ErrInvalidSeriesNumber = errors.New("nfse: invalid DPS series or number")
	// ErrInvalidServiceCode is returned when cTribNac is not 6 digits.
	ErrInvalidServiceCode = errors.New("nfse: service code must be 6 digits (cTribNac) / 3 digits (cTribMun)")
	// ErrInvalidTomador is returned when the service taker has an invalid
	// CPF/CNPJ, an empty or oversized name, or an oversized e-mail.
	ErrInvalidTomador = errors.New("nfse: tomador must have a valid CPF/CNPJ and a name")
	// ErrDANFSeUnavailable is returned when the DANFSe (PDF) cannot be
	// obtained: no DANFSe endpoint configured, or the ADN has none for the key.
	ErrDANFSeUnavailable = errors.New("nfse: DANFSe unavailable")
	// ErrNoNumber is returned when the command carries no DPS number and the
	// emitter has no sequencer to assign one.
	ErrNoNumber = errors.New("nfse: DPS number required (no sequencer configured)")
	// ErrInvalidNBS is returned when cNBS is not 9 digits.
	ErrInvalidNBS = errors.New("nfse: NBS code (cNBS) must be 9 digits")
	// ErrInvalidRegime is returned for a regime other than MEI or ME/EPP.
	ErrInvalidRegime = errors.New("nfse: regime must be MEI or Simples Nacional ME/EPP")
	// ErrInvalidSimplesTaxRate is returned when the approximate Simples tax
	// rate (pTotTribSN) is missing or out of range for an ME/EPP, or given
	// for an MEI (the Sefin forbids it, E0710).
	ErrInvalidSimplesTaxRate = errors.New("nfse: simples tax rate is required for ME/EPP (0.01%-99.99%) and not allowed for MEI")
	// ErrNotFound is returned by Store.GetByID when no emission matches.
	ErrNotFound = errors.New("nfse: emission not found")
	// ErrNoCertificate is returned when the tenant has no A1 certificate on
	// file, so emission cannot proceed.
	ErrNoCertificate = errors.New("nfse: no certificate on file for tenant")
	// ErrCertExpired is returned when the custodied certificate is past its
	// validity; emission fails closed before reaching the ADN.
	ErrCertExpired = errors.New("nfse: certificate expired")
	// ErrEmissionInFlight is returned when another request holds a live
	// reservation for the same Idempotency-Key. The caller should retry after
	// the first request finishes; a retry then replays its result.
	ErrEmissionInFlight = errors.New("nfse: emission with this idempotency key is in flight")
	// ErrEmptyIdempotencyKey is returned by Store.Reserve for an empty key.
	ErrEmptyIdempotencyKey = errors.New("nfse: idempotency key required to reserve")
)

// BusinessError is an ADN business-rule rejection (e.g. duplicate DPS, invalid
// municipal registration). It is a TYPED error rather than an HTTP 200 with an
// HTML body — the lesson from the DASN "200 OK com HTML de erro" regression on
// master: the transport MUST surface a structured rejection the boundary can
// map to a 422, never a silent success.
type BusinessError struct {
	// HTTPStatus is the status the ADN returned (0 when the rejection was
	// carried in a 2xx JSON error envelope).
	HTTPStatus int
	// Items carries every code/message the ADN reported.
	Items []BusinessErrorItem
}

// BusinessErrorItem is a single ADN error entry.
type BusinessErrorItem struct {
	Code    string `json:"codigo"`
	Message string `json:"descricao"`
}

func (e *BusinessError) Error() string {
	if len(e.Items) == 0 {
		return fmt.Sprintf("nfse: ADN business rejection (status %d)", e.HTTPStatus)
	}
	parts := make([]string, 0, len(e.Items))
	for _, it := range e.Items {
		parts = append(parts, it.Code+": "+it.Message)
	}
	return "nfse: ADN business rejection: " + strings.Join(parts, "; ")
}

// AsBusinessError reports whether err is (or wraps) a *BusinessError.
func AsBusinessError(err error) (*BusinessError, bool) {
	var be *BusinessError
	if errors.As(err, &be) {
		return be, true
	}
	return nil, false
}

// TransportError wraps a non-business transport failure (connection, TLS,
// malformed non-JSON response) so the boundary can distinguish it from a
// business rejection and map it to a 502 rather than a 422.
type TransportError struct {
	Op  string
	Err error
}

func (e *TransportError) Error() string { return "nfse: adn transport: " + e.Op + ": " + e.Err.Error() }
func (e *TransportError) Unwrap() error { return e.Err }

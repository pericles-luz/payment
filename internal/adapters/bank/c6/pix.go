package c6

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// PIX immediate-charge (cobrança imediata) support for the C6 adapter.
//
// The lifecycle is: CreateImmediateCharge PUTs an idempotent charge keyed by a
// txid and gets back the QR code (copia-e-cola + render location) and expiry;
// GetImmediateCharge reconciles the authoritative status so settlement never
// trusts a raw webhook (reconcile-before-settle, threat W3).
//
// All PIX endpoints live here so the use-cases never speak HTTP/JSON or know the
// PSP's wire shape (Hexagonal). Security posture is inherited from the foundation
// (HTTPS-only, TLS>=1.2, per-tenant OAuth2 bearer, size-capped responses, no
// secret/PII in errors).

const (
	// defaultPixExpiry is the immediate-charge QR lifetime applied when the caller
	// passes a non-positive expiresIn.
	defaultPixExpiry = time.Hour

	// pixTxIDLen is the length of the derived txid. BACEN requires a txid of 26..35
	// characters from [a-zA-Z0-9]; a 32-char hex digest sits safely inside that
	// range and uses only [0-9a-f].
	pixTxIDLen = 32
)

// compile-time assertion that Provider satisfies the PIX port.
var _ ports.PixProvider = (*Provider)(nil)

// pixCalendario is the charge schedule. Expiracao is the QR lifetime in seconds;
// Criacao is the PSP-assigned creation instant (RFC3339), present on reads.
type pixCalendario struct {
	Criacao   string `json:"criacao,omitempty"`
	Expiracao int64  `json:"expiracao"`
}

// pixValor carries the charge amount as the BACEN decimal string ("10.00").
type pixValor struct {
	Original string `json:"original"`
}

// pixReceipt is one received PIX transaction inside a charge's pix[] array. Each
// carries the amount actually received as a BACEN decimal string ("10.00"); a
// CONCLUIDA charge may carry one or more. Only valor is consumed — the endToEndId,
// payer and timestamps are unmodelled on purpose.
type pixReceipt struct {
	Valor string `json:"valor"`
}

// pixLoc is the QR-code location descriptor returned by the PSP.
type pixLoc struct {
	Location string `json:"location"`
}

// pixDevedor identifies the payer (devedor) on an immediate PIX charge. C6/BACEN
// names the document field cpf OR cnpj by length; nome is the payer's name. The
// fields are omitempty so a charge with no devedor sends no devedor block.
type pixDevedor struct {
	CPF  string `json:"cpf,omitempty"`
	CNPJ string `json:"cnpj,omitempty"`
	Nome string `json:"nome,omitempty"`
}

// pixChargeRequestBody is the JSON sent to C6 to create an immediate PIX charge.
// Devedor is optional (a charge may omit the payer); it is omitted from the wire
// when nil.
type pixChargeRequestBody struct {
	Calendario pixCalendario `json:"calendario"`
	Devedor    *pixDevedor   `json:"devedor,omitempty"`
	Valor      pixValor      `json:"valor"`
}

// buildDevedor maps the request's optional devedor fields into the PSP block, or
// returns nil when no payer was supplied. The document is placed in cpf or cnpj by
// length (14 ⇒ CNPJ, otherwise CPF): the use-case has already validated the id is
// an 11- or 14-digit string before it reaches here, so no further check is needed.
func buildDevedor(req ports.ChargeRequest) *pixDevedor {
	taxID := strings.TrimSpace(req.DebtorTaxID)
	name := strings.TrimSpace(req.DebtorName)
	if taxID == "" && name == "" {
		return nil
	}
	d := &pixDevedor{Nome: name}
	if len(taxID) == 14 {
		d.CNPJ = taxID
	} else {
		d.CPF = taxID
	}
	return d
}

// pixChargeResponseBody is the subset of C6's PIX charge representation we
// consume. Human-readable / unmodelled fields are ignored on purpose.
type pixChargeResponseBody struct {
	TxID          string        `json:"txid"`
	Status        string        `json:"status"`
	Calendario    pixCalendario `json:"calendario"`
	Valor         pixValor      `json:"valor"`
	Loc           pixLoc        `json:"loc"`
	PixCopiaECola string        `json:"pixCopiaECola"`
	// Pix is the list of received transactions, present once the charge has been
	// paid (CONCLUIDA). Reconciliation sums each receipt's valor to learn how much
	// was actually received versus valor.original.
	Pix []pixReceipt `json:"pix"`
}

// CreateImmediateCharge creates an immediate PIX charge at C6 via an idempotent
// PUT on /v1/pix/{txid}. The txid is derived deterministically from the request's
// idempotency anchor (IdempotencyKey, falling back to PaymentID), so a re-submit
// targets the very same resource and the PSP returns the existing charge rather
// than creating a duplicate. The caller's idempotency key is additionally
// forwarded as the Idempotency-Key header (F3b defense-in-depth, SIN-64720).
func (p *Provider) CreateImmediateCharge(ctx context.Context, tenantID string, req ports.ChargeRequest, expiresIn time.Duration) (ports.PixChargeResult, error) {
	token, err := p.tokens.token(ctx, tenantID)
	if err != nil {
		return ports.PixChargeResult{}, err
	}

	// Complete mediation at the money-movement seam: refuse to derive a txid from
	// an empty idempotency anchor. idempotencyKey(req) is "" only when BOTH
	// IdempotencyKey and PaymentID are empty; deriving from "" would make every
	// such charge share the constant txid sha256("")[:32], so two distinct charges
	// would collide on the idempotent PUT and the PSP would return the first one —
	// a silent wrong-amount. Fail securely here rather than trusting upstream to
	// always supply an anchor. Likewise reject a non-positive amount at the
	// boundary: there is no domain guard upstream and a <=0 valor is never a valid
	// PIX charge (SIN-64769, SEC-1/SEC-3).
	if idempotencyKey(req) == "" {
		return ports.PixChargeResult{}, &Error{Op: "create_pix", sentinel: shared.ErrValidation}
	}
	if req.AmountCents <= 0 {
		return ports.PixChargeResult{}, &Error{Op: "create_pix", sentinel: shared.ErrValidation}
	}

	if expiresIn <= 0 {
		expiresIn = defaultPixExpiry
	}
	txid := pixTxID(req)

	payload, err := json.Marshal(pixChargeRequestBody{
		Calendario: pixCalendario{Expiracao: int64(expiresIn / time.Second)},
		Devedor:    buildDevedor(req),
		Valor:      pixValor{Original: formatAmount(req.AmountCents)},
	})
	if err != nil {
		return ports.PixChargeResult{}, &Error{Op: "create_pix", sentinel: shared.ErrValidation}
	}

	endpoint := p.baseURL + "/v1/pix/" + url.PathEscape(txid)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(payload))
	if err != nil {
		return ports.PixChargeResult{}, transportError("create_pix")
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	if idem := idempotencyKey(req); idem != "" {
		httpReq.Header.Set("Idempotency-Key", idem)
	}

	var out pixChargeResponseBody
	if err := p.do(httpReq, "create_pix", &out); err != nil {
		return ports.PixChargeResult{}, err
	}
	return p.toPixResult(out, "create_pix")
}

// GetImmediateCharge reconciles the authoritative state of a PIX charge from C6.
// This is the source of truth for settlement: a webhook may announce a payment,
// but the charge status (and whether it expired) is always read back here, never
// trusted from the raw event (reconcile-before-settle, threat W3).
func (p *Provider) GetImmediateCharge(ctx context.Context, tenantID, txID string) (ports.PixChargeResult, error) {
	token, err := p.tokens.token(ctx, tenantID)
	if err != nil {
		return ports.PixChargeResult{}, err
	}

	endpoint := p.baseURL + "/v1/pix/" + url.PathEscape(txID)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return ports.PixChargeResult{}, transportError("get_pix")
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Accept", "application/json")

	var out pixChargeResponseBody
	if err := p.do(httpReq, "get_pix", &out); err != nil {
		return ports.PixChargeResult{}, err
	}
	return p.toPixResult(out, "get_pix")
}

// pixListResponseBody is the subset of C6's immediate-charge list (GET /v1/pix,
// the BACEN /cob list) we consume: the pagination block and the cobs array. Each
// cob reuses the single-charge wire shape so toPixResult maps it identically.
type pixListResponseBody struct {
	Parametros struct {
		Paginacao struct {
			PaginaAtual            int `json:"paginaAtual"`
			ItensPorPagina         int `json:"itensPorPagina"`
			QuantidadeDePaginas    int `json:"quantidadeDePaginas"`
			QuantidadeTotalDeItens int `json:"quantidadeTotalDeItens"`
		} `json:"paginacao"`
	} `json:"parametros"`
	Cobs []pixChargeResponseBody `json:"cobs"`
}

// ListImmediateCharges lists the immediate PIX charges created within [Start,End]
// via GET /v1/pix?inicio=…&fim=… (BACEN cob list, roteiro 7.4). The window bounds
// are mandatory and rendered as RFC3339 UTC instants; pagination is forwarded only
// when supplied. Like the single-charge reads this is fail-secure on the money: a
// malformed amount in any cob maps to ErrUnavailable rather than reconciling to
// zero.
func (p *Provider) ListImmediateCharges(ctx context.Context, tenantID string, filter ports.PixListFilter) (ports.PixChargeList, error) {
	if filter.Start.IsZero() || filter.End.IsZero() {
		return ports.PixChargeList{}, &Error{Op: "list_pix", sentinel: shared.ErrValidation}
	}
	token, err := p.tokens.token(ctx, tenantID)
	if err != nil {
		return ports.PixChargeList{}, err
	}

	q := url.Values{}
	q.Set("inicio", filter.Start.UTC().Format(time.RFC3339))
	q.Set("fim", filter.End.UTC().Format(time.RFC3339))
	if filter.Page > 0 {
		q.Set("paginacao.paginaAtual", strconv.Itoa(filter.Page))
	}
	if filter.PageSize > 0 {
		q.Set("paginacao.itensPorPagina", strconv.Itoa(filter.PageSize))
	}

	endpoint := p.baseURL + "/v1/pix?" + q.Encode()
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return ports.PixChargeList{}, transportError("list_pix")
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Accept", "application/json")

	var out pixListResponseBody
	if err := p.do(httpReq, "list_pix", &out); err != nil {
		return ports.PixChargeList{}, err
	}

	charges := make([]ports.PixChargeResult, 0, len(out.Cobs))
	for _, cob := range out.Cobs {
		r, err := p.toPixResult(cob, "list_pix")
		if err != nil {
			return ports.PixChargeList{}, err
		}
		charges = append(charges, r)
	}
	return ports.PixChargeList{
		Charges:    charges,
		Page:       out.Parametros.Paginacao.PaginaAtual,
		PageSize:   out.Parametros.Paginacao.ItensPorPagina,
		TotalItems: out.Parametros.Paginacao.QuantidadeTotalDeItens,
		TotalPages: out.Parametros.Paginacao.QuantidadeDePaginas,
	}, nil
}

// toPixResult maps the PSP wire shape into the port result, computing the QR
// expiry from the charge calendar and reconciling the money: valor.original is
// the expected amount and the sum of the pix[] receipts is what was received.
//
// Amount parsing is fail-secure for settlement. An absent amount (empty string)
// reconciles to zero cents — an unpaid charge carries no receipts and a create
// response need not echo valor — and AmountReconciled then refuses to settle. A
// present-but-malformed amount, however, is a corrupt money field we must not
// silently read as zero, so it maps to ErrUnavailable (malformed upstream body),
// matching how a malformed 2xx body is already handled.
func (p *Provider) toPixResult(b pixChargeResponseBody, op string) (ports.PixChargeResult, error) {
	expected, err := parseAmountCents(b.Valor.Original)
	if err != nil {
		return ports.PixChargeResult{}, &Error{Op: op, sentinel: shared.ErrUnavailable}
	}
	var received int64
	for _, r := range b.Pix {
		amount, err := parseAmountCents(r.Valor)
		if err != nil {
			return ports.PixChargeResult{}, &Error{Op: op, sentinel: shared.ErrUnavailable}
		}
		received += amount
	}
	return ports.PixChargeResult{
		TxID:                b.TxID,
		Status:              b.Status,
		QRCodePayload:       b.PixCopiaECola,
		QRCodeLocation:      b.Loc.Location,
		ExpiresAt:           p.pixExpiresAt(b.Calendario),
		ExpectedAmountCents: expected,
		ReceivedAmountCents: received,
	}, nil
}

// maxAmountReais is the per-charge sanity ceiling on the integer (reais) part of
// an amount. cents = ip*100 + fp can integer-overflow int64 for absurd magnitudes
// (ip ≳ 9.2e16), wrapping a huge positive amount to a negative one; fail-secure
// cushions it (a negative expected fails AmountReconciled's >0 guard) but we
// reject it explicitly so a corrupt/oversized money field is denied at the parse
// boundary rather than relying on a downstream guard. R$1e12 (→ 1e14 cents) sits
// far below the int64 ceiling and far above any legitimate single charge.
const maxAmountReais = 1_000_000_000_000

// parseAmountCents parses a BACEN decimal amount string ("10.50") into integer
// cents (1050). It is the inverse of formatAmount and tolerates 0..2 fractional
// digits. An empty string yields zero cents with no error (the amount was not
// reported); any other malformed input — including a magnitude above the
// per-charge ceiling — is an error so callers never read corrupt money as zero.
func parseAmountCents(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	intPart, fracPart := s, ""
	if i := strings.IndexByte(s, '.'); i >= 0 {
		intPart, fracPart = s[:i], s[i+1:]
	}
	if intPart == "" || len(fracPart) > 2 {
		return 0, fmt.Errorf("malformed amount %q", s)
	}
	ip, err := strconv.ParseInt(intPart, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("malformed amount %q: %w", s, err)
	}
	if ip > maxAmountReais {
		return 0, fmt.Errorf("amount %q exceeds per-charge ceiling", s)
	}
	var fp int64
	if fracPart != "" {
		// Pad to 2 digits so "10.5" -> 50 cents, "10.05" -> 5 cents.
		for len(fracPart) < 2 {
			fracPart += "0"
		}
		if fp, err = strconv.ParseInt(fracPart, 10, 64); err != nil {
			return 0, fmt.Errorf("malformed amount %q: %w", s, err)
		}
	}
	cents := ip*100 + fp
	if neg {
		cents = -cents
	}
	return cents, nil
}

// pixExpiresAt derives the QR expiry instant: the PSP-assigned creation time plus
// the expiracao window. When the PSP omits the creation timestamp (e.g. on the
// create response) the adapter clock is used as the base. A non-positive window
// yields the zero time, signalling "no expiry reported".
func (p *Provider) pixExpiresAt(c pixCalendario) time.Time {
	if c.Expiracao <= 0 {
		return time.Time{}
	}
	base := p.now()
	if c.Criacao != "" {
		if t, err := time.Parse(time.RFC3339, c.Criacao); err == nil {
			base = t
		}
	}
	return base.Add(time.Duration(c.Expiracao) * time.Second)
}

// pixTxID derives a BACEN-valid (26..35 chars, [a-zA-Z0-9]) txid from the
// request's idempotency anchor. Being deterministic, it makes the create PUT
// idempotent end-to-end: the same anchor always addresses the same charge.
func pixTxID(req ports.ChargeRequest) string {
	sum := sha256.Sum256([]byte(idempotencyKey(req)))
	return hex.EncodeToString(sum[:])[:pixTxIDLen]
}

// formatAmount renders integer cents as the BACEN decimal string (e.g. 1050 ->
// "10.50"), matching the PIX valor.original contract.
func formatAmount(cents int64) string {
	sign := ""
	if cents < 0 {
		sign = "-"
		cents = -cents
	}
	return fmt.Sprintf("%s%d.%02d", sign, cents/100, cents%100)
}

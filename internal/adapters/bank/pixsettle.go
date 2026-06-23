package bank

import (
	"context"
	"strings"

	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// pixStatusConcluida is the BACEN immediate-charge (cobrança imediata) terminal
// status that means the charge was fully paid. It is the only PIX charge status
// that maps to a settled generic charge.
const pixStatusConcluida = "CONCLUIDA"

// genericStatusPaid is the generic charge status the webhook settlement gate
// treats as payable (it mirrors app.bankStatusPaid, the verbatim "paid" the
// ports.ChargeResult doc names as the generic settled status). The BACEN PIX
// terminal status is translated to it so the generic settlement path can settle a
// CONCLUIDA PIX charge without the app layer learning the BACEN status vocabulary.
const genericStatusPaid = "paid"

// PixSettlementProvider routes the generic settlement *reconcile read* of a
// BankProvider through the BACEN-verified PIX immediate-charge read.
//
// Per the SIN-64780 routing decision (CTO, SIN-64791): C6 settlement reconciles
// against GET …/v1/pix/{txid} (valor.original + pix[] receipts — BACEN-normative
// and already verified by the PIX adapter + pix_test.go), NOT the speculative
// generic GET /charges/{txid}. The generic /charges create/read seam was invented
// (its request body {payment_id, amount_cents, currency} is proprietary, so its
// assumed response shape has zero contract backing); it survives as the abstract
// provider port for a future non-PIX rail but is not the settlement reconcile
// source for C6 at launch.
//
// The wrapper embeds the generic BankProvider so charge creation (and any other
// use of the port) is untouched, and overrides only GetCharge — the settlement
// reconcile read — to read the PIX charge and translate it into a generic
// ChargeResult. parseAmountCents and the receipts sum stay in the PIX adapter,
// shared and fail-secure: a missing/zero read amount reconciles to zero cents and
// the settlement path then refuses to settle (reconcile-before-settle, threat W3).
type PixSettlementProvider struct {
	ports.BankProvider                   // create + the default (unused) charge surface
	pix                ports.PixProvider // settlement reconcile read source
}

// compile-time assertion the wrapper still satisfies the bank port.
var _ ports.BankProvider = (*PixSettlementProvider)(nil)

// NewPixSettlementProvider wraps generic (used for charge creation and as the
// default surface) and pix (used for the settlement reconcile read). Both are
// typically the same concrete C6 provider, which satisfies both ports.
func NewPixSettlementProvider(generic ports.BankProvider, pix ports.PixProvider) *PixSettlementProvider {
	return &PixSettlementProvider{BankProvider: generic, pix: pix}
}

// InvalidateToken forwards a credential-cache eviction to the wrapped provider
// when it supports one (the C6 adapter caches per-tenant OAuth2 tokens and does),
// closing the token-revocation lag (ADR-0003) even though this settlement
// decorator sits in front of the real provider. It is a no-op when the wrapped
// provider exposes no such cache. The decorator always satisfies
// ports.CredentialInvalidator; the wiring only wraps the real C6 provider (the
// stub is returned unwrapped), so a type assertion on the assembled provider
// still distinguishes "has a cache to evict" from the cacheless stub.
func (p *PixSettlementProvider) InvalidateToken(tenantID string) {
	if inv, ok := p.BankProvider.(ports.CredentialInvalidator); ok {
		inv.InvalidateToken(tenantID)
	}
}

// GetCharge reconciles the authoritative charge state via the PIX immediate-charge
// read and maps it onto the generic ChargeResult the settlement path consumes.
//
// The BACEN terminal status CONCLUIDA is translated to the generic settled status
// ("paid"); every other PIX status passes through unchanged so the settlement gate
// (status == paid) never accidentally settles a charge that is not CONCLUIDA.
// Expected and received cents come straight from the PIX reconciliation, so the
// money half of reconcile-before-settle (ChargeResult.AmountReconciled) is
// preserved, including its fail-secure behaviour on a missing amount.
func (p *PixSettlementProvider) GetCharge(ctx context.Context, tenantID, txID string) (ports.ChargeResult, error) {
	r, err := p.pix.GetImmediateCharge(ctx, tenantID, txID)
	if err != nil {
		return ports.ChargeResult{}, err
	}
	return ports.ChargeResult{
		TxID:                r.TxID,
		Status:              translatePixStatus(r.Status),
		ExpectedAmountCents: r.ExpectedAmountCents,
		ReceivedAmountCents: r.ReceivedAmountCents,
	}, nil
}

// translatePixStatus maps the BACEN immediate-charge terminal paid status
// (CONCLUIDA, case-insensitive) to the generic settled status; any other status is
// returned unchanged so it never reads as settled.
func translatePixStatus(pixStatus string) string {
	if strings.EqualFold(pixStatus, pixStatusConcluida) {
		return genericStatusPaid
	}
	return pixStatus
}

package c6

import (
	"context"
	"strings"

	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// C6 scope names, as the PSP grants them on the client_credentials token. They are the
// PSP's vocabulary and stay confined to this adapter; everything above speaks
// ports.BankCapabilities.
const (
	scopePixWrite      = "pix.write"
	scopeCobWrite      = "cob.write"
	scopeCheckoutWrite = "checkout.write"
)

// compile-time assertion that the C6 provider can answer what a credential authorises.
var _ ports.BankCapabilityReader = (*Provider)(nil)

// BankCapabilities reports which payment methods tenantID's C6 credential authorises,
// read from the scopes the PSP GRANTED on the token — not from what we requested.
//
// A tradução é conservadora: exigimos o escopo de ESCRITA de cada modalidade, porque é
// escrever que a compra precisa. Ler sem poder criar não serve de nada ao comprador, e
// oferecer uma modalidade que o banco vai recusar é exatamente o que isto existe para
// evitar.
//
// PIX pede cob.write junto de pix.write: uma cobrança PIX é um `cob`, e uma conta com
// pix.write mas sem cob.write não consegue abrir a cobrança que a loja usa.
func (p *Provider) BankCapabilities(ctx context.Context, tenantID string) (ports.BankCapabilities, error) {
	scopes, err := p.tokens.grantedScopes(ctx, tenantID)
	if err != nil {
		return ports.BankCapabilities{}, err
	}
	has := func(name string) bool {
		_, ok := scopes[name]
		return ok
	}
	caps := ports.BankCapabilities{
		PIX:  has(scopePixWrite) && has(scopeCobWrite),
		Card: has(scopeCheckoutWrite),
	}
	caps.Boleto, caps.Bolepix = p.boletoCapabilities(ctx, tenantID, has)
	return caps, nil
}

// boletoCapabilities translates the bank-slip scope and the tenant's PIX key into the two
// boleto capabilities.
//
// Unlike PIX and cartão, the scope NAME here is not known: it is absent from the published
// C6 OpenAPI (which documents only bearerAuth) and has never been captured from a granted
// token. So when it is unconfigured the answer is Unknown, not false — telling an empresa
// "sua conta não pode emitir boleto" on the strength of a name we never verified would be
// stating something we have not checked.
//
// BolePix carries one extra precondition that is NOT a scope: a registered random (EVP)
// PIX key. The bank does not enforce it — it creates the charge with no QR and reports
// success — so the check has to happen here for the console to be able to say why.
func (p *Provider) boletoCapabilities(ctx context.Context, tenantID string, has func(string) bool) (boleto, bolepix ports.Capability) {
	scope := strings.TrimSpace(p.bankSlipWriteScope)
	switch {
	case scope == "":
		boleto = ports.CapabilityUnknown
	case has(scope):
		boleto = ports.CapabilityGranted
	default:
		boleto = ports.CapabilityDenied
	}

	// Bolepix is never stronger than boleto: a denial upstream dominates.
	if boleto == ports.CapabilityDenied {
		return boleto, ports.CapabilityDenied
	}
	cred, err := p.creds.GetBankCredential(ctx, tenantID, p.bankID)
	if err != nil || strings.TrimSpace(cred.CreditorKey) == "" {
		// No key ⇒ no QR, whatever the scope says. This is a definite no, so it is Denied
		// even when the scope itself is Unknown.
		return boleto, ports.CapabilityDenied
	}
	return boleto, boleto
}

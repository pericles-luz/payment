package c6

import (
	"context"

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
	return ports.BankCapabilities{
		PIX:  has(scopePixWrite) && has(scopeCobWrite),
		Card: has(scopeCheckoutWrite),
	}, nil
}

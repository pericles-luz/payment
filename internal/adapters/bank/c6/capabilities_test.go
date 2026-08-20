package c6

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// O que a empresa PEDE e o que a conta dela TEM são coisas diferentes. A conta da
// empresa 27 não tinha o produto Checkout contratado, e a única evidência disso era o
// C6 responder 403 no meio de uma compra — com o comprador já decidido pelo cartão.
//
// O token diz o mesmo fato antes e de graça: o C6 devolve em `scope` o que CONCEDEU,
// não o que pedimos. Estes testes fixam a leitura desse campo.

// tokenServerWithScope serves a token response carrying the given scope string.
func tokenServerWithScope(t *testing.T, scope string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "tok", "token_type": "Bearer", "expires_in": 600, "scope": scope,
		})
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func capabilitiesFor(t *testing.T, scope string) (bool, bool) {
	t.Helper()
	srv := tokenServerWithScope(t, scope)
	p, err := New(Config{BaseURL: srv.URL, TokenURL: srv.URL + "/oauth/token", HTTPClient: srv.Client()},
		oneTenant("t1", "cli", "seg"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	caps, err := p.BankCapabilities(context.Background(), "t1")
	if err != nil {
		t.Fatalf("BankCapabilities: %v", err)
	}
	return caps.PIX, caps.Card
}

// O escopo real da empresa 27, copiado do token de produção: tem PIX, não tem checkout.
func TestBankCapabilitiesAccountWithoutCheckoutProduct(t *testing.T) {
	t.Parallel()
	const escopoDaEmpresa27 = "cob.write statement.read pix.write lotecobv.read cob.read " +
		"payloadlocation.read lotecobv.write webhook.read cobv.write webhook.write " +
		"schedulepayments.write cobv.read pix.read schedulepayments.read payloadlocation.write"

	pix, card := capabilitiesFor(t, escopoDaEmpresa27)
	if !pix {
		t.Fatal("PIX foi reportado como indisponível para uma conta que tem pix.write e cob.write")
	}
	if card {
		t.Fatal("cartão reportado como disponível para uma conta SEM checkout.write: é\nexatamente esta afirmação que fez a loja oferecer um botão que o C6 recusou com 403")
	}
}

// O escopo real da LM Host, que tem os três de checkout.
func TestBankCapabilitiesAccountWithCheckoutProduct(t *testing.T) {
	t.Parallel()
	const escopoDaLMHost = "checkout.cancel cob.write statement.read checkout.read pix.write " +
		"lotecobv.read cob.read payloadlocation.read lotecobv.write webhook.read cobv.write " +
		"webhook.write schedulepayments.write cobv.read pix.read checkout.write payloadlocation.write"

	pix, card := capabilitiesFor(t, escopoDaLMHost)
	if !pix || !card {
		t.Fatalf("conta com os dois produtos reportou pix=%v card=%v", pix, card)
	}
}

// checkout.read sozinho NÃO habilita cartão: ler sem poder criar não abre cobrança
// nenhuma, e oferecer o botão levaria ao mesmo 403.
func TestBankCapabilitiesReadScopeAloneDoesNotEnableCard(t *testing.T) {
	t.Parallel()
	_, card := capabilitiesFor(t, "pix.write cob.write checkout.read")
	if card {
		t.Fatal("checkout.read sozinho habilitou cartão; falta checkout.write para criar")
	}
}

// PIX exige cob.write junto: a cobrança que a loja abre é um `cob`.
func TestBankCapabilitiesPixRequiresCobWrite(t *testing.T) {
	t.Parallel()
	pix, _ := capabilitiesFor(t, "pix.write pix.read")
	if pix {
		t.Fatal("PIX habilitado sem cob.write; a loja não conseguiria abrir a cobrança")
	}
}

// Escopo vazio não é "pode tudo".
func TestBankCapabilitiesEmptyScopeGrantsNothing(t *testing.T) {
	t.Parallel()
	pix, card := capabilitiesFor(t, "")
	if pix || card {
		t.Fatalf("escopo vazio virou permissão: pix=%v card=%v", pix, card)
	}
}

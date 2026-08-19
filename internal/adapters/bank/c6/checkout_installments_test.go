package c6

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// corpoDoCartao decodifica o payment.card efetivamente enviado ao C6.
type corpoDoCartao struct {
	Type         string `json:"type"`
	Installments int    `json:"installments"`
	Authenticate string `json:"authenticate"`
	InterestType string `json:"interest_type"`
}

func cartaoEnviado(t *testing.T, ps *productServer) corpoDoCartao {
	t.Helper()
	var sent struct {
		Payment struct {
			Card corpoDoCartao `json:"card"`
		} `json:"payment"`
	}
	if err := json.Unmarshal(ps.body(), &sent); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	return sent.Payment.Card
}

func abrirCheckout(t *testing.T, ps *productServer, cardType string, maxParcelas int) (ports.CheckoutResult, error) {
	t.Helper()
	p := ps.provider(t, oneTenant("t1", "client-1", "secret-1"))
	return p.CreateCheckoutSession(context.Background(), "t1", ports.CheckoutRequest{
		SessionID:       "sess-1",
		Currency:        "BRL",
		Items:           []ports.CheckoutItem{{Description: "Pedido", AmountCents: 1500}},
		CardType:        cardType,
		MaxInstallments: maxParcelas,
	})
}

// O teto pedido chega ao C6 como pedido. Até esta mudança o adaptador mandava 1
// fixo, o que significava que NENHUM comprador conseguia parcelar.
func TestCreateCheckoutEnviaOTetoDeParcelas(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	if _, err := abrirCheckout(t, ps, "credit", 3); err != nil {
		t.Fatalf("CreateCheckoutSession: %v", err)
	}
	if got := cartaoEnviado(t, ps).Installments; got != 3 {
		t.Errorf("installments enviado = %d, want 3", got)
	}
}

// Os juros vão para o COMPRADOR, e o campo é sempre enviado.
//
// Omitir faz o C6 assumir BY_SELLER — ou seja, não mandar é escolher que a loja
// pague, por omissão. Este teste existe para que ninguém remova o campo achando que
// é enfeite.
func TestCreateCheckoutMandaJurosDoEmissor(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	if _, err := abrirCheckout(t, ps, "credit", 3); err != nil {
		t.Fatalf("CreateCheckoutSession: %v", err)
	}
	if got := cartaoEnviado(t, ps).InterestType; got != "BY_ISSUER" {
		t.Errorf("interest_type = %q, want BY_ISSUER (omitir faz o C6 assumir BY_SELLER)", got)
	}
}

// Não-regressão: sem teto pedido, o corpo continua idêntico ao que sempre foi
// enviado — parcelas em 1.
func TestCreateCheckoutSemTetoContinuaAVista(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	if _, err := abrirCheckout(t, ps, "credit", 0); err != nil {
		t.Fatalf("CreateCheckoutSession: %v", err)
	}
	if got := cartaoEnviado(t, ps).Installments; got != 1 {
		t.Errorf("installments = %d, want 1 quando nada é pedido", got)
	}
}

// A FAIXA É NOSSA. Sondado contra o C6 real: uma criação com installments: 13
// respondeu 201 — o PSP não valida. Recusar aqui, e ANTES de qualquer chamada, é o
// que impede o problema de só aparecer quando um comprador de verdade for pagar.
func TestCreateCheckoutRecusaForaDaFaixaSemChamarOPSP(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	_, err := abrirCheckout(t, ps, "credit", 13)
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("erro = %v, want validação", err)
	}
	if len(ps.body()) != 0 {
		t.Error("recusa não pode ter chamado o PSP")
	}
}

// A REGRA DO DÉBITO TAMBÉM É NOSSA: o C6 aceitou DEBIT com 3 parcelas na criação.
func TestCreateCheckoutRecusaDebitoParcelado(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	_, err := abrirCheckout(t, ps, "debit", 3)
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("erro = %v, want validação", err)
	}
	if len(ps.body()) != 0 {
		t.Error("recusa não pode ter chamado o PSP")
	}
}

// O teto aplicado volta na resposta, para quem chamou saber o que valeu.
func TestCreateCheckoutEcoaOTetoAplicado(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	res, err := abrirCheckout(t, ps, "credit", 6)
	if err != nil {
		t.Fatalf("CreateCheckoutSession: %v", err)
	}
	if res.MaxInstallments != 6 {
		t.Errorf("MaxInstallments = %d, want 6", res.MaxInstallments)
	}
}

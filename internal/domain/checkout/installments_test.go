package checkout

import "testing"

// Cada parcela precisa passar do mínimo do PSP (R$ 5,00). A regra NÃO é aplicada na
// criação da sessão: o C6 responde 201 e a página hospedada é que recusa, com "Link
// de Pagamento não encontrado" — ou seja, o comprador só descobre com o link na mão,
// já na tela de pagamento. Reduzir aqui é o que transforma isso numa oferta que ele
// pode aceitar.
func TestAffordableInstallments(t *testing.T) {
	t.Parallel()
	casos := []struct {
		nome       string
		totalCents int64
		pedido     int
		quer       int
	}{
		// O caso que nos custou dois links quebrados: R$ 15,00 em 6x daria R$ 2,50
		// por parcela.
		{"R$ 15,00 com teto de 6x cabe em 3x", 1500, 6, 3},
		{"R$ 30,00 com teto de 6x cabe inteiro", 3000, 6, 6},
		{"R$ 30,00 com teto de 3x respeita o teto", 3000, 3, 3},
		{"R$ 12,00 com teto de 6x cabe em 2x", 1200, 6, 2},
		// Abaixo de dois mínimos não há o que parcelar.
		{"R$ 9,00 não parcela", 900, 6, 1},
		{"R$ 5,00 não parcela", 500, 12, 1},
		{"à vista continua à vista", 3000, 1, 1},
		{"sem teto pedido continua à vista", 3000, 0, 1},
		// Divisão exata no limite: R$ 10,00 em 2x dá exatamente R$ 5,00 a parcela.
		{"divisão exata no mínimo é permitida", 1000, 2, 2},
	}
	for _, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			if got := AffordableInstallments(c.totalCents, c.pedido); got != c.quer {
				t.Errorf("AffordableInstallments(%d, %d) = %d, want %d",
					c.totalCents, c.pedido, got, c.quer)
			}
		})
	}
}

// A faixa e a regra do débito são nossas: o PSP aceita 13x e débito parcelado na
// criação, e o problema só apareceria na hora de pagar.
func TestNormalizeInstallments(t *testing.T) {
	t.Parallel()

	if n, err := NormalizeInstallments(CardCredit, 0); err != nil || n != 1 {
		t.Errorf("ausente deve virar 1, got %d (%v)", n, err)
	}
	if n, err := NormalizeInstallments(CardCredit, 12); err != nil || n != 12 {
		t.Errorf("12 é o limite documentado, got %d (%v)", n, err)
	}
	if _, err := NormalizeInstallments(CardCredit, 13); err == nil {
		t.Error("13x tem de ser recusado por nós — o C6 aceita")
	}
	if _, err := NormalizeInstallments(CardDebit, 3); err == nil {
		t.Error("débito parcelado tem de ser recusado por nós — o C6 aceita")
	}
	if n, err := NormalizeInstallments(CardDebit, 1); err != nil || n != 1 {
		t.Errorf("débito à vista é válido, got %d (%v)", n, err)
	}
}

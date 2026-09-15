package c6

import "testing"

// Checking the CHECK DIGITS, not just the width, is what turns a wrong CPF into a named
// field error instead of a round trip to the bank.
//
// Measured against the real C6 sandbox on 15/09/2026: the syntactically fine but invalid
// 12345678901 came back as an opaque 422 whose reason our own API discards
// ("cnpjCpf do grupo pagador não pertence ao Domínio"), and only the probe could show it.
// The arithmetic is free; the round trip and the blind diagnosis were not.
func TestValidTaxIDChecksCheckDigits(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		taxID string
		want  bool
	}{
		// The exact value that cost an hour of diagnosis: right width, wrong check digits.
		{"CPF sequencial invalido", "12345678901", false},
		{"CPF valido", "11144477735", true},
		{"CPF com DV errado no ultimo digito", "11144477736", false},
		{"CPF com DV errado no penultimo", "11144477745", false},
		// Repeated digits satisfy the módulo-11 arithmetic but are not issuable.
		{"CPF todos zeros", "00000000000", false},
		{"CPF todos uns", "11111111111", false},
		{"CNPJ valido", "11222333000181", true},
		{"CNPJ com DV errado", "11222333000182", false},
		{"CNPJ todos iguais", "11111111111111", false},
		// Width and charset still apply.
		{"curto demais", "1114447773", false},
		{"longo demais", "111444777355", false},
		{"com mascara", "111.444.777-35", false},
		{"vazio", "", false},
		{"com letra", "1114447773A", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := validTaxIDDigits(tc.taxID); got != tc.want {
				t.Fatalf("validTaxIDDigits(%q) = %v, want %v", tc.taxID, got, tc.want)
			}
		})
	}
}

// A CNPJ payer is legitimate (a company paying a boleto), so the 14-digit path must accept
// a real one rather than only tolerate the width.
func TestValidTaxIDAcceptsCNPJPayer(t *testing.T) {
	t.Parallel()
	for _, cnpj := range []string{"11222333000181", "57798242000190"} {
		if !validTaxIDDigits(cnpj) {
			t.Fatalf("CNPJ %q must be accepted", cnpj)
		}
	}
}

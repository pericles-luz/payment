package nfse

import "testing"

func TestValidCNPJ(t *testing.T) {
	cases := map[string]bool{
		"67.188.163/0001-10": true,
		"57151944000187":     true,
		"47064135000184":     true,
		"57151944000188":     false,
		"11111111111111":     false,
		"5715194400018":      false,
		"":                   false,
	}
	for in, want := range cases {
		if got := ValidCNPJ(in); got != want {
			t.Errorf("ValidCNPJ(%q) = %v, want %v", in, got, want)
		}
	}
}

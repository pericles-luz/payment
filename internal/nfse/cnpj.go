package nfse

// ValidCNPJ reports whether s (punctuation allowed) is a 14-digit CNPJ with
// correct check digits and not a repeated-digit sequence.
func ValidCNPJ(s string) bool {
	d := onlyDigits(s)
	if len(d) != 14 {
		return false
	}
	same := true
	for i := 1; i < 14; i++ {
		if d[i] != d[0] {
			same = false
			break
		}
	}
	if same {
		return false
	}
	return cnpjDigit(d[:12], 5) == d[12] && cnpjDigit(d[:13], 6) == d[13]
}

// cnpjDigit computes the next check digit for base with weights starting at
// start and cycling 9..2.
func cnpjDigit(base string, start int) byte {
	sum, w := 0, start
	for i := 0; i < len(base); i++ {
		sum += int(base[i]-'0') * w
		w--
		if w < 2 {
			w = 9
		}
	}
	r := sum % 11
	if r < 2 {
		return '0'
	}
	return byte('0' + 11 - r)
}

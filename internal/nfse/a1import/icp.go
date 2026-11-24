package a1import

import (
	"crypto/x509"
	"encoding/asn1"
	"strings"
)

var (
	oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}
	// oidICPBrasilCNPJ is the ICP-Brasil otherName carrying the company's CNPJ
	// in an e-CNPJ certificate (DOC-ICP-04, 2.16.76.1.3.3).
	oidICPBrasilCNPJ = asn1.ObjectIdentifier{2, 16, 76, 1, 3, 3}
)

// CNPJFromCert returns the holder CNPJ (14 digits) of an ICP-Brasil e-CNPJ
// certificate. It reads the SubjectAltName otherName 2.16.76.1.3.3 and falls
// back to the "RAZAO SOCIAL:CNPJ" Common Name convention. ok is false when
// neither yields 14 digits.
func CNPJFromCert(leaf *x509.Certificate) (cnpj string, ok bool) {
	if leaf == nil {
		return "", false
	}
	for _, ext := range leaf.Extensions {
		if !ext.Id.Equal(oidSubjectAltName) {
			continue
		}
		if c, ok := cnpjFromSAN(ext.Value); ok {
			return c, true
		}
	}
	if i := strings.LastIndex(leaf.Subject.CommonName, ":"); i >= 0 {
		if c := digits(leaf.Subject.CommonName[i+1:]); len(c) == 14 {
			return c, true
		}
	}
	return "", false
}

// cnpjFromSAN walks GeneralNames looking for otherName [0] with the ICP-Brasil
// CNPJ type-id; its value is an [0] EXPLICIT string (OCTET/Printable/UTF8).
func cnpjFromSAN(der []byte) (string, bool) {
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(der, &seq); err != nil {
		return "", false
	}
	rest := seq.Bytes
	for len(rest) > 0 {
		var gn asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &gn); err != nil {
			return "", false
		}
		if gn.Class != asn1.ClassContextSpecific || gn.Tag != 0 {
			continue
		}
		var typeID asn1.ObjectIdentifier
		valRest, err := asn1.Unmarshal(gn.Bytes, &typeID)
		if err != nil || !typeID.Equal(oidICPBrasilCNPJ) {
			continue
		}
		var wrapper, inner asn1.RawValue
		if _, err := asn1.Unmarshal(valRest, &wrapper); err != nil {
			continue
		}
		if _, err := asn1.Unmarshal(wrapper.Bytes, &inner); err != nil {
			continue
		}
		if c := digits(string(inner.Bytes)); len(c) == 14 {
			return c, true
		}
	}
	return "", false
}

func digits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

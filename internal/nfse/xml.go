package nfse

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

// XMLDSIG algorithm URIs used in the DPS enveloped signature. The NF-e / NFS-e
// scheme is RSA-SHA256 with C14N exclusive canonicalisation and an enveloped
// transform (the signature is a child of the signed element's document).
const (
	nsDPS          = "http://www.sped.fazenda.gov.br/nfse"
	nsDSig         = "http://www.w3.org/2000/09/xmldsig#"
	algC14NExcl    = "http://www.w3.org/2001/10/xml-exc-c14n#"
	algEnveloped   = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
	algRSASHA256   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	algSHA256Digst = "http://www.w3.org/2001/04/xmlenc#sha256"
	dpsVersao      = "1.01"
)

// SignFunc signs the SHA-256 digest of the SignedInfo and returns the raw
// signature bytes. It is the seam the custody.FiscalSigner plugs into: the
// domain never sees a private key, only hands over a digest and receives a
// signature. digest is exactly 32 bytes (sha256 of the canonical SignedInfo).
type SignFunc func(digest []byte) (sig []byte, err error)

// xmlEscape escapes the five XML predefined entities for element text /
// attribute values. Deterministic output keeps the canonical bytes stable
// between the digest computation and any verifier.
func xmlEscape(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&apos;",
	)
	return r.Replace(s)
}

// formatValor renders cents as a fixed-2-decimal string ("1234" -> "12.34"),
// the vServ representation the ADN expects.
func formatValor(cents int64) string {
	neg := cents < 0
	if neg {
		cents = -cents
	}
	reais := cents / 100
	frac := cents % 100
	s := fmt.Sprintf("%d.%02d", reais, frac)
	if neg {
		s = "-" + s
	}
	return s
}

// verAplic identifies this application in the DPS (TSVerAplic, ≤20 chars).
const verAplic = "lmhost-payment"

// brt is the offset dhEmi is rendered in (TSDateTimeUTC requires an explicit
// offset; the Sistema Nacional works in Brasília time).
var brt = time.FixedZone("BRT", -3*60*60)

// dpsID builds the 45-position Id the schema fixes (TSIdDPS):
// "DPS" + cLocEmi(7) + tipo de inscrição(1: 1=CPF, 2=CNPJ) + inscrição(14)
// + série(5) + nDPS(15), numbers left-padded with zeros. It is referenced by
// the signature (URI="#<id>") and is what the Sefin dedupes on.
func dpsID(d *DPS) string {
	return fmt.Sprintf("DPS%s2%s%05s%015s", d.EmitterMunicipalityCode, d.EmitterCNPJ,
		strings.TrimLeft(d.Series, "0"), d.Number)
}

// marshalInfDPS serialises <infDPS> in the element order of the DPS schema
// (TCInfDPS and its groups) and returns it in Exclusive C14N form — the digest
// input of the signature Reference. infDPS sits in the NFS-e default namespace,
// which is "visibly utilized", so its canonical form carries xmlns itself even
// though the document also declares it on <DPS>; omitting it makes the digest
// differ from what any verifier computes.
func marshalInfDPS(d *DPS) ([]byte, string) {
	id := dpsID(d)
	var b strings.Builder
	fmt.Fprintf(&b, `<infDPS xmlns="%s" Id="%s">`, nsDPS, id)
	fmt.Fprintf(&b, `<tpAmb>%d</tpAmb>`, int(d.Environment))
	fmt.Fprintf(&b, `<dhEmi>%s</dhEmi>`, d.EmittedAt.In(brt).Format("2006-01-02T15:04:05-07:00"))
	fmt.Fprintf(&b, `<verAplic>%s</verAplic>`, verAplic)
	fmt.Fprintf(&b, `<serie>%s</serie>`, d.Series)
	fmt.Fprintf(&b, `<nDPS>%s</nDPS>`, d.Number)
	fmt.Fprintf(&b, `<dCompet>%s</dCompet>`, d.Competencia.date().Format("2006-01-02"))
	b.WriteString(`<tpEmit>1</tpEmit>`) // 1 = the provider emits its own DPS
	fmt.Fprintf(&b, `<cLocEmi>%s</cLocEmi>`, d.EmitterMunicipalityCode)

	fmt.Fprintf(&b, `<prest><CNPJ>%s</CNPJ><regTrib>`, d.EmitterCNPJ)
	fmt.Fprintf(&b, `<opSimpNac>%d</opSimpNac>`, int(d.Regime))
	if d.Regime == SimplesMEEPP {
		// 1 = federal and municipal taxes collected through the Simples.
		// Forbidden for MEI (E0162).
		b.WriteString(`<regApTribSN>1</regApTribSN>`)
	}
	// 0 = no special regime; mandatory for MEI (E0174).
	b.WriteString(`<regEspTrib>0</regEspTrib></regTrib></prest>`)

	if t := d.Tomador; t != nil {
		// TCInfPessoa order: CNPJ|CPF, xNome, email.
		b.WriteString(`<toma>`)
		if len(t.Document) == 14 {
			fmt.Fprintf(&b, `<CNPJ>%s</CNPJ>`, t.Document)
		} else {
			fmt.Fprintf(&b, `<CPF>%s</CPF>`, t.Document)
		}
		fmt.Fprintf(&b, `<xNome>%s</xNome>`, xmlEscape(t.Name))
		if t.Email != "" {
			fmt.Fprintf(&b, `<email>%s</email>`, xmlEscape(t.Email))
		}
		b.WriteString(`</toma>`)
	}

	b.WriteString(`<serv>`)
	fmt.Fprintf(&b, `<locPrest><cLocPrestacao>%s</cLocPrestacao></locPrest>`, d.MunicipalityCode)
	// TCCServ order: cTribNac, cTribMun?, xDescServ, cNBS?.
	fmt.Fprintf(&b, `<cServ><cTribNac>%s</cTribNac>`, d.ServiceCode)
	if d.MunicipalServiceCode != "" {
		fmt.Fprintf(&b, `<cTribMun>%s</cTribMun>`, d.MunicipalServiceCode)
	}
	fmt.Fprintf(&b, `<xDescServ>%s</xDescServ>`, xmlEscape(d.Description))
	if d.NBSCode != "" {
		fmt.Fprintf(&b, `<cNBS>%s</cNBS>`, d.NBSCode)
	}
	b.WriteString(`</cServ>`)
	b.WriteString(`</serv>`)

	b.WriteString(`<valores>`)
	fmt.Fprintf(&b, `<vServPrest><vServ>%s</vServ></vServPrest>`, formatValor(d.ServiceValueCents))
	b.WriteString(`<trib>`)
	// 1 = operação tributável; 1 = ISSQN não retido (retention is forbidden
	// for MEI, E0583). No pAliq: with no retention and the ISS collected
	// through the Simples, the Sefin forbids it for both regimes (E0600,
	// E0625, E0631).
	b.WriteString(`<tribMun><tribISSQN>1</tribISSQN><tpRetISSQN>1</tpRetISSQN></tribMun>`)
	if d.Regime == SimplesMEEPP {
		// ME/EPP must state its approximate Simples rate; indTotTrib is
		// forbidden for it (E0712).
		fmt.Fprintf(&b, `<totTrib><pTotTribSN>%s</pTotTribSN></totTrib>`, formatValor(int64(d.SimplesTaxRateBps)))
	} else {
		// MEI: 0 = no estimated tax total; pTotTribSN is forbidden (E0710).
		b.WriteString(`<totTrib><indTotTrib>0</indTotTrib></totTrib>`)
	}
	b.WriteString(`</trib></valores>`)
	b.WriteString(`</infDPS>`)
	return []byte(b.String()), id
}

// buildSignedInfo builds the canonical <SignedInfo> referencing refID with the
// given digest. Its SHA-256 is what SignFunc signs.
func buildSignedInfo(refID string, infDigest []byte) []byte {
	digestB64 := base64.StdEncoding.EncodeToString(infDigest)
	var b strings.Builder
	fmt.Fprintf(&b, `<SignedInfo xmlns="%s">`, nsDSig)
	fmt.Fprintf(&b, `<CanonicalizationMethod Algorithm="%s"></CanonicalizationMethod>`, algC14NExcl)
	fmt.Fprintf(&b, `<SignatureMethod Algorithm="%s"></SignatureMethod>`, algRSASHA256)
	fmt.Fprintf(&b, `<Reference URI="#%s">`, refID)
	b.WriteString(`<Transforms>`)
	fmt.Fprintf(&b, `<Transform Algorithm="%s"></Transform>`, algEnveloped)
	fmt.Fprintf(&b, `<Transform Algorithm="%s"></Transform>`, algC14NExcl)
	b.WriteString(`</Transforms>`)
	fmt.Fprintf(&b, `<DigestMethod Algorithm="%s"></DigestMethod>`, algSHA256Digst)
	fmt.Fprintf(&b, `<DigestValue>%s</DigestValue>`, digestB64)
	b.WriteString(`</Reference>`)
	b.WriteString(`</SignedInfo>`)
	return []byte(b.String())
}

// SignedDPS is the result of assembling and signing a DPS: the full enveloped
// XML plus the pieces a verifier / audit needs.
type SignedDPS struct {
	// XML is the full <DPS> document with the enveloped <Signature>.
	XML []byte
	// ID is the DPS element Id (referenced by the signature).
	ID string
	// DigestValue is the base64 SHA-256 of the infDPS (the Reference digest).
	DigestValue string
	// SignatureValue is the base64 RSA signature over the SignedInfo.
	SignatureValue string
}

// Sign assembles the enveloped-signature DPS document. It computes the infDPS
// digest, builds the SignedInfo, hashes it, delegates the RSA signing to sign
// (the custody boundary), and embeds SignedInfo + SignatureValue + the leaf
// certificate (DER) into a <Signature> inside the <DPS>. leafDER is the raw
// public certificate the ADN uses to verify — never a private key.
func Sign(d *DPS, sign SignFunc, leafDER []byte) (*SignedDPS, error) {
	if d == nil {
		return nil, ErrEmptyEmitter
	}
	if sign == nil {
		return nil, &TransportError{Op: "sign", Err: fmt.Errorf("nil sign func")}
	}
	infDPS, id := marshalInfDPS(d)
	infDigest := sha256.Sum256(infDPS)

	signedInfo := buildSignedInfo(id, infDigest[:])
	siDigest := sha256.Sum256(signedInfo)

	sig, err := sign(siDigest[:])
	if err != nil {
		return nil, err
	}
	sigB64 := base64.StdEncoding.EncodeToString(sig)
	certB64 := base64.StdEncoding.EncodeToString(leafDER)

	var b strings.Builder
	fmt.Fprintf(&b, `<?xml version="1.0" encoding="UTF-8"?>`)
	fmt.Fprintf(&b, `<DPS xmlns="%s" versao="%s">`, nsDPS, dpsVersao)
	b.Write(infDPS)
	fmt.Fprintf(&b, `<Signature xmlns="%s">`, nsDSig)
	b.Write(signedInfo)
	fmt.Fprintf(&b, `<SignatureValue>%s</SignatureValue>`, sigB64)
	fmt.Fprintf(&b, `<KeyInfo><X509Data><X509Certificate>%s</X509Certificate></X509Data></KeyInfo>`, certB64)
	b.WriteString(`</Signature>`)
	b.WriteString(`</DPS>`)

	return &SignedDPS{
		XML:            []byte(b.String()),
		ID:             id,
		DigestValue:    base64.StdEncoding.EncodeToString(infDigest[:]),
		SignatureValue: sigB64,
	}, nil
}

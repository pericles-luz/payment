package nfse

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/nfse/custody"
)

func mustDPS(t *testing.T) *DPS {
	t.Helper()
	dps, err := NewDPS(validParams())
	if err != nil {
		t.Fatalf("NewDPS: %v", err)
	}
	return dps
}

func TestMarshalInfDPSDeterministicAndEscaped(t *testing.T) {
	p := validParams()
	p.Description = `A & B <consultoria> "x"`
	dps, err := NewDPS(p)
	if err != nil {
		t.Fatalf("NewDPS: %v", err)
	}
	got1, id1 := marshalInfDPS(dps)
	got2, id2 := marshalInfDPS(dps)
	if string(got1) != string(got2) || id1 != id2 {
		t.Fatal("marshalInfDPS not deterministic")
	}
	s := string(got1)
	if strings.Contains(s, "A & B") || !strings.Contains(s, "A &amp; B") {
		t.Errorf("description not escaped: %s", s)
	}
	if !strings.Contains(s, `<CNPJ>47064135000184</CNPJ>`) {
		t.Errorf("emitter missing: %s", s)
	}
	if !strings.Contains(s, `<vServ>150.00</vServ>`) {
		t.Errorf("value missing: %s", s)
	}
	// TSIdDPS: "DPS" + cLocEmi + 2 (CNPJ) + CNPJ + série(5) + nDPS(15).
	if id1 != "DPS355030824706413500018400001000000000000042" {
		t.Errorf("id = %s", id1)
	}
}

// TestSignProducesVerifiableSignature is the end-to-end proof that the domain
// signing path (digest → SignFunc → embedded SignatureValue) yields a signature
// that validates against the leaf public key — exactly what the ADN verifies.
func TestSignProducesVerifiableSignature(t *testing.T) {
	signer := custody.NewLocalTestSigner()
	chain, meta, err := signer.Provision("tenant-A", "47064135000184", 24*time.Hour)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	leaf := chain[0]
	dps := mustDPS(t)

	signFn := func(digest []byte) ([]byte, error) {
		return signer.SignDigest(context.Background(), "tenant-A", meta.Serial, digest)
	}
	signed, err := Sign(dps, signFn, leaf.Raw)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Recompute the SignedInfo digest exactly as Sign did and verify the
	// embedded SignatureValue against the leaf public key.
	infDPS, id := marshalInfDPS(dps)
	if id != signed.ID {
		t.Fatalf("id mismatch: %s vs %s", id, signed.ID)
	}
	infDigest := sha256.Sum256(infDPS)
	si := buildSignedInfo(id, infDigest[:])
	siDigest := sha256.Sum256(si)

	sig, err := base64.StdEncoding.DecodeString(signed.SignatureValue)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	pub, ok := leaf.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("leaf public key not RSA")
	}
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, siDigest[:], sig); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}

	// The full document must embed the leaf certificate and reference the id.
	x := string(signed.XML)
	if !strings.Contains(x, base64.StdEncoding.EncodeToString(leaf.Raw)) {
		t.Error("signed XML missing leaf certificate")
	}
	if !strings.Contains(x, `URI="#`+id+`"`) {
		t.Error("signature does not reference infDPS id")
	}
	// The DigestValue in the doc must equal the recomputed infDPS digest.
	if signed.DigestValue != base64.StdEncoding.EncodeToString(infDigest[:]) {
		t.Error("DigestValue mismatch")
	}
	// Sanity: the embedded leaf parses back.
	if _, err := x509.ParseCertificate(leaf.Raw); err != nil {
		t.Fatalf("leaf DER invalid: %v", err)
	}
}

func TestSignGuards(t *testing.T) {
	dps := mustDPS(t)
	if _, err := Sign(nil, func([]byte) ([]byte, error) { return nil, nil }, nil); !errors.Is(err, ErrEmptyEmitter) {
		t.Errorf("nil dps err = %v", err)
	}
	if _, err := Sign(dps, nil, nil); err == nil {
		t.Error("nil sign func should error")
	}
	wantErr := errors.New("kms down")
	if _, err := Sign(dps, func([]byte) ([]byte, error) { return nil, wantErr }, nil); !errors.Is(err, wantErr) {
		t.Errorf("sign error not propagated: %v", err)
	}
}

package custody

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestNoPrivateKeyMaterialLeaks is the AC-mandated regression proving that no
// private-key material escapes the custody boundary into anything an operator
// or trace could observe (SIN-67528 hard invariant; SIN-67486 AC #3).
//
// It runs the full lifecycle — provision, sign, store the public chain, read it
// back, build a client certificate — while capturing every observable surface:
// the audit events, the PEM the store would persist, and a formatted dump of
// the tls.Certificate. It then asserts the ephemeral private key's raw DER
// bytes appear in none of them. The private key is reached via the unexported
// map (this is an in-package test) ONLY to compute the negative assertion.
func TestNoPrivateKeyMaterialLeaks(t *testing.T) {
	ctx := context.Background()

	var audit strings.Builder
	s := NewLocalTestSigner(WithAuditSink(func(ev AuditEvent) {
		fmt.Fprintf(&audit, "%s company=%s serial=%s at=%s err=%s\n", ev.Op, ev.CompanyID, ev.CertSerial, ev.At.Format(time.RFC3339), ev.Err)
	}))
	store := NewMemoryCertStore()

	chain, meta, err := s.Provision("co-1", "11222333000181", time.Hour)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}

	// Reach the ephemeral private key ONLY to build the leak needle.
	tk := s.keys[mapKey("co-1", meta.Serial)]
	if tk == nil {
		t.Fatal("provisioned key missing from internal map")
	}
	privDER := x509.MarshalPKCS1PrivateKey(tk.priv)
	needleHex := fmt.Sprintf("%x", privDER)
	// The private exponent d is genuinely secret (unlike the modulus, which is
	// public and legitimately inside the certificate). Its leak would be fatal.
	needleD := tk.priv.D.Text(16)

	// Exercise the sign + store + client-cert paths.
	digest := sha256.Sum256([]byte("SignedInfo"))
	if _, err := s.SignDigest(ctx, "co-1", meta.Serial, digest[:]); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := store.PutA1(ctx, "co-1", chain, meta); err != nil {
		t.Fatalf("put: %v", err)
	}
	gotChain, _, err := store.Get(ctx, "co-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	pemStr, err := EncodeChainPEM(gotChain)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	cert, err := s.ClientCertificate(ctx, "co-1")
	if err != nil {
		t.Fatalf("client cert: %v", err)
	}
	certDump := fmt.Sprintf("%+v", cert)

	surfaces := map[string]string{
		"audit log":            audit.String(),
		"persisted PEM":        pemStr,
		"tls.Certificate dump": certDump,
	}
	for name, blob := range surfaces {
		if strings.Contains(blob, needleHex) {
			t.Errorf("%s leaked raw private key DER", name)
		}
		if needleD != "" && strings.Contains(strings.ToLower(blob), strings.ToLower(needleD)) {
			t.Errorf("%s leaked the RSA private exponent", name)
		}
		if strings.Contains(blob, "PRIVATE KEY") {
			t.Errorf("%s contains a PRIVATE KEY marker", name)
		}
	}

	// The audit trail must still carry the actor context SecEng requires.
	if !strings.Contains(audit.String(), "company=co-1") || !strings.Contains(audit.String(), "serial="+meta.Serial) {
		t.Error("audit log missing required actor/serial context")
	}

	// The store's public chain must never yield a private key on the way back.
	if _, err := DecodeChainPEM(pemStr); err != nil {
		t.Errorf("stored PEM did not decode as a pure public chain: %v", err)
	}
}

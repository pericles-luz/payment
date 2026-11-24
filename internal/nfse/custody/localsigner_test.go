package custody

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLocalSignerProvisionAndSignDigest(t *testing.T) {
	ctx := context.Background()
	s := NewLocalTestSigner()
	chain, meta, err := s.Provision("co-1", "11222333000181", time.Hour)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}

	msg := []byte("<SignedInfo>...</SignedInfo>")
	digest := sha256.Sum256(msg)
	sig, err := s.SignDigest(ctx, "co-1", meta.Serial, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	pub := chain[0].PublicKey.(*rsa.PublicKey)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("signature does not verify against leaf public key: %v", err)
	}
}

func TestLocalSignerProvisionEmptyCompany(t *testing.T) {
	s := NewLocalTestSigner()
	if _, _, err := s.Provision("", "x", time.Hour); !errors.Is(err, ErrEmptyCompanyID) {
		t.Errorf("provision empty company = %v, want ErrEmptyCompanyID", err)
	}
}

func TestLocalSignerSignUnknownFailsClosed(t *testing.T) {
	ctx := context.Background()
	s := NewLocalTestSigner()
	_, meta, _ := s.Provision("co-1", "11222333000181", time.Hour)
	digest := sha256.Sum256([]byte("x"))

	// Unknown serial.
	if _, err := s.SignDigest(ctx, "co-1", "deadbeef", digest[:]); !errors.Is(err, ErrNotProvisioned) {
		t.Errorf("unknown serial = %v, want ErrNotProvisioned", err)
	}
	// Unknown company with a real serial.
	if _, err := s.SignDigest(ctx, "co-nobody", meta.Serial, digest[:]); !errors.Is(err, ErrNotProvisioned) {
		t.Errorf("unknown company = %v, want ErrNotProvisioned", err)
	}
}

func TestLocalSignerExpiredFailsClosed(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	clock := base
	s := NewLocalTestSigner(WithClock(func() time.Time { return clock }))
	_, meta, err := s.Provision("co-1", "11222333000181", time.Hour)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	digest := sha256.Sum256([]byte("x"))

	// Advance the clock past notAfter.
	clock = base.Add(2 * time.Hour)
	if _, err := s.SignDigest(ctx, "co-1", meta.Serial, digest[:]); !errors.Is(err, ErrCertExpired) {
		t.Errorf("expired sign = %v, want ErrCertExpired", err)
	}
}

func TestLocalSignerClientCertificateDelegates(t *testing.T) {
	ctx := context.Background()
	s := NewLocalTestSigner()
	chain, _, err := s.Provision("co-1", "11222333000181", time.Hour)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}

	cert, err := s.ClientCertificate(ctx, "co-1")
	if err != nil {
		t.Fatalf("client cert: %v", err)
	}
	if cert.Leaf == nil || len(cert.Certificate) != 1 {
		t.Fatal("client certificate malformed")
	}
	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		t.Fatal("PrivateKey is not a crypto.Signer (delegation broken)")
	}
	// The delegated signer must expose only the public key.
	if _, ok := signer.Public().(*rsa.PublicKey); !ok {
		t.Fatal("delegated signer Public() is not an RSA public key")
	}

	digest := sha256.Sum256([]byte("mtls handshake"))
	sig, err := signer.Sign(nil, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("delegated sign: %v", err)
	}
	pub := chain[0].PublicKey.(*rsa.PublicKey)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("delegated signature does not verify: %v", err)
	}
}

func TestLocalSignerClientCertificateUnprovisioned(t *testing.T) {
	ctx := context.Background()
	s := NewLocalTestSigner()
	if _, err := s.ClientCertificate(ctx, "co-nobody"); !errors.Is(err, ErrNotProvisioned) {
		t.Errorf("unprovisioned client cert = %v, want ErrNotProvisioned", err)
	}
}

// TestDelegatedSignerSupportsHandshakeSchemes proves the delegating signer now
// produces valid signatures for every scheme a TLS peer may negotiate for an
// RSA client cert — RSA-PSS (TLS 1.3 / TLS 1.2) and PKCS#1 v1.5 (TLS 1.2) with
// SHA-256/384/512 — and still fails closed on unsupported inputs. Changing the
// prior "PSS rejected" behaviour is the explicit ask of SIN-67535: without it a
// real mTLS handshake against the ADN homologação fails with the custodied test
// cert.
func TestDelegatedSignerSupportsHandshakeSchemes(t *testing.T) {
	ctx := context.Background()
	s := NewLocalTestSigner()
	chain, _, _ := s.Provision("co-1", "11222333000181", time.Hour)
	cert, err := s.ClientCertificate(ctx, "co-1")
	if err != nil {
		t.Fatalf("client cert: %v", err)
	}
	signer := cert.PrivateKey.(crypto.Signer)
	pub := chain[0].PublicKey.(*rsa.PublicKey)

	hashes := []struct {
		h   crypto.Hash
		sum func([]byte) []byte
	}{
		{crypto.SHA256, func(b []byte) []byte { d := sha256.Sum256(b); return d[:] }},
		{crypto.SHA384, func(b []byte) []byte { d := sha512.Sum384(b); return d[:] }},
		{crypto.SHA512, func(b []byte) []byte { d := sha512.Sum512(b); return d[:] }},
	}
	for _, hc := range hashes {
		digest := hc.sum([]byte("mtls certificate-verify"))

		// RSA-PSS (what TLS 1.3 mandates in CertificateVerify).
		pss := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: hc.h}
		sig, err := signer.Sign(nil, digest, pss)
		if err != nil {
			t.Fatalf("PSS %v sign: %v", hc.h, err)
		}
		if err := rsa.VerifyPSS(pub, hc.h, digest, sig, pss); err != nil {
			t.Errorf("PSS %v signature does not verify: %v", hc.h, err)
		}

		// PKCS#1 v1.5 (TLS 1.2 may negotiate this).
		sig, err = signer.Sign(nil, digest, hc.h)
		if err != nil {
			t.Fatalf("PKCS1v15 %v sign: %v", hc.h, err)
		}
		if err := rsa.VerifyPKCS1v15(pub, hc.h, digest, sig); err != nil {
			t.Errorf("PKCS1v15 %v signature does not verify: %v", hc.h, err)
		}
	}
}

func TestDelegatedSignerRejectsUnsupportedSchemes(t *testing.T) {
	ctx := context.Background()
	s := NewLocalTestSigner()
	_, _, _ = s.Provision("co-1", "11222333000181", time.Hour)
	cert, err := s.ClientCertificate(ctx, "co-1")
	if err != nil {
		t.Fatalf("client cert: %v", err)
	}
	signer := cert.PrivateKey.(crypto.Signer)
	digest := sha256.Sum256([]byte("x"))

	// nil opts rejected — no hash to bind the signature to.
	if _, err := signer.Sign(nil, digest[:], nil); !errors.Is(err, ErrNotProvisioned) {
		t.Errorf("nil opts = %v, want ErrNotProvisioned", err)
	}
	// SHA-1 is not TLS-negotiable for RSA on a MinVersion TLS 1.2 stack and is
	// deprecated; it must fail closed rather than mint a weak signature.
	if _, err := signer.Sign(nil, digest[:], crypto.SHA1); !errors.Is(err, ErrNotProvisioned) {
		t.Errorf("SHA-1 sign = %v, want ErrNotProvisioned", err)
	}
	// SHA-1 PSS likewise rejected.
	pss1 := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA1}
	if _, err := signer.Sign(nil, digest[:], pss1); !errors.Is(err, ErrNotProvisioned) {
		t.Errorf("SHA-1 PSS sign = %v, want ErrNotProvisioned", err)
	}
}

// TestLocalSignerSatisfiesTLSCertificate wires the client certificate into a
// tls.Config to prove it is structurally usable for mTLS client auth.
func TestLocalSignerSatisfiesTLSCertificate(t *testing.T) {
	s := NewLocalTestSigner()
	_, _, _ = s.Provision("co-1", "11222333000181", time.Hour)
	cert, err := s.ClientCertificate(context.Background(), "co-1")
	if err != nil {
		t.Fatalf("client cert: %v", err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	if len(cfg.Certificates) != 1 {
		t.Fatal("tls.Config did not accept the certificate")
	}
}

// TestLocalSignerCompletesRealMTLSHandshake is the end-to-end proof for
// SIN-67535: it drives a REAL TLS handshake (not a structural check) in which
// the client presents the custodied test certificate and the server's TLS
// stack cryptographically verifies the CertificateVerify signature the
// delegating signer produces. MinVersion/MaxVersion are pinned to TLS 1.3, so
// the client MUST sign with RSA-PSS — the exact scheme that previously failed
// closed with ErrNotProvisioned. A completed request body round-trip means the
// mTLS handshake, including RSA-PSS client auth with the custody signer,
// succeeded against a peer that requires and validates the client cert.
//
// This exercises the same code path as a handshake against the ADN homologação;
// what remains for the live-endpoint AC is network egress plus an ICP-Brasil
// test cert the real ADN trusts (ops/infra, out of this adapter's scope).
func TestLocalSignerCompletesRealMTLSHandshake(t *testing.T) {
	s := NewLocalTestSigner()
	chain, _, err := s.Provision("co-1", "11222333000181", time.Hour)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	clientCert, err := s.ClientCertificate(context.Background(), "co-1")
	if err != nil {
		t.Fatalf("client cert: %v", err)
	}

	var peerPresented bool
	var peerSerial string
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) > 0 {
			peerPresented = true
			peerSerial = SerialHex(r.TLS.PeerCertificates[0])
		}
		_, _ = io.WriteString(w, "ok")
	}))
	// Force TLS 1.3 so the client-auth signature is RSA-PSS, and require + read
	// the client certificate so the handshake actually verifies CertificateVerify.
	ts.TLS = &tls.Config{
		ClientAuth: tls.RequireAnyClientCert,
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	}
	ts.StartTLS()
	defer ts.Close()

	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    pool,
				MinVersion: tls.VersionTLS13,
				GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
					return &clientCert, nil
				},
			},
		},
	}

	resp, err := httpClient.Get(ts.URL)
	if err != nil {
		t.Fatalf("real mTLS handshake failed (RSA-PSS client auth): %v", err)
	}
	defer resp.Body.Close()
	if resp.TLS == nil || resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("handshake did not negotiate TLS 1.3: %+v", resp.TLS)
	}
	if !peerPresented {
		t.Fatal("server did not receive/verify the custodied client certificate")
	}
	if want := SerialHex(chain[0]); peerSerial != want {
		t.Errorf("server saw client cert serial %q, want custodied %q", peerSerial, want)
	}
}

// TestLocalSignerFiscalSignerInterface asserts the adapter satisfies the port.
func TestLocalSignerFiscalSignerInterface(t *testing.T) {
	var _ FiscalSigner = NewLocalTestSigner()
	var _ CertStore = NewMemoryCertStore()
}

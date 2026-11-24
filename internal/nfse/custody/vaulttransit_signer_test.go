package custody

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// genericNameRe mirrors Vault's framework.GenericNameRegex, the pattern the
// transit/{sign,keys}/{name} routes bind {name} to: \w(([\w-.]+)?\w)? — which
// has NO "/". A request whose {name} token falls outside it never matches the
// route, so a real Vault answers 404 "unsupported path". The stubs enforce this
// so a key name carrying "/" (the pre-SIN-67698 scheme) fails at the fake
// exactly as it does against real Vault, instead of being silently accepted —
// keeping the fakes FAITHFUL (SIN-67698).
var genericNameRe = regexp.MustCompile(`^\w(([\w.-]+)?\w)?$`)

// unsupportedPath writes Vault's 404 for a name the transit routes cannot bind.
func unsupportedPath(w http.ResponseWriter) {
	http.Error(w, `{"errors":["unsupported path"]}`, http.StatusNotFound)
}

// vaultKeyName mirrors VaultTransitSigner.keyName for the default "a1" prefix, so
// each stub is seeded with EXACTLY the flat, single-segment name the adapter will
// request ("a1.{companyID}.{serial}"). Using the production delimiter keeps the
// fixture in lock-step with keyName.
func vaultKeyName(companyID, serial string) string {
	return "a1" + keySegmentDelimiter + companyID + keySegmentDelimiter + serial
}

// transitStub is an httptest.Server that stands in for Vault's Transit engine.
// It holds the RSA TEST key (the private material a real deployment keeps inside
// Vault) and signs FOR REAL — PKCS#1 v1.5 and RSA-PSS — so the adapter is
// exercised over a genuine HTTP boundary. This is the legitimate boundary stub
// the spec calls for, NOT a mock of storage.
type transitStub struct {
	*httptest.Server
	mu       sync.Mutex
	keys     map[string]*rsa.PrivateKey
	export   map[string]bool // keyName -> exportable/backup-able
	lastPath string
	signCall int
	keyCall  int // GET transit/keys/... reads (exportable preflight)
}

func newTransitStub(t *testing.T) *transitStub {
	t.Helper()
	s := &transitStub{
		keys:   make(map[string]*rsa.PrivateKey),
		export: make(map[string]bool),
	}
	s.Server = httptest.NewServer(http.HandlerFunc(s.handle))
	t.Cleanup(s.Close)
	return s
}

func (s *transitStub) addKey(name string, key *rsa.PrivateKey, exportable bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[name] = key
	s.export[name] = exportable
}

// setExportable flips a key's reported exportable/backup-able flag at runtime,
// modelling an operator who reconfigures the key after it was first verified.
func (s *transitStub) setExportable(name string, exportable bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.export[name] = exportable
}

func (s *transitStub) handle(w http.ResponseWriter, r *http.Request) {
	const prefix = "/v1/transit/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, prefix)
	switch {
	case strings.HasPrefix(rest, "sign/"):
		name := strings.TrimPrefix(rest, "sign/")
		if !genericNameRe.MatchString(name) {
			unsupportedPath(w) // faithful: a "/"-bearing name 404s, like real Vault
			return
		}
		s.handleSign(w, r, name)
	case strings.HasPrefix(rest, "keys/"):
		name := strings.TrimPrefix(rest, "keys/")
		if !genericNameRe.MatchString(name) {
			unsupportedPath(w)
			return
		}
		s.handleKeys(w, r, name)
	default:
		http.Error(w, "unsupported", http.StatusNotFound)
	}
}

func (s *transitStub) handleKeys(w http.ResponseWriter, _ *http.Request, name string) {
	s.mu.Lock()
	s.keyCall++
	_, known := s.keys[name]
	exportable := s.export[name]
	s.mu.Unlock()
	if !known {
		http.Error(w, `{"errors":["no such key"]}`, http.StatusNotFound)
		return
	}
	writeJSON(w, transitKeyResponse{Data: struct {
		Exportable           bool `json:"exportable"`
		AllowPlaintextBackup bool `json:"allow_plaintext_backup"`
	}{Exportable: exportable, AllowPlaintextBackup: exportable}})
}

func (s *transitStub) handleSign(w http.ResponseWriter, r *http.Request, name string) {
	s.mu.Lock()
	s.lastPath = r.URL.Path
	s.signCall++
	key := s.keys[name]
	s.mu.Unlock()
	if key == nil {
		http.Error(w, `{"errors":["no such key"]}`, http.StatusNotFound)
		return
	}
	var req transitSignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	digest, err := base64.StdEncoding.DecodeString(req.Input)
	if err != nil {
		http.Error(w, "bad input", http.StatusBadRequest)
		return
	}
	h, ok := hashFromName(req.HashAlgorithm)
	if !ok {
		http.Error(w, "bad hash", http.StatusBadRequest)
		return
	}
	var sig []byte
	switch req.SignatureAlgorithm {
	case "pss":
		opts := &rsa.PSSOptions{Hash: h, SaltLength: saltFromName(req.SaltLength)}
		sig, err = rsa.SignPSS(rand.Reader, key, h, digest, opts)
	case "pkcs1v15", "":
		sig, err = rsa.SignPKCS1v15(rand.Reader, key, h, digest)
	default:
		http.Error(w, "bad sig alg", http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, "sign failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, transitSignResponse{Data: struct {
		Signature string `json:"signature"`
	}{Signature: "vault:v1:" + base64.StdEncoding.EncodeToString(sig)}})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func hashFromName(n string) (crypto.Hash, bool) {
	switch n {
	case "sha2-256":
		return crypto.SHA256, true
	case "sha2-384":
		return crypto.SHA384, true
	case "sha2-512":
		return crypto.SHA512, true
	default:
		return 0, false
	}
}

func saltFromName(n string) int {
	switch n {
	case "hash":
		return rsa.PSSSaltLengthEqualsHash
	case "auto", "":
		return rsa.PSSSaltLengthAuto
	default:
		return rsa.PSSSaltLengthAuto
	}
}

// newVaultTestLeaf mints an RSA key + self-signed leaf the test controls, so the
// private key can be handed to the Transit stub (mirroring a BYOK import).
func newVaultTestLeaf(t *testing.T, companyID, cnpj string, validFor time.Duration, now time.Time) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	serialInt, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serialInt,
		Subject:               pkix.Name{CommonName: "TEST A1 " + companyID, SerialNumber: HashCNPJ(cnpj)},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(validFor),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return key, leaf
}

// harnessSigner packages everything a parity regression needs from an adapter.
type harnessSigner struct {
	fs        FiscalSigner
	pub       *rsa.PublicKey
	leaf      *x509.Certificate
	companyID string
	serial    string
}

// buildLocalHarness sets up a LocalTestSigner.
func buildLocalHarness(t *testing.T) harnessSigner {
	t.Helper()
	s := NewLocalTestSigner()
	chain, meta, err := s.Provision("co-1", "11222333000181", time.Hour)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	return harnessSigner{fs: s, pub: chain[0].PublicKey.(*rsa.PublicKey), leaf: chain[0], companyID: "co-1", serial: meta.Serial}
}

// buildVaultHarness sets up a VaultTransitSigner against the Transit stub.
func buildVaultHarness(t *testing.T) harnessSigner {
	t.Helper()
	key, leaf := newVaultTestLeaf(t, "co-1", "11222333000181", time.Hour, time.Now())
	serial := SerialHex(leaf)
	stub := newTransitStub(t)
	stub.addKey(vaultKeyName("co-1", serial), key, false)
	store := NewMemoryCertStore()
	if err := store.PutA1(context.Background(), "co-1", []*x509.Certificate{leaf}, A1MetaFromLeaf(leaf, "11222333000181")); err != nil {
		t.Fatalf("putA1: %v", err)
	}
	v, err := NewVaultTransitSigner(VaultTransitConfig{Address: stub.URL, Certs: store, Token: "test-token"})
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return harnessSigner{fs: v, pub: &key.PublicKey, leaf: leaf, companyID: "co-1", serial: serial}
}

var parityHarnesses = []struct {
	name  string
	build func(*testing.T) harnessSigner
}{
	{"local", buildLocalHarness},
	{"vault_transit", buildVaultHarness},
}

// TestParityRealMTLSHandshake is regression (a): a REAL TLS 1.3 handshake driven
// through each adapter's delegating signer, where the client presents the
// custodied test cert and the server cryptographically verifies the
// CertificateVerify signature. TLS 1.3 is pinned, so the client MUST sign with
// RSA-PSS — the exact scheme a v1.5-only signer fails closed on. The httptest
// Transit stub holds the RSA key and signs for real. Passing against BOTH the
// local and the Vault adapter proves the dual-scheme surface is identical (AC #1
// + mandatory parity).
func TestParityRealMTLSHandshake(t *testing.T) {
	for _, hc := range parityHarnesses {
		t.Run(hc.name, func(t *testing.T) {
			h := hc.build(t)
			clientCert, err := h.fs.ClientCertificate(context.Background(), h.companyID)
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
				t.Fatalf("real mTLS handshake failed (RSA-PSS client auth via %s): %v", hc.name, err)
			}
			defer resp.Body.Close()
			if resp.TLS == nil || resp.TLS.Version != tls.VersionTLS13 {
				t.Fatalf("handshake did not negotiate TLS 1.3: %+v", resp.TLS)
			}
			if !peerPresented {
				t.Fatal("server did not receive/verify the custodied client certificate")
			}
			if peerSerial != h.serial {
				t.Errorf("server saw client cert serial %q, want custodied %q", peerSerial, h.serial)
			}
		})
	}
}

// TestParityDPSXMLDSigVerifiesPKCS1v15 is regression (b): the DPS XMLDSIG digest
// signed through each adapter verifies with rsa.VerifyPKCS1v15 against the leaf
// public key. Document signing stays PKCS#1 v1.5 SHA-256 per the NFS-e spec on
// both adapters.
func TestParityDPSXMLDSigVerifiesPKCS1v15(t *testing.T) {
	for _, hc := range parityHarnesses {
		t.Run(hc.name, func(t *testing.T) {
			h := hc.build(t)
			digest := sha256.Sum256([]byte("<SignedInfo>DPS</SignedInfo>"))
			sig, err := h.fs.SignDigest(context.Background(), h.companyID, h.serial, digest[:])
			if err != nil {
				t.Fatalf("sign digest via %s: %v", hc.name, err)
			}
			if err := rsa.VerifyPKCS1v15(h.pub, crypto.SHA256, digest[:], sig); err != nil {
				t.Fatalf("DPS signature does not verify (%s): %v", hc.name, err)
			}
		})
	}
}

// TestVaultSignerDualSchemeDelegated proves the delegating signer routes PSS and
// PKCS#1 v1.5 for every TLS-negotiable SHA-2 hash, with the signatures verifying
// against the leaf public key — the vuln the old delegatedSigner fell closed on.
func TestVaultSignerDualSchemeDelegated(t *testing.T) {
	h := buildVaultHarness(t)
	cert, err := h.fs.ClientCertificate(context.Background(), h.companyID)
	if err != nil {
		t.Fatalf("client cert: %v", err)
	}
	signer := cert.PrivateKey.(crypto.Signer)

	cases := []struct {
		h   crypto.Hash
		sum func([]byte) []byte
	}{
		{crypto.SHA256, func(b []byte) []byte { d := sha256.Sum256(b); return d[:] }},
		{crypto.SHA384, func(b []byte) []byte { d := sha512.Sum384(b); return d[:] }},
		{crypto.SHA512, func(b []byte) []byte { d := sha512.Sum512(b); return d[:] }},
	}
	for _, c := range cases {
		digest := c.sum([]byte("certificate-verify"))
		pss := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: c.h}
		sig, err := signer.Sign(nil, digest, pss)
		if err != nil {
			t.Fatalf("PSS %v sign: %v", c.h, err)
		}
		if err := rsa.VerifyPSS(h.pub, c.h, digest, sig, pss); err != nil {
			t.Errorf("PSS %v does not verify: %v", c.h, err)
		}
		sig, err = signer.Sign(nil, digest, c.h)
		if err != nil {
			t.Fatalf("PKCS1v15 %v sign: %v", c.h, err)
		}
		if err := rsa.VerifyPKCS1v15(h.pub, c.h, digest, sig); err != nil {
			t.Errorf("PKCS1v15 %v does not verify: %v", c.h, err)
		}
	}
}

// TestVaultSignerRejectsUnsupportedSchemes asserts the delegating signer fails
// closed on nil opts and non-TLS-negotiable hashes, never minting a weak sig.
func TestVaultSignerRejectsUnsupportedSchemes(t *testing.T) {
	h := buildVaultHarness(t)
	cert, err := h.fs.ClientCertificate(context.Background(), h.companyID)
	if err != nil {
		t.Fatalf("client cert: %v", err)
	}
	signer := cert.PrivateKey.(crypto.Signer)
	digest := sha256.Sum256([]byte("x"))

	if _, err := signer.Sign(nil, digest[:], nil); !errors.Is(err, ErrNotProvisioned) {
		t.Errorf("nil opts = %v, want ErrNotProvisioned", err)
	}
	if _, err := signer.Sign(nil, digest[:], crypto.SHA1); !errors.Is(err, ErrNotProvisioned) {
		t.Errorf("SHA-1 = %v, want ErrNotProvisioned", err)
	}
	pss1 := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA1}
	if _, err := signer.Sign(nil, digest[:], pss1); !errors.Is(err, ErrNotProvisioned) {
		t.Errorf("SHA-1 PSS = %v, want ErrNotProvisioned", err)
	}
	if _, ok := signer.Public().(*rsa.PublicKey); !ok {
		t.Error("delegated signer Public() is not an RSA public key")
	}
}

// TestVaultSignerTenantScoping is regression (c): the adapter fails closed for an
// empty company_id, refuses a cross-tenant serial, and the Transit URL it calls
// carries the correct company_id path segment.
func TestVaultSignerTenantScoping(t *testing.T) {
	ctx := context.Background()
	keyA, leafA := newVaultTestLeaf(t, "tenant-A", "11222333000181", time.Hour, time.Now())
	keyB, leafB := newVaultTestLeaf(t, "tenant-B", "44555666000199", time.Hour, time.Now())
	serialA, serialB := SerialHex(leafA), SerialHex(leafB)

	stub := newTransitStub(t)
	stub.addKey(vaultKeyName("tenant-A", serialA), keyA, false)
	stub.addKey(vaultKeyName("tenant-B", serialB), keyB, false)
	store := NewMemoryCertStore()
	_ = store.PutA1(ctx, "tenant-A", []*x509.Certificate{leafA}, A1MetaFromLeaf(leafA, "11222333000181"))
	_ = store.PutA1(ctx, "tenant-B", []*x509.Certificate{leafB}, A1MetaFromLeaf(leafB, "44555666000199"))
	v, err := NewVaultTransitSigner(VaultTransitConfig{Address: stub.URL, Certs: store, Token: "t"})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	digest := sha256.Sum256([]byte("DPS"))

	// Empty company_id fails closed with no KMS call.
	if _, err := v.SignDigest(ctx, "", serialA, digest[:]); !errors.Is(err, ErrEmptyCompanyID) {
		t.Errorf("empty company = %v, want ErrEmptyCompanyID", err)
	}
	// Cross-tenant: A presents B's serial -> denied fail-closed.
	if _, err := v.SignDigest(ctx, "tenant-A", serialB, digest[:]); !errors.Is(err, ErrNotProvisioned) {
		t.Errorf("cross-tenant = %v, want ErrNotProvisioned", err)
	}
	// Unknown tenant -> denied.
	if _, err := v.SignDigest(ctx, "tenant-nobody", serialA, digest[:]); !errors.Is(err, ErrNotProvisioned) {
		t.Errorf("unknown tenant = %v, want ErrNotProvisioned", err)
	}

	// Legit sign lands on the correct tenant-scoped Transit path.
	if _, err := v.SignDigest(ctx, "tenant-A", serialA, digest[:]); err != nil {
		t.Fatalf("legit sign A: %v", err)
	}
	stub.mu.Lock()
	last := stub.lastPath
	stub.mu.Unlock()
	if want := "/v1/transit/sign/" + vaultKeyName("tenant-A", serialA); last != want {
		t.Errorf("transit path = %q, want %q", last, want)
	}
	if strings.Contains(last, "tenant-B") {
		t.Errorf("tenant-A sign leaked tenant-B into path %q", last)
	}
}

// TestVaultSignerExpiredFailsClosed asserts an expired certificate is denied
// before any KMS round-trip (AC #9).
func TestVaultSignerExpiredFailsClosed(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	key, leaf := newVaultTestLeaf(t, "co-1", "11222333000181", time.Hour, base)
	serial := SerialHex(leaf)
	stub := newTransitStub(t)
	stub.addKey(vaultKeyName("co-1", serial), key, false)
	store := NewMemoryCertStore()
	_ = store.PutA1(ctx, "co-1", []*x509.Certificate{leaf}, A1MetaFromLeaf(leaf, "11222333000181"))

	clock := base.Add(2 * time.Hour) // past notAfter
	v, err := NewVaultTransitSigner(VaultTransitConfig{Address: stub.URL, Certs: store, Token: "t", Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	digest := sha256.Sum256([]byte("x"))
	if _, err := v.SignDigest(ctx, "co-1", serial, digest[:]); !errors.Is(err, ErrCertExpired) {
		t.Errorf("expired SignDigest = %v, want ErrCertExpired", err)
	}
	if _, err := v.ClientCertificate(ctx, "co-1"); !errors.Is(err, ErrCertExpired) {
		t.Errorf("expired ClientCertificate = %v, want ErrCertExpired", err)
	}
	stub.mu.Lock()
	calls := stub.signCall
	stub.mu.Unlock()
	if calls != 0 {
		t.Errorf("expired path made %d KMS sign calls, want 0 (fail-closed before ADN)", calls)
	}
}

// expiryObservation records one ExpiryObserver callback so a test can assert
// both the emitted value (backing a1_cert_expiry_days) and that it fired.
type expiryObservation struct {
	companyID string
	serial    string
	days      int
}

// TestVaultSignerExpiryObserverEmitsAndFailsClosed is the AC #7 regression: an
// expired certificate must publish a NEGATIVE a1_cert_expiry_days gauge (so
// silent expiry is observable and the D-1 alert fires) AND still be denied on
// the sign / mTLS path before any KMS/ADN round-trip. It fails against the
// pre-SIN-67760 adapter (which never emitted the gauge) and passes after.
func TestVaultSignerExpiryObserverEmitsAndFailsClosed(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	key, leaf := newVaultTestLeaf(t, "co-1", "11222333000181", time.Hour, base)
	serial := SerialHex(leaf)
	stub := newTransitStub(t)
	stub.addKey(vaultKeyName("co-1", serial), key, false)
	store := NewMemoryCertStore()
	_ = store.PutA1(ctx, "co-1", []*x509.Certificate{leaf}, A1MetaFromLeaf(leaf, "11222333000181"))

	var mu sync.Mutex
	var obs []expiryObservation
	observer := func(companyID, serial string, days int) {
		mu.Lock()
		defer mu.Unlock()
		obs = append(obs, expiryObservation{companyID, serial, days})
	}

	clock := base.Add(72 * time.Hour) // 3 days past notAfter
	v, err := NewVaultTransitSigner(VaultTransitConfig{
		Address: stub.URL, Certs: store, Token: "t",
		Now:            func() time.Time { return clock },
		ExpiryObserver: observer,
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	digest := sha256.Sum256([]byte("x"))
	if _, err := v.SignDigest(ctx, "co-1", serial, digest[:]); !errors.Is(err, ErrCertExpired) {
		t.Errorf("expired SignDigest = %v, want ErrCertExpired", err)
	}
	if _, err := v.ClientCertificate(ctx, "co-1"); !errors.Is(err, ErrCertExpired) {
		t.Errorf("expired ClientCertificate = %v, want ErrCertExpired", err)
	}

	// Fail-closed: nothing reached the KMS (and thus never the ADN).
	stub.mu.Lock()
	calls := stub.signCall
	stub.mu.Unlock()
	if calls != 0 {
		t.Errorf("expired path made %d KMS sign calls, want 0 (fail-closed before ADN)", calls)
	}

	// The gauge was published from both read paths, negative and with the
	// on-file serial + tenant id (no CNPJ).
	mu.Lock()
	defer mu.Unlock()
	if len(obs) != 2 {
		t.Fatalf("expiry observer fired %d times, want 2 (SignDigest + ClientCertificate)", len(obs))
	}
	for _, o := range obs {
		if o.companyID != "co-1" || o.serial != serial {
			t.Errorf("observation labels = {%q,%q}, want {co-1,%s}", o.companyID, o.serial, serial)
		}
		if o.days >= 0 {
			t.Errorf("expired cert observed days = %d, want negative", o.days)
		}
	}
}

// TestVaultSignerExpiryObserverPositiveOnValidCert proves the observer also
// fires with the correct POSITIVE remaining-days count on a healthy cert, so a
// tenant approaching D-30/15/7/1 is tracked before it ever expires.
func TestVaultSignerExpiryObserverPositiveOnValidCert(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	key, leaf := newVaultTestLeaf(t, "co-1", "11222333000181", 30*24*time.Hour, base)
	serial := SerialHex(leaf)
	stub := newTransitStub(t)
	stub.addKey(vaultKeyName("co-1", serial), key, false)
	store := NewMemoryCertStore()
	_ = store.PutA1(ctx, "co-1", []*x509.Certificate{leaf}, A1MetaFromLeaf(leaf, "11222333000181"))

	var got expiryObservation
	var fired bool
	v, err := NewVaultTransitSigner(VaultTransitConfig{
		Address: stub.URL, Certs: store, Token: "t",
		Now: func() time.Time { return base },
		ExpiryObserver: func(companyID, serial string, days int) {
			got = expiryObservation{companyID, serial, days}
			fired = true
		},
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	digest := sha256.Sum256([]byte("x"))
	if _, err := v.SignDigest(ctx, "co-1", serial, digest[:]); err != nil {
		t.Fatalf("valid SignDigest = %v, want nil", err)
	}
	if !fired {
		t.Fatal("expiry observer did not fire on a valid sign")
	}
	// leaf.NotAfter = base + 30d, so ExpiresInDays(base) is 30.
	if got.days != 30 {
		t.Errorf("valid cert observed days = %d, want 30", got.days)
	}
	if got.companyID != "co-1" || got.serial != serial {
		t.Errorf("observation labels = {%q,%q}, want {co-1,%s}", got.companyID, got.serial, serial)
	}
}

// TestVaultSignerRefusesExportableKey encodes AC #3: if Transit reports the key
// as exportable/backup-able, the adapter refuses to sign fail-closed.
func TestVaultSignerRefusesExportableKey(t *testing.T) {
	ctx := context.Background()
	key, leaf := newVaultTestLeaf(t, "co-1", "11222333000181", time.Hour, time.Now())
	serial := SerialHex(leaf)
	stub := newTransitStub(t)
	stub.addKey(vaultKeyName("co-1", serial), key, true) // exportable!
	store := NewMemoryCertStore()
	_ = store.PutA1(ctx, "co-1", []*x509.Certificate{leaf}, A1MetaFromLeaf(leaf, "11222333000181"))
	v, err := NewVaultTransitSigner(VaultTransitConfig{Address: stub.URL, Certs: store, Token: "t"})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	digest := sha256.Sum256([]byte("x"))
	if _, err := v.SignDigest(ctx, "co-1", serial, digest[:]); !errors.Is(err, ErrKeyExportable) {
		t.Errorf("exportable key sign = %v, want ErrKeyExportable", err)
	}
	stub.mu.Lock()
	calls := stub.signCall
	stub.mu.Unlock()
	if calls != 0 {
		t.Errorf("exportable key made %d sign calls, want 0", calls)
	}
}

// TestVaultSignerSkipExportableCheck proves the preflight can be disabled for
// policies without Transit read capability — signing then proceeds.
func TestVaultSignerSkipExportableCheck(t *testing.T) {
	ctx := context.Background()
	key, leaf := newVaultTestLeaf(t, "co-1", "11222333000181", time.Hour, time.Now())
	serial := SerialHex(leaf)
	stub := newTransitStub(t)
	stub.addKey(vaultKeyName("co-1", serial), key, true) // exportable, but check skipped
	store := NewMemoryCertStore()
	_ = store.PutA1(ctx, "co-1", []*x509.Certificate{leaf}, A1MetaFromLeaf(leaf, "11222333000181"))
	v, err := NewVaultTransitSigner(VaultTransitConfig{Address: stub.URL, Certs: store, Token: "t", SkipExportableCheck: true})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	digest := sha256.Sum256([]byte("x"))
	sig, err := v.SignDigest(ctx, "co-1", serial, digest[:])
	if err != nil {
		t.Fatalf("sign with check skipped: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
}

// TestVaultSignerExportableCheckTTL is the SIN-67543 hardening #1 regression:
// the confirmed non-exportable verdict is cached only for ExportableCheckTTL.
// Within the TTL the preflight read is skipped (cache hit); once the clock
// advances past it, the adapter re-reads the key config — so a key flipped
// exportable after the first check is caught fail-closed on the next sign,
// closing the per-process TOCTOU window.
func TestVaultSignerExportableCheckTTL(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	clock := base
	key, leaf := newVaultTestLeaf(t, "co-1", "11222333000181", 24*time.Hour, base)
	serial := SerialHex(leaf)
	keyName := vaultKeyName("co-1", serial)
	stub := newTransitStub(t)
	stub.addKey(keyName, key, false)
	store := NewMemoryCertStore()
	_ = store.PutA1(ctx, "co-1", []*x509.Certificate{leaf}, A1MetaFromLeaf(leaf, "11222333000181"))

	v, err := NewVaultTransitSigner(VaultTransitConfig{
		Address: stub.URL, Certs: store, Token: "t",
		ExportableCheckTTL: 5 * time.Minute,
		Now:                func() time.Time { return clock },
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	digest := sha256.Sum256([]byte("DPS"))

	// First sign reads the key config once.
	if _, err := v.SignDigest(ctx, "co-1", serial, digest[:]); err != nil {
		t.Fatalf("first sign: %v", err)
	}
	stub.mu.Lock()
	keyCalls := stub.keyCall
	stub.mu.Unlock()
	if keyCalls != 1 {
		t.Fatalf("after first sign keyCall = %d, want 1", keyCalls)
	}

	// Second sign inside the TTL is a cache hit — no re-read.
	clock = base.Add(4 * time.Minute)
	if _, err := v.SignDigest(ctx, "co-1", serial, digest[:]); err != nil {
		t.Fatalf("cached sign: %v", err)
	}
	stub.mu.Lock()
	keyCalls = stub.keyCall
	stub.mu.Unlock()
	if keyCalls != 1 {
		t.Fatalf("within-TTL sign re-read the key config (keyCall = %d, want 1)", keyCalls)
	}

	// Operator flips the key exportable. Still cached -> TOCTOU window open.
	stub.setExportable(keyName, true)
	if _, err := v.SignDigest(ctx, "co-1", serial, digest[:]); err != nil {
		t.Fatalf("still-cached sign after flip: %v", err)
	}

	// Advance past the TTL: the next sign MUST re-read and now fail closed.
	clock = base.Add(6 * time.Minute)
	if _, err := v.SignDigest(ctx, "co-1", serial, digest[:]); !errors.Is(err, ErrKeyExportable) {
		t.Errorf("post-TTL sign after flip = %v, want ErrKeyExportable", err)
	}
	stub.mu.Lock()
	keyCalls = stub.keyCall
	stub.mu.Unlock()
	if keyCalls != 2 {
		t.Errorf("post-TTL keyCall = %d, want 2 (re-read)", keyCalls)
	}

	// A subsequent flip back to non-exportable is honoured: the exportable
	// verdict was not cached, so the next sign re-reads and succeeds.
	stub.setExportable(keyName, false)
	clock = base.Add(7 * time.Minute)
	if _, err := v.SignDigest(ctx, "co-1", serial, digest[:]); err != nil {
		t.Errorf("sign after flip-back to non-exportable = %v, want success", err)
	}
}

// TestVaultSignerDefaultExportableCheckTTL asserts the zero-value config lands
// on the 10-minute default rather than caching for the process lifetime.
func TestVaultSignerDefaultExportableCheckTTL(t *testing.T) {
	v, err := NewVaultTransitSigner(VaultTransitConfig{Address: "http://x", Certs: NewMemoryCertStore()})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if v.exportableTTL != defaultExportableCheckTTL {
		t.Errorf("default exportableTTL = %v, want %v", v.exportableTTL, defaultExportableCheckTTL)
	}
}

// TestVaultSignerRejectsInvalidKeyChars is the SIN-67543 hardening #2
// regression: company_id / serial carrying anything outside the Transit
// key-segment allowlist (notably "/" and "." / "..") is refused fail-closed
// with ErrInvalidKeyChars, before any KMS round-trip, on every signing entry
// point. This forecloses path-segment injection and traversal by construction.
func TestVaultSignerRejectsInvalidKeyChars(t *testing.T) {
	ctx := context.Background()
	key, leaf := newVaultTestLeaf(t, "co-1", "11222333000181", time.Hour, time.Now())
	serial := SerialHex(leaf)
	stub := newTransitStub(t)
	stub.addKey(vaultKeyName("co-1", serial), key, false)
	store := NewMemoryCertStore()
	_ = store.PutA1(ctx, "co-1", []*x509.Certificate{leaf}, A1MetaFromLeaf(leaf, "11222333000181"))
	v, err := NewVaultTransitSigner(VaultTransitConfig{Address: stub.URL, Certs: store, Token: "t"})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	digest := sha256.Sum256([]byte("x"))

	badSegs := []string{"co-1/extra", "..", ".", "a b", "co\x00", "co%2f", "a/b/c", ""}

	// SignDigest rejects a bad company_id (empty maps to ErrEmptyCompanyID).
	for _, bad := range badSegs {
		wantErr := ErrInvalidKeyChars
		if bad == "" {
			wantErr = ErrEmptyCompanyID
		}
		if _, err := v.SignDigest(ctx, bad, serial, digest[:]); !errors.Is(err, wantErr) {
			t.Errorf("SignDigest company_id=%q = %v, want %v", bad, err, wantErr)
		}
	}
	// SignDigest rejects a bad serial (empty maps to ErrNotProvisioned).
	for _, bad := range badSegs {
		wantErr := ErrInvalidKeyChars
		if bad == "" {
			wantErr = ErrNotProvisioned
		}
		if _, err := v.SignDigest(ctx, "co-1", bad, digest[:]); !errors.Is(err, wantErr) {
			t.Errorf("SignDigest serial=%q = %v, want %v", bad, err, wantErr)
		}
	}
	// ClientCertificate rejects a bad company_id up front.
	for _, bad := range []string{"co-1/extra", "..", "a/b"} {
		if _, err := v.ClientCertificate(ctx, bad); !errors.Is(err, ErrInvalidKeyChars) {
			t.Errorf("ClientCertificate company_id=%q = %v, want ErrInvalidKeyChars", bad, err)
		}
	}
	// Not one of the rejects reached the KMS.
	stub.mu.Lock()
	signCalls, keyCalls := stub.signCall, stub.keyCall
	stub.mu.Unlock()
	if signCalls != 0 || keyCalls != 0 {
		t.Errorf("invalid-char inputs reached KMS: signCall=%d keyCall=%d, want 0/0", signCalls, keyCalls)
	}
}

// TestValidKeySegment is a focused unit test for the charset allowlist helper.
// SIN-67698 tightened the allowlist to EXCLUDE the "." delimiter (previously
// admitted), so keyName's flattening stays injective; "." inside a segment is
// now invalid alongside "/".
func TestValidKeySegment(t *testing.T) {
	valid := []string{"co-1", "tenant-A", "11222333000181", "ab_c-1", "ABC", "0"}
	for _, s := range valid {
		if !validKeySegment(s) {
			t.Errorf("validKeySegment(%q) = false, want true", s)
		}
	}
	// "a.b" / "a.b_c-1" carry the delimiter and are now refused (SIN-67698).
	invalid := []string{"", ".", "..", "a.b", "a.b_c-1", "a/b", "co 1", "co\tx", "a%2fb", "café", "a:b", "a\nb"}
	for _, s := range invalid {
		if validKeySegment(s) {
			t.Errorf("validKeySegment(%q) = true, want false", s)
		}
	}
}

// TestKeyNameFlatInjective pins the SIN-67698 invariants on keyName: it produces
// a single flat, Transit-legal name (matches GenericNameRegex, NEVER contains
// "/"), and the (prefix, company, serial) -> name mapping is injective. The
// injectivity holds because the "." delimiter is excluded from valid segments,
// so the classic ("co1","23") vs ("co","123") concat-collision cannot be forged
// — a delimiter-bearing segment is refused before keyName is ever reached.
func TestKeyNameFlatInjective(t *testing.T) {
	v, err := NewVaultTransitSigner(VaultTransitConfig{Address: "http://x", Certs: NewMemoryCertStore()})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	tuples := []struct{ company, serial string }{
		{"co1", "23"}, // "co1"+"23"  and
		{"co", "123"}, // "co"+"123"  would collide under bare concat
		{"co-1", "0a1b"},
		{"co-1", "0a1b2"}, // serial differs
		{"tenant-A", "deadbeef"},
	}
	seen := map[string]string{}
	for _, tp := range tuples {
		name := v.keyName(tp.company, tp.serial)
		if strings.Contains(name, "/") {
			t.Errorf("keyName(%q,%q)=%q contains \"/\" — 404s against real Vault", tp.company, tp.serial, name)
		}
		if !genericNameRe.MatchString(name) {
			t.Errorf("keyName(%q,%q)=%q outside GenericNameRegex", tp.company, tp.serial, name)
		}
		id := tp.company + "|" + tp.serial
		if prev, dup := seen[name]; dup {
			t.Errorf("keyName collision: (%s) and (%s) both -> %q", prev, id, name)
		}
		seen[name] = id
	}
	// The only way to forge a collision is a segment carrying the delimiter; such
	// a segment is refused up front, so the collision is unreachable by construction.
	for _, bad := range []string{"x.y", "co.1", "0a.1b"} {
		if validKeySegment(bad) {
			t.Errorf("validKeySegment(%q)=true — delimiter-bearing segment would break injectivity", bad)
		}
	}
}

// TestTransitStubRejectsSlashedName is regression (a) for SIN-67698: the FAKE
// answers 404 "unsupported path" for a "/"-bearing key name, exactly as a real
// Vault does (transit/{sign,keys}/{name} bind {name} to GenericNameRegex, which
// has no "/"). This is what makes the stub faithful — the pre-flatten scheme
// "a1/co/serial" failed live but slipped through the old permissive fake.
func TestTransitStubRejectsSlashedName(t *testing.T) {
	stub := newTransitStub(t)
	for _, p := range []string{
		"/v1/transit/sign/a1/co-1/deadbeef",
		"/v1/transit/keys/a1/co-1/deadbeef",
	} {
		resp, err := http.Post(stub.URL+p, "application/json", strings.NewReader(`{}`))
		if err != nil {
			t.Fatalf("POST %s: %v", p, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("POST %s status=%d, want 404 (unsupported path)", p, resp.StatusCode)
		}
		if !strings.Contains(string(body), "unsupported path") {
			t.Errorf("POST %s body=%q, want \"unsupported path\"", p, body)
		}
	}
	// Control: the flat name the adapter actually emits DOES match the route; being
	// unseeded it 404s "no such key" — NOT "unsupported path". Distinguishing the
	// two 404s proves the route matched and only the key is absent.
	flat := "/v1/transit/keys/" + vaultKeyName("co-1", "deadbeef")
	resp, err := http.Get(stub.URL + flat)
	if err != nil {
		t.Fatalf("GET %s: %v", flat, err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if strings.Contains(string(body), "unsupported path") {
		t.Errorf("flat name %q rejected as unsupported path, want route match (no such key)", flat)
	}
}

// TestNewVaultTransitSignerRejectsInvalidPrefix pins that an operator-supplied
// KeyPrefix carrying the delimiter or a "/" (or any out-of-charset byte) is
// refused at construction: the prefix is the leading segment of the flat name,
// so a bad one would break injectivity or 404 the Transit route.
func TestNewVaultTransitSignerRejectsInvalidPrefix(t *testing.T) {
	for _, bad := range []string{"a1.x", "a1/x", "a b", "café"} {
		if _, err := NewVaultTransitSigner(VaultTransitConfig{Address: "http://x", Certs: NewMemoryCertStore(), KeyPrefix: bad}); err == nil {
			t.Errorf("NewVaultTransitSigner(KeyPrefix=%q) = nil error, want rejection", bad)
		}
	}
	// A valid custom prefix still works and drives the flat name.
	v, err := NewVaultTransitSigner(VaultTransitConfig{Address: "http://x", Certs: NewMemoryCertStore(), KeyPrefix: "a1-hml"})
	if err != nil {
		t.Fatalf("valid prefix rejected: %v", err)
	}
	if got, want := v.keyName("co", "ff"), "a1-hml.co.ff"; got != want {
		t.Errorf("keyName with custom prefix = %q, want %q", got, want)
	}
}

// TestVaultSignerAuditPerSchemePerContext encodes AC #5: each Sign emits an
// audit event carrying scheme + context + company + key_ref, and NEVER any key
// material or the signed payload.
func TestVaultSignerAuditPerSchemePerContext(t *testing.T) {
	ctx := context.Background()
	key, leaf := newVaultTestLeaf(t, "co-1", "11222333000181", time.Hour, time.Now())
	serial := SerialHex(leaf)
	stub := newTransitStub(t)
	stub.addKey(vaultKeyName("co-1", serial), key, false)
	store := NewMemoryCertStore()
	_ = store.PutA1(ctx, "co-1", []*x509.Certificate{leaf}, A1MetaFromLeaf(leaf, "11222333000181"))

	var mu sync.Mutex
	var events []AuditEvent
	v, err := NewVaultTransitSigner(VaultTransitConfig{
		Address: stub.URL, Certs: store, Token: "t",
		Audit: func(ev AuditEvent) { mu.Lock(); events = append(events, ev); mu.Unlock() },
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	digest := sha256.Sum256([]byte("SignedInfo"))
	if _, err := v.SignDigest(ctx, "co-1", serial, digest[:]); err != nil {
		t.Fatalf("sign digest: %v", err)
	}
	cert, _ := v.ClientCertificate(ctx, "co-1")
	signer := cert.PrivateKey.(crypto.Signer)
	if _, err := signer.Sign(nil, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}); err != nil {
		t.Fatalf("handshake sign: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	var sawDPS, sawMTLS bool
	for _, ev := range events {
		if ev.Err != "" {
			t.Errorf("unexpected audit error: %+v", ev)
		}
		if ev.KeyRef != "" && !strings.Contains(ev.KeyRef, "co-1") {
			t.Errorf("key_ref missing tenant scope: %q", ev.KeyRef)
		}
		switch ev.Op {
		case "sign_digest":
			sawDPS = true
			if ev.Scheme != "pkcs1v15" || ev.Context != "dps" {
				t.Errorf("dps audit scheme/context = %q/%q", ev.Scheme, ev.Context)
			}
		case "sign_handshake":
			sawMTLS = true
			if ev.Scheme != "pss" || ev.Context != "mtls" {
				t.Errorf("mtls audit scheme/context = %q/%q", ev.Scheme, ev.Context)
			}
		}
	}
	if !sawDPS || !sawMTLS {
		t.Errorf("missing audit events: dps=%v mtls=%v", sawDPS, sawMTLS)
	}
}

// TestVaultSignerTransportErrors covers unreachable Vault + non-2xx responses.
func TestVaultSignerTransportErrors(t *testing.T) {
	ctx := context.Background()
	key, leaf := newVaultTestLeaf(t, "co-1", "11222333000181", time.Hour, time.Now())
	serial := SerialHex(leaf)
	store := NewMemoryCertStore()
	_ = store.PutA1(ctx, "co-1", []*x509.Certificate{leaf}, A1MetaFromLeaf(leaf, "11222333000181"))
	digest := sha256.Sum256([]byte("x"))

	// Server that 500s on sign but reports non-exportable on key read.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/keys/") {
			writeJSON(w, transitKeyResponse{})
			return
		}
		http.Error(w, `{"errors":["boom"]}`, http.StatusInternalServerError)
	}))
	defer srv.Close()
	v, _ := NewVaultTransitSigner(VaultTransitConfig{Address: srv.URL, Certs: store, Token: "t"})
	if _, err := v.SignDigest(ctx, "co-1", serial, digest[:]); !errors.Is(err, ErrVaultTransport) {
		t.Errorf("500 sign = %v, want ErrVaultTransport", err)
	}
	_ = key
}

func TestNewVaultTransitSignerValidation(t *testing.T) {
	store := NewMemoryCertStore()
	if _, err := NewVaultTransitSigner(VaultTransitConfig{Certs: store}); err == nil {
		t.Error("empty address should error")
	}
	if _, err := NewVaultTransitSigner(VaultTransitConfig{Address: "http://x"}); err == nil {
		t.Error("nil cert store should error")
	}
}

func TestVaultSaltLengthMapping(t *testing.T) {
	cases := []struct {
		in   int
		want string
	}{
		{rsa.PSSSaltLengthEqualsHash, "hash"},
		{rsa.PSSSaltLengthAuto, "auto"},
		{32, "32"},
	}
	for _, c := range cases {
		if got := vaultSaltLength(&rsa.PSSOptions{SaltLength: c.in}); got != c.want {
			t.Errorf("vaultSaltLength(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDecodeVaultSignature(t *testing.T) {
	raw := []byte{1, 2, 3, 4}
	env := "vault:v1:" + base64.StdEncoding.EncodeToString(raw)
	got, err := decodeVaultSignature(env)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(got) != string(raw) {
		t.Errorf("decoded %v, want %v", got, raw)
	}
	for _, bad := range []string{"", "nope", "vault:v1", "notvault:v1:AAAA"} {
		if _, err := decodeVaultSignature(bad); err == nil {
			t.Errorf("decodeVaultSignature(%q) should error", bad)
		}
	}
}

func TestVaultHashAlg(t *testing.T) {
	if _, ok := vaultHashAlg(crypto.SHA1); ok {
		t.Error("SHA-1 should not be a valid transit hash")
	}
	if n, ok := vaultHashAlg(crypto.SHA512); !ok || n != "sha2-512" {
		t.Errorf("SHA-512 = %q,%v", n, ok)
	}
}

func TestVaultSignerFiscalSignerInterface(t *testing.T) {
	v, _ := NewVaultTransitSigner(VaultTransitConfig{Address: "http://x", Certs: NewMemoryCertStore()})
	var _ FiscalSigner = v
}

// TestVaultSignerClientCertUnknownTenant asserts a missing tenant yields
// ErrNotProvisioned, never leaking existence.
func TestVaultSignerClientCertUnknownTenant(t *testing.T) {
	v, _ := NewVaultTransitSigner(VaultTransitConfig{Address: "http://x", Certs: NewMemoryCertStore(), Token: "t"})
	if _, err := v.ClientCertificate(context.Background(), "nobody"); !errors.Is(err, ErrNotProvisioned) {
		t.Errorf("unknown tenant client cert = %v, want ErrNotProvisioned", err)
	}
	if _, err := v.ClientCertificate(context.Background(), ""); !errors.Is(err, ErrEmptyCompanyID) {
		t.Errorf("empty tenant client cert = %v, want ErrEmptyCompanyID", err)
	}
}

// TestVaultTransitIntegration runs against a REAL Vault Transit engine when
// VAULT_TEST_ADDR + VAULT_TEST_TOKEN are set (same gating pattern as the MinIO
// adapter). It imports/uses a pre-provisioned test key named
// a1/{VAULT_TEST_COMPANY}/{VAULT_TEST_SERIAL} and asserts a DPS signature
// verifies. Skipped automatically when the env is absent.
func TestVaultTransitIntegration(t *testing.T) {
	addr := os.Getenv("VAULT_TEST_ADDR")
	token := os.Getenv("VAULT_TEST_TOKEN")
	if addr == "" || token == "" {
		t.Skip("VAULT_TEST_ADDR/VAULT_TEST_TOKEN not set; skipping real-Vault integration")
	}
	company := os.Getenv("VAULT_TEST_COMPANY")
	pemChain := os.Getenv("VAULT_TEST_CERT_PEM")
	if company == "" || pemChain == "" {
		t.Skip("VAULT_TEST_COMPANY/VAULT_TEST_CERT_PEM not set; skipping")
	}
	chain, err := DecodeChainPEM(pemChain)
	if err != nil {
		t.Fatalf("decode VAULT_TEST_CERT_PEM: %v", err)
	}
	store := NewMemoryCertStore()
	meta := A1MetaFromLeaf(chain[0], os.Getenv("VAULT_TEST_CNPJ"))
	if err := store.PutA1(context.Background(), company, chain, meta); err != nil {
		t.Fatalf("putA1: %v", err)
	}
	v, err := NewVaultTransitSigner(VaultTransitConfig{Address: addr, Token: token, Certs: store})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	digest := sha256.Sum256([]byte("<SignedInfo>integration</SignedInfo>"))
	sig, err := v.SignDigest(context.Background(), company, meta.Serial, digest[:])
	if err != nil {
		t.Fatalf("real transit sign: %v", err)
	}
	pub, ok := chain[0].PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatal("leaf is not RSA")
	}
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("real transit signature does not verify: %v", err)
	}
}

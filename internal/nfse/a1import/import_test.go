package a1import

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"

	"github.com/ia-dev-sindireceita/payment/internal/nfse/custody"
)

const (
	testCNPJ   = "47064135000184"
	testTenant = "9f2c1a"
	testPass   = "s3nh@-do-A1"
)

var testNow = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

// otherName builds a SAN otherName [0] { type-id, [0] EXPLICIT OCTET STRING }.
func otherName(t *testing.T, oid asn1.ObjectIdentifier, value string) []byte {
	t.Helper()
	inner, err := asn1.Marshal([]byte(value))
	if err != nil {
		t.Fatal(err)
	}
	explicit, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: inner})
	if err != nil {
		t.Fatal(err)
	}
	oidDER, err := asn1.Marshal(oid)
	if err != nil {
		t.Fatal(err)
	}
	der, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: append(oidDER, explicit...)})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// icpSAN mimics an e-CNPJ SubjectAltName: an rfc822Name and the responsible
// person's otherName come BEFORE the CNPJ, as in real certificates.
func icpSAN(t *testing.T, cnpj string) pkix.Extension {
	t.Helper()
	var names []byte
	email, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, Bytes: []byte("contato@empresa.com.br")})
	names = append(names, email...)
	names = append(names, otherName(t, asn1.ObjectIdentifier{2, 16, 76, 1, 3, 4}, "01011980123456789010000000000000000000000000SSPSP")...)
	names = append(names, otherName(t, oidICPBrasilCNPJ, cnpj)...)
	san, err := asn1.Marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: names})
	if err != nil {
		t.Fatal(err)
	}
	return pkix.Extension{Id: oidSubjectAltName, Value: san}
}

type certOpts struct {
	cnpj      string // "" = no CNPJ anywhere
	cn        string
	notBefore time.Time
	notAfter  time.Time
	keyUsage  x509.KeyUsage
	key       any     // signer key; nil = fresh RSA-2048
	issuer    *testCA // nil = the shared trusted test AC
	serial    int64   // 0 = random
}

// testCA is a two-level test hierarchy standing in for ICP-Brasil: a root the
// importer trusts and an intermediate AC that issues the leaves.
type testCA struct {
	root, cert *x509.Certificate
	key        *rsa.PrivateKey
}

func newTestCA(t *testing.T, name string) *testCA {
	t.Helper()
	mk := func(cn string, parent *x509.Certificate, parentKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
			NotBefore: testNow.AddDate(-5, 0, 0), NotAfter: testNow.AddDate(5, 0, 0),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		}
		if parent == nil {
			parent, parentKey = tmpl, k
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &k.PublicKey, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c, k
	}
	root, rootKey := mk(name+" RAIZ", nil, nil)
	inter, interKey := mk(name+" AC", root, rootKey)
	return &testCA{root: root, cert: inter, key: interKey}
}

var (
	sharedCAOnce sync.Once
	sharedCA     *testCA
)

func trustedCA(t *testing.T) *testCA {
	sharedCAOnce.Do(func() { sharedCA = newTestCA(t, "ICP TESTE") })
	return sharedCA
}

// newA1 mints an e-CNPJ leaf issued by the test AC and returns its key, leaf
// and the issuing AC certificate.
func newA1(t *testing.T, o certOpts) (any, *x509.Certificate, *x509.Certificate) {
	t.Helper()
	issuer := o.issuer
	if issuer == nil {
		issuer = trustedCA(t)
	}
	key := o.key
	if key == nil {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		key = k
	}
	if o.notBefore.IsZero() {
		o.notBefore = testNow.AddDate(0, -1, 0)
	}
	if o.notAfter.IsZero() {
		o.notAfter = testNow.AddDate(1, 0, 0)
	}
	if o.keyUsage == 0 {
		o.keyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	}
	serial := big.NewInt(o.serial)
	if o.serial == 0 {
		serial, _ = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: o.cn},
		NotBefore: o.notBefore, NotAfter: o.notAfter, KeyUsage: o.keyUsage,
	}
	if o.cnpj != "" {
		tmpl.ExtraExtensions = []pkix.Extension{icpSAN(t, o.cnpj)}
	}
	var pub any
	switch k := key.(type) {
	case *rsa.PrivateKey:
		pub = &k.PublicKey
	case *ecdsa.PrivateKey:
		pub = &k.PublicKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer.cert, pub, issuer.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return key, leaf, issuer.cert
}

func encodePFX(t *testing.T, enc *pkcs12.Encoder, key any, leaf, ca *x509.Certificate) []byte {
	t.Helper()
	pfx, err := enc.Encode(key, leaf, []*x509.Certificate{ca}, testPass)
	if err != nil {
		t.Fatal(err)
	}
	return pfx
}

type fakeKeys struct {
	calls     int
	companyID string
	key       *rsa.PrivateKey
	err       error
	retired   []string
	retireErr error
}

func (f *fakeKeys) RetireA1Key(_ context.Context, _ string, serial string) error {
	if f.retireErr != nil {
		return f.retireErr
	}
	f.retired = append(f.retired, serial)
	return nil
}

func (f *fakeKeys) ImportA1Key(_ context.Context, companyID string, _ *x509.Certificate, key *rsa.PrivateKey) error {
	f.calls++
	f.companyID = companyID
	// Copy what Vault would receive; Import scrubs key afterwards.
	f.key = &rsa.PrivateKey{PublicKey: key.PublicKey, D: new(big.Int).Set(key.D)}
	return f.err
}

// newImporter trusts only the shared test hierarchy's root; its intermediate
// comes from the .pfx, as most real A1 files ship it.
func newImporterT(t *testing.T, keys KeyCustody) (*Importer, *custody.MemoryCertStore) {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(trustedCA(t).root)
	certs := custody.NewMemoryCertStore()
	return New(keys, certs, WithClock(func() time.Time { return testNow }), WithTrust(roots, x509.NewCertPool())), certs
}

func TestImportFormats(t *testing.T) {
	for _, tc := range []struct {
		name string
		enc  *pkcs12.Encoder
	}{
		{"modern AES (OpenSSL 3 default)", pkcs12.Modern},
		{"legacy 3DES", pkcs12.LegacyDES},
		{"legacy RC2", pkcs12.LegacyRC2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, leaf, ca := newA1(t, certOpts{cnpj: testCNPJ, cn: "EMPRESA TESTE"})
			keys := &fakeKeys{}
			imp, certs := newImporterT(t, keys)

			res, err := imp.Import(context.Background(), testTenant, encodePFX(t, tc.enc, key, leaf, ca), testPass, "47.064.135/0001-84")
			if err != nil {
				t.Fatalf("Import: %v", err)
			}
			wantID := custody.CompanyIDFor(testTenant, testCNPJ)
			if res.CompanyID != wantID || res.CNPJ != testCNPJ {
				t.Errorf("result = %+v, want company %s", res, wantID)
			}
			if keys.companyID != wantID || keys.key.D.Cmp(key.(*rsa.PrivateKey).D) != 0 {
				t.Error("Vault did not receive the certificate's private key under the custody id")
			}
			chain, meta, err := certs.Get(context.Background(), wantID)
			if err != nil {
				t.Fatalf("CertStore.Get: %v", err)
			}
			if len(chain) != 2 || !chain[0].Equal(leaf) || !chain[1].Equal(ca) {
				t.Errorf("stored chain = %d certs, want leaf + CA", len(chain))
			}
			if meta.CNPJHash != custody.HashCNPJ(testCNPJ) || meta.Serial != custody.SerialHex(leaf) {
				t.Errorf("meta = %+v", meta)
			}
		})
	}
}

func TestImportScrubsKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	k, leaf, ca := newA1(t, certOpts{cnpj: testCNPJ, key: rsaKey})
	pfx := encodePFX(t, pkcs12.Modern, k, leaf, ca)
	var seen *rsa.PrivateKey
	keys := keyImporterFunc(func(_ context.Context, _ string, _ *x509.Certificate, key *rsa.PrivateKey) error {
		seen = key
		return nil
	})
	imp, _ := newImporterT(t, keys)
	if _, err := imp.Import(context.Background(), testTenant, pfx, testPass, ""); err != nil {
		t.Fatal(err)
	}
	if seen.D.Sign() != 0 {
		t.Error("private exponent left in memory after Import")
	}
	for _, p := range seen.Primes {
		if p.Sign() != 0 {
			t.Error("prime left in memory after Import")
		}
	}
}

type keyImporterFunc func(context.Context, string, *x509.Certificate, *rsa.PrivateKey) error

func (f keyImporterFunc) ImportA1Key(ctx context.Context, c string, l *x509.Certificate, k *rsa.PrivateKey) error {
	return f(ctx, c, l, k)
}

func (f keyImporterFunc) RetireA1Key(context.Context, string, string) error { return nil }

func TestImportCNPJFromCommonNameFallback(t *testing.T) {
	key, leaf, ca := newA1(t, certOpts{cn: "EMPRESA TESTE LTDA:47064135000184"})
	imp, _ := newImporterT(t, &fakeKeys{})
	res, err := imp.Import(context.Background(), testTenant, encodePFX(t, pkcs12.Modern, key, leaf, ca), testPass, "")
	if err != nil || res.CNPJ != testCNPJ {
		t.Fatalf("Import = %+v, %v", res, err)
	}
}

func TestImportRejects(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	good := func(t *testing.T) []byte {
		k, l, ca := newA1(t, certOpts{cnpj: testCNPJ})
		return encodePFX(t, pkcs12.Modern, k, l, ca)
	}
	build := func(o certOpts) func(*testing.T) []byte {
		return func(t *testing.T) []byte {
			k, l, ca := newA1(t, o)
			return encodePFX(t, pkcs12.Modern, k, l, ca)
		}
	}
	for _, tc := range []struct {
		name     string
		tenant   string
		pfx      func(*testing.T) []byte
		password string
		cnpj     string
		want     error
	}{
		{"no tenant", "", good, testPass, "", ErrEmptyTenant},
		{"empty file", testTenant, func(*testing.T) []byte { return nil }, testPass, "", ErrEmptyPFX},
		{"too large", testTenant, func(*testing.T) []byte { return make([]byte, MaxPFXSize+1) }, testPass, "", ErrPFXTooLarge},
		{"not a pfx", testTenant, func(*testing.T) []byte { return []byte("not a certificate") }, testPass, "", ErrInvalidPFX},
		{"wrong password", testTenant, good, "errada", "", ErrWrongPassword},
		{"other company's CNPJ", testTenant, good, testPass, "11222333000181", ErrCNPJMismatch},
		{"no CNPJ", testTenant, build(certOpts{cn: "PESSOA FISICA"}), testPass, "", ErrNoCNPJ},
		{"expired", testTenant, build(certOpts{cnpj: testCNPJ, notBefore: testNow.AddDate(-2, 0, 0), notAfter: testNow.AddDate(0, 0, -1)}), testPass, "", custody.ErrCertExpired},
		{"not yet valid", testTenant, build(certOpts{cnpj: testCNPJ, notBefore: testNow.AddDate(0, 0, 1)}), testPass, "", ErrCertNotYetValid},
		{"cannot sign", testTenant, build(certOpts{cnpj: testCNPJ, keyUsage: x509.KeyUsageKeyEncipherment}), testPass, "", ErrNotSigningCert},
		{"EC key", testTenant, build(certOpts{cnpj: testCNPJ, key: ecKey}), testPass, "", custody.ErrUnsupportedKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keys := &fakeKeys{}
			imp, certs := newImporterT(t, keys)
			_, err := imp.Import(context.Background(), tc.tenant, tc.pfx(t), tc.password, tc.cnpj)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if keys.calls != 0 {
				t.Error("a rejected certificate reached Vault")
			}
			if _, _, err := certs.Get(context.Background(), custody.CompanyIDFor(testTenant, testCNPJ)); !errors.Is(err, custody.ErrCertNotFound) {
				t.Error("a rejected certificate was stored")
			}
		})
	}
}

func TestImportVaultFailureStoresNothing(t *testing.T) {
	key, leaf, ca := newA1(t, certOpts{cnpj: testCNPJ})
	boom := errors.New("vault down")
	imp, certs := newImporterT(t, &fakeKeys{err: boom})
	if _, err := imp.Import(context.Background(), testTenant, encodePFX(t, pkcs12.Modern, key, leaf, ca), testPass, ""); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want vault error", err)
	}
	if _, _, err := certs.Get(context.Background(), custody.CompanyIDFor(testTenant, testCNPJ)); !errors.Is(err, custody.ErrCertNotFound) {
		t.Error("certificate stored although Vault refused the key: emission would fail at signing")
	}
}

func TestCNPJFromCertNil(t *testing.T) {
	if _, ok := CNPJFromCert(nil); ok {
		t.Error("nil cert must not yield a CNPJ")
	}
}

func TestCertificateLookup(t *testing.T) {
	key, leaf, ca := newA1(t, certOpts{cnpj: testCNPJ})
	imp, _ := newImporterT(t, &fakeKeys{})
	ctx := context.Background()
	if _, err := imp.Certificate(ctx, testTenant, testCNPJ); !errors.Is(err, custody.ErrCertNotFound) {
		t.Fatalf("before import = %v, want ErrCertNotFound", err)
	}
	if _, err := imp.Import(ctx, testTenant, encodePFX(t, pkcs12.Modern, key, leaf, ca), testPass, ""); err != nil {
		t.Fatal(err)
	}
	meta, err := imp.Certificate(ctx, testTenant, "47.064.135/0001-84")
	if err != nil || meta.Serial != custody.SerialHex(leaf) {
		t.Fatalf("after import = %+v, %v", meta, err)
	}
	if _, err := imp.Certificate(ctx, "other-tenant", testCNPJ); !errors.Is(err, custody.ErrCertNotFound) {
		t.Errorf("another tenant saw the certificate: %v", err)
	}
	if _, err := imp.Certificate(ctx, "", testCNPJ); !errors.Is(err, ErrEmptyTenant) {
		t.Errorf("empty tenant = %v", err)
	}
}

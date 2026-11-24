package a1import

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"

	"github.com/ia-dev-sindireceita/payment/internal/nfse/custody"
)

func importPFX(t *testing.T, imp *Importer, o certOpts) (Result, *x509.Certificate, error) {
	t.Helper()
	key, leaf, ca := newA1(t, o)
	res, err := imp.Import(context.Background(), testTenant, encodePFX(t, pkcs12.Modern, key, leaf, ca), testPass, "")
	return res, leaf, err
}

func TestImportRejectsCertificateOutsideTrustedHierarchy(t *testing.T) {
	keys := &fakeKeys{}
	imp, certs := newImporterT(t, keys)
	_, _, err := importPFX(t, imp, certOpts{cnpj: testCNPJ, issuer: newTestCA(t, "AC PIRATA")})
	if !errors.Is(err, ErrUntrustedChain) {
		t.Fatalf("err = %v, want ErrUntrustedChain", err)
	}
	if keys.calls != 0 {
		t.Error("an untrusted certificate reached Vault")
	}
	if _, _, err := certs.Get(context.Background(), custody.CompanyIDFor(testTenant, testCNPJ)); !errors.Is(err, custody.ErrCertNotFound) {
		t.Error("an untrusted certificate was stored")
	}
}

// TestImportDefaultTrustIsICPBrasil: an importer built without WithTrust
// refuses a certificate from a non-ICP hierarchy — production never trusts
// test CAs by accident.
func TestImportDefaultTrustIsICPBrasil(t *testing.T) {
	keys := &fakeKeys{}
	imp := New(keys, custody.NewMemoryCertStore(), WithClock(func() time.Time { return testNow }))
	key, leaf, ca := newA1(t, certOpts{cnpj: testCNPJ})
	_, err := imp.Import(context.Background(), testTenant, encodePFX(t, pkcs12.Modern, key, leaf, ca), testPass, "")
	if !errors.Is(err, ErrUntrustedChain) {
		t.Fatalf("err = %v, want ErrUntrustedChain", err)
	}
}

// TestImportCompletesChainFromIntermediates: a .pfx carrying only the leaf
// validates through the intermediates pool, and the STORED chain includes the
// intermediate (the ADN needs it in the mTLS handshake).
func TestImportCompletesChainFromIntermediates(t *testing.T) {
	ca := trustedCA(t)
	roots, inter := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(ca.root)
	inter.AddCert(ca.cert)
	certs := custody.NewMemoryCertStore()
	imp := New(&fakeKeys{}, certs, WithClock(func() time.Time { return testNow }), WithTrust(roots, inter))

	key, leaf, _ := newA1(t, certOpts{cnpj: testCNPJ})
	pfx, err := pkcs12.Modern.Encode(key, leaf, nil, testPass) // leaf only
	if err != nil {
		t.Fatal(err)
	}
	res, err := imp.Import(context.Background(), testTenant, pfx, testPass, "")
	if err != nil {
		t.Fatalf("leaf-only pfx: %v", err)
	}
	chain, _, _ := certs.Get(context.Background(), res.CompanyID)
	if len(chain) != 2 || !chain[1].Equal(ca.cert) {
		t.Errorf("stored chain has %d certs, want leaf + intermediate", len(chain))
	}
	for _, c := range chain {
		if c.Equal(ca.root) {
			t.Error("the root must not be stored/presented: the peer already has it")
		}
	}
}

func TestImportRotation(t *testing.T) {
	ctx := context.Background()
	keys := &fakeKeys{}
	imp, certs := newImporterT(t, keys)
	companyID := custody.CompanyIDFor(testTenant, testCNPJ)

	firstKey, firstLeaf, firstCA := newA1(t, certOpts{cnpj: testCNPJ, notAfter: testNow.AddDate(0, 6, 0)})
	first, err := imp.Import(ctx, testTenant, encodePFX(t, pkcs12.Modern, firstKey, firstLeaf, firstCA), testPass, "")
	if err != nil {
		t.Fatal(err)
	}
	if first.RetiredSerial != "" || len(keys.retired) != 0 {
		t.Fatalf("first import retired something: %+v %v", first, keys.retired)
	}

	t.Run("re-import of the same certificate retires nothing", func(t *testing.T) {
		if _, err := imp.Import(ctx, testTenant, encodePFX(t, pkcs12.Modern, firstKey, firstLeaf, trustedCA(t).cert), testPass, ""); err != nil {
			t.Fatal(err)
		}
		if len(keys.retired) != 0 {
			t.Errorf("same certificate retired its own key: %v", keys.retired)
		}
	})

	t.Run("renewal retires the previous key", func(t *testing.T) {
		res, leaf, err := importPFX(t, imp, certOpts{cnpj: testCNPJ, notAfter: testNow.AddDate(1, 0, 0)})
		if err != nil {
			t.Fatal(err)
		}
		if res.RetiredSerial != first.Meta.Serial || len(keys.retired) != 1 || keys.retired[0] != first.Meta.Serial {
			t.Fatalf("retired = %v (result %q), want [%s]", keys.retired, res.RetiredSerial, first.Meta.Serial)
		}
		_, meta, _ := certs.Get(ctx, companyID)
		if meta.Serial != custody.SerialHex(leaf) {
			t.Error("the renewed certificate is not the one on file")
		}
	})

	t.Run("older certificate is refused before Vault", func(t *testing.T) {
		calls := keys.calls
		_, _, err := importPFX(t, imp, certOpts{cnpj: testCNPJ, notAfter: testNow.AddDate(0, 3, 0)})
		if !errors.Is(err, ErrOlderCertificate) {
			t.Fatalf("err = %v, want ErrOlderCertificate", err)
		}
		if keys.calls != calls {
			t.Error("a downgrade reached Vault")
		}
	})
}

// TestImportRotationRetireFailureKeepsCurrent: if the old key cannot be
// shredded the import fails, the certificate on file stays the old one, and a
// retry completes the rotation — never an orphan key in Vault.
func TestImportRotationRetireFailureKeepsCurrent(t *testing.T) {
	ctx := context.Background()
	keys := &fakeKeys{}
	imp, certs := newImporterT(t, keys)
	companyID := custody.CompanyIDFor(testTenant, testCNPJ)
	first, _, err := importPFX(t, imp, certOpts{cnpj: testCNPJ, notAfter: testNow.AddDate(0, 6, 0)})
	if err != nil {
		t.Fatal(err)
	}

	key, leaf, ca := newA1(t, certOpts{cnpj: testCNPJ, notAfter: testNow.AddDate(1, 0, 0)})
	pfx := encodePFX(t, pkcs12.Modern, key, leaf, ca)
	keys.retireErr = errors.New("vault down")
	if _, err := imp.Import(ctx, testTenant, pfx, testPass, ""); !errors.Is(err, keys.retireErr) {
		t.Fatalf("err = %v, want the retire failure", err)
	}
	if _, meta, _ := certs.Get(ctx, companyID); meta.Serial != first.Meta.Serial {
		t.Fatal("certificate switched although the old key was not shredded")
	}
	keys.retireErr = nil
	res, err := imp.Import(ctx, testTenant, pfx, testPass, "")
	if err != nil || res.RetiredSerial != first.Meta.Serial {
		t.Fatalf("retry = %+v, %v", res, err)
	}
}

// --- embedded ICP-Brasil bundles ---

// TestICPBrasilRootFingerprints pins the trust anchors. A change here is a
// trust-anchor change: verify the new fingerprint out of band before updating.
func TestICPBrasilRootFingerprints(t *testing.T) {
	want := map[string]string{
		"Autoridade Certificadora Raiz Brasileira v5":  "caa53fc6091c6951887c976e378f6ef89aa6377c55d97b6475422b71ed7e9b17",
		"Autoridade Certificadora Raiz Brasileira v12": "d8478e37ce19c690cf657381e68fe600e4e1a042536830f06847e03e554c4b01",
	}
	got := map[string]string{}
	for _, c := range parsePEMCerts(t, icpRootsPEM) {
		sum := sha256.Sum256(c.Raw)
		got[c.Subject.CommonName] = hex.EncodeToString(sum[:])
	}
	if len(got) != len(want) {
		t.Errorf("roots.pem has %d roots, want %d: %v", len(got), len(want), got)
	}
	for cn, fp := range want {
		if got[cn] != fp {
			t.Errorf("SECURITY: %s fingerprint = %s, want %s", cn, got[cn], fp)
		}
	}
}

// TestICPBrasilBundlesHealthy: every intermediate chains to the embedded
// roots, the RFB ACs that issue e-CNPJ are present, and nothing has expired
// (an expired AC means the bundle is due for regeneration — README.md).
func TestICPBrasilBundlesHealthy(t *testing.T) {
	roots, inter := ICPBrasilRoots(), ICPBrasilIntermediates()
	now := time.Now()
	rfb := 0
	for _, c := range parsePEMCerts(t, icpRootsPEM) {
		if now.AddDate(0, 0, 90).After(c.NotAfter) {
			t.Errorf("root %s expires %s: add its successor", c.Subject.CommonName, c.NotAfter.Format(time.DateOnly))
		}
	}
	for _, c := range parsePEMCerts(t, icpIntermediatesPEM) {
		if strings.Contains(c.Subject.CommonName, "RFB") {
			rfb++
		}
		if now.After(c.NotAfter) {
			t.Errorf("intermediate %s expired %s: regenerate the bundle", c.Subject.CommonName, c.NotAfter.Format(time.DateOnly))
			continue
		}
		if now.AddDate(0, 0, 90).After(c.NotAfter) {
			t.Logf("intermediate %s expires %s", c.Subject.CommonName, c.NotAfter.Format(time.DateOnly))
		}
		if _, err := c.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
			t.Errorf("intermediate %s does not chain to the embedded roots: %v", c.Subject.CommonName, err)
		}
	}
	if rfb < 10 {
		t.Errorf("only %d RFB ACs in the bundle; e-CNPJ issuers are missing", rfb)
	}
}

// TestICPBrasilBundlesHoldOnlyCertificates guards the .gitignore exception
// that lets these *.pem files in: they must never carry anything but public
// CERTIFICATE blocks.
func TestICPBrasilBundlesHoldOnlyCertificates(t *testing.T) {
	for name, b := range map[string][]byte{"roots.pem": icpRootsPEM, "intermediates.pem": icpIntermediatesPEM} {
		n := 0
		for {
			var blk *pem.Block
			blk, b = pem.Decode(b)
			if blk == nil {
				break
			}
			n++
			if blk.Type != "CERTIFICATE" {
				t.Errorf("SECURITY: %s holds a %q block", name, blk.Type)
			}
		}
		if n == 0 {
			t.Errorf("%s has no certificates", name)
		}
	}
}

func parsePEMCerts(t *testing.T, b []byte) []*x509.Certificate {
	t.Helper()
	var out []*x509.Certificate
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			return out
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
}

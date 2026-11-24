//go:build ignore

package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func parse(path string) []*x509.Certificate {
	b, _ := os.ReadFile(path)
	var out []*x509.Certificate
	if strings.Contains(string(b), "BEGIN CERT") {
		for {
			var blk *pem.Block
			blk, b = pem.Decode(b)
			if blk == nil {
				break
			}
			if c, err := x509.ParseCertificate(blk.Bytes); err == nil {
				out = append(out, c)
			}
		}
		return out
	}
	if c, err := x509.ParseCertificate(b); err == nil {
		out = append(out, c)
	}
	return out
}

func write(path, header string, certs []*x509.Certificate) {
	var sb strings.Builder
	sb.WriteString(header)
	for _, c := range certs {
		fp := sha256.Sum256(c.Raw)
		fmt.Fprintf(&sb, "\n# %s\n# not after: %s\n# sha256: %X\n", c.Subject.CommonName, c.NotAfter.UTC().Format("2006-01-02"), fp)
		pem.Encode(&sb, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	os.WriteFile(path, []byte(sb.String()), 0o644)
}

func main() {
	icp, out := os.Args[1], os.Args[2]
	var roots []*x509.Certificate
	pool := x509.NewCertPool()
	for _, v := range []string{"5", "12"} {
		c := parse(filepath.Join(icp, "pem", "v"+v+".pem"))[0]
		roots = append(roots, c)
		pool.AddCert(c)
	}
	inter := x509.NewCertPool()
	var cas []*x509.Certificate
	files, _ := filepath.Glob(filepath.Join(icp, "acs", "*"))
	for _, f := range files {
		for _, c := range parse(f) {
			if c.IsCA {
				inter.AddCert(c)
				cas = append(cas, c)
			}
		}
	}
	now := time.Now()
	seen := map[string]bool{}
	var keep []*x509.Certificate
	for _, c := range cas {
		if now.After(c.NotAfter) || seen[string(c.Raw)] {
			continue
		}
		if c.CheckSignatureFrom(c) == nil && c.Subject.String() == c.Issuer.String() {
			continue // self-signed: a root, not an intermediate
		}
		if _, err := c.Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
			continue
		}
		seen[string(c.Raw)] = true
		keep = append(keep, c)
	}
	sort.Slice(keep, func(i, j int) bool { return keep[i].Subject.CommonName < keep[j].Subject.CommonName })
	date := now.UTC().Format("2006-01-02")
	write(filepath.Join(out, "roots.pem"), fmt.Sprintf(`# ICP-Brasil trust anchors for A1 (e-CNPJ) chain validation.
#
# Source: https://acraiz.icpbrasil.gov.br/credenciadas/RAIZ/ICP-Brasilv{5,12}.crt
# Fetched %s over HTTP and over HTTPS (Let's Encrypt-validated); both identical.
#
# Only the roots of the signing hierarchies that Go's crypto/x509 can verify:
#   v5, v12 — RSA; every e-CNPJ AC in the ITI bundle chains to one of them.
# Excluded: v10 (SSL hierarchy), v11 (code signing), v4/v13 (ECDSA curves Go
# does not parse), v6/v7 (algorithms Go does not verify).
#
# Regenerate: see internal/nfse/a1import/icpbrasil/README.md.
`, date), roots)
	write(filepath.Join(out, "intermediates.pem"), fmt.Sprintf(`# ICP-Brasil intermediate ACs that chain to roots.pem, so an A1 whose .pfx
# carries only the leaf still validates.
#
# Source: https://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/ACcompactado.zip
# Fetched %s over HTTP and over HTTPS (Let's Encrypt-validated); both identical.
# Kept: CA certificates valid on that date whose chain verifies to roots.pem.
#
# Regenerate: see internal/nfse/a1import/icpbrasil/README.md.
`, date), keep)
	fmt.Printf("roots=%d intermediates=%d\n", len(roots), len(keep))
}

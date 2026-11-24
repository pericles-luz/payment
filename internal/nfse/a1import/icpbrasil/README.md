# ICP-Brasil trust bundles

`roots.pem` and `intermediates.pem` are embedded by `internal/nfse/a1import`
to validate that an imported A1 was issued under ICP-Brasil
(ADR-0007, Emenda 2026-10-05).

- **roots.pem** — AC Raiz v5 and v12, the RSA signing hierarchies Go's
  `crypto/x509` verifies. Every e-CNPJ AC in the ITI bundle chains to one of
  them. v10 (SSL), v11 (code signing), v4/v13 (ECDSA curves Go does not parse)
  and v6/v7 (algorithms Go does not verify) are deliberately left out.
- **intermediates.pem** — every non-expired AC from the ITI bundle whose chain
  verifies to `roots.pem`, so an A1 whose `.pfx` carries only the leaf still
  validates (and the full chain is what gets stored and presented in mTLS).

Each certificate is preceded by a comment with its name, expiry and SHA-256.

## Regenerating

Do this when ITI publishes a new root or AC, or before intermediates expire
(`TestICPBrasilBundlesNotExpiringSoon` fails 90 days ahead).

```bash
mkdir -p /tmp/icp/pem /tmp/icp/acs && cd /tmp/icp
for v in 5 12; do
  curl -fsS -o v$v.crt "http://acraiz.icpbrasil.gov.br/credenciadas/RAIZ/ICP-Brasilv$v.crt"
  openssl x509 -in v$v.crt -out pem/v$v.pem 2>/dev/null || openssl x509 -inform DER -in v$v.crt -out pem/v$v.pem
done
curl -fsS -o AC.zip "http://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/ACcompactado.zip"
python3 -c "import zipfile; zipfile.ZipFile('AC.zip').extractall('acs')"
go run <repo>/internal/nfse/a1import/icpbrasil/gen.go /tmp/icp <repo>/internal/nfse/a1import/icpbrasil
```

**Check provenance.** The `acraiz` host serves the same files over HTTPS with
a Let's Encrypt certificate, but sends only the leaf. Fetch the intermediate
from `https://letsencrypt.org/certs/gen-y/int-ye1.pem` (plus
`root-ye-by-x2.pem`), add both to a CA bundle, download again with
`curl --cacert`, and `cmp` the two downloads. Then compare the root SHA-256s in
the new `roots.pem` with the ones pinned in `TestICPBrasilRootFingerprints`.
A root fingerprint change is a trust-anchor change: review it as such.

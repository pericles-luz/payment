package a1import

import (
	"crypto/x509"
	_ "embed"
	"sync"
)

//go:embed icpbrasil/roots.pem
var icpRootsPEM []byte

//go:embed icpbrasil/intermediates.pem
var icpIntermediatesPEM []byte

var (
	icpOnce          sync.Once
	icpRoots         *x509.CertPool
	icpIntermediates *x509.CertPool
)

func loadICP() {
	icpOnce.Do(func() {
		icpRoots = x509.NewCertPool()
		icpRoots.AppendCertsFromPEM(icpRootsPEM)
		icpIntermediates = x509.NewCertPool()
		icpIntermediates.AppendCertsFromPEM(icpIntermediatesPEM)
	})
}

// ICPBrasilRoots returns a copy of the embedded ICP-Brasil trust anchors (AC
// Raiz v5 and v12). Callers may add roots to the copy — e.g. a homologation
// test CA — without affecting other importers.
func ICPBrasilRoots() *x509.CertPool {
	loadICP()
	return icpRoots.Clone()
}

// ICPBrasilIntermediates returns a copy of the embedded ICP-Brasil ACs.
func ICPBrasilIntermediates() *x509.CertPool {
	loadICP()
	return icpIntermediates.Clone()
}

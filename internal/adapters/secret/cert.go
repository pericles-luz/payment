package secret

import (
	"context"
	"sync"

	"github.com/ia-dev-sindireceita/payment/internal/domain/bankcert"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// CertStore is an in-process per-(tenant,bank) mTLS certificate vault, keyed by
// the same composite credKey as Store (the OAuth credential vault). The private
// key is held only in memory and is NEVER returned by a read: reads surface only
// the public metadata (ports.BankCertificateMeta), re-derived from the stored
// public certificate so the key never even reaches the read path. A persistent,
// encrypted-at-rest backing is an orthogonal follow-up (same posture as the OAuth
// Secret today; SIN-66087 plan, ADR-0007 T2). Implements
// ports.BankCertificateWriter and ports.BankCertificateReader.
type CertStore struct {
	mu sync.RWMutex
	// certs is keyed by credKey(tenantID, bankID). A tenant may hold an independent
	// certificate at more than one bank; the bankID subdivides — never relaxes — the
	// tenant scope (ADR-0007 T2).
	certs map[string]ports.BankCertificate
}

// NewCertStore builds an empty CertStore.
func NewCertStore() *CertStore {
	return &CertStore{certs: make(map[string]ports.BankCertificate)}
}

// SetBankCertificate implements ports.BankCertificateWriter. The material has
// already been parsed and validated by the use-case (cert well-formed, not
// expired, key matches); the store only re-checks the non-empty invariants and
// persists under credKey(tenantID, bankID). An empty bankID normalises to the
// default BankIDC6. The private key is held only here and never logged or returned
// (threat C1/C4).
func (s *CertStore) SetBankCertificate(_ context.Context, cert ports.BankCertificate) error {
	if cert.TenantID == "" {
		return shared.NewValidationError("tenant_id", "is required")
	}
	if cert.CertPEM == "" {
		return shared.NewValidationError("cert_pem", "is required")
	}
	if cert.KeyPEM == "" {
		return shared.NewValidationError("key_pem", "is required")
	}
	cert.BankID = defaultBankID(cert.BankID)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.certs[credKey(cert.TenantID, cert.BankID)] = cert
	return nil
}

// GetBankCertificateMeta implements ports.BankCertificateReader. It returns ONLY
// the public metadata of the stored certificate, re-derived from the stored leaf
// certificate via bankcert.ParseCert; the private key never leaves the store. The
// lookup is exact-match with NO fallback: a missing pair returns ErrNotFound and
// never resolves to another bank or tenant (deny-by-default; threat T1/T2). An
// empty bankID resolves to the default BankIDC6 (retro-compat).
func (s *CertStore) GetBankCertificateMeta(_ context.Context, tenantID, bankID string) (ports.BankCertificateMeta, error) {
	s.mu.RLock()
	c, ok := s.certs[credKey(tenantID, bankID)]
	s.mu.RUnlock()
	if !ok {
		return ports.BankCertificateMeta{}, shared.ErrNotFound
	}
	meta, err := bankcert.ParseCert(c.CertPEM)
	if err != nil {
		// The material was validated on write, so a parse failure here is an
		// internal inconsistency — surface it rather than silently returning blanks.
		return ports.BankCertificateMeta{}, err
	}
	return ports.BankCertificateMeta{
		TenantID:          c.TenantID,
		BankID:            c.BankID,
		SubjectCN:         meta.SubjectCN,
		Issuer:            meta.Issuer,
		SerialNumber:      meta.SerialNumber,
		FingerprintSHA256: meta.FingerprintSHA256,
		NotBefore:         meta.NotBefore,
		NotAfter:          meta.NotAfter,
	}, nil
}

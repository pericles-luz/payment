package secret_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

func TestDeleteBankCredential_PresentAndIdempotent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := secret.NewStore(map[string]ports.BankCredential{})
	if err := s.SetBankCredential(ctx, "t1", ports.BankIDC6, "client", "s3cr3t"); err != nil {
		t.Fatalf("set: %v", err)
	}
	// Present → removed; a subsequent read is a clean ErrNotFound.
	if err := s.DeleteBankCredential(ctx, "t1", "c6"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.GetBankCredential(ctx, "t1", ports.BankIDC6); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("read after delete = %v, want ErrNotFound", err)
	}
	// Idempotent: deleting an already-absent pair is a no-op (no oracle).
	if err := s.DeleteBankCredential(ctx, "t1", "c6"); err != nil {
		t.Fatalf("idempotent delete: %v", err)
	}
	// A never-configured pair also returns nil.
	if err := s.DeleteBankCredential(ctx, "unknown", "c6"); err != nil {
		t.Fatalf("absent delete: %v", err)
	}
}

// TestDeleteBankCredential_DoesNotAffectOtherPairs confirms the delete is keyed to
// the exact (tenant, bank) pair and never removes another tenant's credential.
func TestDeleteBankCredential_DoesNotAffectOtherPairs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := secret.NewStore(map[string]ports.BankCredential{})
	_ = s.SetBankCredential(ctx, "t1", ports.BankIDC6, "c1", "x")
	_ = s.SetBankCredential(ctx, "t2", ports.BankIDC6, "c2", "y")
	if err := s.DeleteBankCredential(ctx, "t1", "c6"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.GetBankCredential(ctx, "t2", ports.BankIDC6); err != nil {
		t.Fatalf("t2 credential must survive: %v", err)
	}
}

func TestDeleteBankCertificate_PresentAndIdempotent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cs := secret.NewCertStore()
	certPEM, keyPEM := certKeyPEM(t, "mtls.acme")
	if err := cs.SetBankCertificate(ctx, ports.BankCertificate{TenantID: "t1", BankID: ports.BankIDC6, CertPEM: certPEM, KeyPEM: keyPEM}); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := cs.DeleteBankCertificate(ctx, "t1", "c6"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := cs.GetBankCertificateMeta(ctx, "t1", ports.BankIDC6); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("read after delete = %v, want ErrNotFound", err)
	}
	// Idempotent.
	if err := cs.DeleteBankCertificate(ctx, "t1", "c6"); err != nil {
		t.Fatalf("idempotent delete: %v", err)
	}
	if err := cs.DeleteBankCertificate(ctx, "unknown", "c6"); err != nil {
		t.Fatalf("absent delete: %v", err)
	}
}

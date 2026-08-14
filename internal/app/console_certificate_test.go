package app_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	auditlog "github.com/ia-dev-sindireceita/payment/internal/adapters/audit/inmemory"
	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// newCertConsole wires a ConsoleService over real in-memory stores with the clock
// pinned at certNow() (so the genAdminCertKey validity windows are deterministic)
// and seeds one tenant "t1". It returns the service plus the cert store and audit
// log so a test can assert on what was persisted.
func newCertConsole(t *testing.T) (*app.ConsoleService, *secret.CertStore, *auditlog.Log) {
	t.Helper()
	store := persistence.NewStore()
	creds := secret.NewStore(map[string]ports.BankCredential{})
	certs := secret.NewCertStore()
	log := auditlog.NewLog()
	svc := app.NewConsoleService(app.ConsoleDeps{
		Tenants:    store,
		Pricing:    store,
		Ledger:     store,
		CredWriter: creds,
		CredReader: creds,
		CertWriter: certs,
		CertReader: certs,
		Audit:      log,
		Clock:      fixedClock{t: certNow()},
		IDs:        &seqIDs{},
	})
	seedTenant(t, store, "t1", "Acme", true, 100)
	return svc, certs, log
}

func TestConsoleSetBankCertificate_HappyAndProjection(t *testing.T) {
	t.Parallel()
	svc, certs, log := newCertConsole(t)
	ctx := app.WithOperatorID(context.Background(), auditOperator)
	certPEM, keyPEM := genAdminCertKey(t, "mtls.acme", certNow().Add(-time.Hour), certNow().Add(365*24*time.Hour))

	meta, err := svc.SetBankCertificate(ctx, "t1", "c6", certPEM, keyPEM)
	if err != nil {
		t.Fatalf("set certificate: %v", err)
	}
	if meta.SubjectCN != "mtls.acme" || meta.BankID != ports.BankIDC6 || meta.FingerprintSHA256 == "" {
		t.Fatalf("unexpected meta: %+v", meta)
	}
	// Stored under (t1, c6).
	if _, err := certs.GetBankCertificateMeta(ctx, "t1", "c6"); err != nil {
		t.Fatalf("certificate not stored: %v", err)
	}
	// Audit recorded certificate.set carrying the fingerprint (tx_id), never the key.
	var found bool
	for _, e := range log.Entries() {
		if e.Action() == audit.ActionSetBankCertificate {
			found = true
			if e.TxID() != meta.FingerprintSHA256 {
				t.Errorf("audit tx_id = %q, want fingerprint %q", e.TxID(), meta.FingerprintSHA256)
			}
		}
	}
	if !found {
		t.Fatalf("no certificate.set audit entry")
	}

	// GetBank now projects the certificate as Valid with its public metadata.
	info, err := svc.GetBank(ctx, "t1", "c6")
	if err != nil || info.Cert == nil {
		t.Fatalf("GetBank cert = %+v (%v)", info, err)
	}
	if info.Cert.Status != app.CertStatusValid {
		t.Fatalf("status = %q, want valid", info.Cert.Status)
	}
	if info.Cert.SubjectCN != "mtls.acme" || info.Cert.FingerprintSHA256 != meta.FingerprintSHA256 {
		t.Fatalf("cert projection = %+v", info.Cert)
	}
}

// TestConsoleSetBankCertificate_NeverLeaksKey asserts the private key never reaches
// the returned metadata nor any audit field (threat C1/C4).
func TestConsoleSetBankCertificate_NeverLeaksKey(t *testing.T) {
	t.Parallel()
	svc, _, log := newCertConsole(t)
	ctx := app.WithOperatorID(context.Background(), auditOperator)
	certPEM, keyPEM := genAdminCertKey(t, "cn", certNow().Add(-time.Hour), certNow().Add(time.Hour))

	meta, err := svc.SetBankCertificate(ctx, "t1", "c6", certPEM, keyPEM)
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	keyBody := strings.TrimSpace(strings.Split(keyPEM, "-----")[2])
	if keyBody == "" {
		t.Fatalf("test setup: empty key body")
	}
	// Not in the returned metadata.
	for _, f := range []string{meta.SubjectCN, meta.Issuer, meta.SerialNumber, meta.FingerprintSHA256} {
		if strings.Contains(f, keyBody) {
			t.Fatalf("metadata leaked key material")
		}
	}
	// Not in any audit entry.
	for _, e := range log.Entries() {
		for _, f := range []string{e.OperatorID(), e.TenantID(), e.TxID(), e.BankID(), string(e.Action())} {
			if strings.Contains(f, keyBody) {
				t.Fatalf("audit leaked key material in %q", f)
			}
		}
	}
}

func TestConsoleSetBankCertificate_Rejections(t *testing.T) {
	t.Parallel()
	goodCert, goodKey := genAdminCertKey(t, "cn", certNow().Add(-time.Hour), certNow().Add(time.Hour))
	_, otherKey := genAdminCertKey(t, "other", certNow().Add(-time.Hour), certNow().Add(time.Hour))
	expiredCert, expiredKey := genAdminCertKey(t, "old", certNow().Add(-48*time.Hour), certNow().Add(-24*time.Hour))

	cases := map[string]struct {
		tenant, bank, cert, key string
		wantErr                 error
	}{
		"malformed cert":    {"t1", "c6", "garbage", goodKey, shared.ErrValidation},
		"malformed key":     {"t1", "c6", goodCert, "garbage", shared.ErrValidation},
		"mismatched pair":   {"t1", "c6", goodCert, otherKey, shared.ErrValidation},
		"expired at upload": {"t1", "c6", expiredCert, expiredKey, shared.ErrValidation},
		"unknown bank":      {"t1", "itau", goodCert, goodKey, shared.ErrValidation},
		"unknown tenant":    {"nope", "c6", goodCert, goodKey, shared.ErrNotFound},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			svc, certs, _ := newCertConsole(t)
			ctx := context.Background()
			_, err := svc.SetBankCertificate(ctx, tc.tenant, tc.bank, tc.cert, tc.key)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want Is(%v)", err, tc.wantErr)
			}
			// Nothing persisted under the known tenant/bank on rejection.
			if _, gerr := certs.GetBankCertificateMeta(ctx, "t1", ports.NormalizeBankID(tc.bank)); gerr == nil {
				t.Fatalf("%s: certificate must not be stored on rejection", name)
			}
		})
	}
}

// TestConsoleBankCertStatusProjection covers the lifecycle bands the badge depends
// on. The expired and not-yet-valid certs are written straight to the store (a cert
// can lapse while stored; a rotation cert is pre-provisioned), exercising the read
// projection's certStatusFor branches independent of the upload policy.
func TestConsoleBankCertStatusProjection(t *testing.T) {
	t.Parallel()
	now := certNow()
	cases := []struct {
		name       string
		notBefore  time.Time
		notAfter   time.Time
		wantStatus app.CertStatus
		wantDays   int
	}{
		{"valid", now.Add(-time.Hour), now.Add(365 * 24 * time.Hour), app.CertStatusValid, 365},
		{"expiring", now.Add(-time.Hour), now.Add(10 * 24 * time.Hour), app.CertStatusExpiringSoon, 10},
		{"expired", now.Add(-48 * time.Hour), now.Add(-24 * time.Hour), app.CertStatusExpired, 1},
		{"not yet valid", now.Add(24 * time.Hour), now.Add(40 * 24 * time.Hour), app.CertStatusNotYetValid, 40},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			svc, certs, _ := newCertConsole(t)
			ctx := context.Background()
			certPEM, keyPEM := genAdminCertKey(t, tc.name, tc.notBefore, tc.notAfter)
			// Write directly to the store so an already-expired cert can be projected.
			if err := certs.SetBankCertificate(ctx, ports.BankCertificate{
				TenantID: "t1", BankID: ports.BankIDC6, CertPEM: certPEM, KeyPEM: keyPEM,
			}); err != nil {
				t.Fatalf("seed cert: %v", err)
			}
			info, err := svc.GetBank(ctx, "t1", "c6")
			if err != nil || info.Cert == nil {
				t.Fatalf("GetBank = %+v (%v)", info, err)
			}
			if info.Cert.Status != tc.wantStatus {
				t.Fatalf("status = %q, want %q", info.Cert.Status, tc.wantStatus)
			}
			// DaysToExpiry magnitude (negative when expired).
			got := info.Cert.DaysToExpiry
			if got < 0 {
				got = -got
			}
			if got != tc.wantDays {
				t.Fatalf("daysToExpiry = %d, want %d", got, tc.wantDays)
			}
		})
	}
}

// TestConsoleBankNoCertProjectsNil pins that a bank with no certificate projects a
// nil Cert (the "sem certificado" badge state), independent of the credential.
func TestConsoleBankNoCertProjectsNil(t *testing.T) {
	t.Parallel()
	svc, _, _ := newCertConsole(t)
	info, err := svc.GetBank(context.Background(), "t1", "c6")
	if err != nil {
		t.Fatalf("GetBank: %v", err)
	}
	if info.Cert != nil {
		t.Fatalf("Cert = %+v, want nil", info.Cert)
	}
}

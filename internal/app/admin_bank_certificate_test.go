package app_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
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

// certNow is the instant the admin-certificate tests pin their clock to, so the
// validity-window assertions (expired / valid / not-yet-valid) are deterministic.
func certNow() time.Time { return time.Unix(1700000000, 0).UTC() }

// genAdminCertKey builds a self-signed leaf cert + matching EC key (PEM) for the
// given CN and validity window.
func genAdminCertKey(t *testing.T, cn string, notBefore, notAfter time.Time) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM
}

// newCertAdmin wires an AdminService over real in-memory audit, certificate store
// and tenant store, with the clock fixed at certNow(), and seeds one tenant.
func newCertAdmin(t *testing.T) (*app.AdminService, *auditlog.Log, *secret.CertStore, string) {
	t.Helper()
	store := persistence.NewStore()
	log := auditlog.NewLog()
	certs := secret.NewCertStore()
	admin := app.NewAdminService(app.Deps{
		Tenants:    store,
		Pricing:    store,
		CertWriter: certs,
		Audit:      log,
		Clock:      fixedClock{t: certNow()},
		IDs:        &seqIDs{},
	})
	tn, err := admin.CreateTenant(context.Background(), "Acme")
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	return admin, log, certs, tn.ID()
}

func TestSetBankCertificateHappy(t *testing.T) {
	t.Parallel()
	admin, log, certs, tenantID := newCertAdmin(t)
	ctx := app.WithOperatorID(context.Background(), auditOperator)
	certPEM, keyPEM := genAdminCertKey(t, "mtls.example", certNow().Add(-time.Hour), certNow().Add(365*24*time.Hour))

	meta, err := admin.SetBankCertificate(ctx, tenantID, "c6", certPEM, keyPEM)
	if err != nil {
		t.Fatalf("set certificate: %v", err)
	}
	if meta.SubjectCN != "mtls.example" || meta.BankID != ports.BankIDC6 {
		t.Fatalf("unexpected meta: %+v", meta)
	}
	if meta.FingerprintSHA256 == "" {
		t.Fatalf("fingerprint not returned")
	}
	// Stored under (tenant, c6); reads return only public metadata.
	if _, err := certs.GetBankCertificateMeta(ctx, tenantID, "c6"); err != nil {
		t.Fatalf("read stored certificate meta: %v", err)
	}
	// Audit recorded certificate.set with bank id + fingerprint (in tx_id), no key.
	var found bool
	for _, e := range log.Entries() {
		if e.Action() != audit.ActionSetBankCertificate {
			continue
		}
		found = true
		if e.BankID() != ports.BankIDC6 {
			t.Errorf("audit bank_id: want c6, got %q", e.BankID())
		}
		if e.TxID() != meta.FingerprintSHA256 {
			t.Errorf("audit tx_id should carry the fingerprint: got %q", e.TxID())
		}
	}
	if !found {
		t.Fatalf("no certificate.set audit entry recorded")
	}
}

// TestSetBankCertificateNeverLeaksKeyToAudit asserts the private key never reaches
// any audit entry (threat C1/C4).
func TestSetBankCertificateNeverLeaksKeyToAudit(t *testing.T) {
	t.Parallel()
	admin, log, _, tenantID := newCertAdmin(t)
	ctx := app.WithOperatorID(context.Background(), auditOperator)
	certPEM, keyPEM := genAdminCertKey(t, "cn", certNow().Add(-time.Hour), certNow().Add(time.Hour))

	if _, err := admin.SetBankCertificate(ctx, tenantID, "c6", certPEM, keyPEM); err != nil {
		t.Fatalf("set: %v", err)
	}
	// The key DER bytes (PEM body) must not appear in any audit entry field.
	keyBody := strings.TrimSpace(strings.Split(keyPEM, "-----")[2])
	for _, e := range log.Entries() {
		for _, field := range []string{e.OperatorID(), e.TenantID(), e.TxID(), e.BankID(), string(e.Action())} {
			if keyBody != "" && strings.Contains(field, keyBody) {
				t.Fatalf("audit entry leaked key material in %q", field)
			}
		}
	}
}

func TestSetBankCertificateDefaultsAndNormalizesBank(t *testing.T) {
	t.Parallel()
	admin, _, certs, tenantID := newCertAdmin(t)
	ctx := context.Background()
	certPEM, keyPEM := genAdminCertKey(t, "cn", certNow().Add(-time.Hour), certNow().Add(time.Hour))

	// Empty bank → default c6; padded/mixed-case slug normalizes to the same pair.
	for _, bank := range []string{"", "  C6 "} {
		if _, err := admin.SetBankCertificate(ctx, tenantID, bank, certPEM, keyPEM); err != nil {
			t.Fatalf("set (bank=%q): %v", bank, err)
		}
	}
	if _, err := certs.GetBankCertificateMeta(ctx, tenantID, ports.BankIDC6); err != nil {
		t.Fatalf("certificate not stored under c6: %v", err)
	}
}

func TestSetBankCertificateRejectsUnknownBank(t *testing.T) {
	t.Parallel()
	admin, _, certs, tenantID := newCertAdmin(t)
	ctx := context.Background()
	certPEM, keyPEM := genAdminCertKey(t, "cn", certNow().Add(-time.Hour), certNow().Add(time.Hour))

	_, err := admin.SetBankCertificate(ctx, tenantID, "itau", certPEM, keyPEM)
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation for unknown bank, got %v", err)
	}
	if _, gerr := certs.GetBankCertificateMeta(ctx, tenantID, "itau"); gerr == nil {
		t.Fatalf("unknown-bank certificate must not be stored")
	}
}

func TestSetBankCertificateRejectsUnknownTenant(t *testing.T) {
	t.Parallel()
	admin, _, _, _ := newCertAdmin(t)
	ctx := context.Background()
	certPEM, keyPEM := genAdminCertKey(t, "cn", certNow().Add(-time.Hour), certNow().Add(time.Hour))

	_, err := admin.SetBankCertificate(ctx, "no-such-tenant", "c6", certPEM, keyPEM)
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want ErrNotFound for unknown tenant, got %v", err)
	}
}

// TestSetBankCertificateRejectsBadMaterial covers the parse/validation matrix:
// malformed cert, malformed key, mismatched pair, and a cert already expired at
// upload — all named validation errors (400), nothing stored.
func TestSetBankCertificateRejectsBadMaterial(t *testing.T) {
	t.Parallel()
	goodCert, goodKey := genAdminCertKey(t, "cn", certNow().Add(-time.Hour), certNow().Add(time.Hour))
	_, otherKey := genAdminCertKey(t, "other", certNow().Add(-time.Hour), certNow().Add(time.Hour))
	expiredCert, expiredKey := genAdminCertKey(t, "old", certNow().Add(-48*time.Hour), certNow().Add(-24*time.Hour))

	cases := map[string]struct{ cert, key string }{
		"malformed cert":    {"garbage", goodKey},
		"malformed key":     {goodCert, "garbage"},
		"mismatched pair":   {goodCert, otherKey},
		"expired at upload": {expiredCert, expiredKey},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			admin, _, certs, tenantID := newCertAdmin(t)
			ctx := context.Background()
			_, err := admin.SetBankCertificate(ctx, tenantID, "c6", tc.cert, tc.key)
			if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want ErrValidation for %s, got %v", name, err)
			}
			if _, gerr := certs.GetBankCertificateMeta(ctx, tenantID, "c6"); gerr == nil {
				t.Fatalf("%s: nothing must be stored on rejection", name)
			}
		})
	}
}

// TestSetBankCertificateAcceptsNotYetValid pins that a certificate whose NotBefore
// is in the future is accepted (rotation pre-provisioning) and its window exposed.
func TestSetBankCertificateAcceptsNotYetValid(t *testing.T) {
	t.Parallel()
	admin, _, _, tenantID := newCertAdmin(t)
	ctx := context.Background()
	future := certNow().Add(24 * time.Hour)
	certPEM, keyPEM := genAdminCertKey(t, "future", future, future.Add(365*24*time.Hour))

	meta, err := admin.SetBankCertificate(ctx, tenantID, "c6", certPEM, keyPEM)
	if err != nil {
		t.Fatalf("not-yet-valid cert must be accepted: %v", err)
	}
	if !meta.NotBefore.After(certNow()) {
		t.Fatalf("NotBefore should be in the future: %s", meta.NotBefore)
	}
}

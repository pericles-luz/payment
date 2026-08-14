package adminweb_test

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/adminweb"
	"github.com/ia-dev-sindireceita/payment/internal/app"
)

// certInfo builds a BankInfo carrying a certificate in the given lifecycle band so
// the view projection can be exercised (the unexported CertMeta is only reachable
// through ToBankRows, which mirrors production).
func certInfo(status app.CertStatus, days int) app.BankInfo {
	base := time.Unix(1700000000, 0).UTC()
	return app.BankInfo{
		Slug:          "c6",
		CredentialSet: true,
		Cert: &app.BankCertInfo{
			SubjectCN:         "mtls.acme",
			Issuer:            "CN=Acme CA",
			SerialNumber:      "99",
			FingerprintSHA256: "ab12cd",
			NotBefore:         base,
			NotAfter:          base.Add(time.Duration(days) * 24 * time.Hour),
			Status:            status,
			DaysToExpiry:      days,
		},
	}
}

func TestCertMetaProjectionAndHelpers(t *testing.T) {
	t.Parallel()
	row := adminweb.ToBankRows("t1", []app.BankInfo{certInfo(app.CertStatusExpiringSoon, 1)}, true)[0]
	m := row.Cert
	if m == nil {
		t.Fatalf("cert not projected")
	}
	if !m.StatusExpiring() || m.StatusValid() || m.StatusExpired() || m.StatusNotYetValid() {
		t.Fatalf("status bands wrong: %+v", m)
	}
	if m.DaysToExpiry() != 1 || m.DaysUnit() != "dia" {
		t.Fatalf("days = %d %s, want 1 dia", m.DaysToExpiry(), m.DaysUnit())
	}
	if m.SubjectCN != "mtls.acme" || m.FingerprintSHA256 != "ab12cd" {
		t.Fatalf("metadata not projected: %+v", m)
	}
	if m.NotBeforeBR() == "" || m.NotAfterBR() == "" {
		t.Fatalf("date helpers empty")
	}

	// Plural unit + expired magnitude (negative DaysToExpiry → positive magnitude).
	exp := adminweb.ToBankRows("t1", []app.BankInfo{certInfo(app.CertStatusExpired, -3)}, true)[0].Cert
	if !exp.StatusExpired() || exp.DaysToExpiry() != 3 || exp.DaysUnit() != "dias" {
		t.Fatalf("expired projection wrong: %+v", exp)
	}

	// No certificate → nil Cert.
	none := adminweb.ToBankRows("t1", []app.BankInfo{{Slug: "c6", CredentialSet: true}}, true)[0]
	if none.Cert != nil {
		t.Fatalf("Cert = %+v, want nil", none.Cert)
	}
}

func TestCertStatusBadgeRender(t *testing.T) {
	t.Parallel()
	rd, err := adminweb.New()
	if err != nil {
		t.Fatalf("renderer: %v", err)
	}
	cases := []struct {
		name   string
		info   app.BankInfo
		want   string
		absent string
	}{
		{"valid", certInfo(app.CertStatusValid, 200), "Válido", "Expira"},
		{"expiring", certInfo(app.CertStatusExpiringSoon, 12), "⚠ Expira em 12 dias", "Válido"},
		{"expired", certInfo(app.CertStatusExpired, -5), "✕ Expirado", "Válido"},
		{"not yet valid", certInfo(app.CertStatusNotYetValid, 40), "Entra em vigor em", "Válido"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			row := adminweb.ToBankRows("t1", []app.BankInfo{tc.info}, true)[0]
			rec := httptest.NewRecorder()
			rd.Partial(rec, http.StatusOK, "cert_status_badge", row.Cert)
			body := rec.Body.String()
			if !strings.Contains(body, tc.want) {
				t.Fatalf("badge missing %q: %s", tc.want, body)
			}
			if tc.absent != "" && strings.Contains(body, tc.absent) {
				t.Fatalf("badge should not contain %q: %s", tc.absent, body)
			}
		})
	}

	// Nil cert → "sem certificado".
	rec := httptest.NewRecorder()
	rd.Partial(rec, http.StatusOK, "cert_status_badge", (*adminweb.CertMeta)(nil))
	if !strings.Contains(rec.Body.String(), "sem certificado") {
		t.Fatalf("nil-cert badge = %s", rec.Body.String())
	}
}

// TestCertCardRendersMetadataAndForm pins that the detail card shows the public
// metadata, the multipart upload control, and never an empty private-key field.
func TestCertCardRendersMetadataAndForm(t *testing.T) {
	t.Parallel()
	rd, err := adminweb.New()
	if err != nil {
		t.Fatalf("renderer: %v", err)
	}
	detail := adminweb.BankDetailView{
		Base:   adminweb.NewBase("c6", "tenants", "csrf-xyz", "operador · admin"),
		Tenant: bankTenant(),
		Bank:   adminweb.ToBankRows("t1", []app.BankInfo{certInfo(app.CertStatusValid, 300)}, true)[0],
		Form:   map[string]string{},
		Errors: map[string]string{},
	}
	rec := httptest.NewRecorder()
	rd.Partial(rec, http.StatusOK, "cert_card", detail)
	body := rec.Body.String()
	for _, want := range []string{
		"Certificado mTLS", "mtls.acme", "ab12cd", "multipart/form-data",
		`type="file"`, "Rotacionar certificado", "csrf-xyz", `name="cert_pem"`, `name="key_pem"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("cert card missing %q: %s", want, body)
		}
	}

	// No certificate yet → "Enviar certificado" CTA, no rotation confirm.
	fresh := detail
	fresh.Bank = adminweb.ToBankRows("t1", []app.BankInfo{{Slug: "c6", CredentialSet: true}}, true)[0]
	rec2 := httptest.NewRecorder()
	rd.Partial(rec2, http.StatusOK, "cert_card", fresh)
	body2 := rec2.Body.String()
	if !strings.Contains(body2, "Enviar certificado") || strings.Contains(body2, "hx-confirm") {
		t.Fatalf("fresh cert card wrong: %s", body2)
	}
}

// TestCertMetaLogValueRedacted asserts the structured log projection carries only
// public metadata (no key field exists) and a nil receiver is safe.
func TestCertMetaLogValueRedacted(t *testing.T) {
	t.Parallel()
	row := adminweb.ToBankRows("t1", []app.BankInfo{certInfo(app.CertStatusValid, 90)}, true)[0]
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	logger.Info("cert", "meta", row.Cert)
	out := buf.String()
	if !strings.Contains(out, "ab12cd") || !strings.Contains(out, "mtls.acme") {
		t.Fatalf("log missing public metadata: %s", out)
	}
	if strings.Contains(strings.ToLower(out), "key") {
		t.Fatalf("log should carry no key field: %s", out)
	}

	// Nil receiver renders "[absent]" rather than panicking.
	buf.Reset()
	logger.Info("cert", "meta", (*adminweb.CertMeta)(nil))
	if !strings.Contains(buf.String(), "absent") {
		t.Fatalf("nil cert log = %s", buf.String())
	}
}

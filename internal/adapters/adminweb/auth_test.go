package adminweb_test

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/adminweb"
)

func TestLoginPageRender(t *testing.T) {
	t.Parallel()
	rd := newRenderer(t)
	rec := httptest.NewRecorder()
	rd.LoginPage(rec, 200, adminweb.LoginView{
		CSRF: "csrf-abc", Username: "pericles.luz", Error: "credenciais inválidas", BootstrapVisible: true,
	})
	body := rec.Body.String()
	for _, want := range []string{
		"csrf-abc", "pericles.luz", "credenciais inválidas", "/console/bootstrap",
		`name="username"`, `name="password"`, `name="totp"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("login page missing %q", want)
		}
	}
	// XSS: an attacker-shaped error is auto-escaped by html/template.
	rec2 := httptest.NewRecorder()
	rd.LoginPage(rec2, 401, adminweb.LoginView{Error: "<script>alert(1)</script>"})
	if strings.Contains(rec2.Body.String(), "<script>alert(1)</script>") {
		t.Fatal("error text was not HTML-escaped")
	}
}

func TestLoginPageHidesBootstrapLink(t *testing.T) {
	t.Parallel()
	rd := newRenderer(t)
	rec := httptest.NewRecorder()
	rd.LoginPage(rec, 200, adminweb.LoginView{BootstrapVisible: false})
	if strings.Contains(rec.Body.String(), "/console/bootstrap") {
		t.Fatal("bootstrap link should be hidden when not available")
	}
}

func TestBootstrapPageForm(t *testing.T) {
	t.Parallel()
	rd := newRenderer(t)
	rec := httptest.NewRecorder()
	rd.BootstrapPage(rec, 200, adminweb.BootstrapView{CSRF: "x", Error: "Token de bootstrap inválido."})
	body := rec.Body.String()
	if !strings.Contains(body, `name="token"`) || !strings.Contains(body, "Token de bootstrap inválido.") {
		t.Fatalf("bootstrap form missing fields/error: %s", body)
	}
}

func TestBootstrapPageResultOnce(t *testing.T) {
	t.Parallel()
	rd := newRenderer(t)
	rec := httptest.NewRecorder()
	rd.BootstrapPage(rec, 200, adminweb.BootstrapView{
		Result: &adminweb.BootstrapResultView{
			Username: "pericles.luz", Password: "s3cr3t-pw", TOTPSecret: "ABCDEF", OTPAuthURI: "otpauth://totp/x?secret=ABCDEF",
		},
	})
	body := rec.Body.String()
	for _, want := range []string{"pericles.luz", "s3cr3t-pw", "ABCDEF", "otpauth://totp/x"} {
		if !strings.Contains(body, want) {
			t.Fatalf("bootstrap result missing %q", want)
		}
	}
	// The form must NOT be shown once a result is present.
	if strings.Contains(body, `name="token"`) {
		t.Fatal("form should be replaced by the result view")
	}
}

func TestBootstrapPageProvisionedNotice(t *testing.T) {
	t.Parallel()
	rd := newRenderer(t)
	rec := httptest.NewRecorder()
	rd.BootstrapPage(rec, 409, adminweb.BootstrapView{Provisioned: true})
	body := rec.Body.String()
	if !strings.Contains(body, "uso único") {
		t.Fatalf("expected locked notice, got: %s", body)
	}
	if strings.Contains(body, `name="token"`) {
		t.Fatal("no form when already provisioned")
	}
}

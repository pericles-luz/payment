package adminweb_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/adminweb"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
)

func bankTenant() adminweb.TenantView {
	return adminweb.ToTenantView(tenant.Rehydrate("t1", "Acme Ltda", true, time.Unix(1700000000, 0).UTC()))
}

func TestBankViewHelpers(t *testing.T) {
	t.Parallel()
	infos := []app.BankInfo{
		{Slug: "c6", CredentialSet: true, ClientID: "cid-1", CreditorKey: "pix-1"},
		{Slug: "itau", CredentialSet: false},
	}
	rows := adminweb.ToBankRows("t1", infos, true)
	if len(rows) != 2 {
		t.Fatalf("rows = %d", len(rows))
	}
	if rows[0].DisplayName != "C6 Bank" || !rows[0].Active || rows[0].TenantID != "t1" {
		t.Fatalf("row0 = %+v", rows[0])
	}
	// Unknown slug falls back to upper-cased display name.
	if rows[1].DisplayName != "ITAU" {
		t.Fatalf("fallback name = %q", rows[1].DisplayName)
	}
	if !rows[0].CreditorKeySet() || rows[1].CreditorKeySet() {
		t.Fatalf("creditor-key-set = %v / %v", rows[0].CreditorKeySet(), rows[1].CreditorKeySet())
	}

	opts := adminweb.ToBankTypeOptions([]string{"c6"})
	if len(opts) != 1 || opts[0].Slug != "c6" || opts[0].DisplayName != "C6 Bank" {
		t.Fatalf("opts = %+v", opts)
	}

	full := adminweb.BankListView{Addable: opts}
	empty := adminweb.BankListView{}
	if !full.CanAdd() || empty.CanAdd() {
		t.Fatalf("CanAdd = %v / %v", full.CanAdd(), empty.CanAdd())
	}
}

func TestBankScreensRender(t *testing.T) {
	t.Parallel()
	rd := newRenderer(t)
	tv := bankTenant()

	// Bank list with a configured row + add-bank selector.
	list := adminweb.BankListView{
		Base:    adminweb.NewBase("Bancos", "tenants", "csrf-xyz", "operador · admin"),
		Tenant:  tv,
		Banks:   adminweb.ToBankRows("t1", []app.BankInfo{{Slug: "c6", CredentialSet: true, ClientID: "cid-1"}}, true),
		Addable: adminweb.ToBankTypeOptions([]string{"c6"}),
		Form:    map[string]string{},
		Errors:  map[string]string{},
	}
	rec := httptest.NewRecorder()
	rd.Page(rec, httptest.NewRequest(http.MethodGet, "/console/tenants/t1/banks", nil), "banks", http.StatusOK, list)
	body := rec.Body.String()
	for _, want := range []string{"C6 Bank", "configurada", "Adicionar banco", "csrf-xyz"} {
		if !strings.Contains(body, want) {
			t.Fatalf("bank list missing %q: %s", want, body)
		}
	}

	// Empty list → empty state.
	emptyRec := httptest.NewRecorder()
	rd.Page(emptyRec, httptest.NewRequest(http.MethodGet, "/console/tenants/t1/banks", nil), "banks", http.StatusOK,
		adminweb.BankListView{Base: list.Base, Tenant: tv, Form: map[string]string{}, Errors: map[string]string{}})
	if !strings.Contains(emptyRec.Body.String(), "Nenhum banco configurado") {
		t.Fatalf("empty state missing: %s", emptyRec.Body.String())
	}

	// Bank detail with credential card + creditor key.
	detail := adminweb.BankDetailView{
		Base:   adminweb.NewBase("c6", "tenants", "csrf-xyz", "operador · admin"),
		Tenant: tv,
		Bank:   adminweb.ToBankRows("t1", []app.BankInfo{{Slug: "c6", CredentialSet: true, ClientID: "cid-1", CreditorKey: "pix-1"}}, true)[0],
		Form:   map[string]string{},
		Errors: map[string]string{},
	}
	dRec := httptest.NewRecorder()
	rd.Page(dRec, httptest.NewRequest(http.MethodGet, "/console/tenants/t1/banks/c6", nil), "bank_detail", http.StatusOK, detail)
	dBody := dRec.Body.String()
	for _, want := range []string{"Client ID", "Chave PIX do recebedor", "pix-1"} {
		if !strings.Contains(dBody, want) {
			t.Fatalf("bank detail missing %q: %s", want, dBody)
		}
	}
}

package http_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/billing"
)

// Guardrail A1 — "NUNCA cobrar em nome do C6" (Termo de Uso de APIs C6, cláusula
// 2.11; ver docs/compliance/c6-termo-apis-regras.md, regra A1 / SIN-68741).
//
// Violar A1 = rescisão imediata da parceria com o C6. A regra de produto é: toda
// superfície de faturamento/cobrança do nosso SaaS deve ser inequivocamente sob a
// marca própria (Super Inteligente/tenant), JAMAIS apresentada como cobrança "do
// C6". O C6 é apenas o adquirente/PSP por trás das operações — sua marca não pode
// aparecer nas telas que apresentam o que o tenant paga a nós.
//
// Este teste é a trava de regressão: renderiza cada superfície de faturamento
// visível ao operador/cliente através do servidor real (não só o código-fonte do
// template, mas a saída efetiva, inclusive dados injetados via view-model) e falha
// se qualquer marca do adquirente C6 vazar para uma delas.

// acquirerBrandPatterns casam menções à marca do adquirente C6 que não podem
// aparecer numa superfície de cobrança/fatura do nosso SaaS. `\bc6\b` pega o
// "C6" isolado (chip/logo/rótulo); os demais pegam as formas compostas.
var acquirerBrandPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bc6\b`),
	regexp.MustCompile(`(?i)c6\s*bank`),
	regexp.MustCompile(`(?i)c6bank`),
	regexp.MustCompile(`(?i)banco\s+c6`),
}

func assertNoAcquirerBrand(t *testing.T, surface, body string) {
	t.Helper()
	for _, re := range acquirerBrandPatterns {
		if loc := re.FindStringIndex(body); loc != nil {
			start, end := loc[0]-40, loc[1]+40
			if start < 0 {
				start = 0
			}
			if end > len(body) {
				end = len(body)
			}
			t.Errorf("A1 violado: a superfície de faturamento %q apresenta a marca do adquirente (padrão %s). "+
				"O Termo de Uso de APIs do C6 (cláusula 2.11, regra A1 em docs/compliance/c6-termo-apis-regras.md) "+
				"proíbe cobrar/aparentar cobrar em nome do C6 — a cobrança do SaaS é sempre sob a marca própria.\n…%s…",
				surface, re.String(), body[start:end])
		}
	}
}

// TestBillingSurfacesCarryNoAcquirerBrand_A1 exercita as três superfícies de
// faturamento voltadas ao operador/cliente e garante que nenhuma carrega a marca
// do C6, cumprindo o guardrail A1.
func TestBillingSurfacesCarryNoAcquirerBrand_A1(t *testing.T) {
	t.Parallel()
	f := newConsoleFixture(t)
	ctx := context.Background()

	// Popula as telas com dados reais para exercitar as linhas (não só o estado
	// vazio): um preço por endpoint + um evento no ledger append-only.
	price, err := billing.NewEndpointPricing("t1", "POST /v1/charges", 250)
	if err != nil {
		t.Fatalf("new pricing: %v", err)
	}
	if err := f.store.UpsertEndpointPrice(ctx, price); err != nil {
		t.Fatalf("upsert price: %v", err)
	}
	entry, err := billing.NewLedgerEntry("e1", "t1", "POST /v1/charges", "ref-1", 250, time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatalf("new ledger entry: %v", err)
	}
	if err := f.store.AppendLedgerEntry(ctx, entry); err != nil {
		t.Fatalf("append ledger: %v", err)
	}

	// O token CSRF é aleatório (base64url, alfabeto inclui '-'/'_') e poderia
	// conter "c6" delimitado por acaso — removê-lo do corpo antes de escanear
	// evita falso-positivo; o token não é conteúdo de fatura.
	csrf := csrfToken(t, f.handler, adminToken)

	// Superfícies HTML de faturamento: buscadas como PÁGINA COMPLETA (sem o header
	// HX-Request), que é o que o operador vê — o chrome do layout traz a marca
	// própria "Pagamentos · Admin", provando a atribuição da cobrança a nós.
	htmlSurfaces := []string{
		"/console/tenants/t1/consumption", // consumo — autoritativo p/ faturamento
		"/console/tenants/t1/pricing",     // tarifação por endpoint
	}
	for _, path := range htmlSurfaces {
		rec := fullPageGet(t, f.handler, path, adminToken)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s = %d, want 200", path, rec.Code)
		}
		body := strings.ReplaceAll(rec.Body.String(), csrf.Value, "")
		assertNoAcquirerBrand(t, path, body)
		// Metade positiva do A1: a cobrança é apresentada sob a marca própria.
		if !strings.Contains(body, "Pagamentos") {
			t.Errorf("A1: superfície de faturamento %q não exibe a marca própria (\"Pagamentos\") no chrome", path)
		}
	}

	// CSV de consumo — o artefato mais próximo de uma "fatura" que exportamos.
	rec := consoleGet(t, f.handler, "/console/tenants/t1/consumption.csv", adminToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("consumption.csv = %d, want 200", rec.Code)
	}
	assertNoAcquirerBrand(t, "/console/tenants/t1/consumption.csv", rec.Body.String())
	if cd := rec.Header().Get("Content-Disposition"); assertContainsAny(cd, acquirerBrandPatterns) {
		t.Errorf("A1: nome do arquivo do CSV de faturamento carrega a marca do adquirente: %q", cd)
	}
}

// fullPageGet faz um GET sem o header HX-Request, forçando o render da página
// completa (layout + fragmento) — a superfície que o operador realmente vê.
func fullPageGet(t *testing.T, h http.Handler, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// assertContainsAny reporta se algum padrão casa em s (usado p/ o header do CSV).
func assertContainsAny(s string, pats []*regexp.Regexp) bool {
	for _, re := range pats {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

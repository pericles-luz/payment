package config_test

import (
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/platform/config"
)

func TestFromEnvDefaults(t *testing.T) {
	// Not parallel: mutates process environment.
	for _, k := range []string{"PAYMENT_HTTP_ADDR", "PAYMENT_DB_PATH", "PAYMENT_TENANT_TOKENS", "PAYMENT_ADMIN_TOKENS", "PAYMENT_WEBHOOK_REFS", "PAYMENT_BANK_CREDS", "PAYMENT_RABBIT_URL"} {
		t.Setenv(k, "")
	}
	cfg := config.FromEnv()
	if cfg.HTTPAddr != ":8080" {
		t.Fatalf("default addr: %s", cfg.HTTPAddr)
	}
	if cfg.DBPath != "payment.db" {
		t.Fatalf("default db: %s", cfg.DBPath)
	}
	if len(cfg.TenantTokens) != 0 || len(cfg.AdminTokens) != 0 || len(cfg.BankCreds) != 0 {
		t.Fatal("expected empty maps")
	}
}

func TestFromEnvSecureCookies(t *testing.T) {
	cases := []struct {
		name string
		val  string
		want bool
	}{
		{"explicit true", "true", true},
		{"explicit false", "false", false},
		{"numeric false", "0", false},
		{"numeric true", "1", true},
		{"unparseable falls back to secure default", "maybe", true},
		{"empty falls back to secure default", "", true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PAYMENT_SECURE_COOKIES", tc.val)
			if got := config.FromEnv().SecureCookies; got != tc.want {
				t.Fatalf("SecureCookies(%q) = %v, want %v", tc.val, got, tc.want)
			}
		})
	}
}

func TestFromEnvTrustedProxyHops(t *testing.T) {
	cases := []struct {
		name string
		val  string
		want int
	}{
		{"empty defaults to zero (spoof-proof)", "", 0},
		{"explicit zero", "0", 0},
		{"single hop", "1", 1},
		{"multiple hops", "3", 3},
		{"negative falls back to zero", "-1", 0},
		{"unparseable falls back to zero", "two", 0},
		{"float falls back to zero", "1.5", 0},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PAYMENT_TRUSTED_PROXY_HOPS", tc.val)
			if got := config.FromEnv().TrustedProxyHops; got != tc.want {
				t.Fatalf("TrustedProxyHops(%q) = %d, want %d", tc.val, got, tc.want)
			}
		})
	}
}

func TestFromEnvParsing(t *testing.T) {
	t.Setenv("PAYMENT_HTTP_ADDR", ":9090")
	t.Setenv("PAYMENT_DB_PATH", "/tmp/x.db")
	t.Setenv("PAYMENT_TENANT_TOKENS", "tokA:tenantA, tokB:tenantB ,bad")
	t.Setenv("PAYMENT_ADMIN_TOKENS", "admin1, admin2")
	t.Setenv("PAYMENT_WEBHOOK_REFS", "refAAA:tenantA, refBBB:tenantB")
	t.Setenv("PAYMENT_BANK_CREDS", "tenantA:cidA:secA, malformed:only2, ")
	t.Setenv("PAYMENT_RABBIT_URL", "amqp://localhost")

	cfg := config.FromEnv()
	if cfg.HTTPAddr != ":9090" || cfg.DBPath != "/tmp/x.db" {
		t.Fatal("addr/db mismatch")
	}
	if cfg.TenantTokens["tokA"] != "tenantA" || cfg.TenantTokens["tokB"] != "tenantB" {
		t.Fatalf("tenant tokens: %+v", cfg.TenantTokens)
	}
	if len(cfg.TenantTokens) != 2 {
		t.Fatalf("expected 2 tenant tokens (bad skipped), got %d", len(cfg.TenantTokens))
	}
	if len(cfg.AdminTokens) != 2 {
		t.Fatalf("admin tokens: %+v", cfg.AdminTokens)
	}
	if cfg.WebhookRefs["refAAA"] != "tenantA" || cfg.WebhookRefs["refBBB"] != "tenantB" || cfg.RabbitURL != "amqp://localhost" {
		t.Fatalf("webhook refs/rabbit mismatch: %+v", cfg.WebhookRefs)
	}
	// BankCreds is now keyed by the composite (tenant, bank) pair; a legacy 3-field
	// entry defaults to bank "c6" (ADR-0007 / SIN-66021).
	cred, ok := cfg.BankCreds["tenantA\x00c6"]
	if !ok || cred.ClientID != "cidA" || cred.Secret != "secA" || cred.BankID != "c6" {
		t.Fatalf("bank creds: %+v", cfg.BankCreds)
	}
	if len(cfg.BankCreds) != 1 {
		t.Fatalf("expected 1 bank cred (malformed skipped), got %d", len(cfg.BankCreds))
	}
}

// TestFromEnvRecJWKSMTLSTenant: the designated JWKS mTLS tenant (SIN-69375) is read
// from PAYMENT_C6_REC_JWKS_MTLS_TENANT and defaults to empty (tenantless fetch).
func TestFromEnvRecJWKSMTLSTenant(t *testing.T) {
	if cfg := config.FromEnv(); cfg.C6.RecJWKSMTLSTenant != "" {
		t.Fatalf("default RecJWKSMTLSTenant = %q, want empty", cfg.C6.RecJWKSMTLSTenant)
	}
	t.Setenv("PAYMENT_C6_REC_JWKS_MTLS_TENANT", "tenant-verz")
	if cfg := config.FromEnv(); cfg.C6.RecJWKSMTLSTenant != "tenant-verz" {
		t.Fatalf("RecJWKSMTLSTenant = %q, want %q", cfg.C6.RecJWKSMTLSTenant, "tenant-verz")
	}
}

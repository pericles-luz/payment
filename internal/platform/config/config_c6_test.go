package config_test

import (
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/platform/config"
)

func clearC6Env(t *testing.T) {
	t.Helper()
	for _, k := range []string{"PAYMENT_C6_BASE_URL", "PAYMENT_C6_TOKEN_URL", "PAYMENT_C6_SCOPE", "PAYMENT_C6_TIMEOUT"} {
		t.Setenv(k, "")
	}
}

func TestC6ConfigDefaults(t *testing.T) {
	clearC6Env(t)
	cfg := config.FromEnv()
	if cfg.C6.BaseURL != "" || cfg.C6.TokenURL != "" || cfg.C6.Scope != "" {
		t.Fatalf("C6 endpoints should default empty: %+v", cfg.C6)
	}
	if cfg.C6.Timeout != 15*time.Second {
		t.Fatalf("default C6 timeout: want 15s, got %v", cfg.C6.Timeout)
	}
}

func TestC6ConfigParsing(t *testing.T) {
	clearC6Env(t)
	t.Setenv("PAYMENT_C6_BASE_URL", "https://api.c6.example")
	t.Setenv("PAYMENT_C6_TOKEN_URL", "https://api.c6.example/oauth/token")
	t.Setenv("PAYMENT_C6_SCOPE", "charges.write")
	t.Setenv("PAYMENT_C6_TIMEOUT", "20s")

	cfg := config.FromEnv()
	if cfg.C6.BaseURL != "https://api.c6.example" {
		t.Fatalf("base url: %q", cfg.C6.BaseURL)
	}
	if cfg.C6.TokenURL != "https://api.c6.example/oauth/token" {
		t.Fatalf("token url: %q", cfg.C6.TokenURL)
	}
	if cfg.C6.Scope != "charges.write" {
		t.Fatalf("scope: %q", cfg.C6.Scope)
	}
	if cfg.C6.Timeout != 20*time.Second {
		t.Fatalf("timeout: %v", cfg.C6.Timeout)
	}
}

func TestC6TimeoutFallback(t *testing.T) {
	cases := []struct {
		name string
		val  string
	}{
		{"unparseable", "not-a-duration"},
		{"zero", "0s"},
		{"negative", "-5s"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearC6Env(t)
			t.Setenv("PAYMENT_C6_TIMEOUT", tc.val)
			cfg := config.FromEnv()
			if cfg.C6.Timeout != 15*time.Second {
				t.Fatalf("%s: want fallback 15s, got %v", tc.name, cfg.C6.Timeout)
			}
		})
	}
}

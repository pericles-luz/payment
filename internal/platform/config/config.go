// Package config parses process configuration from the environment. Secrets
// (tokens, per-tenant webhook refs, bank credentials) come from the environment /
// secret manager — never from code or URLs (threat C1). A real deployment swaps
// this for a vault-backed loader; the shape stays the same.
package config

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// Config is the resolved process configuration.
type Config struct {
	HTTPAddr       string
	DBPath         string
	TenantTokens   map[string]string // token -> tenantID
	AdminTokens    []string          // full-access admin tokens (RoleAdmin)
	OperatorTokens []string          // read-only admin tokens (RoleOperator)
	// WebhookRefs maps an opaque per-tenant callback reference (tenantRef) to the
	// tenant it was minted for. The C6 webhook is unsigned, so the unguessable ref
	// embedded in the callback URL (/webhooks/c6/{tenantRef}) IS the per-tenant
	// credential (ADR-0002/F4). Each value must be a 43-char base64url token (mint
	// with httpadapter.GenerateTenantRef); malformed entries are dropped
	// (failure-closed). This is a secret — never log the ref or the full URL.
	WebhookRefs map[string]string               // tenantRef -> tenantID
	BankCreds   map[string]ports.BankCredential // tenantID -> credential
	RabbitURL   string
	// SecureCookies controls the Secure attribute on cookies the HTTP adapter
	// sets (CSRF token, and the admin-UI session cookie). It is a deployment fact,
	// NOT a per-request decision: the service runs plaintext ListenAndServe behind
	// a TLS-terminating proxy, so r.TLS is always nil and X-Forwarded-Proto is
	// client-spoofable — neither can be trusted to gate Secure. Config is
	// unspoofable. Defaults to true (secure-by-default); set PAYMENT_SECURE_COOKIES
	// to a falsey value only for plaintext local development.
	SecureCookies bool
	// C6 holds the C6 bank adapter transport configuration. Endpoints are
	// per-environment and resolved from config (never hard-coded). The per-tenant
	// OAuth2 credentials live in BankCreds / the secret store, not here.
	C6 C6Config
}

// C6Config configures the C6 bank adapter's HTTP/OAuth2 transport. URLs are
// per-environment; the adapter rejects non-HTTPS endpoints (secure-by-default).
// When BaseURL is empty the wiring falls back to the in-memory bank stub.
type C6Config struct {
	BaseURL  string        // C6 REST API base URL (e.g. https://api.c6bank.example)
	TokenURL string        // OAuth2 client_credentials token endpoint
	Scope    string        // optional OAuth2 scope
	Timeout  time.Duration // per-request timeout for the C6 HTTP client
}

// FromEnv builds a Config from environment variables, applying safe defaults.
func FromEnv() Config {
	return Config{
		HTTPAddr:       getenv("PAYMENT_HTTP_ADDR", ":8080"),
		DBPath:         getenv("PAYMENT_DB_PATH", "payment.db"),
		TenantTokens:   parseKV(os.Getenv("PAYMENT_TENANT_TOKENS")),
		AdminTokens:    splitNonEmpty(os.Getenv("PAYMENT_ADMIN_TOKENS")),
		OperatorTokens: splitNonEmpty(os.Getenv("PAYMENT_OPERATOR_TOKENS")),
		WebhookRefs:    parseKV(os.Getenv("PAYMENT_WEBHOOK_REFS")),
		BankCreds:      parseBankCreds(os.Getenv("PAYMENT_BANK_CREDS")),
		RabbitURL:      os.Getenv("PAYMENT_RABBIT_URL"),
		SecureCookies:  getenvBool("PAYMENT_SECURE_COOKIES", true),
		C6: C6Config{
			BaseURL:  os.Getenv("PAYMENT_C6_BASE_URL"),
			TokenURL: os.Getenv("PAYMENT_C6_TOKEN_URL"),
			Scope:    os.Getenv("PAYMENT_C6_SCOPE"),
			Timeout:  getenvDuration("PAYMENT_C6_TIMEOUT", 15*time.Second),
		},
	}
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// getenvBool resolves a boolean env var, falling back to def when the variable is
// unset or unparseable. Failing back to def (true, for the Secure-cookie flag)
// keeps a typo'd value from silently disabling a security control.
func getenvBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

// getenvDuration resolves a duration env var (e.g. "20s", "1m"), falling back to
// def when the variable is unset or unparseable. Failing back to def keeps a
// typo'd value from silently dropping the timeout to zero (no timeout).
func getenvDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return def
	}
	return d
}

// parseKV parses "k1:v1,k2:v2" into a map. Malformed pairs are skipped.
func parseKV(s string) map[string]string {
	m := make(map[string]string)
	for _, pair := range splitNonEmpty(s) {
		k, v, ok := strings.Cut(pair, ":")
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if ok && k != "" && v != "" {
			m[k] = v
		}
	}
	return m
}

// parseBankCreds parses "tenant:clientID:secret,..." into per-tenant credentials.
func parseBankCreds(s string) map[string]ports.BankCredential {
	m := make(map[string]ports.BankCredential)
	for _, item := range splitNonEmpty(s) {
		parts := strings.SplitN(item, ":", 3)
		if len(parts) != 3 {
			continue
		}
		tenant := strings.TrimSpace(parts[0])
		if tenant == "" {
			continue
		}
		m[tenant] = ports.BankCredential{
			TenantID: tenant,
			ClientID: strings.TrimSpace(parts[1]),
			Secret:   strings.TrimSpace(parts[2]),
		}
	}
	return m
}

func splitNonEmpty(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

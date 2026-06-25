// Package config parses process configuration from the environment. Secrets
// (tokens, per-tenant webhook refs, bank credentials) come from the environment /
// secret manager — never from code or URLs (threat C1). A real deployment swaps
// this for a vault-backed loader; the shape stays the same.
package config

import (
	"log/slog"
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
	// ClientCertPath and ClientKeyPath are filesystem paths to the PEM-encoded
	// client certificate and its private key for the mutual-TLS connection C6
	// requires (in addition to the OAuth2 bearer). Both empty ⇒ no client cert is
	// presented (current behaviour preserved). The SECRET (the private key) lives
	// only in the file referenced by the path — never in code, env value, or URL
	// (threat C1); only the path comes from the environment.
	ClientCertPath string
	ClientKeyPath  string
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
		BankCreds:      mergeCreditorKeys(parseBankCreds(os.Getenv("PAYMENT_BANK_CREDS"), slog.Default()), os.Getenv("PAYMENT_BANK_CREDITOR_KEYS"), slog.Default()),
		RabbitURL:      os.Getenv("PAYMENT_RABBIT_URL"),
		SecureCookies:  getenvBool("PAYMENT_SECURE_COOKIES", true),
		C6: C6Config{
			BaseURL:        os.Getenv("PAYMENT_C6_BASE_URL"),
			TokenURL:       os.Getenv("PAYMENT_C6_TOKEN_URL"),
			Scope:          os.Getenv("PAYMENT_C6_SCOPE"),
			Timeout:        getenvDuration("PAYMENT_C6_TIMEOUT", 15*time.Second),
			ClientCertPath: os.Getenv("PAYMENT_C6_CLIENT_CERT"),
			ClientKeyPath:  os.Getenv("PAYMENT_C6_CLIENT_KEY"),
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
//
// Each entry is split on the first two ':' only (strings.SplitN with n=3), so a
// secret that itself contains ':' is preserved verbatim in the final field — it
// is NOT truncated. Entries that are structurally malformed (wrong field count,
// or an empty tenant/clientID/secret) are skipped and logged at warn level so an
// operator can spot a misconfigured PAYMENT_BANK_CREDS instead of debugging an
// opaque auth failure at the PSP. To avoid leaking material, neither the raw
// entry nor the secret is ever logged; only the non-sensitive tenant_id and the
// entry position are included to aid diagnosis.
func parseBankCreds(s string, logger *slog.Logger) map[string]ports.BankCredential {
	if logger == nil {
		logger = slog.Default()
	}
	m := make(map[string]ports.BankCredential)
	for i, item := range splitNonEmpty(s) {
		parts := strings.SplitN(item, ":", 3)
		if len(parts) != 3 {
			logger.Warn("skipping malformed bank credential: expected tenant:clientID:secret",
				slog.Int("entry_index", i), slog.Int("field_count", len(parts)))
			continue
		}
		tenant := strings.TrimSpace(parts[0])
		clientID := strings.TrimSpace(parts[1])
		secret := strings.TrimSpace(parts[2])
		if tenant == "" {
			logger.Warn("skipping bank credential with empty tenant",
				slog.Int("entry_index", i))
			continue
		}
		if clientID == "" || secret == "" {
			logger.Warn("skipping bank credential with empty client_id or secret",
				slog.String("tenant_id", tenant))
			continue
		}
		m[tenant] = ports.BankCredential{
			TenantID: tenant,
			ClientID: clientID,
			Secret:   secret,
		}
	}
	return m
}

// mergeCreditorKeys folds the per-tenant PIX creditor keys parsed from
// PAYMENT_BANK_CREDITOR_KEYS into the BankCredential map produced by
// parseBankCreds. The creditor key (chave do recebedor) is carried in a SEPARATE
// env var — not appended to the PAYMENT_BANK_CREDS tuple — on purpose: that tuple
// keeps the OAuth2 secret as a greedy ':'-tolerant tail (parseBankCreds, SplitN
// n=3), so there is no unambiguous slot to add a 4th field after the secret
// without reinterpreting an existing ':'-bearing secret. A parallel var sidesteps
// that ambiguity and keeps the secret-parsing contract (and its tests) intact
// (ADR-0004 / SIN-65862).
//
// Format: "tenant:creditorKey,tenant2:creditorKey2". A PIX key (email, phone,
// CPF/CNPJ or EVP UUID) never contains ':', so each entry splits cleanly on the
// first ':' (SplitN n=2). Entries that are malformed, or that reference a tenant
// with no bank credential, are skipped and logged at warn level — the routing-
// sensitive key value itself is NEVER logged, only the non-sensitive tenant_id
// and entry position (threat C1/C4).
func mergeCreditorKeys(creds map[string]ports.BankCredential, s string, logger *slog.Logger) map[string]ports.BankCredential {
	if logger == nil {
		logger = slog.Default()
	}
	if creds == nil {
		creds = make(map[string]ports.BankCredential)
	}
	for i, item := range splitNonEmpty(s) {
		parts := strings.SplitN(item, ":", 2)
		if len(parts) != 2 {
			logger.Warn("skipping malformed bank creditor key: expected tenant:creditorKey",
				slog.Int("entry_index", i), slog.Int("field_count", len(parts)))
			continue
		}
		tenant := strings.TrimSpace(parts[0])
		key := strings.TrimSpace(parts[1])
		if tenant == "" || key == "" {
			logger.Warn("skipping bank creditor key with empty tenant or key",
				slog.Int("entry_index", i))
			continue
		}
		cred, ok := creds[tenant]
		if !ok {
			// A creditor key without a matching bank credential cannot route a
			// charge (the OAuth2 identity is missing); skip rather than synthesize a
			// half-credential.
			logger.Warn("skipping bank creditor key for tenant with no bank credential",
				slog.String("tenant_id", tenant))
			continue
		}
		cred.CreditorKey = key
		creds[tenant] = cred
	}
	return creds
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

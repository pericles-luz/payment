// Package config parses process configuration from the environment. Secrets
// (tokens, per-tenant webhook refs, bank credentials) come from the environment /
// secret manager — never from code or URLs (threat C1). A real deployment swaps
// this for a vault-backed loader; the shape stays the same.
package config

import (
	"log/slog"
	"os"
	"sort"
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
	// TrustedProxyHops is the number of trusted reverse proxies between this
	// service and the public internet. It governs how the client IP (used for
	// rate-limit keying and IP-based attribution) is derived from a request:
	//
	//   0  → trust NOBODY: the client IP is the TCP peer (RemoteAddr) and all
	//        X-Forwarded-For / X-Real-IP headers are ignored. Spoof-proof, and
	//        the secure-by-default value. Correct when the service is exposed
	//        directly, or when you are unsure how many proxies front it.
	//   N≥1 → trust exactly N proxy hops: the client IP is the entry the
	//        outermost of your N trusted proxies added to X-Forwarded-For — the
	//        only entry an attacker cannot forge past your own proxies.
	//
	// This replaces chi's middleware.RealIP, which blindly trusted the leftmost
	// X-Forwarded-For value and was therefore spoofable (GO-2026-5775): a client
	// could send an arbitrary X-Forwarded-For to evade rate limits or poison
	// IP-based attribution. Set PAYMENT_TRUSTED_PROXY_HOPS to the real proxy
	// depth of the deployment (the current single-ingress topology is 1).
	// Defaults to 0 (secure-by-default). A negative or unparseable value falls
	// back to 0 so a typo cannot silently start trusting client headers.
	TrustedProxyHops int
	// SelfServeCredIntake enables the self-serve credential intake route
	// (PUT /v1/bank-credential, SIN-69196 / trilha E2). It lets an empresa-cliente
	// rotate its OWN bank credential with its tenant token, in addition to the
	// admin-plane write. Defaults to false (secure / dark-ship): when off the route
	// is not registered, so rollback is a config flip. It does NOT gate the go-live
	// (production credentials are provisioned via the admin intake); it is a
	// fast-follow convenience. Set PAYMENT_SELFSERVE_CRED_INTAKE truthy to enable.
	SelfServeCredIntake bool
	// C6 holds the C6 bank adapter transport configuration. Endpoints are
	// per-environment and resolved from config (never hard-coded). The per-tenant
	// OAuth2 credentials live in BankCreds / the secret store, not here.
	C6 C6Config
	// STGSeed opts into the staging-stub demo seed (SIN-69226): when set AND the
	// bank adapter is the stub (C6.BaseURL empty) AND the store is empty, boot
	// populates a small synthetic two-level-tenancy dataset (Conta "Verz" + two
	// empresas-clientes + a little consumption + one Fatura) so the board can
	// navigate the admin console instead of empty tables. Defaults to false; the
	// seed itself re-checks stub mode and store-emptiness, so this flag alone can
	// never touch a real environment. Set PAYMENT_STG_SEED truthy to enable.
	STGSeed bool
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
	// RecJWKSURL is the absolute https URL of C6's JWKS used to verify the JWS-signed
	// PIX Automático (Recorrência) reads (rec/solicrec/cobr GETs, Accept:
	// application/jose). When empty those reads fail secure (ErrUnavailable) — the
	// recurrence read path stays disabled rather than trusting an unverified mandate
	// document, the correct interim until F4 go-live (SIN-66061). It is a URL, never
	// a secret: only public keys are served from it.
	RecJWKSURL string
	// RateLimitRPS and RateLimitBurst configure the proactive outbound token bucket
	// that paces requests to C6 (Termo A5 — no DoS-shaped load). Zero/unparseable ⇒
	// the adapter's conservative defaults. MaxRetries bounds retries on a retryable
	// status (429/503) with backoff honoring Retry-After (Termo B11); zero ⇒ the
	// adapter default, negative ⇒ single-shot (no retries).
	RateLimitRPS   float64
	RateLimitBurst int
	MaxRetries     int
}

// FromEnv builds a Config from environment variables, applying safe defaults.
func FromEnv() Config {
	logger := slog.Default()
	bankCreds := mergeCreditorKeys(parseBankCreds(os.Getenv("PAYMENT_BANK_CREDS"), logger), os.Getenv("PAYMENT_BANK_CREDITOR_KEYS"), logger)
	logLoadedBankCreds(bankCreds, logger)
	return Config{
		HTTPAddr:            getenv("PAYMENT_HTTP_ADDR", ":8080"),
		DBPath:              getenv("PAYMENT_DB_PATH", "payment.db"),
		TenantTokens:        parseKV(os.Getenv("PAYMENT_TENANT_TOKENS")),
		AdminTokens:         splitNonEmpty(os.Getenv("PAYMENT_ADMIN_TOKENS")),
		OperatorTokens:      splitNonEmpty(os.Getenv("PAYMENT_OPERATOR_TOKENS")),
		WebhookRefs:         parseKV(os.Getenv("PAYMENT_WEBHOOK_REFS")),
		BankCreds:           bankCreds,
		RabbitURL:           os.Getenv("PAYMENT_RABBIT_URL"),
		SecureCookies:       getenvBool("PAYMENT_SECURE_COOKIES", true),
		TrustedProxyHops:    getenvInt("PAYMENT_TRUSTED_PROXY_HOPS", 0),
		SelfServeCredIntake: getenvBool("PAYMENT_SELFSERVE_CRED_INTAKE", false),
		C6: C6Config{
			BaseURL:        os.Getenv("PAYMENT_C6_BASE_URL"),
			TokenURL:       os.Getenv("PAYMENT_C6_TOKEN_URL"),
			Scope:          os.Getenv("PAYMENT_C6_SCOPE"),
			Timeout:        getenvDuration("PAYMENT_C6_TIMEOUT", 15*time.Second),
			ClientCertPath: os.Getenv("PAYMENT_C6_CLIENT_CERT"),
			ClientKeyPath:  os.Getenv("PAYMENT_C6_CLIENT_KEY"),
			RecJWKSURL:     os.Getenv("PAYMENT_C6_REC_JWKS_URL"),
			RateLimitRPS:   getenvFloat("PAYMENT_C6_RATE_LIMIT_RPS", 0),
			RateLimitBurst: getenvInt("PAYMENT_C6_RATE_LIMIT_BURST", 0),
			MaxRetries:     getenvIntSigned("PAYMENT_C6_MAX_RETRIES", 0),
		},
		STGSeed: getenvBool("PAYMENT_STG_SEED", false),
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

// getenvInt resolves a non-negative integer env var, falling back to def when the
// variable is unset, unparseable, or negative. Failing back to def keeps a typo'd
// PAYMENT_TRUSTED_PROXY_HOPS from silently changing which hop the client IP is
// read from (a security control).
func getenvInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return def
	}
	return n
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

// getenvFloat resolves a float env var, falling back to def when the variable is
// unset or unparseable. A typo'd value falls back to def rather than silently
// disabling the outbound rate limit.
func getenvFloat(key string, def float64) float64 {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return def
	}
	return f
}

// getenvIntSigned resolves an integer env var, falling back to def when the
// variable is unset or unparseable. Unlike getenvInt, negative values are
// preserved (e.g. a negative PAYMENT_C6_MAX_RETRIES selects single-shot in the
// adapter).
func getenvIntSigned(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
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

// bankCredKey builds the composite map key for a (tenant, bank) pair, mirroring
// the secret store's keying so a single tenant can hold credentials at more than
// one bank without one overwriting another (ADR-0007). The NUL separator can
// appear in neither a tenant id nor a bank slug, so distinct pairs never collide.
func bankCredKey(tenant, bank string) string { return tenant + "\x00" + bank }

// logLoadedBankCreds emits, at info level, the list of (tenant, bank) pairs that
// were successfully loaded into the credential map. ONLY the non-secret routing
// identifiers (tenant id and bank slug) are logged — NEVER the clientID, secret,
// or creditor key (threat C1/C4). The pairs are sorted for a stable, diffable
// startup line so an operator can confirm at a glance that the expected
// (tenant, bank) slots were parsed. This surfaces a silent misparse of an
// ambiguous colon-bearing legacy secret (SIN-66015/SIN-66021): an unexpected
// orphan pair — e.g. one whose "bank" is what used to be the clientID — shows up
// in the startup line instead of failing opaquely later at the PSP. The count is
// logged separately so an empty map (no credentials configured) is still visible.
func logLoadedBankCreds(creds map[string]ports.BankCredential, logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}
	pairs := make([]string, 0, len(creds))
	for _, c := range creds {
		// "tenant/bank" — both are non-secret routing identifiers. We surface ONLY
		// TenantID and BankID; the clientID, secret and creditor key never appear.
		pairs = append(pairs, c.TenantID+"/"+c.BankID)
	}
	sort.Strings(pairs)
	logger.Info("loaded bank credentials",
		slog.Int("count", len(creds)),
		slog.Any("tenant_bank_pairs", pairs))
}

// parseBankCreds parses the PAYMENT_BANK_CREDS list into per-(tenant, bank)
// credentials. Two entry shapes are accepted (ADR-0007 / SIN-66015):
//
//   - 4-field "tenant:bank:clientID:secret" — the multi-bank form; the bank slug
//     sits BEFORE the clientID.
//   - 3-field "tenant:clientID:secret" — the legacy single-bank form, which maps
//     to the default bank "c6" (ports.BankIDC6), preserving current behaviour.
//
// The secret is ALWAYS the greedy ':'-tolerant tail (the last field of a SplitN),
// so a secret that itself contains ':' is preserved verbatim — it is NOT
// truncated. The number of leading colon-free fields (3 vs 4) selects the shape.
//
// AMBIGUITY (deliberate, documented): a legacy 3-field entry whose secret itself
// contains a ':' is indistinguishable from a 4-field entry, so it would be read as
// the new form (bank = what was the clientID). Such legacy colon-bearing secrets
// MUST migrate to the explicit 4-field form "tenant:c6:clientID:secret". This is
// the cost of folding the bank dimension into the existing variable; it is flagged
// for SecurityEngineer review (SIN-66021). Bank slugs and client ids never contain
// ':', so only a colon-in-secret legacy entry is affected.
//
// Entries that are structurally malformed (too few fields, or an empty
// tenant/clientID/secret) are skipped and logged at warn level so an operator can
// spot a misconfigured PAYMENT_BANK_CREDS instead of debugging an opaque auth
// failure at the PSP. To avoid leaking material, neither the raw entry nor the
// secret is ever logged; only the non-sensitive tenant_id/bank_id and the entry
// position are included to aid diagnosis.
func parseBankCreds(s string, logger *slog.Logger) map[string]ports.BankCredential {
	if logger == nil {
		logger = slog.Default()
	}
	m := make(map[string]ports.BankCredential)
	for i, item := range splitNonEmpty(s) {
		// SplitN n=4 keeps the secret as a greedy tail. 3 leading fields => legacy
		// (bank defaults to c6); 4 => the bank slug is field 2.
		parts := strings.SplitN(item, ":", 4)
		var tenant, bank, clientID, secret string
		switch len(parts) {
		case 3:
			tenant, clientID, secret = parts[0], parts[1], parts[2]
			bank = ports.BankIDC6
		case 4:
			tenant, bank, clientID, secret = parts[0], parts[1], parts[2], parts[3]
		default:
			logger.Warn("skipping malformed bank credential: expected tenant:clientID:secret or tenant:bank:clientID:secret",
				slog.Int("entry_index", i), slog.Int("field_count", len(parts)))
			continue
		}
		tenant = strings.TrimSpace(tenant)
		bank = strings.TrimSpace(bank)
		clientID = strings.TrimSpace(clientID)
		secret = strings.TrimSpace(secret)
		if bank == "" {
			bank = ports.BankIDC6
		}
		if tenant == "" {
			logger.Warn("skipping bank credential with empty tenant",
				slog.Int("entry_index", i))
			continue
		}
		if clientID == "" || secret == "" {
			logger.Warn("skipping bank credential with empty client_id or secret",
				slog.String("tenant_id", tenant), slog.String("bank_id", bank))
			continue
		}
		m[bankCredKey(tenant, bank)] = ports.BankCredential{
			TenantID: tenant,
			BankID:   bank,
			ClientID: clientID,
			Secret:   secret,
		}
	}
	return m
}

// mergeCreditorKeys folds the per-(tenant, bank) PIX creditor keys parsed from
// PAYMENT_BANK_CREDITOR_KEYS into the BankCredential map produced by
// parseBankCreds. The creditor key (chave do recebedor) is carried in a SEPARATE
// env var — not appended to the PAYMENT_BANK_CREDS tuple — on purpose: that tuple
// keeps the OAuth2 secret as a greedy ':'-tolerant tail, so there is no
// unambiguous slot to add a field after the secret without reinterpreting an
// existing ':'-bearing secret (ADR-0004 / SIN-65862).
//
// Two entry shapes are accepted (ADR-0007):
//
//   - 3-field "tenant:bank:creditorKey" — the multi-bank form.
//   - 2-field "tenant:creditorKey" — the legacy form, which targets the default
//     bank "c6" (ports.BankIDC6), preserving current behaviour.
//
// A PIX key (email, phone, CPF/CNPJ or EVP UUID) and a bank slug never contain
// ':', so the field count (2 vs 3) selects the shape unambiguously — unlike the
// secret tuple, there is no colon-in-value ambiguity here. The key is folded into
// the credential at the SAME (tenant, bank) pair: a creditor key for a pair with
// no bank credential is skipped (no half-credential). Entries that are malformed,
// or that reference a pair with no credential, are skipped and logged at warn
// level — the routing-sensitive key value itself is NEVER logged, only the
// non-sensitive tenant_id/bank_id and entry position (threat C1/C4).
func mergeCreditorKeys(creds map[string]ports.BankCredential, s string, logger *slog.Logger) map[string]ports.BankCredential {
	if logger == nil {
		logger = slog.Default()
	}
	if creds == nil {
		creds = make(map[string]ports.BankCredential)
	}
	for i, item := range splitNonEmpty(s) {
		// A creditor key never contains ':'. 2 fields => legacy (bank defaults to
		// c6); 3 => the bank slug is field 2.
		parts := strings.SplitN(item, ":", 3)
		var tenant, bank, key string
		switch len(parts) {
		case 2:
			tenant, key = parts[0], parts[1]
			bank = ports.BankIDC6
		case 3:
			tenant, bank, key = parts[0], parts[1], parts[2]
		default:
			logger.Warn("skipping malformed bank creditor key: expected tenant:creditorKey or tenant:bank:creditorKey",
				slog.Int("entry_index", i), slog.Int("field_count", len(parts)))
			continue
		}
		tenant = strings.TrimSpace(tenant)
		bank = strings.TrimSpace(bank)
		key = strings.TrimSpace(key)
		if bank == "" {
			bank = ports.BankIDC6
		}
		if tenant == "" || key == "" {
			logger.Warn("skipping bank creditor key with empty tenant or key",
				slog.Int("entry_index", i))
			continue
		}
		ck := bankCredKey(tenant, bank)
		cred, ok := creds[ck]
		if !ok {
			// A creditor key without a matching bank credential cannot route a
			// charge (the OAuth2 identity is missing); skip rather than synthesize a
			// half-credential.
			logger.Warn("skipping bank creditor key for tenant/bank with no bank credential",
				slog.String("tenant_id", tenant), slog.String("bank_id", bank))
			continue
		}
		cred.CreditorKey = key
		creds[ck] = cred
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

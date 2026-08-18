// Command c6-webhook-probe is a one-shot, operator-run diagnostic for the C6 PIX
// webhook registration surface (SIN-69580 / ticket A). It exists because the
// production adapter deliberately discards the PSP's RFC7807 "title"/"detail" so
// they cannot leak into logs — correct as a standing policy, but it leaves a 400
// from PUT /v2/pix/webhook/{chave} undebuggable. C6 also returns no machine-readable
// "violacoes" array for that call, so the field-name diagnostic (SIN-69582) comes
// back empty.
//
// This probe reads the SAME environment the api/worker read (config.FromEnv, i.e.
// /opt/payment/.env.stg via the systemd EnvironmentFile) and the SAME durable
// credential vault, then walks three steps in order so a failure localises itself:
//
//  1. OAuth2 client_credentials  — proves the mTLS handshake + credential work.
//  2. GET /v1/statement          — a READ-ONLY business call on a surface the
//     runbook already marks as proven, confirming the
//     token is accepted for real traffic.
//  3. GET then PUT the webhook   — the failing surface, with the FULL response body
//     printed verbatim.
//
// Printing the raw body is the whole point and is a deliberate, scoped exception to
// the adapter's non-leak policy: this is a manual run whose output goes to the
// operator's terminal, never to a log sink. Do not wire this into a service.
//
// The PUT uses a THROWAWAY ref that is never persisted in webhook_tenant_refs, so no
// live capability credential is created by the probe. If C6 accepts it, C6 will hold
// a callback URL that our receiver does not recognise (unregistered ref => 404,
// fail-closed) until the normal in-flow registration re-registers the real one — a
// PUT replaces, so that heals on the next credential write.
//
// Usage (on the receiver VPS, as the payment user, with the env sourced):
//
//	c6-webhook-probe <tenantID>
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/bank/c6"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/sqlite"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/system"
	"github.com/ia-dev-sindireceita/payment/internal/platform/config"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// maxPrintBytes caps how much of a response body is echoed, so a surprise HTML error
// page from an edge cannot flood the terminal.
const maxPrintBytes = 8 << 10

// callbackPathPrefix mirrors the inbound receiver path the real registration uses.
const callbackPathPrefix = "/webhooks/c6/"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "\nc6-webhook-probe: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) != 2 {
		return fmt.Errorf("usage: c6-webhook-probe <tenantID>")
	}
	tenantID := strings.TrimSpace(os.Args[1])

	cfg := config.FromEnv()
	if cfg.C6.BaseURL == "" || cfg.C6.TokenURL == "" {
		return fmt.Errorf("PAYMENT_C6_BASE_URL and PAYMENT_C6_TOKEN_URL are required")
	}
	if cfg.C6.ClientCertPath == "" || cfg.C6.ClientKeyPath == "" {
		return fmt.Errorf("PAYMENT_C6_CLIENT_CERT and PAYMENT_C6_CLIENT_KEY are required (mTLS)")
	}

	ctx := context.Background()
	cred, tenantCert, err := loadTenantMaterial(ctx, cfg, tenantID)
	if err != nil {
		return err
	}
	fmt.Printf("tenant           : %s\n", tenantID)
	fmt.Printf("client_id        : %s\n", cred.ClientID)
	fmt.Printf("creditor key     : %s (len=%d)\n", maskTail(cred.CreditorKey), len(cred.CreditorKey))
	fmt.Printf("base url         : %s\n", cfg.C6.BaseURL)
	if cred.CreditorKey == "" {
		return fmt.Errorf("tenant has no PIX creditor key — nothing to register")
	}

	// Reuse the adapter's hardened client (TLS floor, redirects disabled) and then graft
	// the TENANT's vault certificate over the §8 bootstrap one, mirroring what
	// NewVaultMTLSClient does per request. The live transport selects the cert by the
	// request's tenant via an unexported context key, which this package cannot stamp —
	// so the probe binds the tenant's cert directly instead of falling back to §8 and
	// presenting the wrong identity (the failure this probe first surfaced).
	httpc, err := c6.MTLSHTTPClient(cfg.C6.ClientCertPath, cfg.C6.ClientKeyPath, cfg.C6.Timeout)
	if err != nil {
		return fmt.Errorf("build mTLS client: %w", err)
	}
	if tenantCert != nil {
		httpc.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{*tenantCert}
		fmt.Printf("cert mTLS        : do COFRE (por-tenant)\n")
	} else {
		fmt.Printf("cert mTLS        : do ARQUIVO §8 (%s) — tenant sem cert no cofre\n", cfg.C6.ClientCertPath)
	}

	// --- 1. OAuth2 --------------------------------------------------------------
	section("1. OAuth2 client_credentials (prova mTLS + credencial)")
	token, err := fetchToken(ctx, httpc, cfg, cred)
	if err != nil {
		return err
	}
	fmt.Printf("   token obtido (len=%d)\n", len(token))

	base := strings.TrimRight(cfg.C6.BaseURL, "/")

	// --- 2. Read-only business call ---------------------------------------------
	section("2. GET /v1/statement (somente leitura, superficie ja provada)")
	today := time.Now().UTC()
	stmtURL := fmt.Sprintf("%s/v1/statement?start_date=%s&end_date=%s",
		base, today.AddDate(0, 0, -7).Format("2006-01-02"), today.Format("2006-01-02"))
	if err := call(ctx, httpc, http.MethodGet, stmtURL, token, nil, "application/json"); err != nil {
		return err
	}

	// --- 3. The failing surface --------------------------------------------------
	chavePath := url.PathEscape(cred.CreditorKey)
	webhookURL := base + "/v2/pix/webhook/" + chavePath

	section("3a. GET /v2/pix/webhook/{chave} (leitura da superficie que falha)")
	if err := call(ctx, httpc, http.MethodGet, webhookURL, token, nil, "application/json"); err != nil {
		return err
	}

	ref, err := throwawayRef()
	if err != nil {
		return err
	}
	callback := "https://payment.lmhost.com.br" + callbackPathPrefix + ref
	body, _ := json.Marshal(map[string]string{"webhookUrl": callback})

	section("3b. PUT com Accept: application/json (o que o adapter manda hoje)")
	fmt.Printf("   corpo enviado: {\"webhookUrl\":\"https://payment.lmhost.com.br%s%s\"}\n",
		callbackPathPrefix, maskTail(ref))
	if err := call(ctx, httpc, http.MethodPut, webhookURL, token, body, "application/json"); err != nil {
		return err
	}

	// C6 rejects the PUT with 400 when Accept is application/json, naming
	// application/problem+json as the only accepted response type. Re-issue the exact
	// same request with only that header changed, so the difference is isolated to one
	// variable and the result is proof rather than inference.
	section("3c. MESMO PUT com Accept: application/problem+json (hipotese)")
	if err := call(ctx, httpc, http.MethodPut, webhookURL, token, body, "application/problem+json"); err != nil {
		return err
	}

	// --- 4. The recurrence webhook siblings --------------------------------------
	// Same webhook family, same shared request builder, never proven positive against
	// real C6 (runbook marks recurrence as follow-up). Probing with application/json
	// first is non-destructive WHEN the endpoint rejects it: C6 refuses at content
	// negotiation before mutating, which is why the failing PIX-webhook PUT left
	// nothing registered. If it is instead accepted, a registration IS created on a
	// currently dormant surface (recurrence is off: PAYMENT_C6_REC_JWKS_URL empty), and
	// a later PUT replaces it.
	for _, path := range []string{"/v2/pix/webhookrec", "/v2/pix/webhookcobr"} {
		section("4. PUT " + path + " com Accept: application/json")
		if err := call(ctx, httpc, http.MethodPut, base+path, token, body, "application/json"); err != nil {
			return err
		}
		section("4. MESMO PUT " + path + " com Accept: application/problem+json")
		if err := call(ctx, httpc, http.MethodPut, base+path, token, body, "application/problem+json"); err != nil {
			return err
		}
	}
	return nil
}

// loadTenantMaterial resolves BOTH the tenant's C6 credential and its mTLS client
// certificate from the durable encrypted vault — the pair the live transport actually
// uses. Self-serve clients exist only there, never in the env bootstrap. A tenant with
// no certificate row returns a nil cert so the caller falls back to the §8 path.
func loadTenantMaterial(ctx context.Context, cfg config.Config, tenantID string) (ports.BankCredential, *tls.Certificate, error) {
	if cfg.BankVaultKey == "" {
		fmt.Println("aviso: PAYMENT_BANK_VAULT_KEY ausente — lendo credencial do bootstrap de ambiente")
		cred, err := secret.NewStore(cfg.BankCreds).GetBankCredential(ctx, tenantID, ports.BankIDC6)
		return cred, nil, err
	}
	key, err := hex.DecodeString(cfg.BankVaultKey)
	if err != nil {
		return ports.BankCredential{}, nil, fmt.Errorf("PAYMENT_BANK_VAULT_KEY is not valid hex")
	}
	cipher, err := secret.NewCipher(key)
	if err != nil {
		return ports.BankCredential{}, nil, fmt.Errorf("PAYMENT_BANK_VAULT_KEY invalid: %w", err)
	}
	db, err := sqlite.Open(cfg.DBPath)
	if err != nil {
		return ports.BankCredential{}, nil, fmt.Errorf("open db: %w", err)
	}
	defer func() { _ = db.Close() }()

	cred, err := sqlite.NewCredentialVault(db, cipher, system.Clock{}).GetBankCredential(ctx, tenantID, ports.BankIDC6)
	if err != nil {
		return ports.BankCredential{}, nil, err
	}
	// A missing certificate is not fatal: report it and let the caller use the §8 path,
	// which is exactly what the live transport does.
	cert, certErr := sqlite.NewCertificateVault(db, cipher, system.Clock{}).LoadTLSCertificate(ctx, tenantID, ports.BankIDC6)
	if certErr != nil {
		fmt.Printf("aviso: sem certificado no cofre para este tenant (%v)\n", certErr)
		return cred, nil, nil
	}
	return cred, cert, nil
}

// fetchToken replicates the adapter's client_credentials grant exactly (form body,
// secret only in the Basic auth header) so the probe exercises the same auth path the
// service uses. On failure the raw body IS printed — that is the diagnostic value.
func fetchToken(ctx context.Context, httpc *http.Client, cfg config.Config, cred ports.BankCredential) (string, error) {
	form := url.Values{"grant_type": {"client_credentials"}}
	if cfg.C6.Scope != "" {
		form.Set("scope", cfg.C6.Scope)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.C6.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(cred.ClientID, cred.Secret)

	resp, err := httpc.Do(req)
	if err != nil {
		return "", fmt.Errorf("token transport: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxPrintBytes))
	fmt.Printf("   HTTP %d\n", resp.StatusCode)
	if resp.StatusCode/100 != 2 {
		fmt.Printf("   corpo: %s\n", string(raw))
		return "", fmt.Errorf("token failed with HTTP %d", resp.StatusCode)
	}
	var tr struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(raw, &tr); err != nil || tr.AccessToken == "" {
		return "", fmt.Errorf("token response not understood")
	}
	return tr.AccessToken, nil
}

// call performs one authenticated request and prints status, content-type and the
// response body verbatim (capped). Body is nil for reads.
func call(ctx context.Context, httpc *http.Client, method, endpoint, token string, body []byte, accept string) error {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", accept)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := httpc.Do(req)
	if err != nil {
		return fmt.Errorf("%s transport: %w", method, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxPrintBytes))
	fmt.Printf("   HTTP %d  content-type=%s\n", resp.StatusCode, resp.Header.Get("Content-Type"))
	fmt.Printf("   corpo: %s\n", strings.TrimSpace(string(raw)))
	return nil
}

// throwawayRef mints a ref-shaped value (32 random bytes, base64url, 43 chars) that is
// deliberately NOT persisted, so the probe never creates a live capability credential.
func throwawayRef() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// maskTail renders a sensitive value as first-char + tail so the operator can tell two
// values apart without the full secret reaching the terminal or a paste buffer.
func maskTail(s string) string {
	if len(s) <= 4 {
		return "****"
	}
	return s[:1] + "***" + s[len(s)-1:]
}

func section(title string) { fmt.Printf("\n== %s ==\n", title) }

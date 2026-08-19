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
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
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
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: c6-webhook-probe <tenantID> [--discover-proprietary]")
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
	// A 401 whose credential looks like a PIX key is almost always a field swap in the
	// console. Comparing without printing either value keeps the check safe.
	if strings.EqualFold(strings.TrimSpace(cred.ClientID), strings.TrimSpace(cred.CreditorKey)) {
		fmt.Printf("ATENCAO          : client_id e chave PIX sao O MESMO VALOR — campos trocados\n")
	}
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
		// Which identity the handshake actually presents. A 401 on the token endpoint
		// cannot distinguish "wrong secret" from "certificate of another environment",
		// so the subject is printed to separate the two.
		if len(tenantCert.Certificate) > 0 {
			if leaf, perr := x509.ParseCertificate(tenantCert.Certificate[0]); perr == nil {
				fmt.Printf("cert subject     : %s\n", leaf.Subject.CommonName)
				fmt.Printf("cert emissor     : %s\n", leaf.Issuer.CommonName)
				fmt.Printf("cert validade    : %s ate %s\n",
					leaf.NotBefore.Format("2006-01-02"), leaf.NotAfter.Format("2006-01-02"))
				fmt.Printf("cert sha256      : %x\n", sha256.Sum256(tenantCert.Certificate[0]))
			}
		}
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

	// Read-only mode: stop right after authentication. The default flow WRITES (it PUTs
	// webhook registrations), so inspecting a production credential must never use it.
	if len(os.Args) > 2 && os.Args[2] == "--token-only" {
		return nil
	}

	base := strings.TrimRight(cfg.C6.BaseURL, "/")

	// Discovery mode for the C6-PROPRIETARY webhook surface (/v1/webhooks), which backs
	// boleto/checkout and is documented only as a shape in the runbook — never exercised.
	// READ-ONLY: it lists what is registered under both Accept values so the real contract
	// (field names, service enum, header requirements) can be read off the response before
	// any code is written against it. No write is attempted here on purpose.
	if len(os.Args) > 2 && os.Args[2] == "--discover-proprietary" {
		// This family answers the OPPOSITE of the BACEN one: it demands
		// Accept: application/json and rejects application/problem+json. It also requires
		// the `service` discriminator as a QUERY parameter on the read.
		section("GET /v1/webhooks?service=CHECKOUT (estado atual)")
		if err := call(ctx, httpc, http.MethodGet, base+"/v1/webhooks?service=CHECKOUT", token, nil, "application/json"); err != nil {
			return err
		}
		// Elicit the WRITE contract without creating anything: an empty and then a partial
		// body make the PSP name the fields it requires. A validation rejection happens
		// before any mutation (the same property the Accept rejections demonstrated), so
		// nothing is registered by these calls.
		for _, probe := range []struct {
			method, label, body string
		}{
			{http.MethodPost, "POST corpo vazio", `{}`},
			{http.MethodPost, "POST so service", `{"service":"CHECKOUT"}`},
			{http.MethodPut, "PUT corpo vazio", `{}`},
		} {
			section(probe.label + " /v1/webhooks")
			if err := call(ctx, httpc, probe.method, base+"/v1/webhooks", token, []byte(probe.body), "application/json"); err != nil {
				return err
			}
		}
		return nil
	}

	// --parcelas <n>: open ONE hosted checkout with a ceiling of n parcelas and a
	// LONG expiry, so a human has time to open the page and answer the one question
	// the wire cannot: does the page offer a CHOICE of parcelas up to n, or does it
	// force exactly n? The product decision ("the merchant caps it") presumes a
	// choice, and shipping the wrong reading would force every buyer into n parcelas.
	//
	// Nothing is paid: the session simply expires.
	if len(os.Args) > 3 && os.Args[2] == "--parcelas" {
		n, convErr := strconv.Atoi(strings.TrimSpace(os.Args[3]))
		if convErr != nil || n < 1 || n > 12 {
			return fmt.Errorf("parcelas deve ser 1..12, recebi %q", os.Args[3])
		}
		exp := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
		// R$ 30,00 e não R$ 15,00: cada parcela precisa passar do mínimo de R$ 5,00 do
		// PSP, e o C6 só aplica essa regra na PÁGINA — a criação responde 201 e o link
		// depois diz "Link de Pagamento não encontrado". Com 30 reais, até 6x cabe.
		body := map[string]any{
			"amount": 30.00, "expiration_date_time": exp,
			"payment": map[string]any{"card": map[string]any{
				"type": "CREDIT", "installments": n, "authenticate": "NOT_REQUIRED",
				"interest_type": "BY_ISSUER"}},
		}
		b, mErr := json.Marshal(body)
		if mErr != nil {
			return mErr
		}
		section(fmt.Sprintf("checkout de R$ 30,00 com teto de %dx, valido por 24h", n))
		fmt.Printf("   enviado: %s\n", b)
		return call(ctx, httpc, http.MethodPost, base+"/v1/checkouts/", token, b, "application/json")
	}

	// --installments: probe what C6 accepts on the checkout CREATE for parcelamento,
	// without paying anything.
	//
	// Two questions block the feature and neither has been observed, only assumed:
	//
	//   1. Is payment.card.installments a CEILING the buyer chooses under, or the exact
	//      number of parcelas they must take? The product decision ("the merchant caps
	//      it") presumes the first.
	//   2. Is interest_type: BY_ISSUER accepted? We have only ever seen BY_SELLER, which
	//      C6 fills in by DEFAULT — meaning not sending the field is choosing that the
	//      MERCHANT absorbs the installment interest. That is a money decision made by
	//      omission, which is the worst way to make one.
	//
	// Every request here CREATES a session and none is ever paid: they simply expire.
	// That makes the acceptance half of the experiment free. The ceiling-vs-exact half
	// still needs a human to look at the hosted page (or a headless render of it), which
	// is why the created URLs are printed.
	if len(os.Args) > 2 && os.Args[2] == "--installments" {
		exp := time.Now().Add(20 * time.Minute).UTC().Format(time.RFC3339)
		casos := []struct {
			nome string
			body map[string]any
		}{
			{"3x, juros do EMISSOR (o que queremos mandar)", map[string]any{
				"amount": 15.00, "expiration_date_time": exp,
				"payment": map[string]any{"card": map[string]any{
					"type": "CREDIT", "installments": 3, "authenticate": "NOT_REQUIRED",
					"interest_type": "BY_ISSUER"}}}},
			{"3x, sem interest_type (hoje: C6 assume BY_SELLER)", map[string]any{
				"amount": 15.00, "expiration_date_time": exp,
				"payment": map[string]any{"card": map[string]any{
					"type": "CREDIT", "installments": 3, "authenticate": "NOT_REQUIRED"}}}},
			{"13x (fora da faixa 1..12): C6 recusa ou aceita?", map[string]any{
				"amount": 15.00, "expiration_date_time": exp,
				"payment": map[string]any{"card": map[string]any{
					"type": "CREDIT", "installments": 13, "authenticate": "NOT_REQUIRED"}}}},
			{"DEBITO parcelado: a regra e do C6 ou nossa?", map[string]any{
				"amount": 15.00, "expiration_date_time": exp,
				"payment": map[string]any{"card": map[string]any{
					"type": "DEBIT", "installments": 3, "authenticate": "NOT_REQUIRED"}}}},
			{"R$ 6,00 em 3x: existe minimo POR PARCELA?", map[string]any{
				"amount": 6.00, "expiration_date_time": exp,
				"payment": map[string]any{"card": map[string]any{
					"type": "CREDIT", "installments": 3, "authenticate": "NOT_REQUIRED"}}}},
			{"R$ 3,00 (abaixo do minimo): forma do erro", map[string]any{
				"amount": 3.00, "expiration_date_time": exp,
				"payment": map[string]any{"card": map[string]any{
					"type": "CREDIT", "installments": 1, "authenticate": "NOT_REQUIRED"}}}},
		}

		for _, c := range casos {
			section(c.nome)
			b, err := json.Marshal(c.body)
			if err != nil {
				return err
			}
			fmt.Printf("   enviado: %s\n", b)
			if err := call(ctx, httpc, http.MethodPost, base+"/v1/checkouts/", token, b, "application/json"); err != nil {
				fmt.Printf("   erro de transporte: %v\n", err)
			}
		}
		return nil
	}

	// --get-checkout <sessionID>: read ONE real checkout session and print the PSP's
	// body verbatim. It exists to settle a question our own API cannot answer: the
	// adapter's checkoutResponseBody declares only id/status/url/amount and pins
	// ReceivedAmountCents to 0 on the stated grounds that C6 does not yet return a
	// captured amount ("EM BREVE"). That claim came from a code comment, never from an
	// observed response, and it is the single thing standing between a paid checkout and
	// settlement (SIN-65726). Printing the raw body checks it against the wire.
	if len(os.Args) > 3 && os.Args[2] == "--get-checkout" {
		id := strings.TrimSpace(os.Args[3])
		section("GET /v1/checkouts/" + id + " (corpo bruto)")
		if err := call(ctx, httpc, http.MethodGet, base+"/v1/checkouts/"+id, token, nil, "application/json"); err != nil {
			return err
		}
		return nil
	}

	if len(os.Args) > 2 && os.Args[2] == "--checkout" {
		// The minimal body (amount + payment.card) answered 401, which reads as a
		// permission problem — but /auth reports checkout.write among the granted scopes.
		// So the variants below isolate what the gateway actually objects to: an
		// incomplete payload, the payment method, or the URL shape.
		exp := time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
		full := map[string]any{
			"amount":                7.77,
			"description":           "Smoke sandbox",
			"external_reference_id": "smokechk01",
			"expiration_date_time":  exp,
			"redirect_url":          "https://payment-sbx.lmhost.com.br/",
			"payer": map[string]any{
				"name":   "Fulano de Tal",
				"tax_id": "12345678901",
				"email":  "fulano@example.com",
				"address": map[string]any{
					"street": "Rua das Flores", "number": 123,
					"city": "Brasilia", "state": "DF", "zip_code": "70000000",
				},
			},
			"payment": map[string]any{
				"card": map[string]any{"type": "CREDIT", "installments": 1},
			},
		}
		// Same complete body, only the payment method differs — isolates whether the 401
		// is about PIX-in-checkout specifically or about the payload.
		pixFull := map[string]any{}
		for k, v := range full {
			pixFull[k] = v
		}
		pixFull["external_reference_id"] = "smokechk02"
		pixFull["payment"] = map[string]any{"pix": map[string]any{"key": "AUTO"}}
		// And the body our adapter actually sends today: amount + payment.card only.
		adapterShape := map[string]any{
			"amount":  7.77,
			"payment": map[string]any{"card": map[string]any{"type": "CREDIT", "installments": 1}},
		}
		variants := []struct {
			name string
			body map[string]any
		}{
			{"corpo COMPLETO com cartao", full},
			{"corpo COMPLETO com pix AUTO", pixFull},
			{"corpo que NOSSO adapter envia hoje", adapterShape},
		}
		// Reads first: they create nothing and separate "not authorized for checkout at
		// all" from "not authorized to WRITE". A 404 on a bogus id means the credential
		// got past authorization; a 401 means it did not.
		section("GET /v1/checkouts/{id inexistente} (checkout.read)")
		if err := call(ctx, httpc, http.MethodGet, base+"/v1/checkouts/naoexiste", token, nil, "application/json"); err != nil {
			return err
		}
		section("GET /v1/checkouts/generate/public-key (checkout.keys.read)")
		if err := call(ctx, httpc, http.MethodGet, base+"/v1/checkouts/generate/public-key", token, nil, "application/json"); err != nil {
			return err
		}
		for _, v := range variants {
			b, _ := json.Marshal(v.body)
			section(v.name)
			fmt.Printf("   enviado: %s\n", string(b))
			if err := call(ctx, httpc, http.MethodPost, base+"/v1/checkouts/", token, b, "application/json"); err != nil {
				return err
			}
		}
		return nil
	}

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
	// RFC 6749 allows the client credentials either in the Authorization header
	// (client_secret_basic) or in the form body (client_secret_post). The adapter sends
	// Basic; the published C6 contract documents all three fields IN THE BODY. Production
	// accepts Basic, so the difference never surfaced. Both are tried here, in that order,
	// and the winner is reported — a 401 alone cannot tell "wrong secret" from "wrong
	// client-authentication method".
	attempts := []struct {
		name  string
		build func(url.Values, *http.Request)
	}{
		{"client_secret_basic (o que o adapter manda hoje)", func(_ url.Values, r *http.Request) {
			r.SetBasicAuth(cred.ClientID, cred.Secret)
		}},
		{"client_secret_post (o que o contrato documenta)", nil},
	}
	var lastErr error
	for _, a := range attempts {
		form := url.Values{"grant_type": {"client_credentials"}}
		if cfg.C6.Scope != "" {
			form.Set("scope", cfg.C6.Scope)
		}
		if a.build == nil {
			form.Set("client_id", cred.ClientID)
			form.Set("client_secret", cred.Secret)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.C6.TokenURL, strings.NewReader(form.Encode()))
		if err != nil {
			return "", err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "application/json")
		if a.build != nil {
			a.build(form, req)
		}
		resp, err := httpc.Do(req)
		if err != nil {
			return "", fmt.Errorf("token transport: %w", err)
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxPrintBytes))
		_ = resp.Body.Close()
		fmt.Printf("   %-48s HTTP %d\n", a.name, resp.StatusCode)
		if resp.StatusCode/100 != 2 {
			fmt.Printf("      corpo: %s\n", strings.TrimSpace(string(raw)))
			lastErr = fmt.Errorf("token failed with HTTP %d", resp.StatusCode)
			continue
		}
		var tr struct {
			AccessToken string `json:"access_token"`
			// The certification script documents that /auth echoes the credential's
			// granted scopes. A 403 on a business endpoint is usually a missing scope,
			// so they are printed here to make that diagnosable in one run.
			Scopes any `json:"scopes"`
		}
		if err := json.Unmarshal(raw, &tr); err != nil || tr.AccessToken == "" {
			return "", fmt.Errorf("token response not understood")
		}
		// The token turned out to be OPAQUE (no dots), so no claims exist to inspect. The
		// certification script says /auth returns the granted scopes, so the envelope is
		// printed in full — with the bearer redacted — to find where they actually live.
		{
			var env map[string]any
			if json.Unmarshal(raw, &env) == nil {
				if _, ok := env["access_token"]; ok {
					env["access_token"] = "<REDIGIDO>"
				}
				if b, mErr := json.MarshalIndent(env, "      ", "  "); mErr == nil {
					fmt.Printf("      resposta do /auth: %s\n", string(b))
				}
			}
		}
		if tr.Scopes != nil {
			if b, mErr := json.Marshal(tr.Scopes); mErr == nil {
				fmt.Printf("      escopos (corpo): %s\n", string(b))
			}
		}
		// The granted scopes may travel inside the JWT instead of the envelope. Only the
		// scope-bearing claims are printed — never the token, which is a bearer secret.
		parts := strings.Split(tr.AccessToken, ".")
		fmt.Printf("      formato do token: %d segmento(s) separados por ponto\n", len(parts))
		if len(parts) == 3 {
			payload, dErr := base64.RawURLEncoding.DecodeString(parts[1])
			if dErr != nil {
				fmt.Printf("      payload nao decodifica como base64url: %v\n", dErr)
			}
			if dErr == nil {
				var claims map[string]any
				if uErr := json.Unmarshal(payload, &claims); uErr != nil {
					fmt.Printf("      payload nao e JSON: %v\n", uErr)
				} else {
					// Claim NAMES are always listed: the certification script says the
					// granted scopes come back from /auth, so knowing which claims exist
					// is the first step when a business endpoint answers 401/403.
					names := make([]string, 0, len(claims))
					for k := range claims {
						names = append(names, k)
					}
					sort.Strings(names)
					fmt.Printf("      claims presentes: %s\n", strings.Join(names, ", "))
					for _, k := range []string{"scope", "scopes", "authorities", "permissions", "roles"} {
						if v, ok := claims[k]; ok {
							if b, mErr := json.Marshal(v); mErr == nil {
								fmt.Printf("      claim %s: %s\n", k, string(b))
							}
						}
					}
				}
			}
		}
		return tr.AccessToken, nil
	}
	return "", lastErr
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

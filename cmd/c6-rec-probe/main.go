// Command c6-rec-probe is a one-shot, operator-run diagnostic that answers ONE
// question: what does C6 actually return on a PIX Automático (Recorrência) READ?
//
// Why it exists. It settled a contradiction that no document could: the adapter used
// to read rec/solicrec/cobr with `Accept: application/jose`, a posture recorded as
// captured live in SIN-66034, while the vendored C6 contract declares those reads
// `application/json`. Run against the sandbox on 28/08/2026 it produced the answer:
//
//	Accept: application/json  → 200, Content-Type: application/json
//	Accept: application/jose  → 400 "does not match any defined response types"
//
// C6 refuses the jose header outright, so no JWKS value could ever have made those
// reads work. The adapter now reads JSON. Keep this probe: it is how that class of
// question gets answered, and it is the fastest way to re-check the day C6 changes
// the contract.
//
// It is READ-ONLY: it lists recurrences over a short window. It creates no mandate,
// no charge and no webhook registration, so it is safe to run against a live sandbox.
//
// It reads the SAME environment and the SAME durable credential vault as the api
// (config.FromEnv + the sealed bank_credentials row), so the client secret is never
// handled outside its sanctioned decryption path and never printed. Only response
// METADATA is printed — status, Content-Type, body shape and size. The body itself is
// NOT dumped: a recurrence read carries the payer's CPF/CNPJ and name, the only
// titular PII this service holds (ADR-0008), which is precisely what must not land in
// an operator's terminal or scrollback.
//
// Usage:
//
//	c6-rec-probe <tenantID>            # só leituras (GET /rec), read-only
//	c6-rec-probe <tenantID> locrec     # + POST /v2/pix/locrec (cria uma location)
//
// O modo `locrec` é a ÚNICA parte que ESCREVE, e é a escrita mais benigna do
// contrato: mintar uma location é reservar uma URL de payload — sem pagador, sem
// valor, sem mandato, sem cobrança. Serve para ver, com a resposta crua do banco, por
// que POST /v2/pix/locrec devolveu 404 pela API (SIN-66030). O corpo de erro do C6 é
// um Problema RFC7807 sem PII, então é impresso; num 2xx só metadados saem.
package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/bank/c6"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/system"
	"github.com/ia-dev-sindireceita/payment/internal/platform/config"
	"github.com/ia-dev-sindireceita/payment/internal/platform/persistence"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "erro: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("uso: c6-rec-probe <tenantID>")
	}
	// Modo utilitário: listar os tenants que têm credencial C6 no cofre, para achar um
	// alvo sandbox. Só imprime ids (não é segredo), nunca o material da credencial.
	if strings.TrimSpace(os.Args[1]) == "--list-c6" {
		cfg := config.FromEnv()
		db, err := persistence.Open(context.Background(), cfg.DBDSN, cfg.DBPath)
		if err != nil {
			return fmt.Errorf("abrir banco: %w", err)
		}
		defer func() { _ = db.Close() }()
		rows, err := db.SQL.QueryContext(context.Background(),
			`SELECT tenant_id FROM bank_credentials WHERE bank_id = $1 ORDER BY tenant_id`, ports.BankIDC6)
		if err != nil {
			return fmt.Errorf("consulta: %w", err)
		}
		defer func() { _ = rows.Close() }()
		n := 0
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			fmt.Printf("  tenant com credencial C6: %s\n", id)
			n++
		}
		fmt.Printf("  total: %d\n", n)
		return nil
	}

	tenantID := strings.TrimSpace(os.Args[1])
	cfg := config.FromEnv()
	if cfg.C6.BaseURL == "" || cfg.C6.TokenURL == "" {
		return fmt.Errorf("PAYMENT_C6_BASE_URL / PAYMENT_C6_TOKEN_URL ausentes")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	fmt.Printf("base             : %s\n", cfg.C6.BaseURL)
	fmt.Printf("tenant           : %s\n", tenantID)

	cred, tenantCert, err := loadTenantMaterial(ctx, cfg, tenantID)
	if err != nil {
		return fmt.Errorf("credencial do tenant: %w", err)
	}
	httpc, err := c6.MTLSHTTPClient(cfg.C6.ClientCertPath, cfg.C6.ClientKeyPath, cfg.C6.Timeout)
	if err != nil {
		return fmt.Errorf("cliente mTLS: %w", err)
	}
	if tenantCert != nil {
		httpc.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{*tenantCert}
		fmt.Printf("cert mTLS        : do cofre (por-tenant)\n")
	}

	token, err := fetchToken(ctx, httpc, cfg, cred)
	if err != nil {
		return fmt.Errorf("token: %w", err)
	}
	fmt.Printf("token            : obtido\n\n")

	// The question: same READ, both Accept values. If C6 honours application/jose the
	// body comes back as a compact JWS (three base64url runs separated by dots); if the
	// contract is right it is JSON either way, and the jose read can never succeed.
	fim := time.Now().UTC()
	ini := fim.Add(-24 * time.Hour)
	q := url.Values{
		"inicio": {ini.Format(time.RFC3339)},
		"fim":    {fim.Format(time.RFC3339)},
	}
	endpoint := strings.TrimRight(cfg.C6.BaseURL, "/") + "/v2/pix/rec?" + q.Encode()

	for _, accept := range []string{"application/json", "application/jose"} {
		probe(ctx, httpc, endpoint, token, accept)
	}

	if len(os.Args) >= 3 && strings.TrimSpace(os.Args[2]) == "locrec" {
		fmt.Printf("\n")
		probeLocRec(ctx, httpc, strings.TrimRight(cfg.C6.BaseURL, "/")+"/v2/pix/locrec", token)
	}
	return nil
}

// probeLocRec POSTs the payload-location mint the recurrence journey starts with —
// the exact call the API maps to 404. The BACEN contract takes NO request body, so
// none is sent. Only metadata + the RFC7807 error detail (no PII) are printed.
func probeLocRec(ctx context.Context, httpc *http.Client, endpoint, token string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		fmt.Printf("POST locrec        → erro montando request: %v\n", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Idempotency-Key", "probe-locrec-"+time.Now().UTC().Format("20060102T150405Z"))

	resp, err := httpc.Do(req)
	if err != nil {
		fmt.Printf("POST locrec        → transporte falhou: %v\n", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	head := strings.TrimSpace(string(buf[:n]))
	fmt.Printf("POST %-14s → HTTP %d  Content-Type: %-34s (%d bytes)\n",
		"locrec", resp.StatusCode, resp.Header.Get("Content-Type"), n)
	fmt.Printf("                     corpo: %s\n", head)
}

// probe issues one GET and prints only response metadata — never the body, which
// carries titular PII.
func probe(ctx context.Context, httpc *http.Client, endpoint, token, accept string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		fmt.Printf("Accept %-18s → erro montando request: %v\n", accept, err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", accept)

	resp, err := httpc.Do(req)
	if err != nil {
		fmt.Printf("Accept %-18s → transporte falhou: %v\n", accept, err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	head := buf[:n]

	shape := "desconhecido"
	switch {
	case n == 0:
		shape = "vazio"
	case head[0] == '{' || head[0] == '[':
		shape = "JSON"
	case strings.HasPrefix(string(head), "eyJ"):
		shape = "JWS compacto"
	}
	fmt.Printf("Accept %-18s → HTTP %d  Content-Type: %-34s corpo: %s (%d bytes lidos)\n",
		accept, resp.StatusCode, resp.Header.Get("Content-Type"), shape, n)
	// On an error status the body is a Problema (RFC7807) with no PII, so its detail is
	// the diagnostic and IS printed — the same scoped exception c6-webhook-probe makes.
	if resp.StatusCode/100 != 2 {
		fmt.Printf("                     corpo do erro: %s\n", strings.TrimSpace(string(head)))
	}
}

// loadTenantMaterial mirrors c6-webhook-probe: the credential comes from the sealed
// vault via its normal decryption path, never by hand.
func loadTenantMaterial(ctx context.Context, cfg config.Config, tenantID string) (ports.BankCredential, *tls.Certificate, error) {
	if cfg.BankVaultKey == "" {
		cred, err := secret.NewStore(cfg.BankCreds).GetBankCredential(ctx, tenantID, ports.BankIDC6)
		return cred, nil, err
	}
	key, err := hex.DecodeString(cfg.BankVaultKey)
	if err != nil {
		return ports.BankCredential{}, nil, fmt.Errorf("PAYMENT_BANK_VAULT_KEY não é hex válido")
	}
	cipher, err := secret.NewCipher(key)
	if err != nil {
		return ports.BankCredential{}, nil, fmt.Errorf("PAYMENT_BANK_VAULT_KEY inválida: %w", err)
	}
	db, err := persistence.Open(ctx, cfg.DBDSN, cfg.DBPath)
	if err != nil {
		return ports.BankCredential{}, nil, fmt.Errorf("abrir banco: %w", err)
	}
	defer func() { _ = db.Close() }()

	cred, err := db.CredentialVault(cipher, system.Clock{}).GetBankCredential(ctx, tenantID, ports.BankIDC6)
	if err != nil {
		return ports.BankCredential{}, nil, err
	}
	cert, certErr := db.CertificateVault(cipher, system.Clock{}).LoadTLSCertificate(ctx, tenantID, ports.BankIDC6)
	if certErr != nil {
		fmt.Printf("aviso            : sem certificado no cofre para este tenant (%v)\n", certErr)
		return cred, nil, nil
	}
	return cred, cert, nil
}

// fetchToken replicates the adapter's client_credentials grant: the secret travels only
// in the Basic auth header and is never printed.
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
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(buf[:n])))
	}
	tok := extractJSONString(string(buf[:n]), "access_token")
	if tok == "" {
		return "", fmt.Errorf("resposta sem access_token")
	}
	if sc := extractJSONString(string(buf[:n]), "scope"); sc != "" {
		fmt.Printf("escopos          : %s\n", sc)
	}
	return tok, nil
}

// extractJSONString pulls one top-level string field without pulling in a decoder that
// would keep the whole token document in memory longer than needed.
func extractJSONString(body, field string) string {
	k := `"` + field + `"`
	i := strings.Index(body, k)
	if i < 0 {
		return ""
	}
	rest := body[i+len(k):]
	c := strings.Index(rest, ":")
	if c < 0 {
		return ""
	}
	rest = strings.TrimSpace(rest[c+1:])
	if len(rest) == 0 || rest[0] != '"' {
		return ""
	}
	rest = rest[1:]
	e := strings.Index(rest, `"`)
	if e < 0 {
		return ""
	}
	return rest[:e]
}

package c6

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// defaultRefreshSkew is how long before real expiry a cached token is treated as
// stale, so a token is renewed proactively instead of failing an in-flight call
// at the boundary.
const defaultRefreshSkew = 30 * time.Second

// fallbackTokenTTL is used when the token endpoint omits expires_in. It is short
// so a missing TTL degrades to frequent refresh rather than using a token past
// its real lifetime.
const fallbackTokenTTL = 60 * time.Second

// cachedToken is an access token together with the instant it must be considered
// expired. The token lives only in memory and is never persisted (threat C1).
type cachedToken struct {
	accessToken string
	expiresAt   time.Time
	// scope is the space-separated list the PSP actually GRANTED. It is not
	// necessarily what we asked for: C6 grants what the conta contratou, so this is
	// the only honest source for "esta empresa pode cobrar por cartão?" (SIN-69368).
	scope string
}

// tokenState is the per-tenant cache slot. Its own mutex serializes refreshes for
// a single tenant (so concurrent calls for the same tenant make at most one token
// request) without serializing unrelated tenants.
type tokenState struct {
	mu  sync.Mutex
	tok cachedToken
}

// tokenManager issues and caches OAuth2 client_credentials access tokens per
// tenant. Credentials are resolved from the CredentialStore at fetch time and the
// client secret is sent only in the token request's form body — never logged, never
// stored, never placed in a URL (threat C1/C4).
type tokenManager struct {
	creds ports.CredentialStore
	// bankID binds this token manager to a single bank's credential slot (ADR-0007
	// §3): the OAuth2 credential is resolved for the (tenant, bankID) pair, so a
	// token is never minted under another bank's secret.
	bankID   string
	tokenURL string
	scope    string
	httpc    *http.Client
	now      func() time.Time
	skew     time.Duration
	// sleep espaça as retentativas do 5xx. Injetável para os testes não dormirem de
	// verdade; o padrão respeita o cancelamento do contexto.
	sleep sleepFunc

	mu      sync.Mutex
	entries map[string]*tokenState
}

func newTokenManager(creds ports.CredentialStore, bankID, tokenURL, scope string, httpc *http.Client, now func() time.Time) *tokenManager {
	return &tokenManager{
		creds:    creds,
		bankID:   bankID,
		tokenURL: tokenURL,
		scope:    scope,
		httpc:    httpc,
		now:      now,
		skew:     defaultRefreshSkew,
		sleep:    realSleep,
		entries:  make(map[string]*tokenState),
	}
}

// stateFor returns the cache slot for a tenant, creating it on first use. The
// outer mutex is held only for the map lookup/insert, never across the HTTP call.
func (m *tokenManager) stateFor(tenantID string) *tokenState {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.entries[tenantID]
	if !ok {
		st = &tokenState{}
		m.entries[tenantID] = st
	}
	return st
}

// token returns a valid access token for the tenant, fetching or refreshing it as
// needed. Tokens are isolated per tenant: one tenant's token is never served to
// another, and a refresh for one tenant cannot block another.
func (m *tokenManager) token(ctx context.Context, tenantID string) (string, error) {
	st := m.stateFor(tenantID)
	st.mu.Lock()
	defer st.mu.Unlock()

	if st.tok.accessToken != "" && m.now().Before(st.tok.expiresAt.Add(-m.skew)) {
		return st.tok.accessToken, nil
	}

	// Resolve the tenant's credential lazily and only when a (re)fetch is needed.
	cred, err := m.creds.GetBankCredential(ctx, tenantID, m.bankID)
	if err != nil {
		return "", err
	}
	// The OAuth token endpoint is also behind C6's mTLS, so stamp the tenant onto the
	// fetch context too — the token handshake then presents the tenant's vault
	// certificate, keeping the whole tenant call chain on one identity (SIN-69368).
	tok, err := m.fetch(withTenant(ctx, tenantID), cred)
	if err != nil {
		return "", err
	}
	st.tok = tok
	return tok.accessToken, nil
}

// grantedScopes returns the scopes the PSP GRANTED this tenant, as a set. It reuses the
// token cache, so asking costs a network round trip only when the token is stale — the
// scopes ride along on a fetch that would happen anyway.
//
// O que a empresa PEDE e o que a conta dela TEM são coisas diferentes. Descobrimos do
// jeito caro: a conta da empresa 27 não tinha o produto Checkout, e a única evidência
// era o C6 responder 403 no meio de uma compra. O escopo concedido diz isso ANTES, e é
// o que permite a tela de configuração explicar em vez de deixar o comprador tropeçar.
func (m *tokenManager) grantedScopes(ctx context.Context, tenantID string) (map[string]struct{}, error) {
	st := m.stateFor(tenantID)
	st.mu.Lock()
	defer st.mu.Unlock()

	if st.tok.accessToken == "" || !m.now().Before(st.tok.expiresAt.Add(-m.skew)) {
		cred, err := m.creds.GetBankCredential(ctx, tenantID, m.bankID)
		if err != nil {
			return nil, err
		}
		tok, err := m.fetch(withTenant(ctx, tenantID), cred)
		if err != nil {
			return nil, err
		}
		st.tok = tok
	}
	out := make(map[string]struct{})
	for _, sc := range strings.Fields(st.tok.scope) {
		out[strings.ToLower(sc)] = struct{}{}
	}
	return out, nil
}

// invalidate drops any cached token for tenantID so the next token() call mints a
// fresh one under the tenant's current credential. It is the eviction half of the
// token-revocation-lag fix (ADR-0003): a rotated/revoked credential takes effect
// at once instead of after the cached bearer expires (≤ TTL; 60s fallback). Safe
// for an unknown tenant (no-op) and concurrency-safe against an in-flight refresh:
// it takes the outer lock only to find the slot, then the slot's own lock to zero
// it — the same outer-then-slot order token() uses, never both at once, so no
// lock-order inversion. A refresh already running for the old credential finishes
// into its slot; because the new credential is persisted before invalidate runs,
// any (re)fetch — that in-flight one or the next caller's — resolves the new
// secret from the store.
func (m *tokenManager) invalidate(tenantID string) {
	m.mu.Lock()
	st, ok := m.entries[tenantID]
	m.mu.Unlock()
	if !ok {
		return
	}
	st.mu.Lock()
	st.tok = cachedToken{}
	st.mu.Unlock()
}

// tokenResponse is the subset of the OAuth2 token response we consume.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"scope"`
}

// fetch performs the OAuth2 client_credentials grant.
//
// # Credencial no CORPO, não em Basic
//
// Até 21/09/2026 isto mandava a credencial no cabeçalho `Authorization: Basic`. O
// contrato publicado (docs/compliance/c6-auth-oas.yaml) não menciona Basic em lugar
// nenhum: `client_id`, `client_secret` e `grant_type` são REQUIRED no corpo
// `application/x-www-form-urlencoded`. Basic funcionava por tolerância do servidor, não
// por contrato, e o que não está no contrato pode sumir sem aviso.
//
// O segredo continua fora de URL e fora de log — o corpo de um POST não é nenhum dos
// dois. O que ele não tem é o descarte automático que um Authorization header ganha de
// ferramentas que redigem cabeçalhos; por isso nenhuma parte deste corpo é impressa,
// nem em erro.
//
// # Por que há retentativa aqui, e só aqui
//
// O endpoint de token do sandbox devolve 500 de forma INTERMITENTE. Medido em
// 21/09/2026, dezesseis tentativas alternando as duas formas de apresentar a
// credencial: 3/8 de sucesso com a credencial no corpo, 3/8 com Basic. Não é a forma —
// é o endpoint.
//
// Um 500 no token não falha uma chamada, falha TODAS: sem bearer não há cobrança, não
// há leitura, não há conciliação. E repetir é seguro de um jeito que quase nada mais
// aqui é: o FAQ do C6 (§9) diz que gerar um token novo NÃO invalida o atual, então uma
// retentativa não pode derrubar quem já está usando um. Por isso o limite é pequeno e o
// espaçamento cresce: o objetivo é atravessar um soluço, não martelar um banco caído.
//
// On any non-2xx the body is read solely to extract the safe machine code (via
// mapError); its raw contents are never surfaced.
func (m *tokenManager) fetch(ctx context.Context, cred ports.BankCredential) (cachedToken, error) {
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {cred.ClientID},
		"client_secret": {cred.Secret},
	}
	if m.scope != "" {
		form.Set("scope", m.scope)
	}

	encoded := form.Encode()
	var ultimo error
	for tentativa := 0; ; tentativa++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.tokenURL, strings.NewReader(encoded))
		if err != nil {
			return cachedToken{}, transportError("token")
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "application/json")

		resp, err := m.httpc.Do(req)
		if err != nil {
			// Uma falha de transporte NÃO é repetida: manter a postura de tiro único
			// do adapter. O que se repete aqui é só o 5xx observado do endpoint.
			return cachedToken{}, transportError("token")
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
		status := resp.StatusCode
		_ = resp.Body.Close()

		if status/100 == 2 {
			var tr tokenResponse
			if err := json.Unmarshal(body, &tr); err != nil || tr.AccessToken == "" {
				// A 2xx without a usable token is an upstream contract violation.
				return cachedToken{}, &Error{Op: "token", StatusCode: status, sentinel: shared.ErrUnavailable}
			}
			ttl := time.Duration(tr.ExpiresIn) * time.Second
			if ttl <= 0 {
				ttl = fallbackTokenTTL
			}
			return cachedToken{accessToken: tr.AccessToken, expiresAt: m.now().Add(ttl), scope: tr.Scope}, nil
		}

		ultimo = mapError("token", status, body)
		// Só 5xx. Um 400/401 é resposta sobre a CREDENCIAL, e repeti-la não a conserta
		// — só transforma um erro de configuração em tráfego.
		if status/100 != 5 || tentativa >= tokenMaxRetries {
			return cachedToken{}, ultimo
		}
		if err := m.sleep(ctx, tokenRetryBackoff(tentativa)); err != nil {
			return cachedToken{}, ultimo
		}
	}
}

// tokenMaxRetries bounds the retries on a 5xx from the token endpoint. Three extra
// attempts turn the ~40% success rate measured on the sandbox into ~95%, and still stop
// well short of hammering an endpoint that is genuinely down.
const tokenMaxRetries = 3

// tokenRetryBackoff spaces the retries: 250ms, 500ms, 1s.
func tokenRetryBackoff(tentativa int) time.Duration {
	return 250 * time.Millisecond << tentativa
}

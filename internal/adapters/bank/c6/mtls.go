package c6

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

// CertProvider loads a ready-to-handshake mTLS client certificate for a
// (tenantID, bankID) from the durable certificate vault (SIN-69368). It is the
// consumer-side view (Hexagonal, accept-the-interface-you-need) of the vault's
// LoadTLSCertificate method: the private key is re-assembled inside the adapter and
// handed back only inside the opaque *tls.Certificate — it never crosses this
// boundary as raw PEM, preserving the vault's write-only-key posture. A missing
// (tenantID, bankID) pair returns shared.ErrNotFound, and the transport then presents
// NO certificate for that tenant — never another identity's. Both secret.CertStore
// and sqlite.CertificateVault satisfy it.
type CertProvider interface {
	LoadTLSCertificate(ctx context.Context, tenantID, bankID string) (*tls.Certificate, error)
}

// tenantContextKey carries the resolved tenantID down to the mTLS RoundTripper so it
// can select the tenant's client certificate at handshake time. It is unexported and
// typed so no other package can read or forge it.
type tenantContextKey struct{}

// withTenant stamps tenantID onto ctx for the mTLS transport. Every outbound C6
// request that knows its tenant stamps it (authedJSONRequest, the direct PIX
// builders, the token fetch and the signed recurrence reads) so the per-tenant
// transport can present that tenant's client certificate.
func withTenant(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, tenantContextKey{}, tenantID)
}

// tenantFromContext returns the stamped tenantID, or "" when the request carries
// none (in which case the mTLS transport uses the bootstrap certificate).
func tenantFromContext(ctx context.Context) string {
	t, _ := ctx.Value(tenantContextKey{}).(string)
	return t
}

// MTLSHTTPClient builds an *http.Client whose transport is identical to the
// adapter's default (TLS >= 1.2, redirects disabled as an anti-SSRF guard, a
// bounded idle-connection pool, and a per-request timeout — see defaultHTTPClient)
// but that additionally presents a client certificate so the connection can
// satisfy C6's mutual-TLS requirement. C6 demands an mTLS client certificate on
// the transport in addition to the OAuth2 bearer; this is the wiring for that
// certificate, kept in the adapter so the domain never imports crypto/tls
// (Hexagonal).
//
// The certificate and its private key are loaded from PEM files at certPath /
// keyPath. The key is a SECRET and lives only in that file — never in code, an
// env value, or a URL (threat C1); only the path is configuration. A load failure
// is returned, not swallowed, so the process fails closed at boot (an explicit
// startup error) rather than silently connecting without the client cert.
func MTLSHTTPClient(certPath, keyPath string, timeout time.Duration) (*http.Client, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		// tls.LoadX509KeyPair wraps the os path error; it does not include private
		// key material in its message, so this is safe to surface and log.
		return nil, fmt.Errorf("c6: load mTLS client certificate: %w", err)
	}
	c := defaultHTTPClient(timeout)
	// defaultHTTPClient always installs an *http.Transport with a non-nil
	// TLSClientConfig (MinVersion TLS 1.2); reuse it and graft the client cert so
	// the TLS-floor and transport hardening stay in exactly one place.
	tr := c.Transport.(*http.Transport)
	tr.TLSClientConfig.Certificates = []tls.Certificate{cert}
	return c, nil
}

// NewVaultMTLSClient builds the live C6 *http.Client whose transport sources the
// mTLS client certificate from the DURABLE vault (SIN-69368) instead of a single
// process-wide cert loaded from a path. The certificate is selected PER REQUEST,
// keyed by the request's tenant (stamped via withTenant), so a self-serve cert that
// lands in the vault actually feeds the live handshake — durability now equals
// consumption.
//
// Isolation (acceptance: "isolamento tenant preservado"): Go's connection pool is
// keyed by host, NOT by client certificate, so a single shared transport with a
// tenant-selecting GetClientCertificate would leak tenant A's authenticated
// connection to tenant B on reuse. To prevent that, each tenant gets its OWN
// *http.Transport (its own connection pool) whose GetClientCertificate is bound to
// that tenant; connections are therefore never shared across tenants. The number of
// transports is bounded by the number of tenants that actually transact with C6.
//
// Bootstrap (fallbackCertPath/fallbackKeyPath): the certificate loaded from the §8
// path serves ONLY requests that carry no tenant at all. A load failure of those paths
// fails the boot closed (explicit error), exactly as MTLSHTTPClient does. A tenant
// WITHOUT a vault row never reaches it: it presents no client certificate and C6
// rejects the handshake. See clientCertFor for why that is the only safe outcome.
//
// Rotation: GetClientCertificate re-reads the vault on each new handshake, so a
// rotated certificate (self-serve PUT) is picked up on the next new connection
// without a restart; the per-tenant pool means the old connection is never reused
// under the new identity.
func NewVaultMTLSClient(provider CertProvider, bankID, fallbackCertPath, fallbackKeyPath string, timeout time.Duration) (*http.Client, error) {
	if provider == nil {
		return nil, fmt.Errorf("c6: certificate provider is required for the vault mTLS transport")
	}
	var fallback *tls.Certificate
	if fallbackCertPath != "" || fallbackKeyPath != "" {
		cert, err := tls.LoadX509KeyPair(fallbackCertPath, fallbackKeyPath)
		if err != nil {
			return nil, fmt.Errorf("c6: load bootstrap mTLS client certificate: %w", err)
		}
		fallback = &cert
	}
	// Reuse defaultHTTPClient for the Timeout and the anti-SSRF CheckRedirect, then
	// swap its transport for the per-tenant cert-selecting RoundTripper. The base
	// *http.Transport it built is the hardened template each per-tenant transport is
	// cloned from (TLS >= 1.2, bounded idle pool).
	c := defaultHTTPClient(timeout)
	base := c.Transport.(*http.Transport)
	c.Transport = &mtlsRoundTripper{
		provider:  provider,
		bankID:    bankID,
		fallback:  fallback,
		base:      base,
		perTenant: make(map[string]*http.Transport),
	}
	return c, nil
}

// mtlsRoundTripper dispatches each request to a per-tenant *http.Transport whose TLS
// config presents that tenant's vault certificate. It is the universal execution
// choke point for the C6 client, so every request kind (authed JSON, PIX, token,
// recurrence) flows through the same per-tenant selection.
type mtlsRoundTripper struct {
	provider CertProvider
	bankID   string
	fallback *tls.Certificate
	base     *http.Transport // hardened template; cloned per tenant, never dialed directly

	mu        sync.Mutex
	perTenant map[string]*http.Transport
}

// RoundTrip selects the tenant transport (creating it on first use) and delegates.
func (m *mtlsRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.transportFor(tenantFromContext(req.Context())).RoundTrip(req)
}

// transportFor returns the cached per-tenant transport, building it on first use with
// a GetClientCertificate bound to tenantID. The empty-tenant slot ("") carries the
// bootstrap certificate and serves any request that did not stamp a tenant.
func (m *mtlsRoundTripper) transportFor(tenantID string) *http.Transport {
	m.mu.Lock()
	defer m.mu.Unlock()
	if tr, ok := m.perTenant[tenantID]; ok {
		return tr
	}
	tr := m.base.Clone()
	if tr.TLSClientConfig == nil {
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	tr.TLSClientConfig.GetClientCertificate = m.clientCertFor(tenantID)
	m.perTenant[tenantID] = tr
	return tr
}

// dropTenant discards tenantID's transport and closes the connections it pooled, so
// the tenant's NEXT request dials fresh and re-reads the vault. The certificate write
// paths call it through InvalidateToken.
//
// Sem isso, gravar um certificado não chega ao fio. O pool do Go reaproveita uma
// conexão já estabelecida sem repetir GetClientCertificate, e a varredura de webhook,
// de 60 em 60 segundos, mantém essa conexão abaixo do tempo ocioso de 90 — ela nunca
// expira sozinha. O comentário de rotação acima só é verdade porque este método
// existe: "pega na próxima conexão nova" não vale nada se conexão nova nunca houver.
//
// Seguro para um tenant desconhecido (nada a fazer) e para chamada concorrente com
// uma requisição em voo: a requisição em voo termina no transporte antigo, e como ele
// saiu do mapa nenhuma outra o alcança.
func (m *mtlsRoundTripper) dropTenant(tenantID string) {
	m.mu.Lock()
	tr, ok := m.perTenant[tenantID]
	delete(m.perTenant, tenantID)
	m.mu.Unlock()
	if ok {
		tr.CloseIdleConnections()
	}
}

// clientCertFor returns the handshake callback for tenantID: the vault certificate
// when a row exists, and NOTHING otherwise. A vault error OTHER than ErrNotFound
// (e.g. a wrong KEK) fails the handshake closed rather than silently degrading.
//
// UM TENANT NUNCA CAI NO CERTIFICADO DE BOOTSTRAP. Ele é a identidade de outra
// empresa, e apresentá-lo enquanto se age por um tenant é confusão de identidade — o
// PSP autenticaria o comerciante errado.
//
// Isso também causou uma interrupção real (SIN-69368). Um tenant configurado em
// tempo de execução tem a credencial gravada primeiro e o certificado segundos
// depois. Nessa janela a varredura de webhook, que roda a cada 60 segundos, já
// enumera o tenant: ela abriu conexão sob a identidade de bootstrap, e a conexão foi
// para o pool. O certificado chegar depois não mudou nada — conexão no pool não
// refaz handshake, e a própria cadência de 60 segundos da varredura a manteve abaixo
// do tempo ocioso de 90, então ela também nunca expirou. Toda requisição daquele
// tenant falhou com 500 não mapeado, por mais de uma hora, até um reinício limpar o
// pool.
//
// Falhar o handshake fechado torna essa janela inofensiva: nenhuma conexão é
// estabelecida, nenhuma vai para o pool, e a primeira requisição depois de o
// certificado chegar negocia limpo, com a identidade certa.
func (m *mtlsRoundTripper) clientCertFor(tenantID string) func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		if tenantID != "" {
			cert, err := m.provider.LoadTLSCertificate(context.Background(), tenantID, m.bankID)
			switch {
			case err == nil:
				return cert, nil
			case errors.Is(err, shared.ErrNotFound):
				// Sem certificado para este tenant: NÃO apresenta nenhum. O C6 recusa o
				// handshake, que é o desfecho certo — melhor falhar agora do que se
				// autenticar como outra empresa.
				return &tls.Certificate{}, nil
			default:
				return nil, err
			}
		}
		if m.fallback != nil {
			return m.fallback, nil
		}
		// No certificate configured anywhere: present none. C6 (which requires a
		// verified client cert) then rejects the handshake — fail closed, matching the
		// prior "both paths empty ⇒ no client cert" behaviour.
		return &tls.Certificate{}, nil
	}
}

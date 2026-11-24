package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/nfse"
	"github.com/ia-dev-sindireceita/payment/internal/nfse/a1import"
	"github.com/ia-dev-sindireceita/payment/internal/nfse/adn"
	"github.com/ia-dev-sindireceita/payment/internal/nfse/custody"
	"github.com/ia-dev-sindireceita/payment/internal/platform/config"
	"github.com/ia-dev-sindireceita/payment/internal/platform/persistence"
)

// defaultNFSeKeyPrefix names the payment service's Vault transit keys
// ("payment-a1.{tenant}_{cnpj}.{serial}"), disjoint from go-mei-das's "a1.*",
// so each service's AppRole policy can be scoped to its own keys.
const defaultNFSeKeyPrefix = "payment-a1"

// defaultNFSeMount is the payment's own Transit mount. The signer policy
// grants keys/+ on its mount, so sharing go-mei-das's "transit" would let
// either service delete the other's keys.
const defaultNFSeMount = "payment-transit"

// nfseDepsFromConfig builds the NFS-e custody and ADN transport. It returns
// (nil, nil) when the feature is off; a half-configured feature fails the
// boot closed instead of answering 503 forever.
func nfseDepsFromConfig(c config.NFSeConfig, db *persistence.DB) (*app.NFSeDeps, error) {
	if !c.Enabled {
		return nil, nil
	}
	if err := validateVaultAddr(c.VaultAddr, c.VaultAllowInsecure); err != nil {
		return nil, err
	}
	if c.VaultRoleID == "" || c.VaultSecretID == "" {
		return nil, fmt.Errorf("PAYMENT_NFSE_ENABLED requires PAYMENT_NFSE_VAULT_ROLE_ID and PAYMENT_NFSE_VAULT_SECRET_ID")
	}
	if err := requireHTTPS("PAYMENT_NFSE_ADN_URL", c.ADNURL, false); err != nil {
		return nil, err
	}
	if c.DANFSeURL != "" {
		if err := requireHTTPS("PAYMENT_NFSE_DANFSE_URL", c.DANFSeURL, false); err != nil {
			return nil, err
		}
	}
	vaultHTTP, err := vaultHTTPClient(c.VaultCAFile)
	if err != nil {
		return nil, err
	}
	tokens, err := custody.AppRoleTokenSource(custody.AppRoleConfig{
		Address:    c.VaultAddr,
		RoleID:     c.VaultRoleID,
		SecretID:   c.VaultSecretID,
		HTTPClient: vaultHTTP,
	})
	if err != nil {
		return nil, fmt.Errorf("nfse vault approle: %w", err)
	}
	prefix := c.VaultKeyPrefix
	if prefix == "" {
		prefix = defaultNFSeKeyPrefix
	}
	mount := c.VaultMount
	if mount == "" {
		mount = defaultNFSeMount
	}
	certs := db.NFSeCertStore()
	signer, err := custody.NewVaultTransitSigner(custody.VaultTransitConfig{
		Address:     c.VaultAddr,
		TokenSource: tokens,
		KeyPrefix:   prefix,
		Mount:       mount,
		Certs:       certs,
		HTTPClient:  vaultHTTP,
	})
	if err != nil {
		return nil, fmt.Errorf("nfse vault transit signer: %w", err)
	}
	env := nfse.EnvHomologacao
	if c.Producao {
		env = nfse.EnvProducao
	}
	var opts []adn.Option
	if c.DANFSeURL != "" {
		opts = append(opts, adn.WithDANFSeURL(c.DANFSeURL))
	}
	log.Printf("api: NFS-e enabled (tpAmb=%d, adn=%s, danfse=%t)", int(env), c.ADNURL, c.DANFSeURL != "")
	return &app.NFSeDeps{
		Store:       db.NFSeStore(),
		Certs:       certs,
		Signer:      signer,
		ADN:         adn.NewClient(c.ADNURL, signer, opts...),
		Importer:    a1import.New(signer, certs),
		Environment: env,
	}, nil
}

// vaultHTTPClient trusts the system roots plus, when caFile is set, the PEM
// certificates in it (the lmhost Vault's self-signed CA). A set but unreadable
// or empty file fails the boot.
func vaultHTTPClient(caFile string) (*http.Client, error) {
	if caFile == "" {
		return &http.Client{Timeout: 10 * time.Second}, nil
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("PAYMENT_NFSE_VAULT_CA_FILE: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("PAYMENT_NFSE_VAULT_CA_FILE has no PEM certificate")
	}
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}},
	}, nil
}

// validateVaultAddr fails closed on a plaintext Vault: it carries the AppRole
// secret_id and client tokens.
func validateVaultAddr(addr string, allowInsecure bool) error {
	return requireHTTPS("PAYMENT_NFSE_VAULT_ADDR", addr, allowInsecure)
}

func requireHTTPS(name, raw string, allowInsecure bool) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("PAYMENT_NFSE_ENABLED requires %s", name)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%s is not a valid URL", name)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if allowInsecure {
			log.Printf("WARNING: %s uses plaintext http:// — local development ONLY", name)
			return nil
		}
	}
	return fmt.Errorf("%s must use https:// (got scheme %q)", name, u.Scheme)
}

package main

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/platform/config"
)

func TestNFSeDepsDisabled(t *testing.T) {
	d, err := nfseDepsFromConfig(config.NFSeConfig{}, nil)
	if d != nil || err != nil {
		t.Fatalf("disabled: deps=%v err=%v", d, err)
	}
}

func TestNFSeDepsFailsClosedOnBadConfig(t *testing.T) {
	ok := config.NFSeConfig{
		Enabled: true, VaultAddr: "https://vault.example", VaultRoleID: "r", VaultSecretID: "s",
		ADNURL: "https://sefin.example/SefinNacional",
	}
	cases := []struct {
		name string
		mut  func(*config.NFSeConfig)
		want string
	}{
		{"no vault", func(c *config.NFSeConfig) { c.VaultAddr = "" }, "PAYMENT_NFSE_VAULT_ADDR"},
		{"plaintext vault", func(c *config.NFSeConfig) { c.VaultAddr = "http://vault.example" }, "https://"},
		{"no approle", func(c *config.NFSeConfig) { c.VaultSecretID = "" }, "ROLE_ID"},
		{"no adn", func(c *config.NFSeConfig) { c.ADNURL = "" }, "PAYMENT_NFSE_ADN_URL"},
		{"plaintext adn", func(c *config.NFSeConfig) { c.ADNURL = "http://sefin.example" }, "PAYMENT_NFSE_ADN_URL"},
		{"plaintext danfse", func(c *config.NFSeConfig) { c.DANFSeURL = "http://adn.example" }, "PAYMENT_NFSE_DANFSE_URL"},
		{"bad url", func(c *config.NFSeConfig) { c.ADNURL = "::" }, "not a valid URL"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := ok
			tc.mut(&c)
			_, err := nfseDepsFromConfig(c, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want mention of %q", err, tc.want)
			}
		})
	}
}

func TestRequireHTTPSAllowInsecure(t *testing.T) {
	if err := requireHTTPS("X", "http://localhost:8200", true); err != nil {
		t.Fatalf("allow insecure: %v", err)
	}
}

func TestVaultHTTPClientCA(t *testing.T) {
	if c, err := vaultHTTPClient(""); err != nil || c.Transport != nil {
		t.Fatalf("no CA: %v %v", c, err)
	}
	if _, err := vaultHTTPClient(t.TempDir() + "/missing.pem"); err == nil {
		t.Fatal("missing CA file accepted")
	}
	empty := t.TempDir() + "/empty.pem"
	if err := os.WriteFile(empty, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := vaultHTTPClient(empty); err == nil {
		t.Fatal("CA file without PEM accepted")
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer srv.Close()
	ca := t.TempDir() + "/ca.pem"
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(ca, block, 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := vaultHTTPClient(ca)
	if err != nil {
		t.Fatalf("CA: %v", err)
	}
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatalf("self-signed server not trusted: %v", err)
	}
	_ = resp.Body.Close()
}

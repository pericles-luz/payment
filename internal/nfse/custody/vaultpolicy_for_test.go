package custody

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFiscalSignerVaultPolicyFor(t *testing.T) {
	p := FiscalSignerVaultPolicyFor("payment-transit", "payment-a1")
	for _, want := range []string{
		`path "payment-transit/sign/payment-a1.*"`,
		`path "payment-transit/keys/+"`,
		`path "payment-transit/keys/+/config"`,
		`path "payment-transit/keys/+/import"`,
		`path "payment-transit/wrapping_key"`,
	} {
		if !strings.Contains(p, want) {
			t.Errorf("policy lacks %s:\n%s", want, p)
		}
	}
	if strings.Contains(p, `"transit/`) || strings.Contains(p, "export") && strings.Contains(p, `path "payment-transit/export`) {
		t.Errorf("policy reaches the shared mount or export:\n%s", p)
	}
}

func TestVaultTransitSignerRejectsBadMount(t *testing.T) {
	_, err := NewVaultTransitSigner(VaultTransitConfig{Address: "https://v", Certs: NewMemoryCertStore(), Mount: "bad mount"})
	if err == nil {
		t.Fatal("bad mount accepted")
	}
}

// TestVaultTransitSignerUsesMount proves every call goes to the configured
// mount: a server that only answers under /v1/payment-transit/ (and forwards
// to the faithful transit stub) must see the sign and the key preflight.
func TestVaultTransitSignerUsesMount(t *testing.T) {
	now := time.Now()
	key, leaf := newVaultTestLeaf(t, "co-1", "11222333000181", time.Hour, now)
	serial := SerialHex(leaf)
	stub := newTransitStub(t)
	stub.addKey("payment-a1"+keySegmentDelimiter+"co-1"+keySegmentDelimiter+serial, key, false)
	var paths []string
	var mu sync.Mutex
	mounted := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		const p = "/v1/payment-transit/"
		if !strings.HasPrefix(r.URL.Path, p) {
			http.Error(w, "wrong mount", http.StatusNotFound)
			return
		}
		r.URL.Path = "/v1/transit/" + strings.TrimPrefix(r.URL.Path, p)
		stub.handle(w, r)
	}))
	t.Cleanup(mounted.Close)
	store := NewMemoryCertStore()
	if err := store.PutA1(context.Background(), "co-1", []*x509.Certificate{leaf}, A1MetaFromLeaf(leaf, "11222333000181")); err != nil {
		t.Fatalf("putA1: %v", err)
	}
	v, err := NewVaultTransitSigner(VaultTransitConfig{
		Address: mounted.URL, Certs: store, Token: "t", Mount: "/payment-transit/", KeyPrefix: "payment-a1",
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	digest := sha256.Sum256([]byte("DPS"))
	if _, err := v.SignDigest(context.Background(), "co-1", serial, digest[:]); err != nil {
		t.Fatalf("sign: %v (paths %v)", err, paths)
	}
	for _, p := range paths {
		if !strings.HasPrefix(p, "/v1/payment-transit/") {
			t.Errorf("request outside the mount: %s", p)
		}
	}
	if len(paths) == 0 {
		t.Fatal("no request reached the mount")
	}
}

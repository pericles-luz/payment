package custody

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// shredStub models the Vault Transit key lifecycle that CryptoShred exercises,
// faithfully reproducing the ONE behaviour that makes the two-step delete
// mandatory: a key is created with deletion_allowed=false (the Transit default),
// so DELETE transit/keys/{name} is rejected with HTTP 400 "deletion is not
// allowed for this key" and the key stays present and able to sign until
// POST .../config deletion_allowed=true runs. This is a legitimate boundary
// stub over real HTTP — NOT a mock of storage — mirroring transitStub's posture.
type shredStub struct {
	*httptest.Server
	mu          sync.Mutex
	keys        map[string]*rsa.PrivateKey
	allowDelete map[string]bool
	configCalls int
	deleteCalls int
	order       []string // ops in arrival order, to assert config precedes delete
}

func newShredStub(t *testing.T) *shredStub {
	t.Helper()
	s := &shredStub{
		keys:        make(map[string]*rsa.PrivateKey),
		allowDelete: make(map[string]bool),
	}
	s.Server = httptest.NewServer(http.HandlerFunc(s.handle))
	t.Cleanup(s.Close)
	return s
}

func (s *shredStub) addKey(name string, key *rsa.PrivateKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[name] = key
}

func (s *shredStub) exists(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.keys[name]
	return ok
}

func (s *shredStub) handle(w http.ResponseWriter, r *http.Request) {
	const prefix = "/v1/transit/keys/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		// sign path — only needed so the adapter can prove "sign OK" pre-shred.
		if strings.HasPrefix(r.URL.Path, "/v1/transit/sign/") {
			name := strings.TrimPrefix(r.URL.Path, "/v1/transit/sign/")
			if !genericNameRe.MatchString(name) {
				unsupportedPath(w)
				return
			}
			s.handleSign(w, r, name)
			return
		}
		http.Error(w, "unsupported", http.StatusNotFound)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, prefix)
	// Validate the {name} token (minus the optional /config sub-path) against the
	// same GenericNameRegex real Vault binds, so a "/"-bearing key name 404s here
	// too — the fake stays faithful (SIN-67698).
	isConfig := r.Method == http.MethodPost && strings.HasSuffix(name, "/config")
	keyToken := strings.TrimSuffix(name, "/config")
	if !genericNameRe.MatchString(keyToken) {
		unsupportedPath(w)
		return
	}
	switch {
	case isConfig:
		s.handleConfig(w, r, keyToken)
	case r.Method == http.MethodDelete:
		s.handleDelete(w, name)
	case r.Method == http.MethodGet:
		s.handleRead(w, name)
	default:
		http.Error(w, "unsupported", http.StatusNotFound)
	}
}

func (s *shredStub) handleConfig(w http.ResponseWriter, r *http.Request, name string) {
	var req transitKeyConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.configCalls++
	s.order = append(s.order, "config")
	_, known := s.keys[name]
	if known {
		s.allowDelete[name] = req.DeletionAllowed
	}
	s.mu.Unlock()
	if !known {
		http.Error(w, `{"errors":["no such key"]}`, http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *shredStub) handleDelete(w http.ResponseWriter, name string) {
	s.mu.Lock()
	s.deleteCalls++
	s.order = append(s.order, "delete")
	_, known := s.keys[name]
	allowed := s.allowDelete[name]
	if known && allowed {
		delete(s.keys, name)
	}
	s.mu.Unlock()
	switch {
	case !known:
		http.Error(w, `{"errors":["no such key"]}`, http.StatusNotFound)
	case !allowed:
		// Transit fail-closed default: reject the delete, key survives.
		http.Error(w, `{"errors":["deletion is not allowed for this key"]}`, http.StatusBadRequest)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *shredStub) handleRead(w http.ResponseWriter, name string) {
	s.mu.Lock()
	_, known := s.keys[name]
	s.mu.Unlock()
	if !known {
		http.Error(w, `{"errors":["no such key"]}`, http.StatusNotFound)
		return
	}
	writeJSON(w, transitKeyResponse{Data: struct {
		Exportable           bool `json:"exportable"`
		AllowPlaintextBackup bool `json:"allow_plaintext_backup"`
	}{}})
}

func (s *shredStub) handleSign(w http.ResponseWriter, r *http.Request, name string) {
	s.mu.Lock()
	key := s.keys[name]
	s.mu.Unlock()
	if key == nil {
		http.Error(w, `{"errors":["no such key"]}`, http.StatusNotFound)
		return
	}
	var req transitSignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	digest, err := base64.StdEncoding.DecodeString(req.Input)
	if err != nil {
		http.Error(w, "bad input", http.StatusBadRequest)
		return
	}
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
	if err != nil {
		http.Error(w, "sign failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, transitSignResponse{Data: struct {
		Signature string `json:"signature"`
	}{Signature: "vault:v1:" + base64.StdEncoding.EncodeToString(sig)}})
}

// buildShredAdapter wires a VaultTransitSigner over a shredStub with one tenant
// provisioned (cert on file + Transit key present, deletion_allowed=false).
func buildShredAdapter(t *testing.T) (*VaultTransitSigner, *shredStub, string, string) {
	t.Helper()
	const companyID, cnpj = "co-shred", "11222333000181"
	key, leaf := newVaultTestLeaf(t, companyID, cnpj, time.Hour, time.Now())
	serial := SerialHex(leaf)
	stub := newShredStub(t)
	stub.addKey(vaultKeyName(companyID, serial), key)
	store := NewMemoryCertStore()
	if err := store.PutA1(context.Background(), companyID, []*x509.Certificate{leaf}, A1MetaFromLeaf(leaf, cnpj)); err != nil {
		t.Fatalf("putA1: %v", err)
	}
	v, err := NewVaultTransitSigner(VaultTransitConfig{Address: stub.URL, Certs: store, Token: "t", SkipExportableCheck: true})
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return v, stub, companyID, serial
}

// TestVaultCryptoShred_TwoStepEraseIsIrreversible encodes AC #8 (SIN-67696):
// import → sign OK → crypto-shred (two-step + verify) → sign FAILS because the
// key is erased. It proves the erasure actually happened, not merely that a
// delete was issued, and that config precedes delete.
func TestVaultCryptoShred_TwoStepEraseIsIrreversible(t *testing.T) {
	ctx := context.Background()
	v, stub, companyID, serial := buildShredAdapter(t)
	digest := sha256.Sum256([]byte("dps-signedinfo"))

	// import → sign OK
	if _, err := v.SignDigest(ctx, companyID, serial, digest[:]); err != nil {
		t.Fatalf("sign before shred: got %v, want nil (key must sign pre-shred)", err)
	}

	// crypto-shred (two-step + verify)
	if err := v.CryptoShred(ctx, companyID, serial); err != nil {
		t.Fatalf("CryptoShred: got %v, want nil", err)
	}
	if stub.configCalls != 1 {
		t.Errorf("config calls = %d, want 1 (deletion_allowed=true must be set)", stub.configCalls)
	}
	if stub.deleteCalls != 1 {
		t.Errorf("delete calls = %d, want 1", stub.deleteCalls)
	}
	if len(stub.order) < 2 || stub.order[0] != "config" || stub.order[1] != "delete" {
		t.Errorf("op order = %v, want config before delete", stub.order)
	}

	// sign FAILS — the key is gone (irreversible erasure), fail-closed.
	if _, err := v.SignDigest(ctx, companyID, serial, digest[:]); err == nil {
		t.Fatalf("sign after shred: got nil error, want failure (key must be erased)")
	}
	if stub.exists(vaultKeyName(companyID, serial)) {
		t.Fatalf("key still present after shred — irreversibility not proven")
	}
}

// TestVaultCryptoShred_BareDeleteWouldFail is the negative control pinning the
// gap SIN-67696 closes: a DELETE without the deletion_allowed=true step is
// rejected (HTTP 400) and the key survives and keeps signing. This proves the
// old runbook's bare-DELETE recipe was NOT crypto-shred.
func TestVaultCryptoShred_BareDeleteWouldFail(t *testing.T) {
	ctx := context.Background()
	v, stub, companyID, serial := buildShredAdapter(t)
	name := vaultKeyName(companyID, serial)
	digest := sha256.Sum256([]byte("x"))

	// Issue a bare DELETE directly against the stub (skip step 1), as the old
	// runbook §8 instructed.
	res, err := http.NewRequest(http.MethodDelete, stub.URL+"/v1/transit/keys/"+name, nil)
	if err != nil {
		t.Fatalf("build delete: %v", err)
	}
	resp, err := http.DefaultClient.Do(res)
	if err != nil {
		t.Fatalf("bare delete: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bare delete status = %d, want 400 (deletion not allowed)", resp.StatusCode)
	}
	// Key survives and STILL signs — no erasure happened.
	if !stub.exists(name) {
		t.Fatalf("key gone after a rejected bare delete, want survived")
	}
	if _, err := v.SignDigest(ctx, companyID, serial, digest[:]); err != nil {
		t.Fatalf("sign after bare delete: got %v, want nil (key still live)", err)
	}
}

// TestVaultCryptoShred_VerifyDetectsSurvivingKey proves step 3 is load-bearing:
// if the delete is accepted but the key silently remains, CryptoShred returns
// ErrShredNotVerified instead of a false success.
func TestVaultCryptoShred_VerifyDetectsSurvivingKey(t *testing.T) {
	ctx := context.Background()
	// A stub that ACKs config + delete but never removes the key (Vault lie /
	// eventual-consistency hole).
	stubborn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			writeJSON(w, transitKeyResponse{}) // 200 → key still present
		default:
			w.WriteHeader(http.StatusNoContent) // config + delete "succeed"
		}
	}))
	defer stubborn.Close()
	store := NewMemoryCertStore()
	_, leaf := newVaultTestLeaf(t, "co-1", "11222333000181", time.Hour, time.Now())
	_ = store.PutA1(ctx, "co-1", []*x509.Certificate{leaf}, A1MetaFromLeaf(leaf, "11222333000181"))
	v, err := NewVaultTransitSigner(VaultTransitConfig{Address: stubborn.URL, Certs: store, Token: "t", SkipExportableCheck: true})
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	if err := v.CryptoShred(ctx, "co-1", SerialHex(leaf)); !errors.Is(err, ErrShredNotVerified) {
		t.Fatalf("CryptoShred with surviving key: got %v, want ErrShredNotVerified", err)
	}
}

// TestVaultCryptoShred_StaleSeriesObserverOnSuccess covers the SIN-67763 fix on
// the shred side: a verified erasure fires the stale-series observer once with
// (companyID, serial) so the deprovisioned serial's a1_cert_expiry_days child is
// dropped and NFSeA1CertExpired stops firing for a key that no longer exists.
func TestVaultCryptoShred_StaleSeriesObserverOnSuccess(t *testing.T) {
	ctx := context.Background()
	const companyID, cnpj = "co-shred", "11222333000181"
	key, leaf := newVaultTestLeaf(t, companyID, cnpj, time.Hour, time.Now())
	serial := SerialHex(leaf)
	stub := newShredStub(t)
	stub.addKey(vaultKeyName(companyID, serial), key)
	store := NewMemoryCertStore()
	if err := store.PutA1(ctx, companyID, []*x509.Certificate{leaf}, A1MetaFromLeaf(leaf, cnpj)); err != nil {
		t.Fatalf("putA1: %v", err)
	}
	type call struct{ company, serial string }
	var got []call
	v, err := NewVaultTransitSigner(VaultTransitConfig{
		Address: stub.URL, Certs: store, Token: "t", SkipExportableCheck: true,
		StaleSeriesObserver: func(company, serial string) { got = append(got, call{company, serial}) },
	})
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	if err := v.CryptoShred(ctx, companyID, serial); err != nil {
		t.Fatalf("CryptoShred: got %v, want nil", err)
	}
	if len(got) != 1 || got[0] != (call{companyID, serial}) {
		t.Fatalf("stale-series observer fired %v, want one call {%s, %s}", got, companyID, serial)
	}
}

// TestVaultCryptoShred_StaleSeriesObserverNotFiredWhenUnverified proves the
// observer is bound to the VERIFIED-success path only: when the key survives the
// delete (ErrShredNotVerified), the series is NOT dropped — the key is still live
// and its expiry must stay observable.
func TestVaultCryptoShred_StaleSeriesObserverNotFiredWhenUnverified(t *testing.T) {
	ctx := context.Background()
	// Stub that ACKs config + delete but never removes the key (Vault lie).
	stubborn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			writeJSON(w, transitKeyResponse{}) // 200 → key still present
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer stubborn.Close()
	store := NewMemoryCertStore()
	_, leaf := newVaultTestLeaf(t, "co-1", "11222333000181", time.Hour, time.Now())
	_ = store.PutA1(ctx, "co-1", []*x509.Certificate{leaf}, A1MetaFromLeaf(leaf, "11222333000181"))
	var fired int
	v, err := NewVaultTransitSigner(VaultTransitConfig{
		Address: stubborn.URL, Certs: store, Token: "t", SkipExportableCheck: true,
		StaleSeriesObserver: func(string, string) { fired++ },
	})
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	if err := v.CryptoShred(ctx, "co-1", SerialHex(leaf)); !errors.Is(err, ErrShredNotVerified) {
		t.Fatalf("CryptoShred with surviving key: got %v, want ErrShredNotVerified", err)
	}
	if fired != 0 {
		t.Fatalf("stale-series observer fired %d times on unverified shred, want 0", fired)
	}
}

func TestVaultCryptoShred_FailClosedInputs(t *testing.T) {
	ctx := context.Background()
	v, _, _, _ := buildShredAdapter(t)
	tests := []struct {
		name             string
		companyID, seria string
		want             error
	}{
		{"empty company", "", "AA", ErrEmptyCompanyID},
		{"empty serial", "co-1", "", ErrNotProvisioned},
		{"bad company chars", "co/../evil", "AA", ErrInvalidKeyChars},
		{"bad serial chars", "co-1", "a/b", ErrInvalidKeyChars},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := v.CryptoShred(ctx, tc.companyID, tc.seria); !errors.Is(err, tc.want) {
				t.Fatalf("CryptoShred(%q,%q) = %v, want %v", tc.companyID, tc.seria, err, tc.want)
			}
		})
	}
}

// TestVaultCryptoShred_ConfigErrorAborts covers the step-1 failure path (e.g.
// ACL denies the config write): the shred aborts before delete, fail-closed.
func TestVaultCryptoShred_ConfigErrorAborts(t *testing.T) {
	ctx := context.Background()
	var deleteCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deleteCalls++
		}
		http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
	}))
	defer srv.Close()
	store := NewMemoryCertStore()
	_, leaf := newVaultTestLeaf(t, "co-1", "11222333000181", time.Hour, time.Now())
	_ = store.PutA1(ctx, "co-1", []*x509.Certificate{leaf}, A1MetaFromLeaf(leaf, "11222333000181"))
	v, _ := NewVaultTransitSigner(VaultTransitConfig{Address: srv.URL, Certs: store, Token: "t", SkipExportableCheck: true})
	if err := v.CryptoShred(ctx, "co-1", SerialHex(leaf)); !errors.Is(err, ErrVaultTransport) {
		t.Fatalf("config error: got %v, want ErrVaultTransport", err)
	}
	if deleteCalls != 0 {
		t.Errorf("delete called %d times after config failed, want 0", deleteCalls)
	}
}

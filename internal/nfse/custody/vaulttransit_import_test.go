package custody

import (
	"context"
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// importStub is a Transit stub for the BYOK import path. It owns a real RSA
// wrapping key, so it can unwrap exactly what ImportA1Key sends (RSA-OAEP, then
// AES-KWP) and store the recovered private key — proving the wire format, not
// just that some bytes were posted.
type importStub struct {
	*httptest.Server
	t           *testing.T
	wrapping    *rsa.PrivateKey
	mu          sync.Mutex
	keys        map[string]*rsa.PrivateKey
	exportable  map[string]bool
	importCalls int
	lastImport  transitImportRequest
}

func newImportStub(t *testing.T) *importStub {
	t.Helper()
	wk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s := &importStub{t: t, wrapping: wk, keys: map[string]*rsa.PrivateKey{}, exportable: map[string]bool{}}
	s.Server = httptest.NewServer(http.HandlerFunc(s.handle))
	t.Cleanup(s.Close)
	return s
}

func (s *importStub) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	switch {
	case path == "transit/wrapping_key" && r.Method == http.MethodGet:
		der, _ := x509.MarshalPKIXPublicKey(&s.wrapping.PublicKey)
		writeJSON(w, map[string]any{"data": map[string]any{
			"public_key": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
		}})
	case strings.HasSuffix(path, "/import") && r.Method == http.MethodPost:
		name := strings.TrimSuffix(strings.TrimPrefix(path, "transit/keys/"), "/import")
		var req transitImportRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		s.importCalls++
		s.lastImport = req
		key, err := s.unwrap(req.Ciphertext)
		if err != nil {
			s.t.Errorf("stub could not unwrap import ciphertext: %v", err)
			http.Error(w, "bad ciphertext", http.StatusBadRequest)
			return
		}
		s.keys[name] = key
		s.exportable[name] = req.Exportable
		w.WriteHeader(http.StatusNoContent)
	case strings.HasPrefix(path, "transit/keys/") && r.Method == http.MethodGet:
		name := strings.TrimPrefix(path, "transit/keys/")
		key, ok := s.keys[name]
		if !ok {
			http.Error(w, `{"errors":["no such key"]}`, http.StatusNotFound)
			return
		}
		der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
		writeJSON(w, map[string]any{"data": map[string]any{
			"exportable":             s.exportable[name],
			"allow_plaintext_backup": false,
			"keys": map[string]any{"1": map[string]any{
				"public_key": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
			}},
		}})
	default:
		unsupportedPath(w)
	}
}

func (s *importStub) unwrap(ciphertext string) (*rsa.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}
	n := s.wrapping.Size()
	if len(raw) <= n {
		return nil, errors.New("ciphertext too short")
	}
	aesKey, err := rsa.DecryptOAEP(sha256.New(), nil, s.wrapping, raw[:n], nil)
	if err != nil {
		return nil, err
	}
	der, err := kwpUnwrapForTest(aesKey, raw[n:])
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not rsa")
	}
	return rk, nil
}

// kwpUnwrapForTest is the RFC 5649 inverse of kwpWrap (multi-semiblock case),
// used only by the stub to recover what the client wrapped.
func kwpUnwrapForTest(kek, c []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	if len(c)%8 != 0 || len(c) < 24 {
		return nil, errors.New("bad length")
	}
	n := len(c)/8 - 1
	var a [8]byte
	copy(a[:], c[:8])
	r := make([]byte, len(c)-8)
	copy(r, c[8:])
	var b [16]byte
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			t := uint64(n*j + i)
			binary.BigEndian.PutUint64(b[:8], binary.BigEndian.Uint64(a[:])^t)
			copy(b[8:], r[(i-1)*8:i*8])
			block.Decrypt(b[:], b[:])
			copy(a[:], b[:8])
			copy(r[(i-1)*8:i*8], b[8:])
		}
	}
	if binary.BigEndian.Uint32(a[:4]) != 0xA65959A6 {
		return nil, errors.New("integrity check failed")
	}
	mli := int(binary.BigEndian.Uint32(a[4:]))
	if mli > len(r) || mli <= len(r)-8 {
		return nil, errors.New("bad message length")
	}
	return r[:mli], nil
}

func newImportSigner(t *testing.T, stub *importStub) *VaultTransitSigner {
	t.Helper()
	v, err := NewVaultTransitSigner(VaultTransitConfig{Address: stub.URL, Certs: NewMemoryCertStore(), Token: "t"})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestImportA1KeyRoundTrip(t *testing.T) {
	stub := newImportStub(t)
	v := newImportSigner(t, stub)
	key, leaf := newVaultTestLeaf(t, "tenant_47064135000184", "47064135000184", time.Hour, time.Now())

	if err := v.ImportA1Key(context.Background(), "tenant_47064135000184", leaf, key); err != nil {
		t.Fatalf("ImportA1Key: %v", err)
	}
	name := v.keyName("tenant_47064135000184", SerialHex(leaf))
	got, ok := stub.keys[name]
	if !ok {
		t.Fatalf("key not imported under %q (have %v)", name, stub.keys)
	}
	if !got.Equal(key) {
		t.Error("Vault received a different private key than the one imported")
	}
	if stub.lastImport.Exportable || stub.lastImport.AllowPlaintextBackup {
		t.Errorf("import must be non-exportable: %+v", stub.lastImport)
	}
	if stub.lastImport.Type != "rsa-2048" || stub.lastImport.HashFunction != "SHA256" {
		t.Errorf("import type/hash = %q/%q", stub.lastImport.Type, stub.lastImport.HashFunction)
	}
}

func TestImportA1KeyIdempotentAndConflict(t *testing.T) {
	stub := newImportStub(t)
	v := newImportSigner(t, stub)
	ctx := context.Background()
	key, leaf := newVaultTestLeaf(t, "co", "47064135000184", time.Hour, time.Now())
	if err := v.ImportA1Key(ctx, "co", leaf, key); err != nil {
		t.Fatal(err)
	}
	// Same key again: no second import call, still success.
	if err := v.ImportA1Key(ctx, "co", leaf, key); err != nil {
		t.Fatalf("re-import same key: %v", err)
	}
	if stub.importCalls != 1 {
		t.Errorf("import calls = %d, want 1", stub.importCalls)
	}
	// A different key already sitting under that name is a conflict.
	other, _ := newVaultTestLeaf(t, "co", "47064135000184", time.Hour, time.Now())
	stub.keys[v.keyName("co", SerialHex(leaf))] = other
	if err := v.ImportA1Key(ctx, "co", leaf, key); !errors.Is(err, ErrKeyConflict) {
		t.Errorf("different key under same name = %v, want ErrKeyConflict", err)
	}
}

func TestImportA1KeyRefusesExportableResult(t *testing.T) {
	stub := newImportStub(t)
	v := newImportSigner(t, stub)
	key, leaf := newVaultTestLeaf(t, "co", "47064135000184", time.Hour, time.Now())
	name := v.keyName("co", SerialHex(leaf))
	stub.keys[name] = key
	stub.exportable[name] = true
	if err := v.ImportA1Key(context.Background(), "co", leaf, key); !errors.Is(err, ErrKeyExportable) {
		t.Errorf("exportable key = %v, want ErrKeyExportable", err)
	}
}

func TestImportA1KeyFailsClosed(t *testing.T) {
	stub := newImportStub(t)
	v := newImportSigner(t, stub)
	ctx := context.Background()
	key, leaf := newVaultTestLeaf(t, "co", "47064135000184", time.Hour, time.Now())
	otherKey, _ := newVaultTestLeaf(t, "co", "47064135000184", time.Hour, time.Now())

	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	smallLeaf := *leaf
	smallLeaf.PublicKey = &small.PublicKey

	for _, tc := range []struct {
		name      string
		companyID string
		leaf      *x509.Certificate
		key       *rsa.PrivateKey
		want      error
	}{
		{"empty company", "", leaf, key, ErrEmptyCompanyID},
		{"bad company chars", "co.evil", leaf, key, ErrInvalidKeyChars},
		{"key does not match leaf", "co", leaf, otherKey, ErrKeyCertMismatch},
		{"nil leaf", "co", nil, key, ErrKeyCertMismatch},
		{"unsupported size", "co", &smallLeaf, small, ErrUnsupportedKeySize},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := v.ImportA1Key(ctx, tc.companyID, tc.leaf, tc.key); !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
	if stub.importCalls != 0 {
		t.Errorf("a rejected import reached Vault: %d calls", stub.importCalls)
	}
}

// TestRetireA1KeyAbsentIsNoop: retiring a key Vault no longer has succeeds
// without any write, so a retried rotation is idempotent.
func TestRetireA1KeyAbsentIsNoop(t *testing.T) {
	stub := newImportStub(t)
	v := newImportSigner(t, stub)
	if err := v.RetireA1Key(context.Background(), "co", "deadbeef"); err != nil {
		t.Fatalf("absent key: %v", err)
	}
	if stub.importCalls != 0 {
		t.Error("unexpected write")
	}
	if err := v.RetireA1Key(context.Background(), "co.evil", "deadbeef"); !errors.Is(err, ErrInvalidKeyChars) {
		t.Errorf("bad chars = %v", err)
	}
	if err := v.RetireA1Key(context.Background(), "", "deadbeef"); !errors.Is(err, ErrEmptyCompanyID) {
		t.Errorf("empty company = %v", err)
	}
}

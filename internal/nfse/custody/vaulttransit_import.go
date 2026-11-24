package custody

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
)

var (
	// ErrKeyCertMismatch is returned when the private key does not belong to
	// the leaf certificate it is being imported for.
	ErrKeyCertMismatch = errors.New("custody: private key does not match certificate")
	// ErrUnsupportedKeySize is returned for an RSA modulus Transit cannot
	// import (anything other than 2048/3072/4096 bits).
	ErrUnsupportedKeySize = errors.New("custody: unsupported RSA key size (want 2048/3072/4096)")
	// ErrKeyConflict is returned when a Transit key already exists under the
	// (companyID, serial) name but holds a DIFFERENT public key. Same name and
	// same key is an idempotent re-import, not a conflict.
	ErrKeyConflict = errors.New("custody: transit key exists with a different public key")
)

// ImportA1Key imports the A1 private key into Vault Transit as the
// NON-EXPORTABLE key for (companyID, serial of leaf), using Vault's BYOK flow:
//
//  1. GET transit/wrapping_key (Vault's RSA-4096 wrapping public key);
//  2. wrap the key's PKCS#8 DER with an ephemeral AES-256 key (AES-KWP,
//     RFC 5649), and wrap that AES key with RSA-OAEP-SHA256;
//  3. POST transit/keys/{name}/import with exportable=false and
//     allow_plaintext_backup=false.
//
// It then reads the key back and refuses to report success unless Vault holds
// the leaf's public key with exportable=false. Re-importing the same key under
// the same name is a no-op (idempotent onboarding retry); a different key under
// the same name is ErrKeyConflict.
//
// The plaintext key is used only in this call; the PKCS#8 buffer and the
// ephemeral AES key are zeroed best-effort before returning. The caller owns
// (and should scrub) key itself.
func (v *VaultTransitSigner) ImportA1Key(ctx context.Context, companyID string, leaf *x509.Certificate, key *rsa.PrivateKey) error {
	if companyID == "" {
		return ErrEmptyCompanyID
	}
	if leaf == nil || key == nil {
		return ErrKeyCertMismatch
	}
	serial := SerialHex(leaf)
	if !validKeySegment(companyID) || !validKeySegment(serial) {
		return ErrInvalidKeyChars
	}
	leafPub, ok := leaf.PublicKey.(*rsa.PublicKey)
	if !ok || !leafPub.Equal(&key.PublicKey) {
		return ErrKeyCertMismatch
	}
	keyType, err := transitRSAType(key)
	if err != nil {
		return err
	}
	keyName := v.keyName(companyID, serial)
	ev := AuditEvent{CompanyID: companyID, CertSerial: serial, Op: "import_key", At: v.now().UTC(), KeyRef: keyName}

	exists, err := v.keyExists(ctx, keyName)
	if err != nil {
		ev.Err = err.Error()
		v.emit(ev)
		return err
	}
	if !exists {
		if err := v.importWrapped(ctx, keyName, keyType, key); err != nil {
			ev.Err = err.Error()
			v.emit(ev)
			return err
		}
	}
	if err := v.verifyImported(ctx, keyName, leafPub); err != nil {
		ev.Err = err.Error()
		v.emit(ev)
		return err
	}
	v.emit(ev)
	return nil
}

// RetireA1Key crypto-shreds the key of a certificate replaced by a newer
// import (rotation), with the same two-step erase + verify as CryptoShred. A
// key that is already gone is success, so a retried rotation is idempotent.
func (v *VaultTransitSigner) RetireA1Key(ctx context.Context, companyID, serial string) error {
	if companyID == "" {
		return ErrEmptyCompanyID
	}
	if !validKeySegment(companyID) || !validKeySegment(serial) {
		return ErrInvalidKeyChars
	}
	exists, err := v.keyExists(ctx, v.keyName(companyID, serial))
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	return v.cryptoShred(ctx, companyID, serial, "rotation")
}

func (v *VaultTransitSigner) importWrapped(ctx context.Context, keyName, keyType string, key *rsa.PrivateKey) error {
	var wk transitWrappingKeyResponse
	if err := v.do(ctx, http.MethodGet, v.mount+"/wrapping_key", nil, &wk); err != nil {
		return err
	}
	wrappingKey, err := parseRSAPublicKeyPEM(wk.Data.PublicKey)
	if err != nil {
		return fmt.Errorf("%w: wrapping key: %v", ErrVaultTransport, err)
	}
	ciphertext, err := wrapForTransitImport(wrappingKey, key)
	if err != nil {
		return err
	}
	req := transitImportRequest{
		Ciphertext:           ciphertext,
		Type:                 keyType,
		HashFunction:         "SHA256",
		Exportable:           false,
		AllowPlaintextBackup: false,
	}
	return v.do(ctx, http.MethodPost, v.mount+"/keys/"+pathEscapeKey(keyName)+"/import", req, nil)
}

// verifyImported confirms Vault holds pub under keyName and that the key is
// non-exportable, so a silent policy/default drift can never leave an
// exportable A1 behind a "success".
func (v *VaultTransitSigner) verifyImported(ctx context.Context, keyName string, pub *rsa.PublicKey) error {
	var resp transitKeyDetailResponse
	if err := v.do(ctx, http.MethodGet, v.mount+"/keys/"+pathEscapeKey(keyName), nil, &resp); err != nil {
		return err
	}
	if resp.Data.Exportable || resp.Data.AllowPlaintextBackup {
		return ErrKeyExportable
	}
	for _, ver := range resp.Data.Keys {
		got, err := parseRSAPublicKeyPEM(ver.PublicKey)
		if err == nil && got.Equal(pub) {
			v.verified.Store(keyName, v.now())
			return nil
		}
	}
	return ErrKeyConflict
}

// wrapForTransitImport builds the BYOK ciphertext Vault's import endpoint
// expects: base64( RSA-OAEP-SHA256(wrappingKey, aesKey) || KWP(aesKey, PKCS#8) ).
func wrapForTransitImport(wrappingKey *rsa.PublicKey, key *rsa.PrivateKey) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("custody: marshal pkcs8: %w", err)
	}
	defer zero(der)
	aesKey := make([]byte, 32)
	defer zero(aesKey)
	if _, err := rand.Read(aesKey); err != nil {
		return "", fmt.Errorf("custody: ephemeral aes key: %w", err)
	}
	wrappedAES, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, wrappingKey, aesKey, nil)
	if err != nil {
		return "", fmt.Errorf("custody: oaep wrap: %w", err)
	}
	wrappedKey, err := kwpWrap(aesKey, der)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(append(wrappedAES, wrappedKey...)), nil
}

func transitRSAType(key *rsa.PrivateKey) (string, error) {
	switch key.N.BitLen() {
	case 2048:
		return "rsa-2048", nil
	case 3072:
		return "rsa-3072", nil
	case 4096:
		return "rsa-4096", nil
	}
	return "", ErrUnsupportedKeySize
}

func parseRSAPublicKeyPEM(s string) (*rsa.PublicKey, error) {
	blk, _ := pem.Decode([]byte(s))
	if blk == nil {
		return nil, errors.New("no PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}
	return rsaPub, nil
}

type transitWrappingKeyResponse struct {
	Data struct {
		PublicKey string `json:"public_key"`
	} `json:"data"`
}

type transitImportRequest struct {
	Ciphertext           string `json:"ciphertext"`
	Type                 string `json:"type"`
	HashFunction         string `json:"hash_function"`
	Exportable           bool   `json:"exportable"`
	AllowPlaintextBackup bool   `json:"allow_plaintext_backup"`
}

// transitKeyDetailResponse is GET transit/keys/{name} with the per-version
// public keys Transit returns for asymmetric keys.
type transitKeyDetailResponse struct {
	Data struct {
		Exportable           bool `json:"exportable"`
		AllowPlaintextBackup bool `json:"allow_plaintext_backup"`
		Keys                 map[string]struct {
			PublicKey string `json:"public_key"`
		} `json:"keys"`
	} `json:"data"`
}

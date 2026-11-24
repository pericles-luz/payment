package custody

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ErrKeyExportable is returned fail-closed when the adapter detects that a
// Transit key is provisioned exportable (or backup-able) — the opposite of the
// non-exportable custody invariant (ADR-0007, AC #3). Signing with such a key is
// refused: an exportable key defeats the whole "plaintext never leaves the KMS"
// guarantee, so the adapter treats it as a misconfiguration and never signs.
var ErrKeyExportable = errors.New("custody: transit key is exportable — refusing to sign (non-exportable invariant)")

// ErrVaultTransport is returned when the Transit HTTP call itself fails
// (network, non-2xx status, malformed response). It never carries key material,
// the digest, or the Vault token.
var ErrVaultTransport = errors.New("custody: vault transit transport error")

// ErrInvalidKeyChars is returned fail-closed when a company_id or serial carries
// a character outside the Transit key-segment allowlist [A-Za-z0-9._-], or is a
// bare "." / ".." segment. Both derive from an authenticated tenant context and
// must match the CertStore exactly, so this is defense-in-depth (SIN-67543): it
// forecloses "/"-embedded extra path segments and path traversal by
// construction, before any KMS round-trip and before keyName is interpolated.
var ErrInvalidKeyChars = errors.New("custody: company_id/serial has characters outside the transit key allowlist")

// ErrShredNotVerified is returned fail-LOUD by CryptoShred when the Transit key
// is still present after the delete step. Transit defaults to
// deletion_allowed=false, so a bare DELETE fails closed and the key survives —
// which an operator would mistake for a completed erasure. Fail-closed is
// correct for *signing* but wrong for *erasure*: LGPD art. 18, VI requires the
// erasure to actually succeed, so CryptoShred verifies the key is gone and
// reports this if it is not (SIN-67696). Callers MUST NOT report LGPD erasure as
// complete when they see this.
var ErrShredNotVerified = errors.New("custody: crypto-shred not verified — transit key still present after delete")

// keySegmentDelimiter joins the prefix, company_id and serial into a SINGLE
// Transit key name. It MUST NOT appear in keySegmentRe: excluding the delimiter
// from the per-segment charset is what keeps the (prefix, company_id, serial) ->
// name mapping injective — a segment can never contain the delimiter and forge a
// different tuple that flattens to the same name. "." is chosen because Vault's
// GenericNameRegex admits it inside a name and real inputs never carry it (hex
// serials and UUID/slug company_ids use only [0-9a-f], [-] and alphanumerics).
const keySegmentDelimiter = "."

// keySegmentRe is the per-segment charset allowlist for a Transit key name.
// keyName joins the segments with keySegmentDelimiter into one name matching
// Vault's GenericNameRegex; the delimiter (".") is deliberately EXCLUDED here so
// the flattening stays injective, and so is "/" (a "/" in the name makes Vault's
// transit/{sign,keys} routes 404 "unsupported path"). Anything outside
// [A-Za-z0-9_-] is refused fail-closed before any KMS round-trip.
var keySegmentRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// validKeySegment reports whether s is a safe single component of a Transit key
// name. It rejects "/" (which would 404 "unsupported path" and, pre-flatten,
// injected extra path segments), the "." / ".." traversal segments, and the "."
// delimiter itself — all of which now fall outside keySegmentRe, so the explicit
// dot/dotdot guard is belt-and-suspenders that also documents the intent.
func validKeySegment(s string) bool {
	if s == "." || s == ".." {
		return false
	}
	return keySegmentRe.MatchString(s)
}

// VaultTransitConfig configures a VaultTransitSigner.
type VaultTransitConfig struct {
	// Address is the Vault API base URL (e.g. https://vault.internal:8200).
	Address string
	// Token is a static Vault token (AppRole-derived). Prefer TokenSource in
	// production so short-TTL tokens rotate without rebuilding the adapter. The
	// token is never logged, never placed in an error, and never in a URL.
	Token string
	// TokenSource, when set, is consulted for a fresh token per request and takes
	// precedence over Token. This is the seam for AppRole token renewal.
	TokenSource func(context.Context) (string, error)
	// KeyPrefix is the Transit key-name prefix; defaults to "a1". The full key
	// name is the single flat segment "{KeyPrefix}.{companyID}.{serial}"
	// (ADR-0007, tenant-scoped policy). It must itself be a valid key segment
	// ([A-Za-z0-9_-], no "." delimiter) or NewVaultTransitSigner fails fast.
	KeyPrefix string
	// Mount is the path of the Transit secrets engine; defaults to "transit".
	// A service-specific mount (e.g. "payment-transit") isolates its keys from
	// every other service on the same Vault: the policy grants keys/+ (any
	// name), so a shared mount would let one service delete another's keys.
	Mount string
	// Certs supplies the PUBLIC chain + metadata per tenant. Required: the
	// adapter never holds private material, so ClientCertificate and the
	// expiry/tenant fail-closed checks read the public chain from here.
	Certs CertStore
	// HTTPClient overrides the HTTP client (test hook / connection pooling). A
	// default client with a 10s timeout is used when nil.
	HTTPClient *http.Client
	// Now overrides the clock (test hook). Defaults to time.Now.
	Now func() time.Time
	// Audit, when set, receives one AuditEvent per operation. Never handed key
	// material — AuditEvent carries none.
	Audit func(AuditEvent)
	// SkipExportableCheck disables the defensive per-key "is this key
	// exportable?" preflight. The check is ON by default (secure-by-default);
	// this switch exists only for environments where the Transit read capability
	// is intentionally withheld from the AppRole policy.
	SkipExportableCheck bool
	// ExportableCheckTTL bounds how long a confirmed non-exportable result is
	// cached before the adapter re-reads the key config. Zero uses the default
	// (defaultExportableCheckTTL). A finite TTL closes the TOCTOU window where an
	// operator/attacker with key-config capability flips exportable=true after
	// the first check (SIN-67543): the cached "verified" verdict expires and the
	// next sign re-confirms non-exportability fail-closed.
	ExportableCheckTTL time.Duration
	// ExpiryObserver, when set, is invoked with (companyID, serial, expiryDays)
	// each time the adapter reads a tenant's on-file metadata on the sign / mTLS
	// path, where expiryDays is A1Meta.ExpiresInDays(now) — negative once the
	// certificate is past notAfter. It backs the a1_cert_expiry_days gauge +
	// D-30/15/7/1 alerts (SIN-67760, AC #7). It is called BEFORE the fail-closed
	// expiry check, so an already-expired certificate still publishes its
	// negative gauge (making silent expiry observable) even though signing is
	// then denied with ErrCertExpired before any KMS/ADN round-trip. It must not
	// block; the sign path calls it synchronously.
	ExpiryObserver func(companyID, serial string, expiryDays int)
	// StaleSeriesObserver, when set, is invoked with (companyID, serial) after a
	// SUCCESSFUL CryptoShred, so the tenant's a1_cert_expiry_days child for that
	// serial is dropped from the scrape (SIN-67763). A GaugeVec child otherwise
	// persists for the process lifetime: a crypto-shredded / deprovisioned serial
	// would keep exposing its last (often negative) value and keep the
	// NFSeA1CertExpired alert firing for a key that no longer exists. It is called
	// ONLY on the verified-success path — never when the shred is unverified or
	// aborts — so a series is never dropped while its key is still live. It must
	// not block; CryptoShred calls it synchronously. Pair it with the CertStore's
	// re-import stale hook to also clean up the OLD serial after a rotation.
	StaleSeriesObserver func(companyID, serial string)
}

// defaultExportableCheckTTL bounds the non-exportable cache when the config
// leaves ExportableCheckTTL zero. Ten minutes keeps the preflight cheap (one
// key read per key per ~10min of traffic) while capping the TOCTOU exposure to
// that window.
const defaultExportableCheckTTL = 10 * time.Minute

// VaultTransitSigner is the production FiscalSigner backed by HashiCorp Vault's
// Transit secrets engine (ADR-0007). The A1 private key is imported
// non-exportable into Vault; this adapter ONLY ever calls transit/sign — never
// export or backup — so the plaintext key never enters the application process.
//
// It satisfies the same port as LocalTestSigner and FileSigner and presents an
// identical delegating crypto.Signer surface for mTLS, so the same regression
// tests (real TLS 1.3 handshake, DPS XMLDSIG verify) cover every adapter.
//
// Dual-scheme on ONE key (AC #1): SignDigest signs XMLDSIG with PKCS#1 v1.5
// SHA-256 (NFS-e spec); the mTLS delegating signer routes crypto.SignerOpts →
// RSA-PSS (TLS 1.3 CertificateVerify) or PKCS#1 v1.5 (legacy TLS 1.2) as the ADN
// negotiates. Tenant isolation is fail-closed at the app layer (this adapter's
// (companyID, serial) gate); Vault adds non-exportable custody and audit under
// FiscalSignerVaultPolicy, which is deliberately not templated per tenant
// (ADR-0007, amended 2026-10-05).
//
// It is safe for concurrent use.
type VaultTransitSigner struct {
	address    string
	mount      string
	keyPrefix  string
	certs      CertStore
	httpClient *http.Client
	token      func(context.Context) (string, error)

	now             func() time.Time
	audit           func(AuditEvent)
	expiryObserver  func(companyID, serial string, expiryDays int)
	staleSeries     func(companyID, serial string)
	checkExportable bool
	exportableTTL   time.Duration

	// verified caches, per key name, the instant its non-exportable config was
	// last confirmed. The preflight read is skipped while that verdict is younger
	// than exportableTTL, then re-runs — bounding the TOCTOU window if the key is
	// later flipped exportable (SIN-67543).
	verified sync.Map // map[string]time.Time
}

// NewVaultTransitSigner builds the adapter. It fails fast on a missing address
// or cert store — both are required for a fail-closed, tenant-scoped signer.
func NewVaultTransitSigner(cfg VaultTransitConfig) (*VaultTransitSigner, error) {
	if strings.TrimSpace(cfg.Address) == "" {
		return nil, errors.New("custody: vault address required")
	}
	if cfg.Certs == nil {
		return nil, errors.New("custody: cert store required")
	}
	prefix := cfg.KeyPrefix
	if prefix == "" {
		prefix = "a1"
	}
	// The prefix is the third component of the flattened key name; a "." or any
	// out-of-charset byte in it would break injectivity / 404 the Transit route,
	// so refuse it at construction rather than per sign.
	if !validKeySegment(prefix) {
		return nil, fmt.Errorf("custody: key prefix %q has characters outside the transit key allowlist [A-Za-z0-9_-]", prefix)
	}
	mount := strings.Trim(cfg.Mount, "/")
	if mount == "" {
		mount = "transit"
	}
	if !validMount(mount) {
		return nil, fmt.Errorf("custody: transit mount %q must be [A-Za-z0-9_-] segments", cfg.Mount)
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	tokenFn := cfg.TokenSource
	if tokenFn == nil {
		staticTok := cfg.Token
		tokenFn = func(context.Context) (string, error) { return staticTok, nil }
	}
	ttl := cfg.ExportableCheckTTL
	if ttl <= 0 {
		ttl = defaultExportableCheckTTL
	}
	return &VaultTransitSigner{
		address:         strings.TrimRight(cfg.Address, "/"),
		mount:           mount,
		keyPrefix:       prefix,
		certs:           cfg.Certs,
		httpClient:      hc,
		token:           tokenFn,
		now:             now,
		audit:           cfg.Audit,
		expiryObserver:  cfg.ExpiryObserver,
		staleSeries:     cfg.StaleSeriesObserver,
		checkExportable: !cfg.SkipExportableCheck,
		exportableTTL:   ttl,
	}, nil
}

// keyName is the tenant-scoped Transit key name for (companyID, serial): a single
// flat segment "{prefix}.{companyID}.{serial}". It must be a name Vault's Transit
// routes accept — transit/sign/ and transit/keys/ match {name} with
// framework.GenericNameRegex (\w(([\w-.]+)?\w)?), which has NO "/", so the old
// "{prefix}/{companyID}/{serial}" scheme 404'd "unsupported path" against a real
// Vault (SIN-67698). The "." delimiter is excluded from validKeySegment, so this
// mapping is injective, so two (companyID, serial) pairs can never share a key.
// The sign rule of FiscalSignerVaultPolicy covers the whole "a1.*" namespace;
// which tenant may use which key is decided by assertSignable, not by Vault.
func (v *VaultTransitSigner) keyName(companyID, serial string) string {
	return v.keyPrefix + keySegmentDelimiter + companyID + keySegmentDelimiter + serial
}

// SignDigest signs the XMLDSIG digest with the tenant's Transit key using PKCS#1
// v1.5 SHA-256, as the NFS-e spec fixes for document signing. It fails closed
// before any KMS round-trip on an empty tenant id, an unknown/cross-tenant
// serial, or an expired certificate (AC #4, AC #9).
func (v *VaultTransitSigner) SignDigest(ctx context.Context, companyID, certSerial string, digest []byte) ([]byte, error) {
	if err := v.assertSignable(ctx, companyID, certSerial); err != nil {
		v.emit(AuditEvent{CompanyID: companyID, CertSerial: certSerial, Op: "sign_digest", Scheme: "pkcs1v15", Context: "dps", KeyRef: v.keyName(companyID, certSerial), At: v.now().UTC(), Err: errText(err)})
		return nil, err
	}
	sig, err := v.transitSign(ctx, companyID, certSerial, digest, "pkcs1v15", "sha2-256", "")
	v.emit(AuditEvent{CompanyID: companyID, CertSerial: certSerial, Op: "sign_digest", Scheme: "pkcs1v15", Context: "dps", KeyRef: v.keyName(companyID, certSerial), At: v.now().UTC(), Err: errText(err)})
	return sig, err
}

// ClientCertificate returns the tls.Certificate to present for mTLS client auth.
// The public chain comes from the CertStore; its PrivateKey is a delegating
// crypto.Signer that routes CertificateVerify back through Transit — the private
// key never enters the TLS stack. Fails closed for an empty/unknown tenant or an
// expired certificate.
func (v *VaultTransitSigner) ClientCertificate(ctx context.Context, companyID string) (tls.Certificate, error) {
	if companyID == "" {
		v.emit(AuditEvent{Op: "client_certificate", At: v.now().UTC(), Err: errText(ErrEmptyCompanyID)})
		return tls.Certificate{}, ErrEmptyCompanyID
	}
	if !validKeySegment(companyID) {
		v.emit(AuditEvent{CompanyID: companyID, Op: "client_certificate", At: v.now().UTC(), Err: errText(ErrInvalidKeyChars)})
		return tls.Certificate{}, ErrInvalidKeyChars
	}
	chain, meta, err := v.certs.Get(ctx, companyID)
	if err != nil {
		v.emit(AuditEvent{CompanyID: companyID, Op: "client_certificate", At: v.now().UTC(), Err: errText(ErrNotProvisioned)})
		return tls.Certificate{}, ErrNotProvisioned
	}
	// Same as the sign path: emit the expiry gauge before the fail-closed check
	// so an expired cert publishes its negative value (SIN-67760).
	v.observeExpiry(companyID, meta)
	if meta.IsExpired(v.now()) {
		v.emit(AuditEvent{CompanyID: companyID, CertSerial: meta.Serial, Op: "client_certificate", At: v.now().UTC(), Err: errText(ErrCertExpired)})
		return tls.Certificate{}, ErrCertExpired
	}
	if len(chain) == 0 || chain[0] == nil {
		return tls.Certificate{}, ErrEmptyChain
	}
	leaf := chain[0]
	// ICP-Brasil A1 certificates are RSA; a non-RSA leaf is unusable for
	// signing, so we fail closed rather than hand the TLS stack a broken
	// identity. Practically unreachable — the store only holds RSA A1 chains.
	pub, ok := leaf.PublicKey.(*rsa.PublicKey)
	if !ok {
		return tls.Certificate{}, ErrNotProvisioned
	}
	raw := make([][]byte, len(chain))
	for i, c := range chain {
		raw[i] = c.Raw
	}
	v.emit(AuditEvent{CompanyID: companyID, CertSerial: meta.Serial, Op: "client_certificate", KeyRef: v.keyName(companyID, meta.Serial), At: v.now().UTC()})
	return tls.Certificate{
		Certificate: raw,
		Leaf:        leaf,
		PrivateKey: &vaultDelegatedSigner{
			signer:  v,
			company: companyID,
			serial:  meta.Serial,
			pub:     pub,
		},
	}, nil
}

// signHandshake produces the mTLS CLIENT-AUTH signature with whatever scheme the
// ADN negotiated. RSA-PSS is mandated by TLS 1.3 CertificateVerify; legacy TLS
// 1.2 may pick PKCS#1 v1.5. The peer, not this process, chooses the scheme, so
// both are routed through Transit — this is the exact vuln the delegatedSigner
// previously fell closed on (AC #1). Salt length for PSS honours what crypto/tls
// asks (PSSSaltLengthEqualsHash → Transit salt_length="hash", AC #2). Fails
// closed on nil opts, an unsupported hash, an unknown/cross-tenant key, or an
// expired certificate.
func (v *VaultTransitSigner) signHandshake(ctx context.Context, companyID, serial string, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil {
		return nil, ErrNotProvisioned
	}
	hashAlg, ok := vaultHashAlg(opts.HashFunc())
	if !ok {
		return nil, ErrNotProvisioned
	}
	if err := v.assertSignable(ctx, companyID, serial); err != nil {
		return nil, err
	}
	scheme := "pkcs1v15"
	var saltLen string
	if pss, isPSS := opts.(*rsa.PSSOptions); isPSS {
		scheme = "pss"
		saltLen = vaultSaltLength(pss)
	}
	return v.transitSign(ctx, companyID, serial, digest, scheme, hashAlg, saltLen)
}

// assertSignable is the app-layer fail-closed tenant gate — the layer that
// isolates tenants, since one serve login signs for all of them: a non-empty
// tenant id, a serial that matches the
// tenant's on-file certificate, and a not-yet-expired certificate. Any mismatch
// resolves to ErrNotProvisioned (never leaking existence) or ErrCertExpired
// before any KMS round-trip.
func (v *VaultTransitSigner) assertSignable(ctx context.Context, companyID, serial string) error {
	if companyID == "" {
		return ErrEmptyCompanyID
	}
	if serial == "" {
		return ErrNotProvisioned
	}
	// Charset allowlist on both key segments before any interpolation or KMS
	// round-trip: forecloses "/"-injection and path traversal by construction
	// (SIN-67543).
	if !validKeySegment(companyID) || !validKeySegment(serial) {
		return ErrInvalidKeyChars
	}
	_, meta, err := v.certs.Get(ctx, companyID)
	if err != nil {
		return ErrNotProvisioned
	}
	if meta.Serial != serial {
		return ErrNotProvisioned
	}
	// Publish the expiry gauge from the metadata we just read — BEFORE the
	// fail-closed expiry gate, so an already-expired cert still emits its
	// negative value (a1_cert_expiry_days) and the D-30/15/7/1 alerts fire even
	// though the sign below is denied without reaching the KMS/ADN (SIN-67760).
	v.observeExpiry(companyID, meta)
	if meta.IsExpired(v.now()) {
		return ErrCertExpired
	}
	return nil
}

// observeExpiry publishes the tenant cert's remaining validity (whole days,
// negative once expired) to the configured ExpiryObserver, if any. It reads the
// same clock the fail-closed gate uses so the gauge and the deny decision stay
// consistent. Serial comes from the stored metadata, so the label always
// matches the on-file certificate.
func (v *VaultTransitSigner) observeExpiry(companyID string, meta A1Meta) {
	if v.expiryObserver != nil {
		v.expiryObserver(companyID, meta.Serial, meta.ExpiresInDays(v.now()))
	}
}

// transitSign performs the Transit sign round-trip. It runs the non-exportable
// preflight (once per key), builds the prehashed sign request, and decodes the
// "vault:vN:<base64>" signature. The raw private key is never returned; only the
// signature bytes cross back.
func (v *VaultTransitSigner) transitSign(ctx context.Context, companyID, serial string, digest []byte, sigAlg, hashAlg, saltLen string) ([]byte, error) {
	keyName := v.keyName(companyID, serial)
	if err := v.ensureNonExportable(ctx, companyID, serial); err != nil {
		return nil, err
	}
	body := transitSignRequest{
		Input:              base64.StdEncoding.EncodeToString(digest),
		Prehashed:          true,
		HashAlgorithm:      hashAlg,
		SignatureAlgorithm: sigAlg,
	}
	if sigAlg == "pss" {
		body.SaltLength = saltLen
	}
	var resp transitSignResponse
	if err := v.do(ctx, http.MethodPost, v.mount+"/sign/"+pathEscapeKey(keyName), body, &resp); err != nil {
		return nil, err
	}
	sig, err := decodeVaultSignature(resp.Data.Signature)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrVaultTransport, err)
	}
	return sig, nil
}

// ensureNonExportable reads the Transit key config and refuses to sign if the
// key is exportable or backup-able (AC #3). A confirmed non-exportable verdict
// is cached for exportableTTL, so the read runs at most once per key per TTL
// window rather than once per process — bounding the TOCTOU window if an
// operator flips the key exportable after the first check (SIN-67543). A read
// failure is treated as "cannot confirm non-exportability" and also fails
// closed: Vault must be reachable to sign anyway, so this couples no
// availability the sign path did not already require.
func (v *VaultTransitSigner) ensureNonExportable(ctx context.Context, companyID, serial string) error {
	if !v.checkExportable {
		return nil
	}
	keyName := v.keyName(companyID, serial)
	if raw, ok := v.verified.Load(keyName); ok {
		if verifiedAt, ok := raw.(time.Time); ok && v.now().Sub(verifiedAt) < v.exportableTTL {
			return nil
		}
	}
	var resp transitKeyResponse
	if err := v.do(ctx, http.MethodGet, v.mount+"/keys/"+pathEscapeKey(keyName), nil, &resp); err != nil {
		return err
	}
	if resp.Data.Exportable || resp.Data.AllowPlaintextBackup {
		// Evict any stale positive so a later flip back to non-exportable still
		// re-reads rather than serving an expired verdict.
		v.verified.Delete(keyName)
		return ErrKeyExportable
	}
	v.verified.Store(keyName, v.now())
	return nil
}

// CryptoShred performs the mandatory two-step LGPD erasure (art. 18, VI) of a
// tenant's non-exportable A1 key in Vault Transit:
//
//  1. flip deletion_allowed=true  (POST transit/keys/{name}/config) — Transit
//     defaults to false, so a bare DELETE 400s and leaves the key live+signing;
//  2. delete the key              (DELETE transit/keys/{name});
//  3. verify irreversibility      (GET transit/keys/{name} → 404 "no such key").
//
// Step 1 is NOT optional and step 3 is load-bearing: without the verify, a
// rejected delete (deletion_allowed still false) or a Vault that silently keeps
// the key would read as a successful erasure. If the key survives, CryptoShred
// returns ErrShredNotVerified — fail-LOUD — so the caller never reports the
// erasure as done. On success the cached non-exportable verdict is evicted so a
// later re-import of the same serial re-checks from scratch.
//
// It fails closed before any KMS round-trip on an empty/invalid tenant id or
// serial (same allowlist as signing). This is the adapter method a future
// offboarding/rotation flow calls; the caller pairs it with CertStore.Delete to
// shred the public metadata. Spec: runbook §8; SIN-67696.
func (v *VaultTransitSigner) CryptoShred(ctx context.Context, companyID, serial string) error {
	return v.cryptoShred(ctx, companyID, serial, "offboarding")
}

// cryptoShred is CryptoShred with the audit context ("offboarding" or
// "rotation") recorded on every event.
func (v *VaultTransitSigner) cryptoShred(ctx context.Context, companyID, serial, auditContext string) error {
	if companyID == "" {
		return ErrEmptyCompanyID
	}
	if serial == "" {
		return ErrNotProvisioned
	}
	if !validKeySegment(companyID) || !validKeySegment(serial) {
		return ErrInvalidKeyChars
	}
	keyName := v.keyName(companyID, serial)
	escaped := pathEscapeKey(keyName)

	shredErr := func(err error) error {
		v.emit(AuditEvent{CompanyID: companyID, CertSerial: serial, Op: "crypto_shred", Context: auditContext, KeyRef: keyName, At: v.now().UTC(), Err: errText(err)})
		return err
	}

	// Step 1 — allow deletion (Transit default is deletion_allowed=false).
	if err := v.do(ctx, http.MethodPost, v.mount+"/keys/"+escaped+"/config", transitKeyConfigRequest{DeletionAllowed: true}, nil); err != nil {
		return shredErr(err)
	}
	// Step 2 — delete the key.
	if err := v.do(ctx, http.MethodDelete, v.mount+"/keys/"+escaped, nil, nil); err != nil {
		return shredErr(err)
	}
	// Step 3 — verify the key is gone; erasure must actually have happened.
	exists, err := v.keyExists(ctx, keyName)
	if err != nil {
		return shredErr(err)
	}
	if exists {
		return shredErr(ErrShredNotVerified)
	}
	v.verified.Delete(keyName)
	// The key is verifiably gone: drop the tenant's a1_cert_expiry_days child so a
	// deprovisioned serial stops exposing its last (possibly negative) value and
	// NFSeA1CertExpired stops firing for a key that no longer exists (SIN-67763).
	// Only reached on the verified-success path — never when the shred is
	// unverified or aborts — so a series is never dropped while its key is live.
	if v.staleSeries != nil {
		v.staleSeries(companyID, serial)
	}
	v.emit(AuditEvent{CompanyID: companyID, CertSerial: serial, Op: "crypto_shred", Context: auditContext, KeyRef: keyName, At: v.now().UTC()})
	return nil
}

// keyExists reports whether the Transit key is still present. It reads
// transit/keys/{name} and maps Vault's 404 "no such key" to (false, nil) and a
// 2xx to (true, nil) — the distinction do() collapses into ErrVaultTransport,
// which is why CryptoShred's verify step needs this status-aware probe. It never
// leaks the token or key material, mirroring do()'s no-leak posture.
func (v *VaultTransitSigner) keyExists(ctx context.Context, keyName string) (bool, error) {
	apiPath := v.mount + "/keys/" + pathEscapeKey(keyName)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.address+"/v1/"+apiPath, nil)
	if err != nil {
		return false, fmt.Errorf("%w: build request", ErrVaultTransport)
	}
	tok, err := v.token(ctx)
	if err != nil {
		return false, fmt.Errorf("%w: token source", ErrVaultTransport)
	}
	if tok != "" {
		req.Header.Set("X-Vault-Token", tok)
	}
	res, err := v.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("%w: GET %s", ErrVaultTransport, apiPath)
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 1<<16))
	switch {
	case res.StatusCode == http.StatusNotFound:
		return false, nil
	case res.StatusCode >= 200 && res.StatusCode < 300:
		return true, nil
	default:
		return false, fmt.Errorf("%w: GET %s -> HTTP %d", ErrVaultTransport, apiPath, res.StatusCode)
	}
}

// do issues a Vault API request, attaching the token header and decoding the
// JSON response into out. Errors are wrapped in ErrVaultTransport and never
// include the token, the digest, or the signature.
func (v *VaultTransitSigner) do(ctx context.Context, method, apiPath string, in, out any) error {
	var reqBody io.Reader
	if in != nil {
		buf, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("%w: marshal request", ErrVaultTransport)
		}
		reqBody = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, v.address+"/v1/"+apiPath, reqBody)
	if err != nil {
		return fmt.Errorf("%w: build request", ErrVaultTransport)
	}
	tok, err := v.token(ctx)
	if err != nil {
		return fmt.Errorf("%w: token source", ErrVaultTransport)
	}
	if tok != "" {
		req.Header.Set("X-Vault-Token", tok)
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := v.httpClient.Do(req)
	if err != nil {
		// Wrap without the request URL/token to avoid leaking either.
		return fmt.Errorf("%w: %s %s", ErrVaultTransport, method, apiPath)
	}
	defer res.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(res.Body, 1<<16))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("%w: %s %s -> HTTP %d", ErrVaultTransport, method, apiPath, res.StatusCode)
	}
	if out != nil {
		if err := json.Unmarshal(payload, out); err != nil {
			return fmt.Errorf("%w: decode response", ErrVaultTransport)
		}
	}
	return nil
}

func (v *VaultTransitSigner) emit(ev AuditEvent) {
	if v.audit != nil {
		v.audit(ev)
	}
}

// vaultDelegatedSigner is the crypto.Signer handed to the TLS stack for mTLS
// client auth. It holds only the PUBLIC key and delegates every Sign back to the
// Transit boundary — identical in surface to the test signer's delegatedSigner,
// so one regression test covers both. Document (XMLDSIG) signing does NOT go
// through here; it uses SignDigest, fixed to PKCS#1 v1.5 SHA-256.
type vaultDelegatedSigner struct {
	signer  *VaultTransitSigner
	company string
	serial  string
	pub     crypto.PublicKey
}

func (d *vaultDelegatedSigner) Public() crypto.PublicKey { return d.pub }

// Sign delegates the mTLS CLIENT-AUTH signature back to the adapter, which
// routes to Transit with the negotiated scheme (RSA-PSS on TLS 1.3, PKCS#1 v1.5
// on legacy TLS 1.2). The crypto.Signer interface carries no context, so the
// handshake sign uses a background context bounded by the HTTP client timeout.
// Emits a distinct "sign_handshake" audit op carrying the scheme so the mTLS
// oracle is never conflated with the document oracle in the ledger.
func (d *vaultDelegatedSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	ctx := context.Background()
	sig, err := d.signer.signHandshake(ctx, d.company, d.serial, digest, opts)
	scheme := "pkcs1v15"
	if _, isPSS := opts.(*rsa.PSSOptions); isPSS {
		scheme = "pss"
	}
	d.signer.emit(AuditEvent{
		CompanyID:  d.company,
		CertSerial: d.serial,
		Op:         "sign_handshake",
		Scheme:     scheme,
		Context:    "mtls",
		KeyRef:     d.signer.keyName(d.company, d.serial),
		At:         d.signer.now().UTC(),
		Err:        errText(err),
	})
	return sig, err
}

// --- Transit wire types + helpers ---

type transitSignRequest struct {
	Input              string `json:"input"`
	Prehashed          bool   `json:"prehashed"`
	HashAlgorithm      string `json:"hash_algorithm"`
	SignatureAlgorithm string `json:"signature_algorithm"`
	SaltLength         string `json:"salt_length,omitempty"`
}

type transitSignResponse struct {
	Data struct {
		Signature string `json:"signature"`
	} `json:"data"`
}

type transitKeyResponse struct {
	Data struct {
		Exportable           bool `json:"exportable"`
		AllowPlaintextBackup bool `json:"allow_plaintext_backup"`
	} `json:"data"`
}

// transitKeyConfigRequest is the POST transit/keys/{name}/config body used by
// CryptoShred to flip deletion_allowed=true before deleting the key.
type transitKeyConfigRequest struct {
	DeletionAllowed bool `json:"deletion_allowed"`
}

// vaultHashAlg maps a crypto.Hash to the Transit hash_algorithm name. Only the
// TLS-negotiable SHA-2 hashes are accepted; SHA-1/MD5 fail closed (ok=false).
func vaultHashAlg(h crypto.Hash) (string, bool) {
	switch h {
	case crypto.SHA256:
		return "sha2-256", true
	case crypto.SHA384:
		return "sha2-384", true
	case crypto.SHA512:
		return "sha2-512", true
	default:
		return "", false
	}
}

// vaultSaltLength maps rsa.PSSOptions.SaltLength to the Transit salt_length
// parameter. crypto/tls signs TLS 1.3 CertificateVerify with
// PSSSaltLengthEqualsHash, which MUST map to "hash" — ignoring it produces a
// signature the ADN rejects in CertificateVerify (AC #2).
func vaultSaltLength(pss *rsa.PSSOptions) string {
	switch pss.SaltLength {
	case rsa.PSSSaltLengthEqualsHash:
		return "hash"
	case rsa.PSSSaltLengthAuto:
		return "auto"
	default:
		return strconv.Itoa(pss.SaltLength)
	}
}

// decodeVaultSignature parses Transit's "vault:vN:<base64>" signature envelope
// and returns the raw signature bytes.
func decodeVaultSignature(s string) ([]byte, error) {
	parts := strings.SplitN(s, ":", 3)
	if len(parts) != 3 || parts[0] != "vault" {
		return nil, errors.New("malformed transit signature envelope")
	}
	return base64.StdEncoding.DecodeString(parts[2])
}

// pathEscapeKey escapes the Transit key name for interpolation into a URL path.
// The name is a single flat segment (keyName), so a stray "/" MUST be escaped to
// %2F rather than preserved — the tenant scoping now lives in the "." delimiter,
// not in path segments. validKeySegment already forecloses "/" upstream; this is
// defense-in-depth so no interpolation can inject an extra path segment.
func pathEscapeKey(name string) string {
	return url.PathEscape(name)
}

// validMount accepts a Vault mount path made of key-safe segments.
func validMount(m string) bool {
	for _, seg := range strings.Split(m, "/") {
		if !keySegmentRe.MatchString(seg) {
			return false
		}
	}
	return true
}

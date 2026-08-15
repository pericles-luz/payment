// Package secret provides a CredentialStore adapter. Bank credentials are
// isolated per tenant AND per bank — keyed by the composite (tenantID, bankID)
// pair — and never live in code. The store is loaded from configuration/
// environment (a vault adapter is a drop-in replacement). Secrets are returned
// only transiently and must never be logged (threat C1/C4; ADR-0007).
package secret

import (
	"context"
	"regexp"
	"sync"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// Store is an in-process CredentialStore keyed by the composite (tenantID,
// bankID) pair. The concrete secret values are injected at construction from
// config/env — not hard-coded.
type Store struct {
	mu sync.RWMutex
	// creds is keyed by credKey(tenantID, bankID). A tenant may hold independent
	// credentials at more than one bank; the bankID subdivides — never relaxes —
	// the tenant scope (ADR-0007 T2).
	creds map[string]ports.BankCredential
}

// credKey builds the composite store key for a (tenantID, bankID) pair. The NUL
// separator can appear in neither a tenant id nor a bank slug, so distinct pairs
// can never collide onto the same key (no prefix/normalisation aliasing, ADR-0007
// T2). An empty bankID is normalised to the default BankIDC6 so a legacy
// single-bank credential and an explicit "c6" credential resolve to the same slot.
func credKey(tenantID, bankID string) string {
	return tenantID + "\x00" + defaultBankID(bankID)
}

// defaultBankID resolves an unspecified (empty) bank to the retro-compatible
// default BankIDC6, so pre-multi-bank config and call sites keep working unchanged
// (ADR-0007). A non-empty bankID is returned verbatim — the registry/allowlist
// validation of the slug lives at the request boundary (SIN-66022), not here.
func defaultBankID(bankID string) string {
	if bankID == "" {
		return ports.BankIDC6
	}
	return bankID
}

// NewStore builds a Store from a credential collection (typically loaded from the
// environment/secret manager at startup). Each credential is re-keyed by its own
// (TenantID, BankID) pair, with an empty BankID normalised to the default
// BankIDC6. For backward compatibility a credential whose TenantID is empty is
// keyed (and stamped) under the MAP KEY, preserving the legacy "map key == tenant"
// convenience used by callers that pass a tenant-keyed map of bare credentials.
func NewStore(creds map[string]ports.BankCredential) *Store {
	cp := make(map[string]ports.BankCredential, len(creds))
	for k, v := range creds {
		if v.TenantID == "" {
			v.TenantID = k
		}
		v.BankID = defaultBankID(v.BankID)
		cp[credKey(v.TenantID, v.BankID)] = v
	}
	return &Store{creds: cp}
}

// GetBankCredential returns the credential for the EXACT (tenantID, bankID) pair.
// The lookup is exact-match with NO fallback: a missing pair returns ErrNotFound
// and never resolves to another bank or another tenant (deny-by-default; threat
// T1/T2). An empty bankID resolves to the default BankIDC6 (retro-compat).
func (s *Store) GetBankCredential(_ context.Context, tenantID, bankID string) (ports.BankCredential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.creds[credKey(tenantID, bankID)]
	if !ok {
		return ports.BankCredential{}, shared.ErrNotFound
	}
	return c, nil
}

// Set stores/replaces a credential for the (tenantID, c.BankID) pair (used by the
// admin plane / config reload). It stamps the tenant id and normalises an empty
// bank to the default BankIDC6.
func (s *Store) Set(tenantID string, c ports.BankCredential) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c.TenantID = tenantID
	c.BankID = defaultBankID(c.BankID)
	s.creds[credKey(tenantID, c.BankID)] = c
}

// SetBankCredential implements ports.CredentialWriter: it persists a tenant's
// bank credential for the (tenantID, bankID) pair. The secret is held only in the
// store and never returned, logged or echoed (threat C1/C4). Empty inputs are
// rejected as a validation error without including the secret value in the
// message. An empty bankID is stored under the default BankIDC6 (retro-compat).
func (s *Store) SetBankCredential(_ context.Context, tenantID, bankID, clientID, secret string) error {
	if tenantID == "" {
		return shared.NewValidationError("tenant_id", "is required")
	}
	if clientID == "" {
		return shared.NewValidationError("client_id", "is required")
	}
	if secret == "" {
		return shared.NewValidationError("secret", "is required")
	}
	bankID = defaultBankID(bankID)
	s.mu.Lock()
	defer s.mu.Unlock()
	// Read-modify-write: preserve any CreditorKey already registered for this
	// (tenant, bank) credential. Overwriting the whole struct here used to silently
	// destroy the creditor key whenever an admin rotated the client secret (the
	// creditor key and the secret live in the same aggregate, SIN-66092). The two
	// admin writers (CredentialWriter, CreditorKeyWriter) share s.mu so they can
	// never clobber each other's field.
	cur := s.creds[credKey(tenantID, bankID)]
	cur.TenantID = tenantID
	cur.BankID = bankID
	cur.ClientID = clientID
	cur.Secret = secret
	s.creds[credKey(tenantID, bankID)] = cur
	return nil
}

// DeleteBankCredential implements ports.CredentialDeleter: it hard-removes the
// credential for the (tenantID, bankID) pair (ADR-0012 §5). It is IDEMPOTENT —
// removing an absent pair returns nil, giving the caller no enumeration oracle
// (OWASP A01) and making a repeated "remove bank" click a harmless no-op. Before
// dropping the map slot it ZEROISES the in-memory secret material (Secret and the
// routing-sensitive CreditorKey), the in-process analog of the SQLite
// "UPDATE … SET client_secret=” … DELETE" the ADR prescribes, so a sensitive
// value never lingers in a stale struct (threat C1/C4). An empty bankID resolves
// to the default BankIDC6 (retro-compat).
func (s *Store) DeleteBankCredential(_ context.Context, tenantID, bankID string) error {
	key := credKey(tenantID, defaultBankID(bankID))
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.creds[key]
	if !ok {
		return nil
	}
	// Zeroise before delete: overwrite the sensitive fields in the stored value so
	// no secret survives in a lingering copy, then drop the slot entirely.
	cur.Secret = ""
	cur.CreditorKey = ""
	s.creds[key] = cur
	delete(s.creds, key)
	return nil
}

// pixEVPPattern / pixEmailPattern / pixPhonePattern match the syntactic shapes
// BACEN accepts for a PIX key other than CPF/CNPJ (checked separately as digit
// strings): an EVP random key (UUID), an e-mail, or an E.164 phone. They are a
// SHAPE check, not an ownership or registration check — the PSP is authoritative
// for whether the key exists and belongs to the tenant. Anchored so no
// surrounding junk slips through.
var (
	pixEVPPattern   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	pixEmailPattern = regexp.MustCompile(`^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$`)
	pixPhonePattern = regexp.MustCompile(`^\+[1-9][0-9]{7,14}$`)
)

// validateCreditorKey enforces that a creditor key is a syntactically valid PIX
// key (chave) at the write boundary — not merely non-empty. A registration-time
// shape check keeps an obviously malformed key (a typo, a partial value, an
// account number pasted into the wrong field) from ever reaching the PSP as the
// tenant's fund-routing target (OWASP A01). The error NEVER includes the key
// value (it is routing-sensitive; threat C1/C4). Accepted shapes mirror BACEN:
// EVP/UUID, e-mail (≤77 chars), E.164 phone, or a bare CPF (11) / CNPJ (14)
// digit string.
func validateCreditorKey(key string) error {
	switch {
	case pixEVPPattern.MatchString(key):
		return nil
	case len(key) <= 77 && pixEmailPattern.MatchString(key):
		return nil
	case pixPhonePattern.MatchString(key):
		return nil
	case isTaxIDKey(key):
		return nil
	default:
		return shared.NewValidationError("creditor_key", "is not a valid PIX key (EVP/UUID, e-mail, phone or CPF/CNPJ)")
	}
}

// isTaxIDKey reports whether key is a bare CPF (11) or CNPJ (14) digit string —
// the form BACEN uses for a CPF/CNPJ PIX key. Syntactic (length + digits) only,
// mirroring the PIX immediate-charge devedor check.
func isTaxIDKey(key string) bool {
	if len(key) != 11 && len(key) != 14 {
		return false
	}
	for i := 0; i < len(key); i++ {
		if key[i] < '0' || key[i] > '9' {
			return false
		}
	}
	return true
}

// SetCreditorKey implements ports.CreditorKeyWriter: it records a tenant's PIX
// creditor key (chave do recebedor) on the tenant's EXISTING bank credential,
// read-modify-write under s.mu so the credential's Secret and ClientID are
// preserved (a creditor-key write must never wipe the rotation secret). The key
// targets the tenant's default-bank credential (BankIDC6) — the payment service
// exposes a single creditor-key write path per tenant (no bank dimension on this
// port; ADR-0008). A tenant with no existing credential is rejected with
// shared.ErrNotFound: a creditor key without a bank identity is meaningless and a
// half-credential invites the confused-deputy gap. Empty inputs and a malformed
// PIX key are rejected as validation errors WITHOUT echoing the value (the key is
// routing-sensitive; threat C1/C4).
func (s *Store) SetCreditorKey(_ context.Context, tenantID, creditorKey string) error {
	if tenantID == "" {
		return shared.NewValidationError("tenant_id", "is required")
	}
	if creditorKey == "" {
		return shared.NewValidationError("creditor_key", "is required")
	}
	if err := validateCreditorKey(creditorKey); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := credKey(tenantID, defaultBankID(""))
	cur, ok := s.creds[key]
	if !ok {
		// No bank identity for this tenant — refuse rather than create a
		// half-credential carrying a routing target but no client id/secret.
		return shared.ErrNotFound
	}
	cur.CreditorKey = creditorKey
	s.creds[key] = cur
	return nil
}

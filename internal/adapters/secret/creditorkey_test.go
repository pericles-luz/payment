package secret_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// seedCred returns a store holding one (tenant, c6) credential with a secret and
// client id, so the read-modify-write behaviour of SetCreditorKey can be asserted
// against a real prior credential (no DB mock; the in-memory store is the
// production adapter).
func seedCred(tenantID, clientID, secretVal string) *secret.Store {
	return secret.NewStore(map[string]ports.BankCredential{
		tenantID: {TenantID: tenantID, BankID: ports.BankIDC6, ClientID: clientID, Secret: secretVal},
	})
}

func TestSetCreditorKey_PreservesSecretAndClientID(t *testing.T) {
	t.Parallel()
	const tenantID, clientID, secretVal = "t1", "client-1", "S3cr3t"
	st := seedCred(tenantID, clientID, secretVal)

	const key = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	if err := st.SetCreditorKey(context.Background(), tenantID, key); err != nil {
		t.Fatalf("set creditor key: %v", err)
	}
	got, err := st.GetBankCredential(context.Background(), tenantID, ports.BankIDC6)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.CreditorKey != key {
		t.Errorf("creditor key = %q, want %q", got.CreditorKey, key)
	}
	if got.Secret != secretVal {
		t.Errorf("secret was clobbered: got %q, want %q", got.Secret, secretVal)
	}
	if got.ClientID != clientID {
		t.Errorf("client id was clobbered: got %q, want %q", got.ClientID, clientID)
	}
}

// TestSetBankCredential_PreservesCreditorKey is the wipe-bug regression: rotating
// the client secret (SetBankCredential) MUST NOT destroy a creditor key already
// registered on the same (tenant, bank) credential.
func TestSetBankCredential_PreservesCreditorKey(t *testing.T) {
	t.Parallel()
	const tenantID = "t1"
	st := seedCred(tenantID, "client-old", "secret-old")

	const key = "recebedor@acme.com.br"
	if err := st.SetCreditorKey(context.Background(), tenantID, key); err != nil {
		t.Fatalf("set creditor key: %v", err)
	}
	// Admin rotates the client secret.
	if err := st.SetBankCredential(context.Background(), tenantID, ports.BankIDC6, "client-new", "secret-new"); err != nil {
		t.Fatalf("rotate secret: %v", err)
	}
	got, err := st.GetBankCredential(context.Background(), tenantID, ports.BankIDC6)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.CreditorKey != key {
		t.Errorf("creditor key was wiped by secret rotation: got %q, want %q", got.CreditorKey, key)
	}
	if got.Secret != "secret-new" || got.ClientID != "client-new" {
		t.Errorf("rotation did not take effect: clientID=%q secret=%q", got.ClientID, got.Secret)
	}
}

func TestSetCreditorKey_UnknownTenantNotFound(t *testing.T) {
	t.Parallel()
	st := secret.NewStore(map[string]ports.BankCredential{})
	err := st.SetCreditorKey(context.Background(), "ghost", "a1b2c3d4-e5f6-7890-abcd-ef1234567890")
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want ErrNotFound for tenant without a credential, got %v", err)
	}
}

func TestSetCreditorKey_RejectsEmptyInputs(t *testing.T) {
	t.Parallel()
	st := seedCred("t1", "c", "s")
	if err := st.SetCreditorKey(context.Background(), "", "a1b2c3d4-e5f6-7890-abcd-ef1234567890"); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("empty tenant: want validation error, got %v", err)
	}
	if err := st.SetCreditorKey(context.Background(), "t1", ""); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("empty key: want validation error, got %v", err)
	}
}

// TestSetCreditorKey_ShapeValidation drives the PIX-key shape validator through
// the write boundary: every accepted BACEN shape is stored; every malformed input
// is rejected as a validation error before any write.
func TestSetCreditorKey_ShapeValidation(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		key  string
		ok   bool
	}{
		{"evp uuid lower", "a1b2c3d4-e5f6-7890-abcd-ef1234567890", true},
		{"evp uuid upper", "A1B2C3D4-E5F6-7890-ABCD-EF1234567890", true},
		{"email", "recebedor@acme.com.br", true},
		{"email plus tag", "pix+conta@acme.io", true},
		{"phone e164 br", "+5511999998888", true},
		{"cpf 11 digits", "12345678901", true},
		{"cnpj 14 digits", "12345678000199", true},
		{"empty", "", false},
		{"random text", "not-a-key", false},
		{"uuid missing groups", "a1b2c3d4-e5f6-7890-abcd", false},
		{"uuid bad hex", "g1b2c3d4-e5f6-7890-abcd-ef1234567890", false},
		{"phone no plus", "5511999998888", false},
		{"phone leading zero", "+0511999998888", false},
		{"email no domain dot", "user@localhost", false},
		{"cpf 10 digits", "1234567890", false},
		{"cpf with letters", "1234567890a", false},
		{"digits 12", "123456789012", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st := seedCred("t1", "client", "secret")
			err := st.SetCreditorKey(context.Background(), "t1", c.key)
			if c.ok && err != nil {
				t.Fatalf("key %q: want accepted, got %v", c.key, err)
			}
			if !c.ok && !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("key %q: want validation rejection, got %v", c.key, err)
			}
			if c.ok {
				got, _ := st.GetBankCredential(context.Background(), "t1", ports.BankIDC6)
				if got.CreditorKey != c.key {
					t.Errorf("key %q not stored: got %q", c.key, got.CreditorKey)
				}
			}
		})
	}
}

// TestSetCreditorKey_ErrorNeverEchoesKey asserts the validation error for a
// malformed key never contains the offending value (the key is routing-sensitive).
func TestSetCreditorKey_ErrorNeverEchoesKey(t *testing.T) {
	t.Parallel()
	st := seedCred("t1", "client", "secret")
	const bad = "super-secret-routing-target-typo"
	err := st.SetCreditorKey(context.Background(), "t1", bad)
	if err == nil {
		t.Fatal("want error for malformed key")
	}
	if strings.Contains(err.Error(), bad) {
		t.Fatalf("error leaked the key value: %q", err.Error())
	}
}

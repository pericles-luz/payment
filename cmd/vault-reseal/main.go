// Command vault-reseal rotates the bank secret vault's key-encryption key (KEK)
// by re-encrypting every stored credential and certificate row from the previous
// KEK to the current one. It is an OFFLINE, one-shot operational tool — run it
// with the api process stopped (or during a maintenance window), never on the hot
// path (SIN-69369, follow-up to SIN-69366).
//
// Usage (see docs/ops/bank-vault-kek-rotation-runbook.md for the full procedure):
//
//	PAYMENT_DB_PATH=/data/payment.db \
//	PAYMENT_BANK_VAULT_KEY=<NEW 64-hex-char key> \
//	PAYMENT_BANK_VAULT_KEY_PREVIOUS=<OLD 64-hex-char key> \
//	  vault-reseal
//
// It decrypts each row with the PREVIOUS key and re-encrypts with the NEW key,
// with BOTH tables rewritten inside a SINGLE transaction (all-or-nothing across
// credentials AND certificates — SIN-69372). On any error nothing is committed, so a
// failed run leaves the vault fully readable with the OLD key — set both env vars back
// and retry. Keys are never logged.
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/sqlite"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/system"
	"github.com/ia-dev-sindireceita/payment/internal/platform/config"
	"github.com/ia-dev-sindireceita/payment/migrations"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("vault-reseal: %v", err)
	}
}

func run() error {
	cfg := config.FromEnv()
	ctx := context.Background()

	if cfg.BankVaultKey == "" {
		return fmt.Errorf("PAYMENT_BANK_VAULT_KEY (the NEW key) is required")
	}
	if cfg.BankVaultKeyPrevious == "" {
		return fmt.Errorf("PAYMENT_BANK_VAULT_KEY_PREVIOUS (the OLD key) is required")
	}
	// Identical keys are the one-time AAD migration case (§5 of the runbook): the
	// KEK does not change but every row is re-sealed to upgrade its AAD binding.
	// A genuine KEK rotation supplies two different keys. Both are valid work.
	if cfg.BankVaultKey == cfg.BankVaultKeyPrevious {
		log.Print("vault-reseal: previous and new keys are identical — running the AAD-only migration (no KEK change)")
	}

	newCipher, err := decodeCipher(cfg.BankVaultKey)
	if err != nil {
		return fmt.Errorf("new key: %w", err)
	}
	oldCipher, err := decodeCipher(cfg.BankVaultKeyPrevious)
	if err != nil {
		return fmt.Errorf("previous key: %w", err)
	}

	db, err := sqlite.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	if err := sqlite.Migrate(ctx, db, migrations.FS); err != nil {
		return err
	}

	clock := system.Clock{}
	credVault := sqlite.NewCredentialVault(db, newCipher, clock)
	certVault := sqlite.NewCertificateVault(db, newCipher, clock)

	// Rotate both tables in ONE transaction (SIN-69372): if the certificate rewrite
	// fails after the credential rewrite has been staged, nothing is committed and the
	// vault stays fully readable with the OLD key, so a retry with the same pair works.
	credN, certN, err := sqlite.ResealAll(ctx, credVault, certVault, oldCipher)
	if err != nil {
		return err
	}

	log.Printf("vault-reseal: re-encrypted %d credential row(s) and %d certificate row(s) to the new KEK", credN, certN)
	log.Print("vault-reseal: done — now set PAYMENT_BANK_VAULT_KEY to the new key for the api process and clear PAYMENT_BANK_VAULT_KEY_PREVIOUS")
	return nil
}

// decodeCipher builds an AES-256-GCM cipher from a hex-encoded 32-byte key,
// without ever echoing the key material into an error.
func decodeCipher(hexKey string) (*secret.Cipher, error) {
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("not valid hex")
	}
	c, err := secret.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return c, nil
}

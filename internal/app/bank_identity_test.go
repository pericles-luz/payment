package app_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	auditlog "github.com/ia-dev-sindireceita/payment/internal/adapters/audit/inmemory"
	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// A conta do banco (client_id) é a SEGUNDA identidade que o C6 usa para rotear webhook.
// Só o canal `pix` é registrado pela chave; `rec`, `cobr` e `checkout` vão pela conta.
//
// Quer dizer: dois tenants ativos com chaves PIX DIFERENTES mas a mesma conta C6 ainda
// se sobrescrevem em três dos quatro canais — inclusive `checkout`, que é por onde chega
// o aviso de pagamento com CARTÃO. Dar chaves diferentes resolve um quarto do problema.

// credWriterRecorder records whether the credential write reached the vault.
type credWriterRecorder struct{ writes int }

func (c *credWriterRecorder) SetBankCredential(context.Context, string, string, string, string) error {
	c.writes++
	return nil
}

func newConsoleForClientIDTest(t *testing.T, sharing ports.CreditorKeySharingLookup) (*app.ConsoleService, *credWriterRecorder) {
	t.Helper()
	store := persistence.NewStore()
	rec := &credWriterRecorder{}
	svc := app.NewConsoleService(app.ConsoleDeps{
		Tenants: store, Accounts: store, Pricing: store, Ledger: store,
		CredWriter: rec, Sharing: sharing, Audit: auditlog.NewLog(),
		Clock: fixedClock{t: time.Unix(1000, 0).UTC()}, IDs: &seqIDs{},
	})
	seedTenant(t, store, "t-novo", "Nova", true, 100)
	seedTenant(t, store, "t-ativo", "Ativa", true, 100)
	seedTenant(t, store, "t-suspenso", "Suspensa", false, 100)
	return svc, rec
}

func newAdminForClientIDTest(t *testing.T, sharing ports.CreditorKeySharingLookup) (*app.AdminService, *credWriterRecorder) {
	t.Helper()
	store := persistence.NewStore()
	rec := &credWriterRecorder{}
	svc := app.NewAdminService(app.Deps{
		Tenants: store, Pricing: store, CredWriter: rec, Sharing: sharing,
		Audit: auditlog.NewLog(), Clock: fixedClock{t: time.Unix(1000, 0).UTC()}, IDs: &seqIDs{},
	})
	seedTenant(t, store, "t-novo", "Nova", true, 100)
	seedTenant(t, store, "t-ativo", "Ativa", true, 100)
	return svc, rec
}

func TestConsoleSetBankCredentialRejectsClientIDOfAnotherActiveTenant(t *testing.T) {
	t.Parallel()
	const conta = "cli-compartilhado"
	svc, rec := newConsoleForClientIDTest(t, &fakeSharing{byClientID: map[string][]string{conta: {"t-ativo"}}})

	err := svc.SetBankCredential(context.Background(), "t-novo", conta, "segredo")
	if err == nil {
		t.Fatal("gravou a conta C6 de outra empresa ATIVA: as duas passariam a se\nsobrescrever nos canais rec, cobr e checkout — o aviso de cartão inclusive")
	}
	if !strings.Contains(err.Error(), "outra empresa ativa") {
		t.Fatalf("erro pouco explicativo para quem configura: %v", err)
	}
	if rec.writes != 0 {
		t.Fatalf("a credencial chegou ao cofre mesmo com a recusa (writes=%d)", rec.writes)
	}
}

// O caminho por banco explícito é outro ponto de escrita e não pode divergir do primeiro.
func TestConsoleSetBankCredentialForRejectsClientIDOfAnotherActiveTenant(t *testing.T) {
	t.Parallel()
	const conta = "cli-compartilhado"
	svc, rec := newConsoleForClientIDTest(t, &fakeSharing{byClientID: map[string][]string{conta: {"t-ativo"}}})

	if err := svc.SetBankCredentialFor(context.Background(), "t-novo", ports.BankIDC6, conta, "segredo"); err == nil {
		t.Fatal("o caminho por banco explícito não aplicou a trava")
	}
	if rec.writes != 0 {
		t.Fatalf("writes = %d, want 0", rec.writes)
	}
}

// O admin serve TAMBÉM o self-serve (mesma implementação interna), então cobri-lo cobre
// a rota que a própria empresa-cliente usa.
func TestAdminSetBankCredentialRejectsClientIDOfAnotherActiveTenant(t *testing.T) {
	t.Parallel()
	const conta = "cli-compartilhado"
	svc, rec := newAdminForClientIDTest(t, &fakeSharing{byClientID: map[string][]string{conta: {"t-ativo"}}})

	if err := svc.SetBankCredential(context.Background(), "t-novo", ports.BankIDC6, conta, "segredo"); err == nil {
		t.Fatal("o plano administrativo não aplicou a trava; ele serve também o self-serve")
	}
	if rec.writes != 0 {
		t.Fatalf("writes = %d, want 0", rec.writes)
	}
}

// Um detentor SUSPENSO não disputa: ele nem registra webhook. Barrar por causa dele
// impediria recadastrar uma empresa com a própria conta — que é a situação da Verz.
func TestSetBankCredentialAllowsClientIDHeldOnlyBySuspendedTenant(t *testing.T) {
	t.Parallel()
	const conta = "cli-compartilhado"
	svc, rec := newConsoleForClientIDTest(t, &fakeSharing{byClientID: map[string][]string{conta: {"t-suspenso"}}})

	if err := svc.SetBankCredential(context.Background(), "t-novo", conta, "segredo"); err != nil {
		t.Fatalf("um detentor suspenso não disputa a conta e não deveria bloquear: %v", err)
	}
	if rec.writes != 1 {
		t.Fatalf("writes = %d, want 1", rec.writes)
	}
}

// Rotacionar o próprio segredo mantém o mesmo client_id — não é colisão.
func TestSetBankCredentialAllowsRotatingOwnClientID(t *testing.T) {
	t.Parallel()
	const conta = "cli-proprio"
	svc, rec := newConsoleForClientIDTest(t, &fakeSharing{byClientID: map[string][]string{conta: {"t-novo"}}})

	if err := svc.SetBankCredential(context.Background(), "t-novo", conta, "segredo-novo"); err != nil {
		t.Fatalf("o próprio dono foi barrado da própria conta: %v", err)
	}
	if rec.writes != 1 {
		t.Fatalf("writes = %d, want 1", rec.writes)
	}
}

// Falha fechado, como na chave.
func TestSetBankCredentialFailsClosedWhenLookupFails(t *testing.T) {
	t.Parallel()
	svc, rec := newConsoleForClientIDTest(t, &fakeSharing{err: errors.New("database is locked")})

	if err := svc.SetBankCredential(context.Background(), "t-novo", "cli-1", "segredo"); err == nil {
		t.Fatal("gravou sem conseguir verificar se a conta já tinha dono")
	}
	if rec.writes != 0 {
		t.Fatalf("writes = %d, want 0", rec.writes)
	}
}

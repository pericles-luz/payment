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

// Uma chave PIX pertence a UMA empresa ativa de cada vez.
//
// No C6 o webhook é registrado POR CHAVE, com uma URL só por chave. Duas empresas ativas
// com a mesma chave se sobrescrevem a cada registro: o aviso de pagamento chega por um
// ref que não é do dono da cobrança, é recusado, e a liquidação passa a depender de
// varredura. A empresa 27 viveu isso em produção (SIN-69368). Barrar na GRAVAÇÃO é o
// único lugar onde o problema custa uma mensagem de erro em vez de um pagamento mudo.

// fakeSharing implements ports.CreditorKeySharingLookup with scripted holders.
type fakeSharing struct {
	byKey      map[string][]string
	byClientID map[string][]string
	err        error
}

func (f *fakeSharing) FindTenantsByCreditorKey(_ context.Context, _, key string) ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.byKey[key], nil
}

func (f *fakeSharing) FindTenantsByClientID(_ context.Context, _, clientID string) ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.byClientID[clientID], nil
}

// creditorKeyRecorder records whether the write actually reached the vault.
type creditorKeyRecorder struct {
	writes int
}

func (c *creditorKeyRecorder) SetCreditorKey(context.Context, string, string) error {
	c.writes++
	return nil
}

// newConsoleForKeyTest wires a console with the sharing lookup and two tenants: "t-ativo"
// (active) and "t-suspenso" (suspended).
func newConsoleForKeyTest(t *testing.T, sharing ports.CreditorKeySharingLookup) (*app.ConsoleService, *creditorKeyRecorder) {
	t.Helper()
	store := persistence.NewStore()
	rec := &creditorKeyRecorder{}
	svc := app.NewConsoleService(app.ConsoleDeps{
		Tenants:        store,
		Accounts:       store,
		Pricing:        store,
		Ledger:         store,
		CreditorWriter: rec,
		Sharing:        sharing,
		Audit:          auditlog.NewLog(),
		Clock:          fixedClock{t: time.Unix(1000, 0).UTC()},
		IDs:            &seqIDs{},
	})
	seedTenant(t, store, "t-novo", "Nova", true, 100)
	seedTenant(t, store, "t-ativo", "Ativa", true, 100)
	seedTenant(t, store, "t-suspenso", "Suspensa", false, 100)
	return svc, rec
}

func TestSetCreditorKeyRejectsKeyHeldByAnotherActiveTenant(t *testing.T) {
	t.Parallel()
	const chave = "11999990000"
	svc, rec := newConsoleForKeyTest(t, &fakeSharing{byKey: map[string][]string{chave: {"t-ativo"}}})

	err := svc.SetCreditorKey(context.Background(), "t-novo", chave)
	if err == nil {
		t.Fatal("gravou uma chave que outra empresa ATIVA já usa: as duas passariam a se\nsobrescrever no C6 e os avisos de pagamento seriam recusados")
	}
	if !strings.Contains(err.Error(), "outra empresa ativa") {
		t.Fatalf("erro pouco explicativo para quem está configurando: %v", err)
	}
	if rec.writes != 0 {
		t.Fatalf("a chave chegou ao cofre mesmo com a recusa (writes=%d)", rec.writes)
	}
}

// Um detentor SUSPENSO não disputa nada — ele nem registra webhook. Barrar por causa
// dele impediria uma empresa de reaproveitar a própria chave depois de recadastrada,
// que é exatamente a situação da Verz hoje.
func TestSetCreditorKeyAllowsKeyHeldOnlyBySuspendedTenant(t *testing.T) {
	t.Parallel()
	const chave = "11999990000"
	svc, rec := newConsoleForKeyTest(t, &fakeSharing{byKey: map[string][]string{chave: {"t-suspenso"}}})

	if err := svc.SetCreditorKey(context.Background(), "t-novo", chave); err != nil {
		t.Fatalf("um detentor suspenso não disputa a chave e não deveria bloquear: %v", err)
	}
	if rec.writes != 1 {
		t.Fatalf("writes = %d, want 1", rec.writes)
	}
}

// Regravar a PRÓPRIA chave é rotação, não colisão.
func TestSetCreditorKeyAllowsRewritingOwnKey(t *testing.T) {
	t.Parallel()
	const chave = "11999990000"
	svc, rec := newConsoleForKeyTest(t, &fakeSharing{byKey: map[string][]string{chave: {"t-novo"}}})

	if err := svc.SetCreditorKey(context.Background(), "t-novo", chave); err != nil {
		t.Fatalf("o próprio dono foi barrado da própria chave: %v", err)
	}
	if rec.writes != 1 {
		t.Fatalf("writes = %d, want 1", rec.writes)
	}
}

// Falha fechado: sem resposta da consulta, não grava. Uma chave gravada por engano é
// cara de descobrir e cara de desfazer; um erro transitório custa "tente de novo".
func TestSetCreditorKeyFailsClosedWhenLookupFails(t *testing.T) {
	t.Parallel()
	svc, rec := newConsoleForKeyTest(t, &fakeSharing{err: errors.New("database is locked")})

	if err := svc.SetCreditorKey(context.Background(), "t-novo", "11999990000"); err == nil {
		t.Fatal("gravou sem conseguir verificar se a chave já tinha dono")
	}
	if rec.writes != 0 {
		t.Fatalf("writes = %d, want 0", rec.writes)
	}
}

// A remoção de config de banco desregistra no PSP por CHAVE (canal PIX) e por CONTA do
// client_id (canais de recorrência) — quer dizer, sobre a IDENTIDADE, não sobre este
// tenant. Se outro tenant ATIVO divide essa identidade, remover um derruba a inscrição
// VIVA do outro. E nada a refaz: a varredura de renovação está desligada.
//
// É concreto: a Verz tem o mesmo cadastro duas vezes, um suspenso e um ativo, com a
// mesma chave. Limpar o suspenso deixaria a empresa ativa sem webhook, em silêncio.
func TestRemoveBankConfigSkipsPSPWhenIdentitySharedWithActiveTenant(t *testing.T) {
	t.Parallel()
	const chave = "11999990000"
	events := []string{}
	dereg := &recordingDeregistrar{}
	order := &orderRecorder{events: &events, cred: ports.BankCredential{CreditorKey: chave, ClientID: "cli-1"}}

	store := persistence.NewStore()
	svc := app.NewConsoleService(app.ConsoleDeps{
		Tenants: store, Accounts: store, Pricing: store, Ledger: store,
		CredDeleter: order, Creds: order, WebhookDeregistrar: dereg,
		Sharing: &fakeSharing{byKey: map[string][]string{chave: {"t1", "t-ativo"}}},
		Audit:   auditlog.NewLog(),
		Clock:   fixedClock{t: time.Unix(1000, 0).UTC()}, IDs: &seqIDs{},
	})
	seedTenant(t, store, "t1", "Suspensa", false, 100)
	seedTenant(t, store, "t-ativo", "Ativa", true, 100)

	if err := svc.RemoveBankConfig(context.Background(), "t1", ports.BankIDC6); err != nil {
		t.Fatalf("RemoveBankConfig: %v", err)
	}
	if len(dereg.calls) != 0 {
		t.Fatalf("desregistrou no PSP %v: essa inscrição é da empresa ATIVA que divide a\nchave, e nada a refaria", dereg.calls)
	}
	// O nosso lado tem de sair mesmo assim — a remoção não vira no-op.
	if !contains(events, "delete-credential") {
		t.Fatalf("a credencial não foi apagada: %v", events)
	}
}

// A contrapartida: sem ninguém dividindo a identidade, desregistra os três canais como
// sempre — deixar inscrição órfã no PSP faria o C6 nos chamar por uma credencial que
// não existe mais.
func TestRemoveBankConfigStillDeregistersWhenIdentityNotShared(t *testing.T) {
	t.Parallel()
	const chave = "11999990000"
	events := []string{}
	dereg := &recordingDeregistrar{}
	order := &orderRecorder{events: &events, cred: ports.BankCredential{CreditorKey: chave, ClientID: "cli-1"}}

	store := persistence.NewStore()
	svc := app.NewConsoleService(app.ConsoleDeps{
		Tenants: store, Accounts: store, Pricing: store, Ledger: store,
		CredDeleter: order, Creds: order, WebhookDeregistrar: dereg,
		Sharing: &fakeSharing{byKey: map[string][]string{chave: {"t1"}}},
		Audit:   auditlog.NewLog(),
		Clock:   fixedClock{t: time.Unix(1000, 0).UTC()}, IDs: &seqIDs{},
	})
	seedTenant(t, store, "t1", "Acme", true, 100)

	if err := svc.RemoveBankConfig(context.Background(), "t1", ports.BankIDC6); err != nil {
		t.Fatalf("RemoveBankConfig: %v", err)
	}
	if len(dereg.calls) != 3 {
		t.Fatalf("desregistrou %v, esperava os três canais (pix, rec, cobr)", dereg.calls)
	}
	if dereg.pixKey != chave {
		t.Fatalf("canal PIX desregistrado pela chave %q, want %q", dereg.pixKey, chave)
	}
}

// Falha fechado também aqui: sem saber se alguém divide a identidade, NÃO desregistra.
// Deixar inscrição órfã é reparável; derrubar o webhook de uma empresa ativa é mudo.
func TestRemoveBankConfigSkipsPSPWhenSharingLookupFails(t *testing.T) {
	t.Parallel()
	events := []string{}
	dereg := &recordingDeregistrar{}
	order := &orderRecorder{events: &events, cred: ports.BankCredential{CreditorKey: "11999990000", ClientID: "cli-1"}}

	store := persistence.NewStore()
	svc := app.NewConsoleService(app.ConsoleDeps{
		Tenants: store, Accounts: store, Pricing: store, Ledger: store,
		CredDeleter: order, Creds: order, WebhookDeregistrar: dereg,
		Sharing: &fakeSharing{err: errors.New("database is locked")},
		Audit:   auditlog.NewLog(),
		Clock:   fixedClock{t: time.Unix(1000, 0).UTC()}, IDs: &seqIDs{},
	})
	seedTenant(t, store, "t1", "Acme", true, 100)

	if err := svc.RemoveBankConfig(context.Background(), "t1", ports.BankIDC6); err != nil {
		t.Fatalf("RemoveBankConfig: %v", err)
	}
	if len(dereg.calls) != 0 {
		t.Fatalf("desregistrou %v sem conseguir verificar quem divide a identidade", dereg.calls)
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

# payment

Plataforma de pagamentos multi-tenant em Go, usada como SaaS por outros
sistemas. Intermedeia cobranças/pagamentos de várias empresas (tenants) contra
bancos (C6 primeiro), com tarifação por endpoint, área administrativa e
consumidores assíncronos.

Este repositório é a **fundação de engenharia** (workstream #1). O adapter real
do banco C6, PIX Automático, BolePix e checkout são workstreams seguintes.

## Arquitetura — Hexagonal (Ports & Adapters)

O núcleo de domínio é **puro**: não importa `database/sql`, `net/http` nem SDKs
de terceiros. Todo efeito colateral fica atrás de um *port* (interface), com
*adapters* concretos plugáveis.

```
            driving adapters                         driven adapters (ports out)
        (entram no app pelo input)                  (o app sai pelo output)
   ┌───────────────────────────────┐        ┌──────────────────────────────────┐
   │ HTTP API tenant  (cmd/api)     │        │ Repository      → SQLite | memory │
   │ Admin plane      (cmd/api)     │        │ MessageBus      → RabbitMQ| memory│
   │ Bank webhook     (cmd/api)     │  ───►  │ BankProvider    → stub (C6 depois)│
   │ Worker/consumers (cmd/worker)  │        │ CredentialStore → secret/env      │
   └───────────────┬───────────────┘        │ Clock, IDProvider → system        │
                   │                         └──────────────────────────────────┘
                   ▼
        ┌────────────────────────┐
        │ internal/app (use-cases)│  orquestra domínio + ports
        ├────────────────────────┤
        │ internal/domain         │  agregados puros: payment | tenant | billing
        │   + invariantes         │
        └────────────────────────┘
```

### Layout

| Caminho | Responsabilidade |
|---------|------------------|
| `internal/domain/{payment,tenant,billing,shared}` | Agregados puros e invariantes. Sem infra. |
| `internal/ports` | Interfaces de saída (Repository, MessageBus, BankProvider, CredentialStore, Clock, IDProvider, ProcessedEventStore). |
| `internal/app` | Serviços de aplicação (use-cases): criar cobrança, webhook, admin. |
| `internal/adapters/persistence/sqlite` | Repository em SQLite (driver puro-Go `modernc.org/sqlite`). |
| `internal/adapters/persistence/inmemory` | Repository em memória — demonstra plugabilidade e serve testes. |
| `internal/adapters/messaging/rabbitmq` | MessageBus em RabbitMQ (`amqp091-go`). |
| `internal/adapters/messaging/inmemory` | MessageBus em memória (fallback/teste). |
| `internal/adapters/bank` | `BankProvider` stub (C6 é workstream seguinte). |
| `internal/adapters/secret` | `CredentialStore` — credenciais bancárias isoladas por tenant, fora do código. |
| `internal/adapters/system` | `Clock` e `IDProvider` (id aleatório, não sequencial). |
| `internal/adapters/http` | Driving adapter HTTP: API tenant, admin, webhook, auth, rate-limit. |
| `internal/platform/config` | Configuração via ambiente (segredos fora do código). |
| `cmd/api`, `cmd/worker` | Entrypoints: wiring dos adapters + graceful shutdown. |
| `migrations` | SQL portável (SQLite agora, Postgres depois), com passo de rollback. |
| `docs/security` | Threat model + baseline seguro (gate de revisão do PR). |
| `docs/compliance` | Conformidade contratual C6 (Termo de APIs): **regras BLOQUEANTES A1–A7** + gap analysis ([`c6-termo-apis-regras.md`](docs/compliance/c6-termo-apis-regras.md)). |

### Plugabilidade demonstrada

Trocar a persistência de **SQLite** para **memória** (ou o bus de RabbitMQ para
memória) é mudança **só de wiring** em `cmd/` — o domínio e os use-cases não
mudam. Ambos os adapters de `Repository` implementam as mesmas interfaces em
`internal/ports` e há teste de integração para o adapter SQLite
(`internal/adapters/persistence/sqlite/sqlite_test.go`).

## Multi-tenancy e segurança (resumo)

- `tenant_id` em todos os agregados e queries; `Repository` **sempre** escopado
  por tenant. O `tenant_id` vem da credencial autenticada, **nunca** do input.
- Tarifação por endpoint: tabela `endpoint_pricing(tenant_id, endpoint, price_cents)`
  + ledger append-only autoritativo de billing.
- Credenciais bancárias isoladas por tenant via `CredentialStore` — nenhum
  segredo em código, URL ou log.
- API deny-by-default: autenticação em todo endpoint, validação na borda
  (DTOs explícitos, rejeição de campos desconhecidos), **idempotency keys** em
  escrita, rate-limit por tenant/IP.
- Webhook do banco: autenticação failure-closed (mTLS em produção; segredo
  comparado em tempo constante no scaffold), **idempotência/anti-replay** e
  **reconciliação** com o banco antes de marcar pago (o webhook é só gatilho).

Detalhes e modelo de ameaças em [`docs/security`](docs/security/README.md).

## Como rodar e testar

Requer Go 1.26+ (versão estável atual; o gate `govulncheck` exige uma stdlib sem
vulnerabilidades conhecidas chamadas pelo código).

```bash
# Build de tudo
go build ./...

# Vet + testes + gate de cobertura (>85%, exclui cmd/ que é só wiring)
go vet ./...
bash scripts/coverage.sh 85

# Subir a API (SQLite local + bus em memória)
PAYMENT_TENANT_TOKENS="tok-acme:tenant-id-acme" \
PAYMENT_ADMIN_TOKENS="admin-token" \
PAYMENT_WEBHOOK_SECRET="dev-webhook-secret" \
PAYMENT_BANK_CREDS="tenant-id-acme:client-id:client-secret" \
go run ./cmd/api

# Worker (consumidores)
go run ./cmd/worker
```

Variáveis de ambiente (todas opcionais, com defaults seguros):

| Var | Default | Descrição |
|-----|---------|-----------|
| `PAYMENT_HTTP_ADDR` | `:8080` | Endereço de escuta da API. |
| `PAYMENT_DB_PATH` | `payment.db` | Caminho do arquivo SQLite. |
| `PAYMENT_TENANT_TOKENS` | — | `token:tenantID,...` (em produção: IdP/mTLS). |
| `PAYMENT_ADMIN_TOKENS` | — | Tokens do plano admin, separados por vírgula. |
| `PAYMENT_WEBHOOK_SECRET` | — | Segredo do webhook (em produção: mTLS). |
| `PAYMENT_BANK_CREDS` | — | `tenant:clientID:secret,...` (em produção: vault). |
| `PAYMENT_BANK_CREDITOR_KEYS` | — | `tenant:creditorKey,...` — chave PIX do recebedor por tenant, injetada na cob/cobv (ADR-0004). Não-segredo, mas sensível a roteamento; nunca logada. |
| `PAYMENT_RABBIT_URL` | — | URL do RabbitMQ (vazio = bus em memória). |

> Os tokens/segredos acima são de **desenvolvimento**. Em produção use um IdP /
> secret manager / mTLS — a forma das interfaces não muda.

### Migrations

Migrations vivem em `migrations/` e são embarcadas no binário. São escritas em
SQL portável visando Postgres depois (sem tipos específicos de SQLite); cada
migração tem o par `*.up.sql` / `*.down.sql` (passo de rollback
backward-compatible).

## Governança de branch / PR

Repositório de desenvolvimento: **fork** `ia-dev-sindireceita/payment`
(default branch `main`). Upstream de produção: `pericles-luz/payment`.

- Trabalhe a partir de `main` do fork, em uma **branch de feature**.
- Abra PR para `ia-dev-sindireceita/payment:main`. **No máximo 1 PR aberto por
  vez** no fork (por engenheiro).
- **Só o CTO faz merge** no fork. Engenheiros não dão `gh pr merge`.
- CI precisa estar **verde** (build, vet, gofmt, test, cobertura > 85%,
  staticcheck, govulncheck) antes do merge — os checks são *required*.
- Promoção para `pericles-luz/payment` (produção) é feita pelo CTO, **1 PR
  aberto por vez**, com merge só pelo board.

## CI / gates (bloqueiam merge)

`.github/workflows/ci.yml` roda em todo PR:

1. `go build ./...`
2. `go vet ./...`
3. `gofmt -l .` (falha se houver arquivo não formatado)
4. `scripts/coverage.sh 85` — testes + **cobertura > 85%** (falha o job se ≤ 85%)
5. `staticcheck ./...`
6. `govulncheck ./...`

Configure esses checks como **required** na proteção da branch `main` do fork.

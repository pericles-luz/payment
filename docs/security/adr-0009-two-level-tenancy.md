# ADR-0009 — Tenancy de dois níveis (usuário-API → empresas-clientes)

- **Status:** Aceito — premissa comercial/regulatória (modelo **(a)**, PSP-Indireto pass-through) **ratificada pelo CEO em 2026-08-12** ([SIN-69119](/SIN/issues/SIN-69119)), por conformidade com a decisão de board SIN-67474/67476 (split-payment: motor é do banco; não somos marketplace) e com o guardrail **A1** (nunca cobrar/custodiar em nome do C6).
- **Design:** CTO — `plans/SIN-69119-tenancy-2-niveis-design.md` (§2, §3, §4, §6). **F0 (fundação, este ADR + schema):** Coder ([SIN-69124](/SIN/issues/SIN-69124)). **Aprovação de impl:** review = SecurityEngineer → approval = CTO.
- **Keystone de:** [SIN-69118](/SIN/issues/SIN-69118) (go-live produção C6 / 1º cliente Verz). **Bloqueia** as trilhas B (billing/faturas), C (admin UX) e D (manual OpenAPI).
- **Lentes:** Hexagonal (Ports & Adapters), DDD-lite (agregados separados), Secure-by-default / Least-privilege / OWASP A01 (Broken Access Control), Reversibilidade / blast-radius, Boring-tech.

## Contexto

O modelo hoje é **plano**: 1 token = 1 tenant = 1 empresa. Auditado no código (design §1):

- **Choke-point ÚNICO de resolução de tenant** — `tenantAuthMiddleware` (`internal/adapters/http/auth.go`), registrado uma vez em `r.Route("/v1", …)`. Todo handler `/v1` lê o tenant apenas via `tenantFromContext(ctx)`, **nunca** de input do cliente (isolamento server-enforced, já testado — `rbac_test.go`).
- **Choke-point ÚNICO de metering** — `LedgerRepository.AppendLedgerEntry`, chamado dentro da UoW transacional junto à escrita do pagamento (atomicidade — `atomicity_test.go`). Preço já é por `(tenant × rota)`.
- **Credenciais/certs keyed por `(tenantID, bankID)`** (ADR-0007/0008), inalterados.

O go-live do 1º cliente (Verz) precisa de um **2º nível**: um **usuário-API / revendedor** que agrupa várias **empresas-clientes**, fatura por uso e administra o conjunto — **sem** custodiar fundos.

## Decisão

### 1. `empresa-cliente ≡ tenant`; `Account` é um agregado NOVO *acima* do tenant

Adotamos o **modelo (a)**: cada empresa-cliente detém a **própria** credencial C6 e recebe o **próprio** dinheiro; a empresa-cliente **é um `tenant`** no modelo atual. Nós/Verz **nunca** custodiamos nem roteamos fundos → permanecemos **PSP-Indireto pass-through**. Verz revende **ACESSO ao gateway**, faturado por uso; o dinheiro do PIX/boleto nunca passa por Verz nem por nós.

O modelo (b) — Verz detém UMA credencial C6 e as empresas-clientes são sub-recebedores — foi **rejeitado**: nos tornaria custodiante/roteador de fundos = split nativo (que o C6 não oferece, SIN-67475) = trilha regulada PSP-Direto. Fora de escopo, evitado pelo board.

O 2º nível — o **`Account`** (usuário-API / revendedor) — tem três papéis e **nenhum** toca dinheiro: (1) identidade de acesso à API; (2) alvo de rollup de billing; (3) agrupador administrativo.

### 2. Modelo de domínio

```
Account{ id, name, active, createdAt }              // agregado NOVO, sem credencial de banco
Tenant{  id, name, active, createdAt, accountID }    // + accountID (dono)
```

- Um `Account` possui N `Tenant`s **por referência (id)**, não por composição — agregados **separados** (DDD-lite). O self-join `tenants.parent_tenant_id` foi **rejeitado** (design §4 nota): misturaria "conta vs. empresa" na mesma tabela, abrindo ambiguidade e o risco de um tenant virar pai de si.
- **Invariante:** um tenant pertence a **exatamente um** account. `accountID` é **IMUTÁVEL** após atribuído — sem re-parent → sem deriva de atribuição de billing/dados. No domínio, `Tenant.AssignAccount` é *set-once*: liga a partir de vazio, é idempotente para o mesmo id e **rejeita** a religação a um account diferente.
- **Semântica NULL-safe:** `accountID`/`account_id` vazio/NULL ⇒ **"self-account do tenant"**. Um tenant legado plano é só um account de 1 tenant, 1:1.

### 3. Escopo de auth — token escopado por empresa-cliente (F1, fora deste F0)

O token continua resolvendo **direto** para um `tenantID`; adicionalmente resolveremos o `accountID` dono no MESMO `tenantAuthMiddleware`, injetando `ctxAccountID` (novo) além do `ctxTenantID` (inalterado). **A empresa-cliente é selecionada pelo próprio token — não há seletor de cliente no request.** Assim o **isolamento entre empresas-clientes é IDÊNTICO ao isolamento entre tenants de hoje** (já server-enforced, já testado): não existe seletor para errar, então uma classe inteira de Broken Access Control (**OWASP A01**) é projetada para fora. O account é **atribuição-only**; nunca amplia o escopo de tenant.

### 4. Migração `0007` (backward-compatible, ships dark)

- cria `accounts(id, name, active, created_at)`;
- adiciona `tenants.account_id TEXT NULL` + FK → `accounts(id)`;
- **backfill self-account 1:1** por tenant existente (id derivado `'acct-' || tenant.id`, name/active/created_at espelhados) e seta `account_id`;
- adiciona `billing_ledger.account_id TEXT NULL` (+ backfill do self-account) e índice `(account_id, at)` para o rollup da fatura;
- `endpoint_pricing` **permanece keyed por tenant** — preço por empresa-cliente já sai de graça; nada muda;
- `0007_*.down.sql` dropa índice/colunas/tabela em ordem FK-safe — **reversível**.

> **Escopo de F0 vs. §4 completo:** o `0007` deste F0 entrega `accounts` + `tenants.account_id` + `billing_ledger.account_id` (design §6, linha F0). O `audit_log.account_id` ("completude forense do rollup por usuário-API") é **deferido para F2**: um teste-whitelist de segurança (`TestAuditSchemaCarriesNoSecretColumn`) fixa o conjunto exato de colunas de `audit_log` para barrar coluna portadora de segredo (ameaça C1/C4), e adicionar `account_id` exige atualizar a allow-list desse teste (mesma manutenção que `bank_id` exigiu em 0003/SIN-66044) — o que requer autorização do CTO pela regra de imutabilidade de testes. O backfill `SET account_id = 'acct-' || tenant_id` é igualmente correto quando a coluna for adicionada, então nenhum dado forense se perde na espera.

## Garantias de segurança (tecidas no design)

1. **Choke-point único de resolução** permanece `tenantAuthMiddleware`; o account é resolvido no mesmo ponto, server-side, nunca de input. Sem 2ª via.
2. **Isolamento entre empresas-clientes = isolamento entre tenants atual** (token→tenant direto). O nível account nunca enfraquece o escopo de tenant.
3. **Listagens por account** (F3) filtram deny-by-default; empresa de outro account = 404, não oráculo cross-account.
4. **Sem seletor de cliente** no modelo primário ⇒ sem nova superfície A01.
5. **Migração backward-compatible** com backfill self-account e `down` reversível; contrato `/v1` e keying `(tenant,bank)` intocados.

## Consequências

- **Blast radius mínimo (dark ship):** nenhum handler `/v1`, nenhuma linha de metering existente e nenhuma credencial `(tenant,bank)` muda de forma. O F0 apenas alarga o schema e o domínio.
- **Reversível:** `0007.down` restaura o modelo plano; o domínio tolera `accountID` vazio (self-account) sem mudança de comportamento.
- **Desbloqueia** F1 (choke-point carrega account), F2 (metering por account — coluna já existe), F3 (admin accounts/empresas-clientes) e F4/trilha B (faturas por account).
- **Fora de escopo (F5, sob demanda):** account-token único + seletor `X-Client-Company` para revendedores self-service — aditivo, autorizado contra o account (deny-by-default, 404 sem oráculo), resolve para o mesmo `ctxTenantID`.

## Pendências não-bloqueantes

- **Board:** modelo de preço no nível account vs. por empresa-cliente (tabela final). Não bloqueia F0–F3 (design §8).

## Alternativas consideradas

- **Self-join `tenants.parent_tenant_id`** — rejeitado (§2): ambiguidade de agregado + risco de auto-parent.
- **Modelo (b) — Verz como merchant C6 único, empresas como sub-recebedores** — rejeitado (§1): trilha regulada PSP-Direto / split nativo inexistente no C6.
- **Token único + seletor de empresa-cliente no header/path** — adiado para F5 opcional (§3): introduz superfície A01 desnecessária para o go-live da Verz.

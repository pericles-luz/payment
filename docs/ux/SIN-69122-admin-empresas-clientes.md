# SIN-69122 — Área admin: empresas-clientes, uso por cliente e faturas (UX + spec de implementação)

**Trilha C de [SIN-69118] (produção · 1º cliente Verz).** Depende de A (tenancy 2 níveis,
[SIN-69119]) e coordena com B (bilhetagem/faturas, [SIN-69121]). Ambas `done`+`merged`.

**Status:** spec para aceite (CTO/UX). **Autor:** Coder. **Data:** 2026-08-12.

Objetivo: fechar o gap entre o domínio de 2 níveis (que já existe e navega no escuro)
e o console HTMX (que hoje só enxerga `tenant` plano). Este documento é a especificação
de UX **e** de implementação, aterrada no código já mergeado, de forma que
FrontendCoder/Coder possam implementar sem novas decisões de arquitetura após o aceite.

---

## 1. Terminologia (contrato de nomes na UI)

O plano e o domínio usam dois níveis. A UI precisa de rótulos estáveis em pt-BR:

| Domínio / plano | Papel | Rótulo na UI | Exemplo |
|---|---|---|---|
| `account.Account` | usuário-API / revendedor (paga a fatura, é o "dono" do token) | **Conta** (menu: **Contas**) | Verz |
| `tenant.Tenant` (com `AccountID`) | empresa-cliente que opera as vendas | **Empresa-cliente** (dentro da Conta) | um cliente da Verz |

Regra: uma **Conta** possui N **empresas-clientes**. A Conta nunca guarda credencial de
banco e nunca toca em dinheiro (modelo (a) PSP-Indireto, ADR-0009). Credenciais, certificados
mTLS, chave PIX e bilhetagem continuam ancorados na **empresa-cliente** (tenant), exatamente
como hoje.

> **Retrocompat (ADR-0009 §4):** um tenant legado/plano pertence à sua *self-account*
> derivada `acct-<tenantID>` (`account.SelfAccountID`). Na UI isso aparece como uma Conta
> implícita "1 empresa" — ver §6.

---

## 2. O que JÁ existe (não refazer)

Console HTMX (`internal/adapters/http/console_handlers.go`, `internal/adapters/adminweb/`),
todo tenant-cêntrico, RBAC deny-by-default + CSRF + rate-limit já aplicados no grupo `/console`:

- **Tenants:** lista com busca/status (`/console/tenants`), criar (`/tenants/new`),
  detalhe (`/tenants/{id}`), suspender/ativar.
- **Sub-abas do tenant:** Bancos, Tarifação, **Consumo** (range de datas + linhas + CSV:
  `/consumption`, `/consumption/rows`, `/consumption.csv`), **Faturas**
  (gerar `POST /invoices`, listar `/invoices`, baixar `/invoices/{invId}.csv`).
- **Domínio de 2 níveis pronto, no escuro:**
  - `account.Account` (id, name, active, createdAt; `New`/`Rehydrate`; `SelfAccountID`).
  - `tenant.Tenant.AccountID()` — vínculo com a Conta dona.
  - `billing.LedgerEntry.AccountID()` carimbado no choke-point (F1/F2) e o port
    `LedgerReader.ListLedgerEntriesByAccount(ctx, accountID)` — **o rollup
    account→tenant→endpoint já tem caminho de dados**.
  - `invoice.Invoice.AccountID()`; `ConsoleService.GenerateInvoice` já estampa `t.AccountID()`.

**Conclusão:** os dados de 2 níveis existem e são atribuíveis. Falta **superfície de UI**:
plano de Contas, visão de uso agregada por Conta, e faturas na ótica da Conta.

---

## 3. Gaps a implementar (o novo trabalho)

1. **Plano de Contas no console** — inexistente. Sem listar/criar/detalhar Conta, sem ver as
   empresas-clientes sob uma Conta, sem vincular empresa→Conta, sem suspender/ativar Conta.
   Não há `AccountStore` no `ConsoleService` nem rotas `/console/accounts`.
2. **Uso por empresa-cliente com rollup de Conta** — o consumo por tenant existe; falta a
   visão "uso da Conta" (soma por empresa-cliente sob a Conta, range de datas, CSV). Caminho
   de dados já existe (`ListLedgerEntriesByAccount`), falta use-case + handler + template.
3. **Faturas na ótica da Conta** — gerar/ver/baixar por empresa-cliente existe; falta listar
   as faturas de todas as empresas-clientes de uma Conta e (opcional) gerar o lote do período.

---

## 4. Arquitetura da informação e navegação

Menu principal (`layout.html`) hoje tem só **Tenants**. Nova IA:

```
Contas                      → /console/accounts            (nova aba de topo)
  └ <Conta> Visão geral     → /console/accounts/{acctId}
      ├ Empresas-clientes   → /console/accounts/{acctId}            (lista aninhada na visão geral)
      ├ Uso (Conta)         → /console/accounts/{acctId}/consumption
      └ Faturas (Conta)     → /console/accounts/{acctId}/invoices
Empresas-clientes           → /console/tenants             (aba existente, mantida)
  └ <Empresa> …             → /console/tenants/{id}/…       (Bancos/Tarifação/Consumo/Faturas — inalterado)
```

Decisões de IA:

- **Duas portas de entrada, uma verdade.** "Contas" é a entrada revenda-cêntrica (Verz →
  seus clientes). "Empresas-clientes" continua sendo a entrada operacional (a lista plana de
  todos os tenants). A tela de detalhe da empresa-cliente é a MESMA `tenant_detail`; ganha
  só um *breadcrumb* e um campo "Conta" (§5.3).
- **Não duplicar as telas do tenant.** Uso/Faturas da Conta são **rollups** que ligam para as
  telas por-empresa já existentes; não reimplementam bancos/tarifação/credenciais.
- **`aria-current`, `hx-get`/`hx-target="#main"`/`hx-push-url="true"`** exatamente no padrão de
  `tenant_detail.html` (navegação por swap parcial, com deep-link e histórico).

---

## 5. Telas (spec detalhada)

Cada tela lista: rota(s), view-model, template novo, e o port/use-case que falta. Todo
handler herda o middleware do grupo `/console` (auth+CSRF+rate-limit) — nenhuma exceção.

### 5.1 Contas — lista + criar

- **Rotas:** `GET /console/accounts` (página), `GET /console/accounts/rows` (partial de busca),
  `GET /console/accounts/new` (form), `POST /console/accounts` (criar).
- **UI:** espelha `tenants_list.html` + `tenant_new.html`. Colunas: Nome, Status
  (Ativa/Suspensa), Nº de empresas-clientes, Criada em. Busca por nome + filtro de status via
  `hx-get` em `keyup changed delay:300ms` (padrão da lista de tenants). Botão "Nova conta".
- **Criar:** form com um campo `name` (obrigatório, ≤200, `account.New` valida). Erros de campo
  renderizados inline (padrão `fieldErrors`). Sucesso → detalhe da Conta via `BodyWithOOB`
  (mesmo padrão de `consoleCreateTenant`).
- **Falta (impl):**
  - Port app-level `AccountStore` no `ConsoleService`:
    `SaveAccount`, `FindAccountByID`, `ListAccounts(ctx, query)`,
    `CountTenantsByAccount(ctx, acctID)` (ou reusar `ListTenantsByAccount`).
  - Adaptadores sqlite + inmemory (tabela `accounts` já criada na migração 0007).
  - Use-cases `CreateAccount`, `ListAccounts`, `GetAccount`.
  - View-models `AccountView`, `AccountListView`, `NewAccountView` + `ToAccountView(s)`.
  - Templates `accounts_list.html`, `account_new.html`, partial `account_rows`.

### 5.2 Conta — visão geral + empresas-clientes aninhadas + vincular

- **Rota:** `GET /console/accounts/{acctId}` — cabeçalho da Conta (nome, status, ações
  Suspender/Ativar espelhando o tenant) + **lista de empresas-clientes** sob a Conta.
- **Vincular empresa-cliente à Conta.** Duas formas, ambas necessárias:
  1. **Criar já vinculada:** `GET /console/accounts/{acctId}/tenants/new` + `POST
     /console/accounts/{acctId}/tenants` → cria o tenant já com `AccountID = acctId`.
  2. **Reatribuir existente:** `POST /console/tenants/{id}/account` com corpo `account_id`
     (mover uma empresa-cliente de uma Conta para outra; usado na migração de legados e em
     correção administrativa).
- **Ações da Conta:** `POST /console/accounts/{acctId}/suspend` e `/activate`
  (`Account.Deactivate`/`Activate`). Semântica de suspensão de Conta e seu efeito sobre auth
  (bloquear tokens das empresas-clientes?) é **decisão de A/segurança** — ver §7 open items;
  na v1 a suspensão é rótulo administrativo sem efeito em auth até o CTO ratificar.
- **Falta (impl):**
  - `ListTenantsByAccount(ctx, acctID)` no `TenantStore` (+ adaptadores).
  - `tenant` precisa de um caminho de reatribuição de Conta (`Tenant.AssignAccount(acctID)` ou
    via use-case `MoveTenantToAccount`) — **cruza fronteira de domínio, requer OK do CTO**
    (§7). A criação-já-vinculada NÃO cruza fronteira nova (o construtor de tenant já aceita
    accountID no F0), então pode ir antes.
  - Template `account_detail.html` (cabeçalho + tabela de empresas-clientes com link para
    `/console/tenants/{id}`), `account_tenant_new.html`.

### 5.3 Empresa-cliente (tenant_detail) — mostrar a Conta

- Alteração mínima em `tenant_detail.html`: breadcrumb passa a `Contas / <Conta> / <Empresa>`
  quando `AccountID` não é self-account; card "Conta" read-only com link para
  `/console/accounts/{acctId}`. Para tenant legado (self-account) mostra "Conta própria
  (legado)".
- **Falta:** `TenantView` ganha `AccountID`/`AccountName`; handler resolve o nome da Conta.

### 5.4 Uso por Conta (rollup)

- **Rotas:** `GET /console/accounts/{acctId}/consumption` (página, range de datas default 30d
  via clock injetado — mesmo truque de SIN-66089), `.../consumption/rows` (partial),
  `.../consumption.csv` (download).
- **UI:** reusa o padrão de `consumption.html`. Agrupamento: **por empresa-cliente** (uma linha
  por tenant sob a Conta: chamadas totais + valor total no período), com link para o consumo
  detalhado por-endpoint da empresa (`/console/tenants/{id}/consumption`). Rodapé com o total
  da Conta. Controles de range idênticos (`<input type="date">`, `consumptionDateLayout`).
- **Falta (impl):**
  - Use-case `AccountConsumptionInRange(ctx, acctID, rng)` sobre
    `LedgerReader.ListLedgerEntriesByAccount` — agrega por `TenantID` (o port já existe).
  - View-models `AccountConsumptionView` + linhas por tenant; `ToAccountConsumptionView`.
  - Template `account_consumption.html` + partial de linhas; CSV writer (locale-neutro, mesmo
    formato decimal do CSV de fatura/consumo).

### 5.5 Faturas por Conta

- **Rotas:** `GET /console/accounts/{acctId}/invoices` (lista todas as faturas das
  empresas-clientes da Conta), `POST /console/accounts/{acctId}/invoices` (gerar o **lote** do
  período: uma fatura por empresa-cliente com consumo no range), reuso do download existente
  `/console/tenants/{id}/invoices/{invId}.csv`.
- **UI:** reusa `invoices.html`. Tabela: Empresa-cliente, Período, Total (R$), Gerada em,
  [baixar CSV]. Form "Gerar faturas do período" com `start_date`/`end_date` (obrigatórios,
  `parseInvoicePeriod` já existe). Total da Conta no rodapé.
- **Falta (impl):**
  - `ListInvoicesByAccount(ctx, acctID)` no `InvoiceStore` (+ adaptadores) — hoje só existe
    `ListInvoices(tenantID)`.
  - Use-case `GenerateAccountInvoices(ctx, acctID, rng)` iterando as empresas-clientes da
    Conta e chamando o `GenerateInvoice` já existente (idempotência append-only preservada:
    regerar cria nova fatura timestamped, nunca sobrescreve — invariante do domínio invoice).
  - View-model `AccountInvoicesView`; template `account_invoices.html`.
  - **Preço nível-Conta** (fatura consolidada vs. por-empresa) é decisão de board — ver §7.
    A v1 entrega faturas **por empresa-cliente** agrupadas na Conta; nada de recomputo de preço
    (soma do ledger, invariante do domínio invoice).

---

## 6. Migração / retrocompat / reversibilidade

- **Sem nova migração de schema.** `accounts` e `tenants.account_id` já vieram na 0007 (F0),
  com backfill self-account 1:1. `billing_ledger.account_id` (F2) e `invoices.account_id` (B)
  já existem. Esta trilha é **só superfície de leitura/escrita sobre schema existente**.
- **Ships surfacing, não dark.** Hoje toda Conta é uma self-account `acct-<tenantID>`. Na
  lista de Contas, self-accounts aparecem como "Conta própria (1 empresa, legado)" e podem ser
  filtradas por padrão (toggle "mostrar contas próprias"), para não poluir a lista com uma
  Conta por tenant legado. Contas "reais" (ex.: Verz) são criadas via §5.1 e recebem
  empresas-clientes via §5.2.
- **Rollback:** as rotas `/console/accounts/*` são aditivas; remover o bloco de rotas e o item
  de menu "Contas" volta ao console tenant-plano sem tocar em dados. Nenhuma migração a
  reverter. As telas por-tenant seguem funcionando isoladamente.
- **Retrocompat de auth/bilhetagem:** inalterada — o carimbo de `AccountID` no ledger e a
  self-account derivada já garantem que tenant legado continua faturável isoladamente.

---

## 7. Itens que cruzam fronteira / decisão (antes ou durante a impl)

1. **Reatribuir empresa→Conta (§5.2.2)** muta o `Tenant` num eixo novo (a Conta dona). Cruza
   fronteira de domínio → **OK do CTO** antes de mergear esse pedaço. A criação-já-vinculada
   (§5.2.1) e todo o resto (leitura/rollup) **não** cruzam fronteira e podem ir primeiro.
2. **Efeito de suspender uma Conta** sobre os tokens/auth das empresas-clientes é decisão de
   segurança (trilha A / SecurityEngineer). v1: rótulo administrativo sem efeito em auth.
3. **Modelo de preço nível-Conta** (fatura consolidada da Conta vs. por-empresa) é decisão de
   **board/produto** (já registrada como pendente no plano SIN-69118). v1: faturas por
   empresa-cliente agrupadas na Conta.

Nenhum desses três bloqueia o miolo entregável (Contas CRUD + empresas aninhadas +
rollup de uso + lista/lote de faturas por Conta em leitura).

---

## 8. Segurança (herdada, não negociável)

- Todas as rotas novas entram no grupo `/console` já existente: **auth deny-by-default**,
  **CSRF** nos POST, **rate-limit** (`consoleLimiter`), `securityHeaders`. Nenhuma rota nova
  fora do grupo.
- **Isolamento:** todo acesso a empresa-cliente/fatura/consumo é keyed por id de recurso e
  resolvido server-side; nunca confiar em id vindo só do cliente sem checar o vínculo
  Conta→empresa. O rollup por Conta usa `ListLedgerEntriesByAccount(acctID)` — não vaza
  ledger de outra Conta.
- **Saída HTML** sempre via `html/template` (auto-escape) — sem `template.HTML` cru em nome de
  Conta/empresa (defende contra XSS armazenado; nomes são input de admin).
- **Sem segredo em URL/log.** Contas não carregam credencial; ids de Conta são opacos e não
  sensíveis, mas seguem o padrão de mascaramento de path já vigente.
- **Sem PII na fatura/consumo por Conta** (só ids, contagens e dinheiro) — igual ao invoice.

---

## 9. Critérios de aceite (spec)

1. Terminologia Conta/empresa-cliente ratificada por UX/CTO (ou ajuste de rótulos aqui).
2. IA/navegação (§4) aceita — em especial as duas portas de entrada e a não-duplicação das
   telas por-tenant.
3. Escopo v1 aceito: Contas CRUD + empresas aninhadas + criação-já-vinculada + rollup de uso
   por Conta + lista/lote de faturas por Conta; reatribuição (§5.2.2), efeito de suspensão e
   preço nível-Conta ficam gated (§7).

## 10. Critérios de aceite (impl, quando for a FrontendCoder/Coder)

- Cobertura > 85% em todo pacote tocado (`app`, `adminweb`, adaptadores sqlite/inmemory).
- `go test ./...`, `go vet ./...`, `staticcheck ./...` limpos.
- Sem mock de banco: adaptador inmemory documentado + teste sqlite real.
- HTMX por swap parcial, sem framework JS; `aria-current` e deep-link como no tenant_detail.
- QA valida os fluxos no navegador (criar Conta, vincular empresa, ver rollup, gerar lote de
  faturas, baixar CSV).

---

## 11. Faseamento sugerido da implementação (pós-aceite)

| Fase | Entrega | Cruza fronteira? |
|---|---|---|
| C1 | `AccountStore` + adaptadores + Contas lista/criar/detalhe + menu | não |
| C2 | Empresas-clientes aninhadas + criação-já-vinculada + campo Conta no tenant_detail | não |
| C3 | Rollup de uso por Conta (tela + CSV) | não |
| C4 | Faturas por Conta (lista + lote do período + reuso do CSV) | não |
| C5 | Reatribuição empresa→Conta | **sim — OK do CTO** |

C1–C4 são o miolo vendável para a Verz; C5 é operacional e pode vir depois.

---

Referências: plano `companies/.../plans/SIN-69118-producao-verz.md`; ADR-0009 (tenancy 2
níveis); [SIN-69119] design; [SIN-69121] faturas; [SIN-69124/69126/69127] F0/F1/F2 tenancy;
[SIN-66089] truque de range default via clock.

# ADR-0012 — Política de edição e exclusão de Conta, empresa-cliente e banco

- **Status:** **Aceito** — CTO, 2026-08-15 ([SIN-69354](/SIN/issues/SIN-69354))
- **Autor:** CTO. **Review de impl:** SecurityEngineer (ações destrutivas + manuseio de material de credencial) → **Aprovação:** CTO.
- **Lentes:** Hexagonal (Ports & Adapters), Secure-by-default API, Least privilege, Defense in depth, OWASP A01, Reversibilidade / blast-radius, LGPD / append-only.

## Contexto

A área administrativa (`adminweb`, entregue em [SIN-69157](/SIN/issues/SIN-69157)) permite criar e consultar Contas (nível 1), empresas-clientes / tenants (nível 2) e configurações de banco (cred + cert por (tenant, bankID)). O board ([SIN-69118](/SIN/issues/SIN-69118)) requisitou a capacidade de **editar nomes** e **excluir** as três entidades.

As três entidades têm perfis de risco muito diferentes:

| Entidade | Histórico em repouso | Material sensível |
|---|---|---|
| Conta (`accounts`) | ledger, faturas, audit_log — todos com `account_id` | nenhum |
| Empresa-cliente / tenant (`tenants`) | ledger, faturas, audit_log, pii_access_log, mandatos de recorrência | nenhum |
| Config de banco (`bank_credentials`, `bank_certificates`) | **nenhum** — é apenas configuração operacional | chave privada mTLS + client_secret de credencial |

## Decisão

### 1. Renomear Conta e empresa-cliente (`PATCH name`)

- Adicionar método de domínio `Rename(name string) error` em `account.Account` e `tenant.Tenant` com as mesmas regras de validação do `New` (non-blank, ≤ 200 chars).
- Rotas admin: `PATCH /admin/accounts/{id}` (campo `name`) e `PATCH /admin/tenants/{id}` (campo `name`).
- Persistência via `SaveAccount` / `SaveTenant` já existentes — UPDATE direto no banco.
- Auditado via `audit_log` com `account_id` (operação `rename_account` / `rename_tenant`).
- Mesma-404 para IDs inexistentes (sem oráculo de enumeração — A01/A07).
- Self-accounts derivadas (`acct-<tenantID>`) **não podem ser renomeadas diretamente**; o nome da self-account reflete o tenant subjacente. Operação retorna 400 com mensagem genérica se tentada sobre uma self-account.

### 2. Renomear banco

**Não implementado.** `bankID` é um slug da allow-list fechada (`ports.KnownBankIDs()`, atualmente apenas `c6`). Não é um rótulo editável pelo usuário — é a identidade técnica do PSP. Se no futuro for necessário um alias de exibição por tenant, abre-se issue separada com ADR próprio.

### 3. "Excluir" Conta — **soft-delete / desativação**

- Semântica: **`Deactivate()`** (já existe no domínio), `active = false`, `deactivated_at` registrado.
- **Não** remove registros. Ledger, faturas e `audit_log` com `account_id` são append-only e podem ser exigidos por retenção LGPD/fiscal. Hard-delete violaria a retenção.
- Efeitos em cascata:
  - Tenants da Conta: **não são desativados em cascata** (cada tenant pode ter histórico próprio e pode ser transferido no futuro). A UI deve avisar o operador sobre tenants ativos dependentes antes de confirmar.
  - API calls com chave-de-Conta desativada → `401` (o guard existente em B2/ADR-0011 já verifica `account.Active` — a chave-de-Conta é inválida sem uma Conta ativa).
- Rota admin: `DELETE /admin/accounts/{id}` → desativação; resposta `200` com `{ "deactivated": true }`.
- Auditado: `deactivate_account`.
- Reversível pelo admin via `POST /admin/accounts/{id}/activate` (re-ativação).
- Self-accounts derivadas não podem ser desativadas diretamente; usar a desativação de tenant (§4) em vez disso.

### 4. "Excluir" empresa-cliente / tenant — **soft-delete / desativação**

- Semântica idêntica a §3: `Deactivate()`, `active = false`.
- Efeitos:
  - Transações PIX, leituras de recorrência e cobranças em andamento que referenciam o tenant continuam existindo no histórico.
  - Token do tenant (modelo a) → `401` se `tenant.Active == false` (guard já checa — `tenantAuthMiddleware`).
  - Chave-de-Conta + seletor (modelo b, ADR-0011): se o tenant selecionado via `X-Client-Tenant` estiver desativado, `401` / `403` conforme o guard existente.
  - pii_access_log referencia tenant_id e permanece intacto (LGPD retenção).
- Rota admin: `DELETE /admin/tenants/{id}` → desativação; `POST /admin/tenants/{id}/activate`.
- Auditado: `deactivate_tenant`.

### 5. "Excluir" banco (remover configuração de cred + cert) — **hard-delete do material sensível**

- Semântica: **remoção hard** do par `(tenantID, bankID)` dos stores de credencial e certificado.
  - `bank_credentials`: linha removida do banco (sem soft-delete — não há histórico de negócio vinculado ao par).
  - `bank_certificates`: linha removida; chave privada deve ser **zerada antes do DELETE** no adapter SQLite (`UPDATE … SET key_pem = '' WHERE … ` antes do `DELETE`; já é write-only em repouso).
- Justificativa: o par (tenantID, bankID) é **configuração operacional pura** — não ancora ledger, faturas, pii_access_log nem mandatos. Hard-delete é seguro e preferível a manter material de credencial/chave desativado em repouso.
- Pré-condição verificada pela UI: alertar que **remover a configuração de banco interrompe novas transações** para o tenant naquele banco imediatamente.
- Rotas admin: `DELETE /admin/tenants/{tenantID}/banks/{bankID}` (remove cred + cert do par num único handler transacional).
- Auditado: `remove_bank_config` com `bank_id` no payload do evento — nunca logar o material secreto.
- Mesma-404 se o par não existir (sem oráculo).
- Novos ports necessários:
  - `CredentialDeleter` — `DeleteBankCredential(ctx, tenantID, bankID) error`
  - `BankCertificateDeleter` — `DeleteBankCertificate(ctx, tenantID, bankID) error`

### 6. UI / UX (adminweb HTMX)

- Renomear: modal inline (HTMX `hx-put`) com campo `name` e confirmação; resposta partial swap.
- Excluir Conta / tenant: botão "Desativar" com diálogo de confirmação (JavaScript `confirm()` ou HTMX `hx-confirm`). Mostrar contagem de entidades dependentes antes de confirmar.
- Excluir banco: botão "Remover banco" com aviso explícito que interrompe transações. Confirmação obrigatória.
- Estados desativados: badges "Desativada" na listagem; excluídos de operações novas mas acessíveis via filtro "Incluir desativadas" (evitar data-loss percebido).

### 7. Cobertura de testes

- Testes unitários de domínio: `Rename`, `Deactivate`, invariants (self-account, blank name, too-long).
- Testes de use-case: rename + deactivate account/tenant, hard-delete bank config (incluindo cascata parcial: cred existe mas cert não, e vice-versa).
- Coverage gate mantido > 85% (script `scripts/coverage.sh`).

## Alternativas consideradas

| Alternativa | Motivo da rejeição |
|---|---|
| Hard-delete Conta/tenant | Viola append-only ledger/faturas; cria FK orphans em audit_log/pii_access_log; incompatível com retenção LGPD. |
| Soft-delete banco (flag `active`) | Mantém material sensível (chave privada) em repouso sem necessidade; hard-delete elimina o risco sem custo — nenhum histórico é perdido. |
| Nome editável para banco (alias per-tenant) | Scope-creep; banks são slugs técnicos de uma allow-list fechada; se necessário, ADR separado. |

## Consequências

- Novas rotas admin: `PATCH /admin/accounts/{id}`, `PATCH /admin/tenants/{id}`, `DELETE /admin/accounts/{id}`, `DELETE /admin/tenants/{id}`, `POST /admin/accounts/{id}/activate`, `POST /admin/tenants/{id}/activate`, `DELETE /admin/tenants/{tenantID}/banks/{bankID}`.
- Novos ports: `CredentialDeleter`, `BankCertificateDeleter`.
- Novas migrações: **zero** para soft-delete — `active` (INTEGER 0/1) já existe em `accounts` e `tenants` (migr 0007); o timestamp de desativação é capturado via `audit_log` (já com `account_id`). Hard-delete de banco usa `DELETE` sem DDL novo. Se futuramente a UI precisar mostrar `deactivated_at` diretamente, abre-se migr 0012 para a coluna; fora do escopo inicial.
- Choke-point de auth já rejeita tokens de tenant inativo e chaves de Conta inativa — nenhum gap de auth novo para os casos de desativação.
- Ships-dark não necessário: as novas rotas só são visíveis no console admin (autenticado); não afetam o plano de dados nem o plano de API do cliente.

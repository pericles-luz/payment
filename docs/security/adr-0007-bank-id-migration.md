# ADR-0007 — Passo de migração: `bank_id` na credencial bancária (aditivo, reversível)

Companion de [adr-0007-multi-bank-credential-per-tenant.md](adr-0007-multi-bank-credential-per-tenant.md)
(SIN-66021). Documenta o passo de schema do item #5 do escopo.

## Estado atual (importante)

As credenciais bancárias **não são persistidas em tabela** hoje. Elas são
carregadas do ambiente (`PAYMENT_BANK_CREDS` / `PAYMENT_BANK_CREDITOR_KEYS`) para
um `CredentialStore` **in-memory** (`internal/adapters/secret`), agora chaveado
pelo par composto `(tenantID, bankID)` (ADR-0007). O schema persistido
(`migrations/0001_init.*`) cobre `tenants`, `payments`, `endpoint_pricing`,
`billing_ledger` e `processed_events` — **nenhuma** tabela de credencial.

Portanto, a dimensão `bank_id` é hoje 100% retrocompatível **sem** migração de
banco: config legada de 3 campos e chamadas internas resolvem o default `c6`
(`ports.BankIDC6`). Este documento é o **passo aditivo a aplicar QUANDO** uma
tabela de credencial passar a ser persistida (ex.: vault-backed `CredentialWriter`,
`internal/adapters/secret/crypto.go`).

## Passo aditivo (Postgres-portável)

Para uma futura tabela `bank_account` (ou `bank_credentials`) que hoje seria
chaveada só por `tenant_id`:

```sql
-- up: aditivo, sem downtime, sem backfill manual.
ALTER TABLE bank_account
    ADD COLUMN bank_id TEXT NOT NULL DEFAULT 'c6';

-- A PK/UNIQUE passa a ser o par composto (defesa em profundidade, ADR-0007 T2).
-- Toda linha legada já é (tenant, 'c6'), preservando o comportamento atual.
ALTER TABLE bank_account
    DROP CONSTRAINT bank_account_pkey,
    ADD  CONSTRAINT bank_account_pkey PRIMARY KEY (tenant_id, bank_id);
```

```sql
-- down: rollback limpo. Nenhum dado de banco-único é perdido (todos são 'c6').
ALTER TABLE bank_account
    DROP CONSTRAINT bank_account_pkey,
    ADD  CONSTRAINT bank_account_pkey PRIMARY KEY (tenant_id);
ALTER TABLE bank_account
    DROP COLUMN bank_id;
```

## Portabilidade (SQLite agora, Postgres depois)

Segue as notas de `migrations/0001_init.up.sql`:

- `bank_id` é `TEXT NOT NULL DEFAULT 'c6'` — tipo portável (idêntico em SQLite e
  Postgres); o slug é não-secreto e canônico (lower-case, do registry).
- O default na coluna garante que toda linha existente vire `(tenant, 'c6')` na
  aplicação do `up`, sem passo de backfill.
- **SQLite:** `ALTER TABLE … ADD COLUMN` é suportado; a recriação de PRIMARY KEY
  composta exige a recriação da tabela (padrão `CREATE TABLE new … INSERT SELECT …
  DROP … RENAME`) — documentar inline no arquivo de migração quando ele existir,
  como faz `0001_init`. Em Postgres o `DROP/ADD CONSTRAINT` é direto.
- Teste de portabilidade: o mesmo arquivo `.up.sql`/`.down.sql` deve aplicar e
  reverter limpo contra o engine de teste do repo (hoje SQLite, via
  `migrations.FS`), exatamente como `0001_init` é exercido.

## Reversibilidade

- **Aditivo:** o `up` só adiciona coluna + reаpontamento de PK; nenhuma coluna ou
  linha é destruída.
- **Rollback = `DROP COLUMN bank_id`** (após restaurar a PK simples). Como todas as
  linhas pré-multi-banco são `'c6'`, o estado anterior é restaurado byte-a-byte.
- Sem feature flag necessária: o default `'c6'` + lookup exato preservam o
  comportamento de um-banco-só durante e após o deploy.

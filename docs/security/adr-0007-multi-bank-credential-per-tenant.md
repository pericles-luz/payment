# ADR-0007 — Credencial bancária por tenant passa a ser chaveada por `(tenantID, bankID)` (multi-banco)

- **Status:** Aceito — ratificado pelo CTO em 2026-06-26 ([SIN-66020](/SIN/issues/SIN-66020), headline de [SIN-66015](/SIN/issues/SIN-66015)).
- **Decisão de design pai:** [SIN-66015](/SIN/issues/SIN-66015) ([#document-plan](/SIN/issues/SIN-66015#document-plan)). Sucessor de [ADR-0004](adr-0004-c6-creditor-key-per-tenant.md).
- **Autor:** SecurityEngineer. **Decisor:** CTO (revisão+merge dual-channel).
- **Implementação (a seguir, com este ADR como pré-requisito):** #2 schema (`bank_id` no store), #3 roteamento (seletor de banco na borda). SecurityEngineer é o revisor de segurança pré-merge de ambos.

## Contexto

Hoje a identidade bancária de um tenant é chaveada **só** por `tenantID`:
`CredentialStore.GetBankCredential(ctx, tenantID)` devolve **uma** `BankCredential`
(`ClientID`/`Secret`/`CreditorKey`). Isso é correto enquanto existe **um único
banco** (C6). O escopo de [SIN-66015](/SIN/issues/SIN-66015) ("API para os
serviços" / multi-banco) introduz mais de um PSP por tenant: um mesmo tenant pode
ter credenciais distintas em C6 e em outro banco, com `client_id`/`secret`/mTLS e
chave-recebedor **independentes** por banco.

O modelo atual não comporta isso: a chave do mapa é o `tenantID`, então um segundo
banco para o mesmo tenant **sobrescreveria** o primeiro. Precisamos de uma
dimensão de banco na credencial **antes** de qualquer código de roteamento, porque
a forma como o banco é selecionado e resolvido é uma **decisão de segurança**
(confused-deputy / roteamento de fundos), não um detalhe de implementação.

Restrições herdadas que o desenho respeita:

- O `tenantID` **sempre** vem da autenticação (TB2 do [threat-model](threat-model.md)),
  **nunca** de parâmetro controlado pelo cliente.
- Segredo (`Secret`) e chave-recebedor (`CreditorKey`) **nunca** são logados
  ([ADR-0004](adr-0004-c6-creditor-key-per-tenant.md); `String()`/`LogValue()` redigem).
- Mudança aditiva e reversível (padrão dos ADRs 0002/0004): sem passo destrutivo,
  rollback limpo.

## Decisão

Adotamos credencial chaveada por **par composto `(tenantID, bankID)`**.

### 1. `bankID` — slug não-secreto, validado contra um registry

- `bankID` é um **slug** estável e não-secreto (ex.: `"c6"`). É um identificador
  de roteamento, **não** um segredo: pode aparecer em logs, métricas e mensagens
  de erro **não-distintivas** (ver "Sem-oráculo").
- Todo `bankID` é **validado contra um registry** de bancos suportados pela
  plataforma (allowlist; *secure default* = deny). Um slug fora do registry é
  rejeitado na borda antes de tocar o store — `denylist` nunca; só `allowlist`.
- **Default retrocompatível `"c6"`:** onde um `bankID` não é fornecido (config
  legada, migração, chamada interna pré-multi-banco), resolve-se para `"c6"`. Isso
  preserva 100% do comportamento atual de um-banco-só.

### 2. `ports.BankCredential` ganha `BankID` (não-secreto)

```go
type BankCredential struct {
    TenantID    string
    BankID      string // NOVO — slug não-secreto do banco (default "c6")
    ClientID    string
    Secret      string // [REDACTED]
    CreditorKey string // [REDACTED] — sensível a roteamento de fundos (ADR-0004)
}
```

`BankID` é **não-secreto** e entra em `String()` e `LogValue()` ao lado de
`TenantID`/`ClientID`. `Secret` e `CreditorKey` **continuam `[REDACTED]`**. Isso é
deliberado: precisamos do `bank_id` em logs/auditoria para reconstruir qual banco
roteou uma cobrança, e ele não vaza nada sensível.

### 3. Só `CredentialStore`/`CredentialWriter` ganham a dimensão `bankID`

```go
type CredentialStore interface {
    GetBankCredential(ctx context.Context, tenantID, bankID string) (BankCredential, error)
}
type CredentialWriter interface {
    SetBankCredential(ctx context.Context, tenantID, bankID, clientID, secret string) error
}
```

Os **providers** (adapters de banco) mantêm a assinatura `(ctx, tenantID, …)`.
Cada **instância** de adapter é construída **vinculada ao seu próprio `bankID`**
(o adapter C6 carrega `bankID="c6"`); internamente ela resolve
`GetBankCredential(ctx, tenantID, p.bankID)`. O port de cobrança/pagamento
(`BankProvider`, `PixChargeProvider`, etc.) **não muda** — o banco já está fixado
na identidade do adapter, não passa pela requisição de negócio. Isso mantém o
blast radius pequeno: a dimensão `bankID` vive **só** no boundary de credencial.

### 4. Seletor de banco na borda — **campo `bank` no corpo/rota**, não header `X-Bank-Id`

Decisão ratificada: o banco que atende uma requisição é selecionado por um
**campo `bank` de primeira-classe no contrato** (corpo JSON do request ou segmento
de rota), **não** por um header `X-Bank-Id`.

Razões:

- **Mediação completa e contrato explícito:** o seletor faz parte do schema
  validado do request (tipo/allowlist no registry), versionado junto do resto do
  payload. Headers `X-*` ad-hoc tendem a escapar de validação de schema, de
  logging estruturado e de testes de contrato.
- **Auditoria:** `bank` no corpo aparece naturalmente no log de auditoria da
  operação; um header custom costuma ser descartado pela borda HTTP.
- **Cache/proxy:** headers custom interagem mal com cache/proxy (`Vary`); um campo
  no corpo/rota não tem essa pegadinha.
- **`bank` é só um seletor _dentro do conjunto do tenant_**, nunca uma fonte de
  autoridade. O `tenantID` continua vindo **exclusivamente** da auth. Um `bank`
  forjado só consegue apontar para bancos que **o próprio tenant** configurou —
  e, se não configurou, **deny** (ver T1 abaixo).

## Threat model

Numeração alinhada ao [threat-model.md](threat-model.md) (STRIDE por componente).
A superfície nova é "seleção e resolução de banco dentro do escopo do tenant".

### T1 — Confused-deputy / OWASP A01 (Elevation/Tampering) — **Crítica**

**Ameaça:** atacante autenticado como `tenantA` envia `bank=bankX` para fazer a
plataforma rotear fundos/cobrança sob credencial que não é de `tenantA`, ou para
um banco que `tenantA` não configurou, esperando um *fallback* para a credencial
de outro banco.

**Mitigação (deny-by-default, fail-closed):**

1. `tenantID` vem **só** da auth; `bank` é **só seletor** dentro do conjunto de
   bancos configurados desse tenant.
2. `GetBankCredential(ctx, tenantID, bankID)` faz **lookup exato** do par
   `(tenantID, bankID)`. **Não existe fallback**: se `(tenantA, bankX)` não tem
   credencial, retorna `ErrNotFound` — **nunca** cai para `(tenantA, bankY)` nem
   para um banco "default" com credencial de terceiro.
3. `bankID` é validado contra o **registry** (allowlist) antes do lookup; slug
   desconhecido é rejeitado.

**Risco residual:** se um operador **configurar errado** a credencial de um tenant
apontando para a conta de outro (erro de provisioning), o código a respeita. Isso
é um controle **de processo** (admin plane / runbook de provisioning), fora do
escopo deste boundary. Mitigado por revisão de provisioning e auditoria do
`bank_id`/`client_id` (não-secretos) no log.

### T2 — Isolamento cross-tenant **e** cross-bank (Information disclosure) — **Crítica**

**Ameaça:** uma credencial `(tenantA, bankX)` ser resolvível por `(tenantB, *)` ou
por `(tenantA, bankY)`.

**Mitigação:** a chave do store é o **par composto** `(tenantID, bankID)`. O lookup
é igualdade exata dos dois componentes. Não há wildcard, prefixo, nem normalização
que colapse pares distintos. Defesa em profundidade na camada de persistência
(item #2 da implementação): a PK/UNIQUE da tabela é `(tenant_id, bank_id)` e, quando
houver RLS, a policy filtra por `tenant_id` da sessão — o `bank_id` **não** relaxa
o escopo de tenant, apenas o subdivide.

**Risco residual:** colisão de slug por normalização inconsistente (ex.: `"C6"` vs
`"c6"`). Mitigado exigindo o slug **canônico** (lower-case, do registry) tanto na
escrita quanto na leitura; o registry é a única fonte de slugs válidos.

### T3 — Sem-oráculo de existência (Information disclosure / enumeração) — **Alta**

**Ameaça:** mensagens de erro distintas permitirem ao atacante distinguir "este
tenant não tem esse banco" de "esse banco não existe na plataforma", vazando o
mapa de bancos por tenant ou o catálogo interno.

**Mitigação:** **mesmo erro** para os dois casos no caminho de resolução de
credencial — `ErrNotFound` internamente, **401/404 indistinto** na borda (mesmo
shape, mesmo corpo, mesmo timing-class). A borda **não** diferencia "slug fora do
registry" de "tenant não tem credencial para esse slug" na resposta ao cliente.
Segue o padrão da C6-D webhook (mesma-401 anti-enumeração, [ADR de C6-D / SIN-64753]).

**Risco residual:** canais laterais de *timing* (lookup em mapa in-memory vs DB)
são desprezíveis aqui e fora do modelo de ameaça para este boundary; anotado para
revisão se o store passar a fazer I/O de latência variável por banco.

### T4 — Redaction / vazamento de segredo (Information disclosure) — **Alta**

**Ameaça:** o novo campo aumentar a superfície de log e vazar `Secret`/`CreditorKey`.

**Mitigação:** `BankID` é **não-secreto** e entra em `String()`/`LogValue()`;
`Secret` e `CreditorKey` **permanecem `[REDACTED]`** (regressão pinada pelos testes
existentes `TestBankCredentialStringRedactsSecret`/`...CreditorKey`, que **não**
podem ser enfraquecidos — regra-3 do quality bar). O `SetBankCredential` continua
rejeitando entradas vazias **sem** incluir o valor do segredo na mensagem.

**Risco residual:** nenhum novo identificado; o `bank_id` em log é desejado para
auditoria e não é sensível.

### T5 — Migração / disponibilidade (Denial of service por deploy) — **Média**

**Ameaça:** a migração de schema quebrar linhas existentes ou exigir downtime.

**Mitigação:** migração **aditiva** — `ALTER TABLE … ADD COLUMN bank_id NOT NULL
DEFAULT 'c6'`. Toda credencial legada vira `(tenant, 'c6')` automaticamente,
preservando o comportamento atual. **Rollback limpo:** `DROP COLUMN bank_id`
restaura o estado anterior (nenhum dado de banco-único é perdido, pois todos são
`'c6'`). Sem passo destrutivo, sem backfill manual. A var de ambiente de config
(`PAYMENT_BANK_CREDS`/`PAYMENT_BANK_CREDITOR_KEYS`) ganha um campo `bank` opcional
com default `c6` — ausência ⇒ comportamento atual (mesma estratégia aditiva do
ADR-0004).

## Opções consideradas

- **(A) Par composto `(tenantID, bankID)` no boundary de credencial — ESCOLHIDA.**
  Dimensão de banco contida no único lugar que precisa dela; ports de negócio
  inalterados; aditivo/reversível.
- **(B) Mapa aninhado `tenant → bank → cred` exposto aos use-cases.** Rejeitada:
  vaza a dimensão de banco para todo use-case, aumenta o blast radius e convida
  o `bankID` a transitar como dado de negócio (risco de confused-deputy maior).
- **(C) Seletor por header `X-Bank-Id`.** Rejeitada: escapa de validação de
  schema, de logging estruturado e de testes de contrato; interação ruim com
  cache/proxy; pior trilha de auditoria (ver Decisão #4).
- **(D) Codificar o banco no `tenantID` (ex.: `tenantA@c6`).** Rejeitada:
  sobrecarrega a identidade de tenant (que vem da auth), corrompe o escopo de
  isolamento e quebra o invariante "tenant sempre da auth, banco é seletor".

## Consequências

- **Multi-banco habilitado** sem mudar os ports de negócio: só credencial.
- **Isolamento reforçado:** par composto + PK `(tenant_id, bank_id)` + deny-by-default
  sem fallback fecham confused-deputy e cross-bank de uma vez.
- **Retrocompatível:** default `'c6'` e migração aditiva ⇒ zero mudança de
  comportamento para o estado atual de um-banco-só; rollback é `DROP COLUMN`.
- **Auditável:** `bank_id` não-secreto em logs/auditoria permite reconstruir
  roteamento de fundos por banco sem vazar segredo.
- **Boring technology:** estende o store/var-de-config existentes; sem infra nova.
- **Dependência:** a implementação #2 (schema) e #3 (roteamento) **devem** passar
  por revisão de segurança pré-merge (SecurityEngineer) validando: lookup exato
  do par, ausência de fallback, mesma-401 sem-oráculo, redaction do novo campo,
  e migração aditiva/reversível.

## Riscos conhecidos (residual, pós-decisão)

- **Provisioning incorreto** (operador aponta credencial errada) — controle de
  processo, fora deste boundary; mitigado por revisão + auditoria do `bank_id`.
- **Normalização de slug** — exige slug canônico do registry na escrita e na
  leitura para evitar colisão `"C6"`/`"c6"`.
- **Timing side-channel** na resolução — desprezível no store atual; reavaliar se
  o lookup passar a fazer I/O de latência variável por banco.
- **Registry como ponto único** — a allowlist de bancos vira superfície de
  configuração sensível; sua escrita deve ser tratada como mudança de segurança
  (revisão), não config trivial.

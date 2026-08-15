# ADR-0011 — Chave-de-Conta + seletor de empresa-cliente por chamada (revendedor Verz)

- **Status:** **Aceito** — CEO **endossou o modelo (b)** em 2026-08-14 ([SIN-69274](/SIN/issues/SIN-69274), comment `e1e4d056`) com condições (i)–(iv) e **deu o go de impl** em 2026-08-14 (SIN-69261): _"Vamos de modelo B e preciso de conseguir gerar e rotacionar a chave bearer que cada conta usará para acessar nossa API, começando por verz"_ — a decisão do board-humano em prosa resolve o gate formal (interação board-only `5e458c95` + confirmation `893e5a39`). **Impl DESTRAVADA:** filhas B1–B5 abertas, flag-gated default-off, review SecurityEngineer → CTO.
- **Autor:** CTO. **Review de impl:** SecurityEngineer (authz por-request load-bearing / A01-IDOR) → **Aprovação:** CTO.
- **Supersede:** o trecho **primário** de [ADR-0009](adr-0009-two-level-tenancy.md) §3 ("**sem seletor de cliente** no request") e a alternativa "Token único + seletor" (lá **adiada** como F5 opcional). Este ADR **promove** o F5 pré-desenhado (ADR-0009 §67 / Consequências) de "opcional, sob demanda" para **caminho de acesso adotado do revendedor Verz**. O restante de ADR-0009 (Account acima do tenant, `empresa-cliente ≡ tenant`, PSP-Indireto pass-through, migração `0007`, choke-point único) **permanece válido e é a fundação deste ADR**.
- **Lentes:** Secure-by-default API, Least privilege, Defense in depth, **OWASP A01 (Broken Access Control) / IDOR**, Hexagonal (Ports & Adapters), DDD-lite, Reversibilidade / blast-radius, Boring-tech.

## Contexto

Ao logar no `/console` (SIN-69261 → ADR-0010), o **board declarou o modelo operacional da Verz** em 5 pontos:

1. board cadastra a Verz como **Conta**;
2. Verz tem **uma chave rotacionável** para usar a API;
3. Verz cadastra suas **empresas-clientes e credenciais via API**;
4. **a cada chamada, Verz informa para qual cliente** está operando (para casar a credencial certa);
5. **bilhetagem na Conta da Verz**.

Batido contra o **contrato hoje deployado** (`docs/api/openapi.yaml` + `internal/adapters/http/auth.go`): (1) e (5) já são suportados; (2), (3) e (4) **divergem**. O deployado é o **modelo (a)**: o token é escopado por **empresa-cliente (tenant)** — `AuthenticateTenantPrincipal` mapeia `token→tenant`, a Account é derivada server-side (atribuição-only, `StoreAccountResolver`), e **não existe seletor de cliente** (openapi: "a empresa-cliente é derivada do token, nunca de um parâmetro"). Isso foi desenhado assim de propósito em ADR-0009 §3 para **projetar A01/IDOR para fora**.

Os 5 pontos do board **são o modelo (b)** (padrão Stripe-Connect `Stripe-Account`): **uma chave de Conta** (ponto 2) + **seletor de cliente por chamada** (ponto 4). Adotá-lo **reintroduz deliberadamente** a superfície A01 que ADR-0009 evitou — logo o guard "o cliente selecionado pertence à Conta da chave" passa a ser **controle load-bearing**.

A fundação para (b) **já existe no código** (ships-dark de ADR-0009/SIN-69126): o choke-point único `tenantAuthMiddleware` já resolve `Principal{TenantID, AccountID}` e há `AccountResolver`/`StoreAccountResolver` lendo `tenants.account_id`. Este ADR **adiciona um segundo caminho de autenticação** (chave-de-Conta + seletor) **ao lado** do caminho token→tenant, sem removê-lo.

## Decisão

Adotar o **modelo (b)** como caminho de acesso do **revendedor** (Conta com N empresas-clientes), **aditivo** e **flag-gated**, mantendo o modelo (a) intacto para retrocompat.

### 1. Dois caminhos de autenticação no MESMO choke-point (deny-by-default)

O `tenantAuthMiddleware` (choke-point único, `internal/adapters/http/auth.go`) passa a distinguir a natureza do token apresentado:

- **Token de tenant (modelo (a), inalterado):** resolve `token→tenant` direto; **nenhum seletor é lido**; se um seletor estiver presente numa chamada com token de tenant, é **rejeitado** (o token de tenant **não tem autoridade** para selecionar outra empresa-cliente — fecha escalonamento). Isolamento idêntico ao de hoje.
- **Chave-de-Conta (modelo (b), novo):** resolve `chave→accountID`. A chave **não** carrega, por si, um tenant — ela **exige** um **seletor de empresa-cliente** no request (header, ex. `X-Client-Tenant: <tenantID>`; nunca em query string — regra "no secrets/selector-in-URL" é estética/log, o valor em si vai no header). O choke-point então aplica o **guard load-bearing** (§2) e, só em sucesso, injeta `ctxTenantID = <selecionado>` e `ctxAccountID = <account da chave>`. Todo handler `/v1` continua lendo **apenas** `tenantFromContext(ctx)` — **zero mudança nos handlers**; a diferença é 100% no choke-point.

### 2. Guard de autorização por-request — **load-bearing, fail-closed** (condição CEO (i))

Para uma chamada com chave-de-Conta e seletor `X-Client-Tenant: T`:

```
account := authenticate(accountKey)                 // chave → accountID; falha → 401 genérico
T       := parseSelector(X-Client-Tenant)           // ausente numa chave-de-Conta → 400 (seletor obrigatório)
owner   := AccountResolver.ResolveAccountID(ctx, T) // lê tenants.account_id (porta, sem SQL no middleware)
if owner == "" || owner != account.ID {             // T não existe OU pertence a outra Conta
    → 404 (NÃO 403): mesma resposta de "tenant inexistente" — sem oráculo de enumeração cross-account (A01)
}
inject ctxTenantID=T, ctxAccountID=account.ID       // só aqui o escopo é concedido
```

- **Fail-closed sem exceção:** qualquer erro de leitura, seletor malformado, `owner==""`, ou `owner != account.ID` ⇒ **negado**. Nunca "na dúvida, permite".
- **Sem oráculo (A01):** "cliente de outra Conta" e "cliente inexistente" retornam **a mesma 404** — o atacante com uma chave-de-Conta válida não consegue enumerar tenants de outras Contas. (Espelha a garantia de ADR-0009 §58: "empresa de outro account = 404, não oráculo".)
- **Least privilege:** a chave-de-Conta concede escopo **exatamente** sobre os tenants cujo `account_id == account.ID` — nunca mais.

### 3. Emissão / rotação da chave-de-Conta (condição CEO (iii), parte 1)

- A Conta ganha uma **chave rotacionável** (secret opaco ≥256-bit, comparação constant-time, **hash em repouso** — nunca em claro, nunca logada; `LogValue` redige). Store durável atrás de porta (hexagonal), keyed por `accountID`.
- **Rotação = create==rotate idempotente** (mesmo padrão de SIN-69196 para credencial bancária): PUT/rotate emite nova chave, invalida a anterior após janela de graça curta (ou imediatamente — decidir no plano; default = imediato, mais seguro). Exibição **única** no momento da emissão (como o bootstrap do console, ADR-0010).
- **Retrocompat:** tokens de tenant (modelo (a)) continuam válidos em paralelo; uma Conta pode ter **ambos** durante transição.

### 4. Provisionamento self-serve de empresa-cliente via `/v1` (condição CEO (iii), parte 2)

Hoje criar tenant + emitir a chave dele é **admin-plane** (`/admin/tenants/...`). O modelo (b) exige que a **Verz** cadastre suas empresas-clientes **via API** (ponto 3 do board). Nova rota `/v1` **autenticada pela chave-de-Conta**, deny-by-default, que:

- cria uma **empresa-cliente (tenant)** já com `account_id = account.ID` da chave (atribuição **server-side**, imutável — invariante set-once de ADR-0009 §2; a Verz **não** escolhe o account, ele vem da chave → sem cross-account);
- retorna o identificador do tenant criado (para uso no seletor `X-Client-Tenant`);
- a **credencial bancária** do novo tenant continua via `PUT /v1/bank-credential` self-serve já existente (SIN-69196), agora endereçável pelo seletor.
- **Idempotency-Key** obrigatório no create (padrão de write endpoints; evita duplicidade em retry).

### 5. Contrato / openapi

`docs/api/openapi.yaml` é atualizado: a nota "empresa-cliente derivada do token, nunca de parâmetro" ganha a **ressalva do caminho chave-de-Conta** (o seletor `X-Client-Tenant` é o mecanismo **autorizado** de seleção, mediado pelo guard §2). Documentar o header, os códigos (400 seletor ausente, 404 cross-account/inexistente, 401 chave inválida) e o fluxo de provisionamento §4.

## Threat model do seletor (condição CEO (iv))

| # | Ameaça | Mitigação (load-bearing em **negrito**) |
|---|--------|------------------------------------------|
| **T1** | Chave-de-Conta A seleciona tenant da Conta B (IDOR/A01 cross-account) | **Guard §2: `owner != account.ID` ⇒ 404**, fail-closed. Teste de regressão obrigatório. |
| **T2** | Enumeração de tenants de outras Contas via seletor | **Mesma-404** para inexistente e cross-account — sem oráculo. |
| **T3** | Token de **tenant** (modelo (a)) tenta usar seletor para pular para outra empresa | Seletor **rejeitado** em token de tenant — token de tenant não tem autoridade de seleção. |
| **T4** | Seletor ausente numa chave-de-Conta ⇒ ambiguidade / default perigoso | Seletor **obrigatório** para chave-de-Conta ⇒ 400. **Nunca** cai num tenant default. |
| **T5** | Vazamento/replay da chave-de-Conta = acesso a TODAS as empresas da Conta (blast radius maior que modelo (a)) | Rotação idempotente §3 + hash em repouso + limiter inbound + **escopo limitado ao account** (nunca cross-account, T1). Trade-off aceito e documentado: 1 chave = N clientes **da mesma Conta** — nunca além. |
| **T6** | Provisionamento §4 usado para criar tenant sob outra Conta | `account_id` vem **da chave**, server-side, imutável — a Verz não informa account. |
| **T7** | Guard depende de leitura que pode falhar aberto | `AccountResolver` já é **fail-safe** hoje (retorna `""` em erro) — mas no caminho (b) `owner==""` ⇒ **404**, não permissivo. A semântica muda de "fallback self-account" (modelo (a) dark) para **"nega"** (modelo (b)). Explicitar no código + teste. |

## Consequências

- **Blast radius contido por flag:** todo o caminho (b) é **gated por flag, default-off** (padrão SIN-69196). Deploy com flag off = comportamento idêntico a hoje (modelo (a)). Liga-se só para a Conta Verz quando o board confirmar.
- **A01 reintroduzida DE PROPÓSITO, mitigada por design:** o guard §2 é a única linha entre uma chave-de-Conta e o isolamento cross-account. Por isso **review de SecurityEngineer é obrigatório** (condição CEO (ii)) e o guard exige **teste de regressão dedicado** (T1–T4) antes de qualquer merge.
- **Handlers `/v1` inalterados:** a mudança vive 100% no choke-point + provisionamento; a superfície de código nova é pequena e auditável.
- **Coexistência (a)+(b):** nenhuma Conta é forçada a migrar; modelo (a) permanece válido. Verz usa (b); tenants legados usam (a).
- **Metering (ponto 5) já funciona:** o ledger já carrega `account_id` (F2/SIN-69127); com `ctxTenantID` resolvido pelo seletor, o rollup por Conta continua correto sem mudança.

## Reversibilidade

Rollback é **flag + fiação**: desligar a flag da chave-de-Conta ⇒ o choke-point ignora o seletor e só aceita tokens de tenant (modelo (a)). Nenhuma migração destrutiva; a coluna `account_id` já existe (0007). As chaves-de-Conta emitidas ficam inertes com a flag off. Sem mudança de schema irreversível.

## Alternativas consideradas

- **Manter modelo (a) puro (zero-código)** — rejeitado pelo board/CEO para a Verz: força a Verz a gerenciar N tokens (um por empresa-cliente), ergonomia ruim que não escala com o negócio de revenda. Permanece o default para tenants não-revendedores.
- **Seletor na URL/path (`/v1/clients/{tid}/...`)** — rejeitado: multiplicaria a superfície de rota e colocaria o seletor em logs/URLs. Header `X-Client-Tenant` num choke-point único é menor superfície e mais fácil de auditar.
- **Split nativo / Verz como merchant único** — já rejeitado em ADR-0009 §1 (nos tornaria PSP-Direto custodiante). **Fora de escopo, inalterado** — (b) NÃO custodia fundos: cada empresa-cliente mantém a própria credencial C6 e recebe o próprio dinheiro; a chave-de-Conta é só **identidade de acesso**, não roteamento de fundos. Continuamos PSP-Indireto pass-through.

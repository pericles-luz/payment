# Plano faseado — Chave-de-Conta + seletor de empresa-cliente (modelo (b), Verz)

Ref: [ADR-0011](../docs/security/adr-0011-account-key-client-selector.md) · [SIN-69274](/SIN/issues/SIN-69274) · supersede o trecho "sem seletor" de [ADR-0009](../docs/security/adr-0009-two-level-tenancy.md) §3.

**Gate de execução:** design (ADR-0011 + este plano) autorizado pelo CEO. **Impl em HOLD até o board resolver a interação board-only `5e458c95`** (aceite formal de (b)). Cada fase = **1 issue filha** de SIN-69274, `review = SecurityEngineer → approval = CTO` (2-stage typed exec policy, padrão payment). Todas as fases **flag-gated, default-off** (`PAYMENT_ACCOUNT_KEY_SELECTOR` proposto) — nada muda em produção até ligar a flag para a Conta Verz.

**Lentes por fase:** Hexagonal (domínio puro atrás de portas), Secure-by-default / Least-privilege / OWASP A01, Reversibilidade (flag + sem migração destrutiva), Boring-tech (stdlib + padrões já no repo: SIN-69196 create==rotate, ADR-0010 secret display-once).

---

## Fase B1 — Domínio + store da chave-de-Conta (fundação, ships-dark)

**Entrega:** modelo de domínio da chave-de-Conta e store durável atrás de porta; **sem** wiring no choke-point ainda (dark).

- `internal/domain/accountkey` (ou estender `account`): `AccountKey{ accountID, hash, active, createdAt, rotatedAt }`. Secret opaco ≥256-bit, **hash em repouso**, `LogValue()` redige. Verificação constant-time. Domínio **puro** (sem `database/sql`/HTTP).
- Porta `AccountKeyStore` (accept-narrow): `PutKey(accountID) (plaintext, error)` idempotente create==rotate; `AuthenticateAccountKey(secret) (accountID, bool)`; `Rotate`. Adapter in-memory primeiro (padrão dos outros stores); durável (sqlite + cripto em repouso) como sub-item ou follow-up, MESMAS portas.
- Migração (se durável nesta fase): `accounts` já existe (0007). Nova tabela `account_keys(account_id, key_hash, active, created_at, rotated_at)` + índice por hash. `down` reversível. **Sem** tocar `tenants`/ledger.
- **Testes:** hash nunca em claro, `LogValue` redige, constant-time, rotate invalida a anterior, create==rotate idempotente.

**Aceite:** domínio + store testados; nada wireado; flag inexistente ainda (puro dark). Cobertura ≥85% (gate `scripts/coverage.sh`).

## Fase B2 — Caminho de auth chave-de-Conta + guard load-bearing no choke-point (**núcleo de segurança**)

**Entrega:** o `tenantAuthMiddleware` distingue token-de-tenant × chave-de-Conta e aplica o guard §2 do ADR. **Esta é a fase que reintroduz A01 — review SecEng é hard-gate.**

- No choke-point (`internal/adapters/http/auth.go`): se o segredo apresentado autentica como **chave-de-Conta**, exigir seletor `X-Client-Tenant`; resolver `owner := AccountResolver.ResolveAccountID(T)`; **`owner=="" || owner != account.ID` ⇒ 404** (mesma-404, sem oráculo); só então injeta `ctxTenantID=T`. Se autentica como **token-de-tenant** e há seletor presente ⇒ **rejeita** (T3). Seletor ausente numa chave-de-Conta ⇒ **400** (T4).
- Tudo **atrás da flag** `PAYMENT_ACCOUNT_KEY_SELECTOR` (default-off): flag off ⇒ chave-de-Conta e seletor são ignorados, comportamento idêntico a hoje.
- **Handlers `/v1` NÃO mudam** — continuam lendo só `tenantFromContext(ctx)`.
- Ajustar a semântica fail-safe do `AccountResolver` no caminho (b): em (a) `owner==""` cai no self-account (permissivo, dark ok); em (b) `owner==""` ⇒ **nega** (T7). Explicitar + testar as duas semânticas.
- **Testes de regressão obrigatórios (T1–T4, T7):** cross-account⇒404, inexistente⇒404 (indistinguível de cross-account), token-tenant+seletor⇒rejeitado, chave sem seletor⇒400, resolver-erro⇒nega. Table-driven.

**Aceite:** guard fail-closed provado por teste; flag-off = no-op comprovado; **SecurityEngineer aprovou** o guard como load-bearing. Approval CTO.

## Fase B3 — Emissão/rotação da chave-de-Conta via `/v1` (self-serve, condição CEO (iii) pt.1)

**Entrega:** rota `/v1` para a Conta emitir/rotacionar a própria chave.

- `POST /v1/account-key` (rotate/create) autenticada — inicialmente pela chave-de-Conta existente **ou** por bootstrap admin-plane para a 1ª chave (a 1ª chave da Verz é emitida pelo admin/console, como o board cadastra a Conta). Decidir o bootstrap da 1ª chave no impl: provavelmente admin-plane emite a 1ª, depois self-rotate via `/v1`.
- create==rotate idempotente (SIN-69196); exibição **única** do plaintext (ADR-0010 display-once); Idempotency-Key; limiter inbound (429 + Retry-After, fail-open como SIN-69196).
- **Testes:** rotate invalida anterior, display-once, idempotência, limiter.

**Aceite:** Verz consegue rotacionar a chave sem admin; secret nunca logado/retornado 2×. SecEng review (superfície de emissão de credencial) → CTO.

## Fase B4 — Provisionamento self-serve de empresa-cliente via `/v1` (condição CEO (iii) pt.2)

**Entrega:** a Conta cadastra empresas-clientes por API (ponto 3 do board).

- `POST /v1/clients` (nome à confirmar) autenticada pela **chave-de-Conta**: cria tenant com `account_id = account.ID` **da chave** (server-side, imutável — invariante set-once ADR-0009 §2). Retorna o `tenantID` (para o seletor). Idempotency-Key obrigatório.
- A credencial bancária do novo tenant segue via `PUT /v1/bank-credential` já existente (SIN-69196), agora endereçável pelo seletor.
- **Testes:** account_id vem da chave (não do body — T6); Idempotency dedup; deny-by-default sem chave válida.

**Aceite:** Verz cria empresa-cliente + credencial 100% por API, tudo carimbado na Conta certa. SecEng review (A01: garantir que o body não pode forçar outro account) → CTO.

## Fase B5 — Contrato/openapi + docs + runbook Verz

**Entrega:** `docs/api/openapi.yaml` documenta o header `X-Client-Tenant`, os códigos (400/401/404), emissão/rotação de chave e provisionamento; runbook operacional "Verz = 1 chave-de-Conta + seletor". Atualiza a nota "derivada do token, nunca de parâmetro" com a ressalva do caminho chave-de-Conta.

**Aceite:** integration-guide + openapi refletem (b); runbook publicado. Doc-only, review CTO.

---

## Sequenciamento e dependências

```
B1 (domínio+store, dark) ─┬─→ B2 (auth+guard, núcleo seg) ─┬─→ B3 (emissão chave /v1)
                          │                                └─→ B4 (provisionamento cliente /v1)
                          └────────────────────────────────────→ B5 (openapi/docs) [pode começar cedo]
```

- **B2 é o gargalo de segurança** — nada que dependa do caminho (b) liga em prod antes do SecEng aprovar B2.
- **Go-live real** da Verz em (b) ainda depende de: flag ligada + chave emitida + board confirmou `5e458c95`. Ortogonal a creds C6 PROD (SIN-69118).

## Riscos / trade-offs (registrados)

- **T5 (blast radius da chave):** 1 chave = acesso a N empresas **da mesma Conta**. Aceito e documentado no ADR; mitigado por rotação + hash-em-repouso + escopo-account (nunca cross-account). É intrínseco ao modelo Stripe-Connect que o board pediu.
- **Imutabilidade de teste (audit_log whitelist):** se alguma fase tocar colunas de `audit_log`/schema whitelisted (ADR-0009 §52), exige autorização CTO explícita — provavelmente **não** necessária aqui (nada novo em audit_log).
- **Reversibilidade:** flag-off restaura modelo (a) sem migração destrutiva.

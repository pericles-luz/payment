# Runbook — Go-live de produção C6 (cutover, smoke test, rollback)

- **Escopo:** operacionalizar o go-live de **produção** da integração C6 para o
  primeiro cliente (Verz): config de deploy prod, checklist go/no-go, smoke test
  de menor blast-radius e plano de rollback. É o artefato de execução do cutover.
- **Contexto de arquitetura:** modelo (a) ratificado (SIN-69119) — `empresa-cliente
  ≡ tenant`; o cofre de credencial/cert permanece keyed `(tenant, bank)` **sem
  mudança**. Trilha E **operacionaliza** prod; não redesenha o cofre. O intake de
  credencial de produção reusa o caminho já hardenado (admin/console), não há
  endpoint novo.
- **Config de referência:** `.env.prod.sample` (raiz do repo) — shape completo de
  todos os knobs `PAYMENT_*` de prod, sem segredos.
- **Fonte de design:** plano `SIN-69120-go-live-c6-prod-cutover.md` (§2 config,
  §3 checklist, §4 smoke, §5 rollback).
- **Lentes:** Secure-by-default · Reversibilidade/blast-radius · Defense in depth
  · Boring technology · Least-privilege.
- **Dono:** CTO orquestra. **Aprovação de execução:** CEO (mudança de produção)
  + operador para as credenciais reais.

> ⚠️ **Segredo de produção do cliente.** A credencial/senha C6 do cliente
> **NUNCA** trafega em issue/comentário Paperclip, e-mail em claro, chat ou log
> (LGPD + guardrail de credencial de custódia). Ela chega ao operador por canal
> confidencial e é entrada **direto no console sobre TLS**. Se não existir canal
> confidencial, **pare e escale ao CEO** — não improvise canal.

---

## 1. Intake de credenciais de produção (operado por ADMIN)

Decisão (CTO, SIN-69120 §1): para o go-live Verz, **intake operado por admin**,
reusando o caminho existente e já security-reviewed. Self-serve por cliente é
fast-follow opt-in (filha E2), **não** bloqueia go-live.

Caminho de intake (nenhum endpoint novo):

- `PUT /admin/tenants/{tenantID}/bank-credential` → `handleSetBankCredential`
  (`internal/adapters/http/handlers.go`), `RoleAdmin`,
  `SetBankCredential(tenant, bank, clientID, secret)` — keyed `(tenant,bank)`
  (SIN-66023).
- Console HTMX `consoleSetBankCredential` / `consoleSetBankCertificate`
  (`internal/adapters/http/console_handlers.go`) → cofre keyed `(tenant,bank)`
  (SIN-66087/66088). Cert mTLS: parse x509 antes, `tls.X509KeyPair` match, chave
  write-only, `LogValue` redigido.

**Controle load-bearing (defense in depth):** o risco não é o endpoint (já
hardenado) — é o **canal** pelo qual o segredo chega ao operador. Mandatório:

1. Segredo de produção do cliente **nunca** em issue/comentário/e-mail em
   claro/chat/log.
2. Handoff por canal confidencial (cofre / one-time-secret link, ou entrada
   presencial pelo operador com o cliente). Sem canal confidencial → **escalar ao
   CEO antes**.
3. Operador entra o segredo direto no console sobre TLS; cofre write-only;
   rotação/revogação pelo mesmo caminho (SIN-66088 badges de expiração).

---

## 2. Config de deploy de produção (delta staging→prod)

Todos os knobs estão em `.env.prod.sample`. Overrides prod-críticos:

| Knob | Prod | Efeito se errado |
|---|---|---|
| `PAYMENT_C6_BASE_URL` / `PAYMENT_C6_TOKEN_URL` | URLs reais C6 prod | vazio = stub in-memory (zero tráfego real) — é também o ponto de rollback |
| `PAYMENT_C6_SCOPE` | conforme contrato prod | escopo OAuth insuficiente → 403 no C6 |
| `PAYMENT_C6_CLIENT_CERT` / `PAYMENT_C6_CLIENT_KEY` | PEM mTLS prod, 0600 + owner | handshake mTLS falha |
| `PAYMENT_TRUSTED_PROXY_HOPS` | **1** (atrás de 1 proxy) | 0 = client-IP **spoofável** (atribuição/rate-limit furáveis, SIN-68747) |
| `PAYMENT_SECURE_COOKIES` | **true** | cookies fora de TLS |
| `PAYMENT_C6_RATE_LIMIT_RPS` / `_BURST` / `_MAX_RETRIES` | conforme quota prod | estourar quota C6 / retries indevidos |
| `PAYMENT_ADMIN_TOKENS` / `PAYMENT_OPERATOR_TOKENS` / `PAYMENT_TENANT_TOKENS` | tokens prod rotacionáveis (vault) | least-privilege quebrado; nunca em repo |
| `PAYMENT_WEBHOOK_BASE_URL` / `PAYMENT_WEBHOOK_REFS` | capability-URL prod por tenant | webhook C6 não chega / path não mascarado |
| `PAYMENT_DB_PATH` | volume durável + backup | perda de estado financeiro |

Wiring dos knobs prod-críticos **confirmado** em `main`:
`PAYMENT_TRUSTED_PROXY_HOPS` → `config.go` (`getenvInt`, default 0) → aplicado em
`server.go` via `clientIPMiddleware(hops)` (substitui o `RealIP` spoofável);
`PAYMENT_SECURE_COOKIES` → `config.go` (`getenvBool`, default true). Ambos têm
teste table-driven de parsing (`config_test.go`, `client_ip_test.go`).

**Migrations:** `0001..0006` aplicadas + backup antes do cutover. `0007` (tenancy
F0) é backward-compatible (NULL = self-account) e pode chegar depois; a trilha E
**não** aguarda F0.

---

## 3. Checklist de cutover (go/no-go)

**Pré-cutover (T-1):**
- [ ] Gate de aprovação **CEO** para a execução do cutover com creds reais
      (mudança de produção). C6 já aprovou prod (SIN-69118); o gate aqui é a
      execução.
- [ ] Creds/cert de produção C6 recebidos por canal confidencial (§1) e entrados
      no cofre keyed `(tenant,bank)` pelo operador — **um por empresa-cliente**.
- [ ] Migrations `0001..0006` aplicadas no DB prod; **backup do DB tomado**.
- [ ] Config prod revisada contra `.env.prod.sample` / tabela §2:
      `PAYMENT_TRUSTED_PROXY_HOPS=1`, `PAYMENT_SECURE_COOKIES=true`, base/token URL
      prod, rate-limit ativo, tokens de prod do vault.
- [ ] Webhook C6 prod registrado (capability-URL por tenant) + ingress mascara o
      path; dedup por `event_key` ativo.
- [ ] Health `/healthz` verde no binário prod.

**Cutover:**
- [ ] Deploy do binário prod (CD durável: build→ship→restart→healthz).
- [ ] Smoke test controlado (§4) — 1 operação real de baixo valor.
- [ ] Verificar que a trilha de auditoria durável gravou a operação
      (`audit_log` + `bank_id`, SIN-66044).

**Pós-cutover:**
- [ ] Reconcile-before-settle confirmado no fluxo real.
- [ ] Monitor de consumo/billing atribuindo corretamente ao tenant
      (empresa-cliente).
- [ ] Comunicar go-live ao CEO/Verz.

---

## 4. Smoke test de produção (menor operação reversível)

- **Sequência:** leitura primeiro (OAuth 200 + `extrato` / `GET cob`), depois
  **1 cobrança PIX de valor mínimo** (≤ menor valor permitido) contra a conta C6
  de produção do cliente-piloto, **com o cliente ciente**. PIX é reversível
  (devolução) e de menor blast-radius que boleto/checkout.
- **Critério de sucesso:** 201/200 real do C6 prod; `audit_log` gravado; webhook
  recebido + dedup; valor liquida na conta C6 **do próprio cliente** (confirma
  modelo (a) pass-through — nós não custodiamos).
- **Se falhar:** rollback §5; **não repetir cegamente**.

Ver também `docs/ops/c6-smoke-e2e-runbook.md` para o roteiro de smoke detalhado.

---

## 5. Plano de rollback

- **Blast-radius baixo por design:** cutover não é migração destrutiva; é flip de
  config + deploy.
- **Rollback de config:** reverter `PAYMENT_C6_BASE_URL` / `PAYMENT_C6_TOKEN_URL`
  para vazio/sandbox → adapter volta ao **stub in-memory**, zero tráfego ao C6
  prod. Reverter o binário para a release anterior (CD).
- **Rollback de credencial:** revogar/rotacionar a credencial no cofre
  (write-only, mesmo caminho de intake) — o cliente re-onboarda no reintento.
- **Migrations:** `0007` tem `down.sql` reversível (SIN-69119 §4); as demais já em
  prod são backward-compatible. Nenhum passo de cutover exige migração destrutiva.
- **Reconciliação:** qualquer cobrança de smoke pendente é devolvida via PIX
  (reversível) e reconciliada.

---

## 6. Referências

- Plano de design: `SIN-69120-go-live-c6-prod-cutover.md` (trilha E).
- Config: `.env.prod.sample` (raiz do repo) · `.env.example` (shape genérico dev).
- `docs/ops/ingress-runbook.md` — TLS/ingress + mascaramento de path do webhook.
- `docs/ops/c6-smoke-e2e-runbook.md` — roteiro de smoke e2e.
- `docs/ops/incident-response-c6.md` — resposta a incidente C6 (C12/C13).
- Wiring: `internal/platform/config/config.go`, `internal/adapters/http/server.go`
  (`clientIPMiddleware`), `internal/adapters/http/handlers.go`,
  `internal/adapters/http/console_handlers.go`.
- Tenancy modelo (a): SIN-69119. Go-live umbrella: SIN-69118.

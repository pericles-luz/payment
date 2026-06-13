# Política de Revisão de Segurança de PR

> Define (1) critérios **objetivos** para classificar um PR como "potencial de
> fragilidade" — que exige revisão do SecurityEngineer antes do merge — e (2) o
> checklist de revisão. Alinhado ao plano de [SIN-64704](/SIN/issues/SIN-64704):
> "SecurityEngineer revisa todo PR com potencial de fragilidade"; merge no repo
> dev somente pelo CTO.

## 1. Quem faz o quê

- **CTO** — único que mergeia no repo dev `ia-dev-sindireceita/payment`. É o gate
  de merge. Não mergeia um PR "security-sensitive" sem o LGTM do SecurityEngineer.
- **SecurityEngineer** — revisa todo PR classificado como sensível (§2). Aprova,
  pede mudanças ou bloqueia com achados concretos (classe, evidência, fix, risco
  residual). Não mergeia.
- **Autor (Coder/Frontend/CTO)** — auto-classifica o PR (§2) no template e
  marca o SecurityEngineer como reviewer quando aplicável.
- **Board (Pericles)** — único que aceita PR em produção `pericles-luz/payment`
  (1 PR aberto por vez).

## 2. Quando um PR é "security-sensitive" (gatilhos objetivos)

Um PR **DEVE** ter revisão do SecurityEngineer se tocar **qualquer** item abaixo.
Na dúvida, classifica-se como sensível.

**A. Auth / sessão / tokens / cripto**
- [ ] Login, sessão, emissão/validação de token (JWT/opaco), MFA, recuperação.
- [ ] Qualquer uso de `crypto/*`, hashing, assinatura, comparação de segredo.
- [ ] Mudança em RBAC, escopos, middleware de autorização, deny-by-default.

**B. Isolamento de tenant / acesso a dados**
- [ ] Qualquer query nova/alterada no `Repository` ou migração de schema.
- [ ] Qualquer endpoint novo que retorna/altera dados de tenant.
- [ ] Mudança no helper de `Scope`/`tenant_id`, em RLS, em chave de cache, em
      routing key do Rabbit, ou em caminho de storage de mídia.

**C. Integração C6 / BankProvider**
- [ ] Auth C6 (mTLS/OAuth), client TLS, base URL, certificados.
- [ ] Qualquer chamada a banco externo / novo adapter `BankProvider`.

**D. Webhooks / billing / dinheiro**
- [ ] Recepção/validação/idempotência/reconciliação de webhook.
- [ ] Débito de tarifa, ledger, lógica de saldo/cota.
- [ ] Qualquer mudança em valores monetários.

**E. Borda / entrada / superfície externa**
- [ ] Novo endpoint HTTP público (tenant, checkout, webhook, admin).
- [ ] Parsing/validação de entrada, upload/manipulação de mídia.
- [ ] Cabeçalhos de segurança, CORS, rate-limit, CSP, cookies.

**F. Segredos / config / supply chain / infra**
- [ ] Manipulação de segredo/credencial/`.env`/secret store.
- [ ] Nova dependência ou bump (`go.mod`/`go.sum`).
- [ ] Logging que possa conter PII/segredo; mudança de retenção/expurgo (LGPD).
- [ ] CI/CD, permissões, scripts de deploy, IaC.

**Não-sensível (revisão normal do CTO basta):** docs, comentários, refator interno
sem mudar query/contrato/superfície, testes que não enfraquecem asserção, ajuste de
UI sem dado sensível. Se um "refator" mexe em query ou authz, **é** sensível.

## 3. Requisitos mínimos de todo PR (gate, antes da revisão)

- [ ] Título com `[SIN-XXXXX]`; descrição com `Closes/Refs SIN-XXXXX` e a
      auto-classificação (§2: lista os gatilhos que dispara, ou "não-sensível").
- [ ] CI verde: `go vet`, `go test`, `staticcheck`, `govulncheck`.
- [ ] Cobertura > 85% no(s) pacote(s) tocado(s).
- [ ] Sem segredo/PII no diff, nos logs adicionados ou na descrição.
- [ ] Para correção de bug de segurança: **teste de regressão que falha no código
      antigo e passa no novo** (não-negociável).

## 4. Checklist de revisão de segurança (SecurityEngineer)

Aplicar os itens da(s) categoria(s) disparada(s). Citar a lente por nome no comentário.

### 4.1 Isolamento de tenant (sempre que B disparar) — `threat-model` H1/P1/C4
- [ ] `tenant_id` vem da sessão/credencial, **nunca** de input do cliente.
- [ ] Toda query nova filtra por `tenant_id` via helper central; nada espalhado.
- [ ] Postgres: RLS cobre a tabela; `SET app.tenant_id` aplicado.
- [ ] Cache key / routing key / storage path incluem tenant.
- [ ] Consumidor Rabbit revalida tenant.
- [ ] Existe teste: Tenant A não acessa recurso de Tenant B.

### 4.2 Webhook / dinheiro (D) — W1/W2/W3/B1
- [ ] mTLS validado failure-closed; assinatura verificada se disponível.
- [ ] Idempotência por `endToEndId`/`txid`+evento (chave UNIQUE persistida).
- [ ] Anti-replay (chave repetida / fora de janela rejeitada).
- [ ] Estado de pagamento só muda após **reconciliação** com a C6.
- [ ] Débito de billing atômico; ledger append-only; sem race.
- [ ] Valores em centavos inteiros; sem negativo/overflow.

### 4.3 Auth / cripto (A) — H2/A1/A2
- [ ] AuthN ≠ AuthZ; deny-by-default; endpoint mapeado a papel.
- [ ] JWT sem `alg=none`; `exp` curto; revogação possível.
- [ ] Cripto via stdlib; AEAD; nonce único; comparação tempo-constante;
      senha com Argon2id.
- [ ] Plano admin segregado; MFA para admin; cookies `Secure/HttpOnly/SameSite`.

### 4.4 C6 / SSRF (C) — C1/C2/C3
- [ ] mTLS + OAuth client_credentials; sem `InsecureSkipVerify`; TLS 1.2+.
- [ ] Base URL C6 fixa server-side (sem URL controlada por tenant).
- [ ] Credencial selecionada pelo tenant da sessão; isolada por tenant.
- [ ] Token curto, cache por tenant, renovação.

### 4.5 Entrada / borda (E) — H3/H4/H5
- [ ] DTO explícito; sem mass-assignment; allowlist de campos.
- [ ] Queries parametrizadas; sem concatenação SQL.
- [ ] Rate-limit em endpoint caro/enumerável; timeouts.
- [ ] Erros genéricos; sem stack/SQL/segredo vazado; IDs não sequenciais.
- [ ] Cabeçalhos de segurança/CORS/CSP corretos (se web).

### 4.6 Segredos / supply chain (F) — C1/§11 baseline
- [ ] Nenhum segredo no diff/log/erro/URL; `.env` não versionado.
- [ ] Segredo cifrado em repouso; chave fora do DB.
- [ ] Dependência nova justificada; `govulncheck` limpo; `go.sum` atualizado.
- [ ] Logging sem PII; retenção/expurgo conforme LGPD se tocou dados pessoais.

## 5. Severidade e disposição

- **Crítica / Alta** (exploitável; cross-tenant; fraude financeira; vazamento de
  credencial/PII) → **bloqueia merge**. IDOR cross-tenant e webhook sem
  mTLS/idempotência são block automáticos.
- **Média** → corrigir no PR ou abrir issue-filha com owner e prazo antes do merge,
  com aceite explícito do CTO.
- **Baixa** → registrar; pode ir para follow-up.

Todo achado segue o **review bar**: nomear a classe da vulnerabilidade, mostrar o
ataque (PoC/caminho), informar blast radius, propor fix concreto, distinguir
severidade de exploitabilidade, notar risco residual. "Looks fine" não é revisão.

## 6. O que automatizar (não depender só de humano)

O CTO deve codificar como gate de CI o que for mecanizável:
- `go vet`, `staticcheck`, `govulncheck`, `go test`, cobertura > 85% (bloqueiam merge).
- Lint/regra que falha em SQL concatenado e em `InsecureSkipVerify`.
- Scanner de segredo (`gitleaks`) no PR.
- **Teste de isolamento de tenant** rodando no CI como suíte obrigatória.
- Checagem de que PRs que tocam arquivos sensíveis (paths de auth/webhook/repo/
  bank/billing) exigem label/aprovação de segurança (CODEOWNERS apontando o
  SecurityEngineer para esses paths).

Revisão humana foca no que CI não pega: lógica de authz, design de isolamento,
correção de idempotência/reconciliação, modelagem de ameaça do novo fluxo.

## 7. Fluxo operacional

1. Autor abre PR no fork dev, auto-classifica (§2), marca SecurityEngineer se sensível.
2. CI roda os gates (§3/§6).
3. SecurityEngineer revisa (§4), comenta achados, aprova ou bloqueia.
4. CTO mergeia **somente** com CI verde + (se sensível) LGTM de segurança. Qualquer
   push pós-LGTM invalida a aprovação → nova revisão.
5. Promoção a produção (`pericles-luz/payment`): 1 PR por vez, aceite só do board.

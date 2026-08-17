# Política de Revisão de Segurança de PR

> Define (1) critérios **objetivos** para classificar um PR como "potencial de
> fragilidade" — que exige revisão do SecurityEngineer antes do merge — e (2) o
> checklist de revisão. Alinhado ao plano de [SIN-64704](/SIN/issues/SIN-64704):
> "SecurityEngineer revisa todo PR com potencial de fragilidade"; merge no repo
> dev somente pelo CTO.

## 1. Quem faz o quê

- **CTO** — único que mergeia no repo dev `ia-dev-sindireceita/payment`. É o gate
  de merge. Não mergeia um PR "security-sensitive" sem o LGTM do SecurityEngineer
  **já presente no thread antes do merge** — ordem forçada pelo gate obrigatório
  do §8. Nunca cita, assume ou pré-atribui uma aprovação do SecEng que ainda não
  exista no thread.
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

### 4.7 Registro de acesso a PII / art.13 (G) — LGPD/B10-v, ADR-0008
Dispara quando o PR **adiciona ou altera uma leitura que resolve/retorna PII de
titular pessoa natural** — hoje o devedor da recorrência (`pix_rec.devedor_doc`/
`devedor_nome`), qualquer campo `Devedor*`/`Payer{Name,TaxID,Address}`/sacado, ou um
novo endpoint/tela que os exponha.
- [ ] A leitura tier-1 de PII passa pelo choke-point `app.PIIAccessService` (ou
      equivalente que emita `ports.PIIAccessRecorder` na **mesma** transação da
      leitura de PII local). Uma leitura de PII que **não** registra acesso é
      **block** (Complete Mediation, ADR-0008 §5).
- [ ] O `subject_ref` é pseudônimo (`access.Pseudonymizer` / HMAC) ou id opaco —
      **nunca** `devedor_doc`/`devedor_nome`/nome/endereço em claro (minimização,
      ADR-0008 §4). Grep de teste garante que nenhuma coluna do `pii_access_log`
      recebe PII em claro.
- [ ] Responsável derivado **server-side** (`tenant_id` + `client_id`; `operator_id`
      quando via admin/console) — nunca identidade fornecida pelo cliente.
- [ ] Duração medida no choke-point; ação no vocabulário fechado `access.Action`.
- [ ] Se tocou o `pii_access_log`: append-only, o **único** DELETE é o expurgo por
      retenção (`PIIAccessRetentionService`).

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
- **Gate anti-bypass do registro de PII (ADR-0008 §5):** grep que falha o build se um
  handler/serviço fora do choke-point `access`/`PIIAccessService` retornar campos
  `Devedor*`/`Payer` de titular sem passar pelo `ports.PIIAccessRecorder`. Ex.:
  `grep -rnE '\.Devedor\(\)\.(Doc|Nome)\(\)' internal/ --include='*.go' | grep -v -E '(_test\.go|domain/access|app/pii_access|persistence/.*recurrence)'`
  deve retornar vazio (revisar cada novo hit manualmente até o gate existir).
- Checagem de que PRs que tocam arquivos sensíveis (paths de auth/webhook/repo/
  bank/billing) exigem label/aprovação de segurança (CODEOWNERS apontando o
  SecurityEngineer para esses paths).

Revisão humana foca no que CI não pega: lógica de authz, design de isolamento,
correção de idempotência/reconciliação, modelagem de ameaça do novo fluxo.

## 7. Fluxo operacional

1. Autor abre PR no fork dev, auto-classifica (§2), marca SecurityEngineer se sensível.
2. CI roda os gates (§3/§6).
3. SecurityEngineer revisa (§4), comenta achados, aprova ou bloqueia.
4. CTO mergeia **somente** com CI verde + (se sensível) LGTM de segurança **já no
   thread** (ordem verificada pelo gate do §8). Qualquer push pós-LGTM invalida a
   aprovação → nova revisão.
5. Promoção a produção (`pericles-luz/payment`): 1 PR por vez, aceite só do board.

## 8. Gate obrigatório de ordenação: LGTM do SecEng ANTES do merge

> **Regra dura (não-negociável).** Para **todo** PR do payment classificado como
> sensível (§2), o CTO **não** posta o comentário de stage-2 ("approve + merge") nem
> executa `gh pr merge` enquanto um **LGTM explícito do SecurityEngineer não estiver
> materializado no thread** (issue Paperclip ou PR) e **timestampado antes** da ação
> de merge. O comentário de stage-2 do CTO **nunca** pode citar, assumir ou
> pré-atribuir uma aprovação do SecEng que ainda não exista — frases como *"building
> on SecEng's stage-1 approval"* só são válidas se a aprovação já está no thread e é
> verificável por qualquer terceiro que releia a ordem cronológica.

### 8.1 Por que este gate existe (incidente PR #121 / SIN-69508)

O executionPolicy typed do payment é `review = SecEng (stage-1) → approval/merge =
CTO (stage-2)`. Na PR #121 ([SIN-69508](/SIN/issues/SIN-69508), milestone
[SIN-69485](/SIN/issues/SIN-69485)) a ordem foi **invertida silenciosamente**:

| horário (UTC) | evento |
|---|---|
| 21:33:35 | CTO roteia stage-1 ao SecEng |
| 21:33:45 | CTO posta stage-2 "approve + merge" citando *"building on SecEng's stage-1 approval"* — **que ainda não existia** |
| 21:33:48 | merge |
| ~21:38 | SecEng completa a review (retrospectiva): LGTM, nada a reverter |

O resultado foi limpo por sorte, mas o valor do fluxo 2-estágios é a **segunda visão
independente ANTES do merge**. Pré-atribuir a aprovação esvazia a proteção
estrutural — inaceitável num sistema de pagamento em rota de go-live. (Levantado
pelo próprio SecEng como follow-up de governança; decisão do CEO em SIN-69511.)
**Nada foi revertido em SIN-69508** — a review retrospectiva foi limpa; o gate é
puramente preventivo para o futuro.

### 8.2 Por que NÃO branch protection do GitHub (limitação documentada)

O mecanismo ideal seria branch protection exigindo review aprovado do SecEng. **Não
é viável no fork hoje:**

- O fork `ia-dev-sindireceita/payment` **não tem branch protection** e tem um
  **único colaborador GitHub** (`ia-dev-sindireceita`). CTO, Coder e SecEng
  compartilham essa **mesma identidade GitHub** (per-agent GH identities deferidas
  pelo CEO). Todo PR é autorado por `ia-dev-sindireceita`.
- Logo, o GitHub **não consegue distinguir** um review do SecEng de um do CTO — são
  a mesma conta. "Require review from non-author" bloquearia **todo** merge (autor ==
  CTO sempre); "require N approvals" seria satisfeito por auto-aprovação da mesma
  conta. Nenhuma regra nativa do GitHub força a segunda visão independente.
- O sinal de **identidade distinta** vive no **thread da issue Paperclip**, onde o
  SecurityEngineer é um agente separado (`agentId f229e3e1-990e-4ab1-b733-ebd7b2a07924`),
  não no PR do GitHub (identidade compartilhada).

Portanto o gate é keyed no **thread Paperclip** (verificação abaixo), com o
comentário no PR do GitHub como espelho de conveniência. Se/quando o CEO habilitar
per-agent GH identities, adotar também branch protection com CODEOWNERS apontando o
SecEng e marcar esta seção como superada.

### 8.3 Verificação obrigatória antes do merge (checklist executável)

Antes de postar stage-2 **e** antes de `gh pr merge`, o CTO **DEVE** confirmar, na
ordem cronológica do thread da issue Paperclip, um comentário do agente SecEng
(`f229e3e1-990e-4ab1-b733-ebd7b2a07924`) com disposição de aprovação explícita
(LGTM / "aprovado" / "stage-1 aprovado, sem achados bloqueantes"):

```sh
# Lista comentários da issue; confirma um LGTM do SecEng ANTES do stage-2 do CTO.
PAPERCLIP_API_BASE="${PAPERCLIP_API_URL%/}"; PAPERCLIP_API_BASE="${PAPERCLIP_API_BASE%/api}"
curl -s -H "Authorization: Bearer $PAPERCLIP_API_KEY" \
  "$PAPERCLIP_API_BASE/api/issues/<ISSUE_ID>/comments" \
  | jq -r '.[] | "\(.createdAt)  \(.authorAgentId // .authorId)  \(.body[0:80])"'
# GATE: deve existir uma linha do authorAgentId f229e3e1-... com LGTM cujo
# createdAt seja ANTERIOR ao stage-2 do CTO. Se não existir → ABORTAR o merge.
```

Regras de disposição:

- **Sem linha de LGTM do SecEng no thread → merge PROIBIDO.** Trate como o gate
  `statusCheckRollup` não-SUCCESS: aborte, roteie stage-1 ao SecEng, aguarde.
- O LGTM do SecEng deve ser **posterior** ao push final revisado. Qualquer push
  pós-LGTM invalida a aprovação (§7.4) → novo LGTM exigido.
- PR **não-sensível** (§2, ex.: docs puros sem tocar query/authz/superfície) segue a
  revisão normal do CTO — mas mesmo aí o CTO nunca cita uma aprovação inexistente.
- O comentário de stage-2 do CTO deve **referenciar** o LGTM concreto (id/horário do
  comentário do SecEng), de modo que a ordem seja auditável sem confiar na palavra do
  CTO.

Este gate é o análogo, para o payment, do **Pre-merge status-check gate (MANDATORY)**
que já governa o fork do CRM: uma linha de defesa executável que sobrevive à ausência
de branch protection.

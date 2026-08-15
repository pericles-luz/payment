# Threat Model + Contrato de Endpoint — Self-serve intake de credencial por empresa-cliente

- **Issue:** [SIN-69129](/SIN/issues/SIN-69129) ([SIN-69118·E2], fast-follow da trilha E / [SIN-69120](/SIN/issues/SIN-69120)).
- **Status:** **Proposto — THREAT MODEL PRIMEIRO.** Nenhuma implementação até o
  hard-gate do SecurityEngineer nesta issue. Este documento é o artefato de aceite.
- **Autor:** Coder. **Dono do threat model / decisor de segurança:** SecurityEngineer.
  **Impl (depois do aceite):** Coder.
- **Não bloqueia go-live.** O go-live Verz usa o intake admin-operado já hardenado
  (`go-live-c6-prod.md` §1). Este endpoint é escala self-service opt-in.
- **Método:** STRIDE sobre o novo endpoint + trust boundaries + reuso do cofre
  existente. Severidade: **Crítica / Alta / Média / Baixa**.
- **Lentes:** OWASP A01 (broken access control) · Secure-by-default · Least-privilege
  · Defense-in-depth · Hexagonal.
- **Referências:** ADR-0007 (credencial multi-banco por-tenant, cofre keyed
  `(tenant,bank)`); ADR-0008 (write-path chave recebedor); ADR-0009 (tenancy 2
  níveis); [SIN-69126] (Principal{AccountID,TenantID} no choke-point); [SIN-66023]
  (`PUT /admin/.../bank-credential`); `threat-model.md` (modelo-mãe).

---

## 1. Contexto e delta

Hoje o intake de credencial de banco é **só admin-operado**: `PUT
/admin/tenants/{tenantID}/bank-credential` (`handleSetBankCredential`) atrás de
`adminAuthMiddleware` + `requireRole(RoleAdmin)`; o `tenantID` alvo vem do
**path** e o chamador é um operador da plataforma (token admin). O segredo
transita direto para o cofre `secret.Store` keyed `(tenantID, bankID)`, write-only,
redigido em `String()/LogValue()` (threat C1/C4).

Para escalar revendedores (Verz e futuros), a **própria empresa-cliente** deveria
poder submeter/rotacionar a sua credencial C6 autenticando com o **seu token
escopado** (SIN-69119 §3.3 / SIN-69126: token → empresa-cliente direto, **sem
seletor de tenant** → sem superfície A01 de troca de escopo).

**Delta de superfície (por que exige threat model dedicado):** este é um endpoint
novo que **recebe um segredo de banco de produção do cliente** vindo de um ator
**semi-confiável** (o tenant), não de um admin privilegiado. O ativo (credencial
C6 de produção) é o mesmo de altíssimo valor; muda **quem** o envia e **por qual
plano de autenticação**. O cofre e a porta de escrita **não mudam** — reusamos
`CredentialWriter.SetBankCredential` atrás da mesma porta hexagonal.

### 1.1 Princípio load-bearing (deriva o desenho inteiro)

> O `tenantID` do write vem **exclusivamente** do `ctxTenantID` resolvido no
> choke-point de auth a partir do token — **nunca** de path, body ou query. Não
> existe parâmetro de tenant no contrato. Logo não há nada para o cliente adulterar:
> a ausência de seletor **projeta o A01 para fora** (SIN-69119 §3.3).

---

## 2. Ativos, atores, trust boundary

- **Ativo protegido:** credencial C6 de **produção** da empresa-cliente
  (`client_id` + `secret`; futura rotação de cert mTLS é fora de escopo desta
  primeira entrega — ver §7). Classe: **Confidencial (segredo)** — mesmo tier do
  intake admin.
- **Ator que autentica:** empresa-cliente (tenant) via **token escopado**
  (`AuthenticateTenantPrincipal` → `Principal{TenantID, AccountID}`). Confiança:
  **semi-confiável** (autenticado, mas hostil-potencial dentro do próprio escopo).
- **Fronteira nova:** Internet → plano **tenant** (`/v1/...`), que até aqui só
  **lê/cria cobranças** e **nunca escreveu segredos**. Este endpoint é a **primeira
  escrita de segredo no plano tenant**. Todo o resto do plano tenant continua
  read/charge-only.

---

## 3. Análise STRIDE do endpoint

| # | Categoria | Ameaça | Severidade | Mitigação (obrigatória na impl) |
|---|-----------|--------|------------|----------------------------------|
| S1 | Spoofing | Requisição não autenticada tenta gravar credencial | Crítica | Deny-by-default: `tenantAuthMiddleware` já roda antes do handler (`/v1` group). Token inválido → 401 antes de qualquer lógica. |
| S2 | Spoofing | Tenant A forja escopo para gravar como Tenant B (cross-tenant / cross-account) | **Crítica (A01)** | `tenantID` do write = `tenantFromContext(ctx)` **server-side**; **nenhum** parâmetro de tenant no contrato. Impossível endereçar outro tenant. Cross-account idem: o token resolve 1 tenant só. |
| T1 | Tampering | Body adultera `bank` para banco não-allowlistado / injeta campo extra | Alta | `ports.NormalizeBankID` + `IsKnownBankID` na borda (deny-by-default, espelha `handleSetBankCredential`); decode estrito. Só `bank`/`client_id`/`secret` aceitos. |
| T2 | Tampering | Sobrescrever a própria credencial destrói a anterior sem trilha | Média | Write é rotação legítima (é o ponto do endpoint). Auditar cada escrita (§4 R1); invalidar token cache (`CredentialInvalidator`) para não servir bearer antigo (ADR-0003). |
| R1 | Repudiation | Não há prova de quem/quando rotacionou a credencial | Alta | `audit_log` append-only: `Action credential.set`, `tenant_id`, `bank_id`, `account_id`, `client_id` (**nunca** o secret), timestamp, origem `self-serve`. Reusa domínio `audit`. |
| I1 | Info disclosure | Secret vaza em log/erro/URL/response | **Crítica** | Secret **nunca** em URL (é body de PUT/POST, não path/query). Response ecoa só `{tenant_id, bank, client_id, status}` (sem secret) — espelha `bankCredentialView`. `BankCredential.LogValue()` redige. Erro de validação **não ecoa** o valor. |
| I2 | Info disclosure | Resposta/latência distinta revela existência de outro tenant (oráculo de enumeração) | Alta | Sem seletor não há "outro tenant" para sondar. Não expor GET do secret (write-only). 404 uniforme para qualquer rota fora do próprio escopo (herdado do choke-point). |
| D1 | DoS | Flood de rotações satura cofre / token endpoint C6 | Média | Rate-limit por-tenant no endpoint (bucket dedicado, ver §5). Escrita é O(1) no cofre; sem fan-out síncrono ao C6 (a invalidação de cache é local e best-effort). |
| E1 | Elevation | Tenant vira admin / grava fora do próprio escopo | **Crítica (A01)** | Escopo é o próprio tenant, ponto final. Nenhum caminho concede RoleAdmin. Token tenant **não** habilita rotas `/admin`. |
| E2 | Elevation | Replay de um write antigo capturado reintroduz secret revogado | Alta | Idempotência opcional por `Idempotency-Key` (§5); rotação é last-write-wins mas cada write é auditado e invalida o cache — replay grava o mesmo valor, não escala privilégio. Ver questão aberta Q2. |

**Conclusão STRIDE:** nenhuma ameaça nova de arquitetura além das já mitigadas
pelo choke-point de tenant + cofre write-only. O ganho de segurança do desenho
**sem seletor** é que a classe A01 (a mais perigosa aqui) é **eliminada por
construção**, não mitigada por check.

---

## 4. Auditoria, redação e privacidade

- **R1 — audit_log (append-only):** toda escrita emite uma entrada
  `audit.ActionSetBankCredential` com `tenant_id`, `bank_id`, `account_id`
  (derivado do Principal), `client_id`, `origin=self-serve`, timestamp. **Nunca** o
  secret. Reusa o adaptador durável existente (SIN-66025/66044) — sem nova tabela.
- **Redação:** `BankCredential.String()`/`LogValue()` já redigem `Secret` e
  `CreditorKey` (threat C1/C4). Nenhuma nova rota de log toca o secret.
- **pii_access_log:** **não se aplica** — credencial de banco é segredo, não PII de
  titular (LGPD). Este endpoint não lê `devedor_doc/nome` (a única PII em repouso,
  ver `sin-68744`). Nenhuma nova interação com `pii_access_log`.
- **Sem oráculo:** validação que rejeita nunca ecoa o valor rejeitado; deny é
  uniforme (401 sem token, 400 bank inválido, 400 campos vazios) — sem 403/404
  discriminatório que revele escopo alheio (não há escopo alheio endereçável).

---

## 5. Contrato de endpoint (proposto — reusa a porta do cofre)

**Rota (plano tenant, dentro do group `/v1` já sob `tenantAuthMiddleware`):**

```
PUT /v1/bank-credential
Authorization: Bearer <token-escopado-da-empresa-cliente>
Idempotency-Key: <opaco, opcional>        # ver Q2
Content-Type: application/json

{ "bank": "c6", "client_id": "<id>", "secret": "<secret>" }
```

- **Sem `tenantID` no path** (princípio §1.1). O tenant vem de `ctxTenantID`.
- **Handler (proposto):** `handleTenantSetBankCredential` — espelha
  `handleSetBankCredential` **exceto** que `tenantID := tenantFromContext(r.Context())`
  em vez de `chi.URLParam`. Chama a **mesma** `s.<svc>.SetBankCredential(ctx,
  tenantID, bank, clientID, secret)` (porta `CredentialWriter`) + invalida cache
  (`CredentialInvalidator`).
- **Resposta 200:** `{ "tenant_id", "bank", "client_id", "status":"ok" }` —
  **sem** secret (reusa `bankCredentialView`).
- **Erros:** 401 (sem/inválido token — pelo middleware), 400 (bank não
  allowlistado, campos vazios), 429 (rate-limit), 405 (método). Envelope `{"error":...}`
  existente. Nenhum 403/404 que revele outro tenant.
- **Rate-limit:** bucket por-tenant dedicado à rotação de credencial (baixo QPS
  esperado); reusa o padrão de limiter existente (SIN-68742) ou um guard leve.
  **Decisão de parâmetro fica com SecEng.**

**Hexagonal:** nenhuma porta nova. `CredentialWriter.SetBankCredential` já existe
e já é a fronteira. O handler tenant é um segundo **driving adapter** para a mesma
porta — o secret transita direto ao cofre, nunca entra em domain state.

**Alternativa `POST` vs `PUT`:** `PUT` (idempotente, substitui a credencial do
`(tenant,bank)`) casa com a semântica de rotação e com o verbo do endpoint admin.
Recomendo `PUT`. Confirmar com SecEng.

---

## 6. Reversibilidade / rollout

- **Feature flag:** endpoint atrás de flag `PAYMENT_SELFSERVE_CRED_INTAKE`
  (default **off**). Go-live Verz não depende dele; liga-se quando SecEng aprovar e
  a UX self-serve existir.
- **Sem migração:** cofre e audit_log já existem. Rollback = desligar a flag; o
  intake admin continua o caminho canônico.
- **Blast radius:** um tenant só consegue afetar a **própria** credencial. Falha do
  endpoint não afeta cobranças nem o intake admin.

---

## 6.5. Delta — intake self-serve de certificado mTLS (private key em trânsito) — SIN-69346

Segunda superfície self-serve, **entregue** (não mais "fora de escopo"): a
empresa-cliente envia seu PRÓPRIO par certificado/chave via `PUT /v1/bank-certificate`,
autenticada pelo próprio token, reusando 1:1 a arquitetura do intake de credencial
acima. **Toda a análise das seções 2–6 se aplica sem alteração** (mesmo trust
boundary, mesmo A01-por-construção `tenantID = ctxTenantID`, mesma allow-list `{c6}`,
mesmo limiter inbound dedicado + `Retry-After`, mesma flag `PAYMENT_SELFSERVE_CRED_INTAKE`,
mesma auditoria com `origin=self-serve`, zero migração). Este delta cobre **apenas o
ativo novo e mais sensível: a chave privada em trânsito**.

### 6.5.1. Por que a chave privada é mais sensível que o `client_secret`

Um `client_secret` OAuth2 é rotacionável e só vale contra o token endpoint do PSP.
A **chave privada mTLS** autentica o canal de transporte inteiro contra o C6 e, se
vazar, permite personificar a empresa-cliente na conexão TLS. Logo, o manuseio da
chave recebe controle **estrito e explicitamente testado**, acima do secret.

### 6.5.2. Controles de manuseio da private key (todos com teste dedicado)

| # | Controle | Onde | Verificação |
|---|----------|------|-------------|
| K1 | **Nunca ecoada no response** | handler `handleTenantSetBankCertificate` retorna só `bankCertificateView` (fingerprint, subject, issuer, serial, janela de validade) — **não existe campo de chave** na struct | Teste `TestSelfServeCertWritesOwnTenant`/`…CreateEqualsRotate` afirmam que o corpo base64 da chave NÃO aparece no response |
| K2 | **Write-only no cofre** | par vai para `secret.CertStore` keyed `(tenant, bank)`; a chave nunca é lida de volta por nenhuma rota (não há GET de chave) | `bankcert`/`CertStore` redigem material sensível; nenhum caminho de leitura expõe `key_pem` |
| K3 | **Nunca logada** | `BankCertificate`/material seguem o padrão `LogValue`/redação (threat C1/C4); o handler não loga o corpo; erro de validação **não ecoa** o PEM | herdado do padrão de redação da seção 4; erro é código nomeado (`invalid request` / validação), sem eco do input |
| K4 | **Validada server-side ANTES do cofre** | `Parse` (x509) + casamento `tls.X509KeyPair` + **rejeição de cert expirado** (`NotAfter < now`) no use-case → `400` (nunca `500`), material ruim nunca chega ao storage | `TestSelfServeCertRejectsExpired`, `TestSelfServeCertRejectsMismatchedKey` |
| K5 | **TLS-only** | a chave só transita no corpo de um `PUT` sobre TLS (nunca em URL/path/query — mesma regra I1 do secret) | contrato: `key_pem` é campo de body, jamais parâmetro de rota |
| K6 | **Auditoria sem a chave** | `NewSelfServeCertificateSetEntry` grava who/tenant/bank + **fingerprint** (id público) em `tx_id`, `origin=self-serve`; nunca a chave (não há parâmetro de chave no construtor) | `TestSelfServeCertWritesOwnTenant` afirma `origin=self-serve` no trail; construtor não tem campo de chave |

### 6.5.3. Delta STRIDE frente ao intake de credencial

Único item que muda de peso: **I1 (Info disclosure do segredo)** sobe de *Crítica*
para *Crítica+* pela natureza da chave privada — mitigado pelos K1–K6 acima
(response só-metadados, write-only, sem log, validação no boundary). Todos os demais
itens (S/T/R/D/E e I2 oráculo) são **idênticos** ao intake de credencial: sem
seletor não há A01/oráculo cross-tenant; limiter próprio cobre D; flag cobre
reversibilidade. **Nenhum novo vetor** é introduzido além do manuseio da chave, já
coberto.

---

## 7. Fora de escopo desta primeira entrega (fast-follow do fast-follow)

- ~~**Rotação de cert mTLS self-serve** (`BankCertificate`)~~ — **ENTREGUE em
  SIN-69346**; ver seção 6.5 (delta private-key). A allow-list, o limiter dedicado
  e a auditoria `origin` são reusados 1:1 do intake de credencial.
- **Chave do recebedor (creditor key) self-serve:** é routing-sensitive (A01
  confused-deputy, ADR-0004/0008). Mantém-se admin-only por ora.
- **UX/console HTMX self-serve:** entrega separada após o aceite do contrato
  (loop-in UX/CTO). Este doc cobre só backend + threat model.

---

## 8. Questões abertas para o SecurityEngineer (hard gate)

- **Q1 — Rate-limit:** parâmetros do bucket por-tenant para rotação de credencial
  (RPS/burst)? Reusar `SIN-68742` limiter ou guard dedicado?
- **Q2 — Idempotência/replay (E2):** `Idempotency-Key` é suficiente, ou exigimos
  também um nonce/janela anti-replay? Rotação é last-write-wins — replay reescreve
  o mesmo valor sem escalar, mas confirmar o apetite.
- **Q3 — Verbo:** `PUT /v1/bank-credential` (recomendado) vs `POST`?
- **Q4 — `bank` no body:** manter `bank` selecionável (allowlist) ou fixar `c6`
  nesta entrega e adiar multi-banco self-serve?
- **Q5 — Confirmação do "sem oráculo":** validar que nenhum código de erro/tempo
  do handler distingue estados que revelem escopo — dado que não há tenant
  endereçável além do próprio, acredito ser N/A, mas peço confirmação.

**Gate:** implementação (handler + testes de isolamento cross-tenant
server-enforced, write-only, redação, rate-limit) só começa após o LGTM do
SecurityEngineer neste documento e nas respostas Q1–Q5.

# Baseline Seguro — Plataforma de Pagamentos

> Requisitos **obrigatórios** (MUST) e recomendados (SHOULD) para a fundação
> ([SIN-64705](/SIN/issues/SIN-64705)), o adapter C6 e todo PR subsequente.
> Estes itens são critérios de aceite de segurança e alimentam o checklist de
> revisão de PR (`pr-review-policy.md`). Postura: **failure-closed, least privilege**.

Índice: [1. Segredos](#1-gestão-de-segredos) · [2. Isolamento de tenant](#2-isolamento-de-tenant)
· [3. Auth C6 (mTLS/OAuth)](#3-autenticação-c6-mtls--oauth2) · [4. Webhooks: idempotência & replay](#4-webhooks-idempotência-e-anti-replay)
· [5. Validação de entrada](#5-validação-de-entrada) · [6. Billing atômico](#6-billing-atômico)
· [7. Cripto](#7-criptografia) · [8. AuthN/AuthZ & Admin](#8-authn--authz--plano-admin)
· [9. Logging & auditoria](#9-logging--auditoria) · [10. Hardening HTTP](#10-hardening-http)
· [11. Dependências/CI](#11-dependências--supply-chain) · [12. PIX/BCB & LGPD](#12-conformidade-pixbcb--lgpd)

---

## 1. Gestão de segredos

- **MUST** Nenhum segredo em código, log, mensagem de erro, URL ou imagem.
  `.env` já está no `.gitignore`; manter assim.
- **MUST** Credenciais C6 por tenant (`client_id`, `client_secret`,
  **chave privada do certificado mTLS**) armazenadas cifradas em repouso
  (ver §7). Em SQLite/Postgres, coluna cifrada com AEAD; chave de cifragem fora
  do DB (env/secret store), **nunca** versionada.
- **MUST** Segredos injetados em runtime (env/secret manager), não embutidos no binário.
- **MUST** Comparação de segredos/tokens em **tempo constante** (`crypto/subtle`).
- **SHOULD** Pre-commit `gitleaks`/`trufflehog` como defesa em profundidade.
- **MUST** Runbook de rotação de credencial por tenant (write-only na admin;
  credencial antiga revogada após rotação).

## 2. Isolamento de tenant

> Classe de bug que bloqueia merge automaticamente: IDOR/BOLA cross-tenant.

- **MUST** `tenant_id` **sempre** derivado da credencial autenticada
  (sessão/token), **nunca** de parâmetro de path/query/body do cliente.
- **MUST** Toda leitura/escrita no `Repository` filtra por `tenant_id`. Centralizar
  num helper único — não espalhar `WHERE tenant_id = ?` por handler:

  ```go
  // O scope carrega o tenant da sessão; o Repository o exige em toda operação.
  type Scope struct{ TenantID TenantID }

  func (r *sqlRepo) GetCharge(ctx context.Context, s Scope, id ChargeID) (Charge, error) {
      // tenant_id vem do Scope (sessão), não de input do cliente
      row := r.db.QueryRowContext(ctx,
          `SELECT ... FROM charges WHERE id = ? AND tenant_id = ?`, id, s.TenantID)
      // ... ErrNotFound se não casar — NÃO ErrForbidden (não revelar existência)
  }
  ```

- **MUST** Postgres: **RLS** (`ROW LEVEL SECURITY`) por `tenant_id` como 2ª camada
  (defense in depth), com `SET app.tenant_id` por conexão/transação. SQLite não
  tem RLS → a camada de aplicação é a única; reforça a obrigatoriedade do helper.
- **MUST** IDs externos não sequenciais (UUIDv7/ULID) para reduzir enumeração.
- **MUST** Chaves de cache, nomes de fila/routing key e caminhos de storage
  incluem `tenant_id`. Sem URL de mídia/recurso adivinhável entre tenants.
- **MUST** Jobs/consumidores assíncronos re-derivam e revalidam o tenant; a
  mensagem não é fonte de autoridade.
- **MUST (teste)** Suite de isolamento: Tenant A nunca acessa recurso de Tenant B
  (API, repo, fila). Regressão obrigatória (ver `pr-review-policy.md`).

## 3. Autenticação C6 (mTLS + OAuth2)

> Confirmar o mecanismo exato no spec C6 (`autenticação.yaml`); requisitos abaixo
> valem de todo modo.

- **MUST** OAuth2 **client_credentials** sobre **mTLS** com a C6. Token de vida
  curta; cache **por tenant** com expiração; renovação automática.
- **MUST** TLS 1.2+; validar cadeia do servidor; **nunca** `InsecureSkipVerify`.
- **MUST** Certificado/chave cliente por tenant carregados do secret store; chave
  privada nunca em log nem em DB plaintext.
- **MUST** Base URL da C6 fixa por configuração **server-side** (sem endpoint C6
  controlado por tenant) → previne SSRF (ameaça C2).
- **MUST** Escopos OAuth mínimos necessários por operação (least privilege).
- **SHOULD** Circuit breaker + timeout + retry com backoff idempotente nas chamadas C6.

## 4. Webhooks: idempotência e anti-replay

> Superfície de maior risco (W1/W2/W3). Failure-closed.

- **MUST** Autenticar o emissor: **mTLS** validando o certificado cliente da C6
  (cadeia + pin do issuer). Sem certificado válido → **rejeitar** (não processar).
- **MUST** Se o spec C6 fornecer assinatura HMAC/JWS do payload, verificá-la em
  tempo constante além do mTLS.
- **MUST Idempotência:** chave = `endToEndId`/`txid` + tipo de evento. Tabela
  `processed_webhook_events(idempotency_key UNIQUE, tenant_id, received_at)`.
  Evento já visto → ACK sem reprocessar.
- **MUST Anti-replay:** rejeitar evento fora de janela de tempo razoável (se o
  payload tiver timestamp confiável) e qualquer `idempotency_key` repetido.
- **MUST Reconciliação:** o webhook é **gatilho**, não verdade. Antes de marcar
  uma cobrança como paga, **consultar a C6** (`GET cob/{txid}`) e confiar na
  resposta autenticada. Indisponibilidade da C6 → enfileirar reconciliação;
  **nunca** marcar pago só com base no payload recebido.
- **MUST** Processamento assíncrono: validar+dedupe barato na borda, enfileirar no
  Rabbit, processar no consumidor (idempotente). DLQ + limite de retry.
- **MUST** ACK rápido à C6 (2xx) apenas após persistir a recepção idempotente;
  nunca acoplar o ACK ao sucesso da reconciliação.

## 5. Validação de entrada

- **MUST** Validar tipo, tamanho, faixa, formato e **semântica**. Allowlist > denylist.
- **MUST** DTO de entrada explícito por endpoint; **sem** bind direto na entidade de
  domínio (previne mass-assignment — ameaça H4). Campos como `tenant_id`,
  `status`, `price` nunca aceitos do cliente.
- **MUST** Queries **parametrizadas** sempre; concatenação de SQL proibida.
- **MUST** Validar valores monetários como inteiros em centavos (sem float);
  rejeitar negativos/overflow.
- **MUST** Validar CPF/CNPJ, chave PIX e `txid` por formato antes de qualquer uso.
- **MUST** Rejeitar entrada ambígua em vez de "sanitizar".

## 6. Billing atômico

- **MUST** Débito de tarifa **atômico** com a operação (transação ou
  `UPDATE saldo ... WHERE saldo >= custo` + checagem de linhas afetadas).
  Sem janela em que requisições concorrentes burlam a cota (ameaça B1).
- **MUST** Ledger **append-only autoritativo**; saldo é derivado do ledger, não
  o contrário. Cada lançamento com idempotency key por evento tarifável.
- **MUST** Tarifação editável **somente** no plano admin (RBAC); tenant read-only
  sobre o próprio preço.
- **SHOULD** Reconciliação periódica ledger × eventos para detectar divergência.

## 7. Criptografia

- **MUST** Não inventar cripto. Usar `crypto/*` da stdlib ou libsodium.
- **MUST** AEAD para cifragem simétrica de segredos em repouso
  (AES-256-GCM ou ChaCha20-Poly1305); nonce único por operação, **nunca**
  reutilizado com a mesma chave.
- **MUST** Hash de senha (se houver login local admin): **Argon2id** (ou bcrypt/scrypt).
  Nunca MD5/SHA1/SHA2 puro para senha.
- **MUST** Comparações de segredo em tempo constante (`crypto/subtle.ConstantTimeCompare`).
- **MUST** Runbook de rotação de chave de cifragem (envelope encryption: chave de
  dados cifrada por chave mestra rotacionável).

## 8. AuthN / AuthZ & plano admin

- **MUST** Distinguir autenticação de autorização; deny-by-default em authz.
- **MUST** JWT (se usado): `alg` fixo allowlisted (sem `none`/confusão de chave),
  `exp` curto, mecanismo de revogação. Preferir token opaco + sessão server-side
  quando possível.
- **MUST** Cookies de sessão (admin web): `Secure`, `HttpOnly`, `SameSite=Strict`;
  rotação de sessão em mudança de privilégio.
- **MUST** Plano admin **segregado** do plano tenant (mesmo binário, middleware e
  rotas distintas; tenant comum nunca alcança rota admin).
- **MUST** Cada endpoint (tenant e admin) mapeado a um papel/escopo **antes** do
  merge. "Adiciono a checagem depois" é rejeitado.
- **SHOULD→MUST(admin)** MFA TOTP para contas admin (blast radius = todos os tenants).
- **MUST** Credenciais bancárias write-only na admin (mascaradas após cadastro;
  nunca reexibidas em claro).

## 9. Logging & auditoria

- **MUST** Logar eventos de segurança: authn, decisões de authz negadas, mudança
  de privilégio/config/tarifação, cadastro/rotação de credencial, recepção e
  reconciliação de webhook, ações admin (ator + tenant-alvo + antes/depois).
- **MUST** **Nunca** logar segredos, tokens, chave privada, CPF/CNPJ ou dados de
  cartão/conta em claro. Redigir/mascarar PII (ver §12 LGPD).
- **MUST** Contexto suficiente para reconstruir um incidente (request id,
  tenant id, idempotency key) sem expor o conteúdo sensível.
- **SHOULD** Logs centralizados com evidência de adulteração; alertas em anomalia
  (picos de 4xx/401, replay detectado, falha de reconciliação).

## 10. Hardening HTTP

- **MUST** TLS na borda; HSTS. Sem endpoint sensível em HTTP claro.
- **MUST** Rate-limit por **tenant** e por **IP** em: autenticação, criação de
  cobrança (chama C6), webhook, e endpoints enumeráveis. Backoff exponencial.
- **MUST** Timeouts de servidor e de cliente HTTP (read/write/idle) configurados.
- **MUST** CORS restrito (sem `*` com credenciais; sem refletir origem arbitrária).
- **MUST (checkout/admin web)** Cabeçalhos: CSP estrita (sem `unsafe-inline`),
  `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`;
  CSRF token ou `SameSite=Strict` em ações que mudam estado.
- **MUST** Erros genéricos ao cliente; nada de stack/SQL/segredo na resposta.

## 11. Dependências / supply chain

- **MUST** `go.mod`/`go.sum` commitados; dependências pinadas.
- **MUST** CI roda `govulncheck`, `staticcheck`, `go vet`, `go test` — bloqueia
  merge se qualquer um falhar (gate já previsto no plano).
- **MUST** Cobertura > 85% (gate); testes de regressão de segurança contam.
- **SHOULD** Triagem de Dependabot/`osv-scanner`; cautela com pacotes recém-publicados
  e typosquats.

## 12. Conformidade PIX/BCB & LGPD

### PIX / BCB
- **MUST** Idempotência e rastreabilidade por `txid`/`endToEndId` (alinhado ao §4).
- **MUST** Reconciliação autoritativa com o PSP (não confiar só em webhook).
- **MUST** Sigilo bancário: dados de pagamento são **regulados** → cripto em
  trânsito e repouso, acesso least-privilege, isolamento por tenant.
- **SHOULD** Atender requisitos de segurança da API PIX do BCB (mTLS, OAuth,
  certificados) conforme o spec C6 — confirmar nos anexos.

### LGPD
- **MUST** Minimização: coletar/armazenar só o necessário ao pagamento.
- **MUST** Definir e aplicar **retenção** (padrão configurável; default conservador);
  expurgo efetivo, não soft-delete, ao fim do prazo / sob direito de eliminação,
  ressalvada a guarda legal de registros financeiros.
- **MUST** Direito de eliminação que **de fato apaga** (ou pseudonimiza quando a lei
  exigir retenção do registro financeiro).
- **MUST** Logs sem PII em claro (mascarar CPF/CNPJ, chave PIX, nome).
- **MUST** Base legal e papel (controlador/operador) por tenant documentados; a
  plataforma é tipicamente **operadora** dos dados do tenant.
- **SHOULD** DPIA quando houver tratamento de alto risco; trilha de consentimento
  para qualquer fusão de identidade entre canais.
- **MUST** Encarregado/contato e processo de resposta a incidente definidos antes do go-live.

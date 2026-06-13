# Threat Model — Plataforma de Pagamentos

> Escopo: SIN-64706. Método: STRIDE por componente + trust boundaries + DFD.
> Revisar a cada mudança de superfície de ataque (novo endpoint, novo banco,
> novo canal). Severidade qualitativa: **Crítica / Alta / Média / Baixa**.

## 1. Visão do sistema

Plataforma multi-tenant em Go (hexagonal) que intermedeia cobranças/pagamentos
de várias empresas (tenants) contra bancos (C6 primeiro), com billing por
endpoint e área administrativa.

### 1.1 Atores

| Ator | Confiança | Descrição |
|------|-----------|-----------|
| Tenant (cliente B2B) | Semi-confiável | Consome a API com sua credencial; só pode ver/agir sobre os próprios dados. |
| Pagador final (cliente do tenant) | Não confiável | Paga um PIX/boleto; interage via link de checkout. |
| Admin da plataforma | Privilegiado | Gerencia tenants e tarifação. Alvo de alto valor. |
| Banco C6 (PSP) | Externo confiável (autenticado) | Origem dos webhooks; destino das chamadas de cobrança. |
| Atacante externo | Hostil | Internet; tenta IDOR cross-tenant, forjar webhook, roubar credencial. |
| Atacante interno / tenant malicioso | Hostil autenticado | Tenta escapar do próprio escopo de tenant. |

### 1.2 Ativos (classificação de dados)

- **Regulado (LGPD/sigilo bancário):** CPF/CNPJ do pagador, nome, chave PIX,
  valores, `txid`/`endToEndId`, dados de cobrança, extrato/conciliação.
- **Confidencial (segredo):** credenciais C6 por tenant (client_id/secret,
  **chave privada do certificado mTLS**), tokens OAuth, segredos de webhook,
  chaves de assinatura de token de sessão admin.
- **Interno:** configuração de tarifação, ledger de billing, logs de auditoria.
- **Público:** documentação, páginas de checkout (sem PII sensível em URL).

### 1.3 Trust boundaries

```
                         Internet (não confiável)
   ┌───────────────┬──────────────────┬─────────────────────┐
   │ Tenant API    │ Checkout pagador │  Webhook C6 (mTLS)   │
   ▼               ▼                  ▼                       │
┌──────────────────────────────────────────────────────────┐│
│  TB1: Borda HTTP  (TLS, rate-limit, authz, validação)     ││
│  ┌────────────────────────────────────────────────────┐  ││
│  │ TB2: Domínio (hexagonal core) — tenant scoping      │  ││
│  │   payments | tenants | billing                      │  ││
│  └───┬───────────────┬──────────────┬──────────────────┘  ││
│      ▼ Repository     ▼ MessageBus    ▼ BankProvider       ││
│  ┌─────────┐    ┌──────────┐    ┌──────────────────┐      ││
│  │TB3: DB  │    │TB4:Rabbit│    │TB5: C6 (mTLS+OAuth│◄─────┘│
│  │SQLite/PG│    │  MQ      │    │ client_credentials│       │
│  └─────────┘    └──────────┘    └──────────────────┘       │
│  TB6: Admin plane (RBAC, MFA recomendada, auditoria)       │
└────────────────────────────────────────────────────────────┘
```

- **TB1** Internet ↔ borda HTTP. Toda requisição cruza authn + authz + validação.
- **TB2** Borda ↔ domínio. Toda operação carrega `tenant_id` derivado da credencial
  autenticada, **nunca** de parâmetro controlado pelo cliente.
- **TB3** Domínio ↔ persistência. Toda query filtra por `tenant_id`.
- **TB4** Domínio ↔ RabbitMQ. Mensagens carregam `tenant_id`; consumidores re-validam.
- **TB5** Plataforma ↔ C6. mTLS + OAuth2; credencial isolada por tenant.
- **TB6** Plano administrativo, privilégio elevado, segregado do plano tenant.

### 1.4 Principais fluxos de dados

1. **Criar cobrança PIX** — Tenant→API→domínio→`BankProvider`(C6 cria cob)→
   retorna `txid`/QRCode→persiste→debita billing do endpoint.
2. **PIX Automático** — autorização recorrente (consentimento) + cobranças
   subsequentes disparadas pela plataforma.
3. **BolePix** — emissão de boleto híbrido (boleto + QR PIX).
4. **Checkout** — página/link para o pagador final concluir o pagamento.
5. **Webhook C6** — C6→borda webhook (mTLS)→valida→enfileira evento→consumidor
   concilia (GET cob/{txid}) e atualiza estado→notifica tenant.
6. **Billing** — cada chamada tarifável debita o ledger do tenant (atômico).
7. **Admin** — CRUD de tenants, credenciais bancárias, tabela de tarifação.

---

## 2. STRIDE por componente

> Cada ameaça lista **mitigação** (detalhe em `secure-baseline.md`).

### 2.1 Borda HTTP / API do tenant (TB1)

| ID | STRIDE | Ameaça | Sev | Mitigação |
|----|--------|--------|-----|-----------|
| H1 | **E**oP / IDOR (BOLA) | Tenant A lê/altera cobrança de Tenant B trocando `txid`/`id` na URL. | **Crítica** | `tenant_id` derivado da credencial; toda query `WHERE tenant_id = ?` via helper central; nunca aceitar `tenant_id` do cliente. §2,§3 baseline. |
| H2 | **S**poofing | Reuso/forja de token de API; `alg=none` em JWT. | Alta | Token opaco ou JWT com `alg` fixo allowlisted, exp curto, rotação; sem aceitar `none`. |
| H3 | **D**oS | Flood em endpoints caros (criação de cobrança chama C6). | Alta | Rate-limit por tenant **e** por IP; timeouts; circuit breaker no `BankProvider`. |
| H4 | **T**ampering | Mass-assignment: cliente injeta `tenant_id`, `price`, `status` no corpo. | Alta | Allowlist de campos de entrada; DTO explícito; nunca bind direto em entidade. |
| H5 | **I**nfo disclosure | Erro vaza stack/SQL/credencial; enumeração de `txid`. | Média | Erros genéricos ao cliente; IDs não sequenciais (UUID/ULID); logs sem PII/segredo. |
| H6 | **R**epudiation | Tenant nega ter criado cobrança. | Média | Log de auditoria assinado por requisição (quem, quando, tenant, ação, idem-key). |

### 2.2 Webhook C6 (TB1→TB5) — superfície de maior risco

| ID | STRIDE | Ameaça | Sev | Mitigação |
|----|--------|--------|-----|-----------|
| W1 | **S**poofing | Atacante POSTa webhook forjado marcando cobrança como paga. | **Crítica** | mTLS: validar certificado cliente C6 (cadeia + pinning do issuer); rejeitar sem cert válido (**failure-closed**). Verificar assinatura se o spec C6 fornecer. |
| W2 | **T**ampering / replay | Reenvio de webhook legítimo para duplicar crédito/efeito. | **Crítica** | Idempotência por `endToEndId`/`txid`+evento; tabela de eventos processados; janela de replay. §4 baseline. |
| W3 | **Insecure design** | Confiar no payload do webhook como verdade financeira. | Alta | Webhook é só *gatilho*; **reconciliar** sempre via GET cob/{txid} na C6 antes de mudar estado de pagamento. |
| W4 | **D**oS | Flood de webhooks. | Média | Rate-limit na borda webhook; processamento assíncrono (Rabbit) com backpressure; dedupe barato antes do trabalho caro. |
| W5 | **I**nfo disclosure | URL de webhook adivinhável / por tenant vaza relação. | Baixa | Endpoint único autenticado por mTLS; resolver tenant pelo conteúdo conciliado, não pela URL. |

### 2.3 Integração C6 / BankProvider (TB5)

| ID | STRIDE | Ameaça | Sev | Mitigação |
|----|--------|--------|-----|-----------|
| C1 | **I**nfo disclosure | Vazamento de client_secret / chave privada mTLS por tenant. | **Crítica** | Segredos fora do código e dos logs; cofre/secret store; chave privada nunca em DB plaintext (cripto em repouso); least-privilege de acesso. §1 baseline. |
| C2 | **S**poofing (SSRF) | Config de endpoint/callback aponta para host interno. | Alta | Base URL C6 fixa por config server-side, não por tenant; allowlist de host; sem fetch de URL controlada por tenant. |
| C3 | **T**ampering | TLS rebaixado / MITM com a C6. | Alta | TLS 1.2+; validar cadeia; mTLS; sem `InsecureSkipVerify`. |
| C4 | **E**oP | Credencial de Tenant A usada para operar conta de Tenant B. | **Crítica** | Seleção de credencial estritamente pelo `tenant_id` da sessão; teste de isolamento. |
| C5 | **R**epudiation | Token OAuth de vida longa, sem rotação. | Média | Tokens curtos; renovação por client_credentials; cache por tenant com expiração. |

### 2.4 Persistência (TB3) — multi-tenancy

| ID | STRIDE | Ameaça | Sev | Mitigação |
|----|--------|--------|-----|-----------|
| P1 | **E**oP / IDOR | Query sem filtro de tenant → vazamento cross-tenant. | **Crítica** | Filtro `tenant_id` obrigatório no `Repository`; helper central; em Postgres, **RLS** como 2ª camada (defense in depth). §2 baseline. |
| P2 | **I**njection | SQL injection. | Alta | Queries parametrizadas sempre; proibir concatenação; `staticcheck`/lint. |
| P3 | **I**nfo disclosure | Backup/arquivo SQLite com PII e credenciais sem cripto. | Alta | Cripto em repouso; chaves bancárias cifradas em coluna; controle de acesso a backup. |
| P4 | **T**ampering | Migração quebra constraint de isolamento. | Média | Revisão de migrations; testes de isolamento rodam pós-migração. |

### 2.5 RabbitMQ / eventos assíncronos (TB4)

| ID | STRIDE | Ameaça | Sev | Mitigação |
|----|--------|--------|-----|-----------|
| Q1 | **T**ampering | Consumidor confia em `tenant_id` da mensagem sem revalidar. | Alta | Re-validar tenant/escopo no consumidor; mensagem não é fonte de autoridade. |
| Q2 | **I**nfo disclosure | Vhost/fila compartilhada vaza eventos entre tenants. | Média | Routing por tenant; least-privilege nas credenciais Rabbit; sem PII desnecessária no payload. |
| Q3 | **D**oS / dup | Reentrega causa efeito duplicado (cobrança/billing). | Alta | Handlers idempotentes; dedupe por chave; DLQ + limite de retry. |

### 2.6 Billing / ledger

| ID | STRIDE | Ameaça | Sev | Mitigação |
|----|--------|--------|-----|-----------|
| B1 | **T**ampering (race) | Requisições concorrentes burlam débito/tarifa. | Alta | Débito atômico (transação/`UPDATE ... WHERE`); ledger autoritativo, não estado derivado. §4 baseline. |
| B2 | **R**epudiation | Disputa sobre o que foi cobrado. | Média | Ledger append-only auditável; idempotency key por evento tarifável. |
| B3 | **E**oP | Tenant altera a própria tabela de tarifação. | Alta | Tarifação só editável no plano admin (RBAC); tenant é read-only sobre o próprio preço. |

### 2.7 Plano administrativo (TB6)

| ID | STRIDE | Ameaça | Sev | Mitigação |
|----|--------|--------|-----|-----------|
| A1 | **E**oP | Endpoint admin acessível por tenant comum. | **Crítica** | Plano admin segregado; RBAC deny-by-default; cada endpoint admin mapeado a papel. |
| A2 | **S**poofing | Conta admin comprometida → acesso a todos os tenants e credenciais. | **Crítica** | MFA (TOTP) para admin; sessão curta; rotação em mudança de privilégio; auditoria. |
| A3 | **R**epudiation | Mudança de tarifação/credencial sem rastro. | Alta | Auditoria de toda ação admin (ator, alvo-tenant, antes/depois). |
| A4 | **I**nfo disclosure | Admin lista credenciais bancárias em claro. | Alta | Credenciais nunca exibidas após cadastro (write-only/masked); rotação suportada. |

---

## 3. Riscos priorizados (top da fila)

1. **W1/W2 — Webhook forjado ou replay marca cobrança como paga.** Maior valor
   para o atacante (fraude financeira direta). Mitigação: mTLS failure-closed +
   idempotência + **reconciliação obrigatória** com a C6 antes de mudar estado.
2. **H1/P1/C4 — IDOR/quebra de isolamento de tenant.** Vazamento de dados de
   pagamento entre empresas (LGPD + sigilo bancário). Mitigação: tenant scoping
   central + RLS + testes de isolamento como gate.
3. **C1 — Vazamento de credencial/chave mTLS por tenant.** Comprometimento total
   da conta bancária do tenant. Mitigação: secret store + cripto em repouso +
   least privilege + zero segredo em log.
4. **A2 — Comprometimento de conta admin.** Blast radius = todos os tenants.
   Mitigação: MFA + auditoria + segregação do plano admin.
5. **B1 — Race em billing.** Tenant consome além da cota / não é cobrado.
   Mitigação: débito atômico + ledger autoritativo.

## 4. Premissas e itens a confirmar

- Mecanismo exato de autenticidade do webhook e da API C6 (mTLS, assinatura,
  OAuth scopes) **a confirmar nos anexos de SIN-64704**. O baseline assume
  mTLS + OAuth2 client_credentials; ajustar se o spec divergir.
- `BankProvider` é um port — cada novo banco re-passa por este threat model
  (auth, webhook, isolamento de credencial).
- Reconciliação síncrona com a C6 assume disponibilidade da API; degradar para
  fila de reconciliação se a C6 estiver indisponível (nunca marcar pago sem
  confirmação).

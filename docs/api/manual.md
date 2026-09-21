# Manual de casos de uso — API de Pagamentos Sindireceita

Cookbook end-to-end da API de Pagamentos. Cada caso traz o fluxo e exemplos
`curl` de request/response verificados contra os handlers. É o companheiro
prático do contrato formal `openapi.yaml` (mesma pasta) e do
`integration-guide.md` (visão de onboarding). Sempre que um caso cita uma
operação, o `operationId` correspondente do `openapi.yaml` está entre parênteses.

> **Segredos nos exemplos.** Todo segredo aqui é placeholder: `ak_xxx`
> (chave-de-Conta), `<TENANT_TOKEN>` (token de empresa-cliente), `<ADMIN_TOKEN>`
> (token de admin). Nunca cole segredo real em issue, log ou comentário.

---

## 0. Conceitos e convenções

### Linguagem ubíqua (dois níveis de tenancy)

| Termo | O que é |
|---|---|
| **Sistema-usuário / Conta (revendedor)** | Quem compra a API (1º cliente: **Verz**). Identidade = **chave-de-Conta** (`ak_…`). |
| **Empresa-cliente (tenant)** | A empresa final que vende online sob a Conta. Identidade = `tenant_id`. |
| **Banco** | O PSP onde o dinheiro liquida (hoje **C6**). Cada empresa-cliente traz sua **própria** credencial e certificado (modelo PSP-Indireto: o dinheiro liquida direto na conta dela). |

Um sistema-usuário pode ter **várias** empresas-clientes. A escolha da
empresa-cliente por chamada é feita pelo header `X-Client-Tenant` (ver §2 e §8).

### Dois modelos de autenticação

| Modelo | Bearer | Seleção da empresa-cliente | Flag |
|---|---|---|---|
| **(a)** token por empresa-cliente | `<TENANT_TOKEN>` | derivada do token (sem seletor) | sempre on |
| **(b)** revendedor (chave-de-Conta) | `ak_…` | header `X-Client-Tenant` a cada chamada `/v1` | `PAYMENT_ACCOUNT_KEY_SELECTOR` (default-off) |

No modelo (b) o seletor `X-Client-Tenant` é o **único** mecanismo autorizado de
escolha, mediado pelo guard de autorização por-request (ADR-0011 §2): a chave só
opera sobre empresas-clientes da **própria Conta**. Um token de empresa-cliente
(modelo a) **não** aceita seletor — enviar `X-Client-Tenant` com ele → `400`.

### Convenções globais (valem para todo `/v1`)

- **Autenticação:** `Authorization: Bearer <...>`. Ausente/inválido → `401`.
- **Valores monetários:** sempre em **centavos** (inteiro). R$ 10,00 → `1000`.
- **Datas/hora:** RFC 3339 (`2026-08-20T00:00:00-03:00`), exceto o extrato que
  usa `YYYY-MM-DD`.
- **Idempotência:** rotas de escrita de recurso (charges, pix, boletos, checkout,
  DDA, account-key, clients) exigem `Idempotency-Key`. Reenvio com a mesma chave
  não duplica o efeito.
- **Erros:** envelope uniforme `{"error":"..."}` (não é RFC 7807).
- **Cross-tenant = `404`, não `403`:** um recurso de outra empresa responde
  `404` (mesma resposta de "não existe") — sem oráculo de existência.
- **Limites de entrada:** corpo até 1 MiB (`413` acima); campos JSON
  desconhecidos → `400`.
- **Rate limit:** token-bucket por empresa (burst 20, 10 req/s) → `429`
  (faça backoff).

### Ambientes

| Ambiente | Base URL (definida por deploy) |
|---|---|
| Produção | `https://api.pagamentos.sindireceita.example` |
| Homologação | `https://homolog.api.pagamentos.sindireceita.example` |

Nos exemplos abaixo, `$BASE` = a base URL do ambiente.

---

## 1. Onboarding do sistema-usuário — emitir e rotacionar a chave-de-Conta

**Quando:** provisionar um novo revendedor (ex.: Verz) no modelo (b).

### 1.1 Bootstrap: o admin emite a **1ª** chave (`adminMintAccountKey`)

A primeira chave de uma Conta é emitida pelo plano administrativo e entregue ao
cliente por **canal seguro** (nunca comentário público). `Idempotency-Key`
obrigatório.

```bash
curl -X POST "$BASE/admin/accounts/acct-verz/account-key" \
  -H "Authorization: Bearer <ADMIN_TOKEN>" \
  -H "Idempotency-Key: 1f0c3a9e-verz-bootstrap-001"
```

`201 Created` — o segredo aparece **uma única vez** (display-once):

```json
{ "account_id": "acct-verz", "secret": "ak_9f2c…redigido…", "status": "created" }
```

Guarde o `secret` em cofre no ato. Um **replay** com a mesma `Idempotency-Key`
**não** reexibe o segredo:

```json
// 409 Conflict
{ "error": "idempotency key already used; the secret is shown only once — rotate with a fresh Idempotency-Key for a new secret" }
```

> Se o emissor de chaves não estiver montado no deploy → `503`
> (`account key issuance unavailable`).

### 1.2 Self-rotate: a Conta rotaciona a **própria** chave (`rotateAccountKey`)

Depois do bootstrap, a Conta rotaciona sozinha usando a chave **atual** — a
Conta vem do próprio Bearer, nunca de parâmetro (uma chave nunca rotaciona a de
outra Conta). Rota `flag-gated`; com a flag off ela **não existe**.

```bash
curl -X POST "$BASE/v1/account-key" \
  -H "Authorization: Bearer ak_9f2c…atual…" \
  -H "Idempotency-Key: 2a7d…rotacao-2026-09"
```

`201 Created` (create==rotate — a chave anterior é invalidada; a resposta é
byte-idêntica a uma emissão, sem revelar se já havia chave):

```json
{ "account_id": "acct-verz", "secret": "ak_4b81…novo…", "status": "created" }
```

---

## 2. Provisionar empresa-cliente e usar o seletor

**Quando:** a Conta cria uma empresa-cliente e passa a endereçá-la por chamada.

### 2.1 Criar a empresa-cliente (`provisionClient`)

Autenticada **pela chave-de-Conta**. O corpo aceita só `name`; **não** aceita
`account_id` (a Conta vem sempre da chave, server-side — A01/T6). `Idempotency-Key`
obrigatório.

```bash
curl -X POST "$BASE/v1/clients" \
  -H "Authorization: Bearer ak_4b81…" \
  -H "Idempotency-Key: prov-loja-alfa-001" \
  -H "Content-Type: application/json" \
  -d '{ "name": "Loja Alfa Ltda" }'
```

`201 Created`:

```json
{ "tenant_id": "tnt-loja-alfa", "account_id": "acct-verz", "name": "Loja Alfa Ltda" }
```

Guarde o `tenant_id`: é o valor do seletor `X-Client-Tenant`.

### 2.2 Endereçar a empresa-cliente por chamada

Toda chamada `/v1` no modelo (b) leva a chave-de-Conta **mais** o seletor:

```bash
curl "$BASE/v1/statement?inicio=2026-08-01&fim=2026-08-30" \
  -H "Authorization: Bearer ak_4b81…" \
  -H "X-Client-Tenant: tnt-loja-alfa"
```

Semântica do seletor (parâmetro `ClientSelector` no `openapi.yaml`):

- Empresa-cliente de **outra** Conta ou inexistente → `404` (sem oráculo).
- Seletor **ausente** numa chave-de-Conta → `400`.
- Seletor enviado junto com um **token de empresa-cliente** (modelo a) → `400`
  (o token não tem autoridade de seleção).

---

## 3. Intake self-serve de credencial e certificado do banco

**Quando:** a empresa-cliente entrega/rotaciona o material bancário dela.
`flag-gated` por `PAYMENT_SELFSERVE_CRED_INTAKE` (default-off — desligada, as
rotas retornam `404`). O tenant é o **chamador autenticado** (token de
empresa-cliente, ou chave-de-Conta + seletor no modelo b), nunca vem do
corpo/URL → A01 eliminado por construção. Allow-list self-serve: `{c6}`.

### 3.1 Credencial PSP (`setSelfServeBankCredential`)

`secret` é **write-only**: nunca é retornado, logado ou ecoado. `create==rotate`
(última escrita vence; resposta byte-idêntica → sem oráculo de existência). Sem
`Idempotency-Key` (a idempotência é natural do last-write-wins).

```bash
curl -X PUT "$BASE/v1/bank-credential" \
  -H "Authorization: Bearer <TENANT_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{ "bank": "c6", "client_id": "c6-client-uuid", "secret": "<C6_CLIENT_SECRET>" }'
```

`200 OK` (só campos não-secretos):

```json
{ "tenant_id": "tnt-loja-alfa", "bank": "c6", "client_id": "c6-client-uuid", "status": "ok" }
```

Banco fora da allow-list (`{c6}`) → `400 { "error": "invalid request" }` (sem eco
do valor).

### 3.2 Certificado mTLS (`setSelfServeBankCertificate`)

Par `cert_pem`/`key_pem`. A **chave privada** (`key_pem`) é write-only: validada
server-side (parse x509, casamento cert/chave, **rejeição de certificado
expirado** → `400`, nunca `500`) e nunca retornada. A resposta traz só metadados
**públicos**. Envie sempre sobre TLS. Bucket de rate-limit separado do intake de
credencial.

```bash
curl -X PUT "$BASE/v1/bank-certificate" \
  -H "Authorization: Bearer <TENANT_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{ "bank": "c6", "cert_pem": "-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----\n", "key_pem": "-----BEGIN PRIVATE KEY-----\n…\n-----END PRIVATE KEY-----\n" }'
```

`200 OK` (metadados públicos; nunca a chave):

```json
{
  "tenant_id": "tnt-loja-alfa",
  "bank": "c6",
  "subject_cn": "loja-alfa.example",
  "issuer": "C6 Bank CA",
  "serial_number": "0A1B2C3D",
  "fingerprint_sha256": "9f:2c:…",
  "not_before": "2026-08-01T00:00:00Z",
  "not_after": "2027-08-01T00:00:00Z",
  "status": "ok"
}
```

Certificado expirado → `400` (nunca `500`).

---

## 4. Venda online / cobrança

Todas as rotas desta seção são tenant-scoped: no modelo (a) o Bearer é o
`<TENANT_TOKEN>`; no modelo (b) some `-H "Authorization: Bearer ak_…"` e
adicione `-H "X-Client-Tenant: <tenant_id>"`. Todas exigem `Idempotency-Key`.
Os exemplos abaixo usam o modelo (a) para encurtar.

### 4.1 Checkout hospedado (`createCheckout` / `getCheckout` / `cancelCheckout`)

Abre uma sessão de checkout hospedada — o comprador é redirecionado para
`redirect_url`.

```bash
curl -X POST "$BASE/v1/checkout" \
  -H "Authorization: Bearer <TENANT_TOKEN>" \
  -H "Idempotency-Key: chk-pedido-5521" \
  -H "Content-Type: application/json" \
  -d '{
        "currency": "BRL",
        "items": [ { "description": "Plano Pro", "amount_cents": 9900 } ],
        "expires_in_seconds": 3600
      }'
```

`201 Created`:

```json
{
  "session_id": "chk_abc123",
  "status": "pending",
  "redirect_url": "https://pay.c6bank.example/checkout/chk_abc123",
  "amount_cents": 9900
}
```

Reconciliar / cancelar:

```bash
curl "$BASE/v1/checkout/chk_abc123"          -H "Authorization: Bearer <TENANT_TOKEN>"   # getCheckout
curl -X DELETE "$BASE/v1/checkout/chk_abc123" -H "Authorization: Bearer <TENANT_TOKEN>"  # cancelCheckout
```

A liquidação chega pelo webhook C6 (§6.2), não por polling obrigatório.

### 4.2 PIX cobrança imediata (`createPix` / `getPix` / `listPix`)

```bash
curl -X POST "$BASE/v1/pix" \
  -H "Authorization: Bearer <TENANT_TOKEN>" \
  -H "Idempotency-Key: pix-venda-8890" \
  -H "Content-Type: application/json" \
  -d '{ "amount_cents": 4990, "currency": "BRL", "expires_in_seconds": 3600,
        "devedor": { "tax_id": "12345678909", "name": "Fulano" } }'
```

`201 Created`:

```json
{
  "txid": "E1234...",
  "status": "ATIVA",
  "qr_code": "00020126...BR.GOV.BCB.PIX...",
  "qr_code_location": "https://.../pix/v2/...",
  "expires_at": "2026-08-16T21:00:00Z",
  "amount_cents": 4990
}
```

Consultar uma cobrança (`getPix`) ou listar por janela de datas (`listPix`,
`?start=&end=` — a rota estática `/pix` é roteada antes de `/pix/{txid}`):

```bash
curl "$BASE/v1/pix/E1234..."                       -H "Authorization: Bearer <TENANT_TOKEN>"
curl "$BASE/v1/pix?start=2026-08-01&end=2026-08-16" -H "Authorization: Bearer <TENANT_TOKEN>"
```

### 4.3 PIX cobrança com vencimento — cobv (`createCobV` / `getCobV` / `updateCobV`)

Cobrança com data de vencimento, multa, juros e desconto (o `txid` é gerado
server-side no create; get/update o endereçam).

```bash
curl -X POST "$BASE/v1/pix/cobv" \
  -H "Authorization: Bearer <TENANT_TOKEN>" \
  -H "Idempotency-Key: cobv-fatura-2026-09" \
  -H "Content-Type: application/json" \
  -d '{ "amount_cents": 15000, "currency": "BRL",
        "due_date": "2026-09-10T00:00:00-03:00", "validity_days": 30,
        "fine_bps": 200, "monthly_interest_bps": 100,
        "creditor_key": "loja-alfa@pix.example" }'
```

`201 Created` retorna `txid`, `qr_code` e a janela de vencimento. Alterar
(`updateCobV`, `PUT /v1/pix/cobv/{txid}`) usa o mesmo corpo.

**`PUT` e `PATCH` não são a mesma coisa, e a diferença é dinheiro.** O `PUT`
(`updateCobV`) manda o conjunto COMPLETO de parâmetros e substitui; o `PATCH`
(`reviseCobV`) manda só o que mudou. Mandar um corpo parcial no `PUT` apaga em
silêncio o que foi omitido — a multa que o pagador já aceitou, o desconto prometido.

```bash
# Só o vencimento muda; multa, juros e desconto ficam como estão.
curl -X PATCH "$BASE/v1/pix/cobv/TX123" \
  -H "Authorization: Bearer <TENANT_TOKEN>" \
  -H "Idempotency-Key: cobv-fatura-2026-09-prorroga" \
  -H "Content-Type: application/json" \
  -d '{ "due_date": "2026-09-20T00:00:00-03:00" }'
```

Listar por janela (`listCobV`): `start` e `end` em RFC3339, no máximo 30 dias.

```bash
curl "$BASE/v1/pix/cobv?start=2026-09-01T00:00:00Z&end=2026-09-30T00:00:00Z" \
  -H "Authorization: Bearer <TENANT_TOKEN>"
```

A cobrança **imediata** tem o mesmo par: `PATCH /v1/pix/{txid}` (`revisePix`) revisa
o que já existe. Não há "criar deixando o PSP escolher o txid": o nosso `txid` nasce da
âncora de idempotência, e é essa derivação que faz um reenvio acertar a mesma cobrança
em vez de cobrar o comprador duas vezes.

### 4.4 Boleto BolePix (`createBoleto` / `getBoleto` / `updateBoleto` / `deleteBoleto`)

```bash
curl -X POST "$BASE/v1/boletos" \
  -H "Authorization: Bearer <TENANT_TOKEN>" \
  -H "Idempotency-Key: bol-pedido-771" \
  -H "Content-Type: application/json" \
  -d '{ "amount_cents": 25000, "currency": "BRL",
        "due_date": "2026-09-15T00:00:00-03:00",
        "fine_bps": 200, "monthly_interest_bps": 100,
        "discounts": [ { "days_before_due": 5, "bps": 300 } ],
        "payer": { "name": "Cliente XPTO", "tax_id": "12345678000199",
                   "address": { "street": "Rua A", "number": 100,
                                "city": "SP", "state": "SP", "zip_code": "01000000" } } }'
```

`201 Created` traz `boleto_id`, `barcode`/`digitable_line`, `qr_code` (BolePix) e
`our_number`. Alteração de vencimento/valor/multa (`updateBoleto`, `PUT`) e
baixa/cancelamento (`deleteBoleto`, `DELETE`) endereçam por `boleto_id`.

Listar o que foi emitido (`listBoletos`, `GET /v1/boletos`) exige **ao menos um**
intervalo — `payment_date`, `due_date` ou `credit_date` —, cada um com as **duas**
pontas e no máximo 60 dias. São perguntas diferentes ("o que foi pago", "o que vence",
"o que cai na conta") e o banco as responde separadamente; meio intervalo responde
`400`, porque o banco responderia alguma coisa e não seria a janela que se quis.

```bash
curl "$BASE/v1/boletos?due_date_from=2026-09-01&due_date_to=2026-09-30&status=PAID" \
  -H "Authorization: Bearer <TENANT_TOKEN>"
```

---

### 4.5 BolePix: campos obrigatórios e o que o banco não faz

Duas exigências do banco que recusam o registro quando ausentes:

- **`description`** — descrição impressa no boleto, vista pelo pagador. Máximo 100
  caracteres.
- **`payer.address.neighborhood`** — o bairro. O endereço do pagador é validado
  integralmente na emissão.

O QR Code do PIX vem **na própria resposta do registro**, não numa consulta posterior:
uma cobrança BolePix é pagável por boleto ou por PIX desde o momento em que é criada.
Ele é gerado a partir da chave aleatória registrada da empresa-cliente.

### Escolher a modalidade: `payment_method`

`POST /v1/boletos` aceita `payment_method`: `"boleto"` (boleto simples) ou `"bolepix"`
(a mesma cobrança, pagável também por QR Code PIX). **Ausente equivale a `boleto`** — o
padrão promete o menos.

Antes, a modalidade não era escolhida: o QR era anexado sempre que a empresa tinha chave
aleatória registrada. Isso tornava indistinguíveis dois resultados muito diferentes — "foi
pedido um boleto simples" e "foi pedido um BolePix, mas a empresa está mal configurada, e o
pagador recebeu um boleto sem QR".

**`bolepix` sem chave EVP registrada é recusado com `400`, antes de qualquer chamada ao
banco.** O banco nunca avisaria: o contrato diz que uma chave ausente ou inválida cria a
cobrança do mesmo jeito, apenas sem QR. A falha só apareceria na hora do pagamento, para
quem está pagando. Para saber se a conta autoriza a modalidade, leia
`GET /v1/bank-capabilities` (campos `boleto` e `bolepix`) — `null` ali significa "ainda não
verificamos", que é diferente de `false`.

A resposta ecoa `payment_method`, e `qr_code` é **omitido** numa cobrança `boleto` em vez de
vir vazio.

**Alteração existe, e é parcial.** `PATCH /v1/boletos/{id}` (ou `PUT`, alias mantido)
altera vencimento, validade, valor, multa, juros e desconto. Só os campos presentes mudam:
omitir um campo o preserva, e **não** é o mesmo que enviar zero — `amount_cents: 0` zeraria
a cobrança. `valid_until` exige `due_date` junto, porque o banco conta a validade em dias
**após** o vencimento.

> Até 15/09/2026 este manual afirmava que alteração não existia e a rota respondia `400`.
> O contrato publicado do banco tem `PATCH /v2/bank_slips/{external_reference_id}`: o que
> estava errado era o verbo e o caminho que tentávamos, não a operação.

**PDF.** `GET /v1/boletos/{id}/pdf` devolve o documento em binário (`application/pdf`),
pronto para entregar ao navegador ou anexar num e-mail. Como carrega dados pessoais do
pagador, a resposta vai com `Cache-Control: no-store`.

### 4.6 Cobrança com vencimento (cobv): devedor completo e chave obrigatória

A cobv é um **documento formal de cobrança** entregue ao pagador, e o banco exige mais
que a cobrança imediata:

- **`devedor` completo** — além de `tax_id` e `name`, são obrigatórios `street`, `city`,
  `state` (UF) e `zip_code`. Na cobrança **imediata** o devedor continua opcional e sem
  endereço; a exigência é específica da cobv.
- **`creditor_key`** — obrigatória. Se omitida, resolvemos da credencial da
  empresa-cliente; não havendo nem lá, a chamada é recusada **antes** de ir ao banco,
  com o campo nomeado.

Ambas as validações acontecem no nosso boundary, então um campo faltando volta como erro
nomeado em vez de um `400` opaco do PSP.

### 4.7 Remover a configuração de banco também desliga as notificações

Remover a configuração de banco de uma empresa-cliente (console → *remover banco*) passou
a **desregistrar os callbacks no PSP** antes de apagar credencial e certificado.

A ordem é o ponto: a desregistração se autentica com a credencial que está prestes a ser
apagada, e o callback PIX é endereçado pela chave do recebedor guardada nela. Feita depois,
seria impossível — e o banco continuaria chamando uma URL cuja credencial não existe mais,
entregando notificações que nunca reconciliam.

É best-effort: se o PSP estiver indisponível, a remoção **acontece assim mesmo**. Recusar
por causa do banco deixaria o operador preso exatamente com o resíduo que isso remove. A
falha fica registrada em log (nunca a URL, que embute o segredo).

Uma limitação do contrato: só as superfícies BACEN expõem remoção (PIX, mandato e cobrança
recorrente). A superfície própria do C6 — a do **checkout** — tem apenas cadastro e
consulta, então esse canal permanece registrado até ser sobrescrito.

## 4.1 Pagamento recorrente — PIX Automático (Jornada 3)

**Quando:** mensalidade ou assinatura, com liberação imediata do serviço no
primeiro pagamento. O pagador lê **um** QR Code composto que ao mesmo tempo
liquida a primeira cobrança e autoriza os débitos futuros.

> Superfície flag-gated: `PAYMENT_PIX_RECURRENCE`. Com a flag desligada as rotas
> não existem (404).

O fluxo tem duas metades, e a fronteira entre elas é o que mais confunde na
primeira integração:

- **Você controla** os passos 1–4 e 7 (criar cobrança, location, mandato, obter o
  QR, cobrar cada ciclo).
- **Você não controla** os passos 5–6: o pagador autoriza dentro do app do
  **próprio banco dele**, e essa aprovação só chega até você pelo webhook. Até ela
  chegar, toda cobrança recorrente responde `409` — de propósito.

```bash
# 1. Cobrança imediata — é ela que o QR composto liquida. Guarde o txid.
curl -X POST "$BASE/v1/pix" \
  -H "Authorization: Bearer <TENANT_TOKEN>" \
  -H "Idempotency-Key: assinatura-4712-primeira" \
  -d '{"amount_cents": 9900, "currency": "BRL", "expires_in_seconds": 1800}'
# → {"txid": "TX123...", "qr_code": "..."}

# 2. Location do payload da recorrência (createLocRec). Sem corpo.
curl -X POST "$BASE/v1/pix/locrec" \
  -H "Authorization: Bearer <TENANT_TOKEN>" \
  -H "Idempotency-Key: assinatura-4712-loc"
# → {"id": 108, "location": "pix.example.com/qr/v2/rec/..."}

# 3. Mandato, amarrado à location E ao txid da cobrança imediata (createRec).
curl -X POST "$BASE/v1/pix/rec" \
  -H "Authorization: Bearer <TENANT_TOKEN>" \
  -H "Idempotency-Key: assinatura-4712-mandato" \
  -d '{
        "contrato": "ASSIN-4712",
        "objeto": "Mensalidade",
        "devedor": {"tax_id": "02989131415", "name": "Beltrano da Silva"},
        "data_inicial": "2026-10-01",
        "periodicidade": "MENSAL",
        "retry_policy": "PERMITE_3R_7D",
        "loc_id": 108,
        "journey_txid": "TX123...",
        "amount_cents": 9900
      }'
# → {"id_rec": "RR...", "status": "CRIADA", "journey_status": "AGUARDANDO_DEFINICAO"}

# 4. O QR composto que a loja exibe (getRec com qr=true).
#    Sem informar txid: usamos o journey_txid que ficou gravado no passo 3.
curl "$BASE/v1/pix/rec/RR.../?qr=true" \
  -H "Authorization: Bearer <TENANT_TOKEN>"
# → {"status":"CRIADA","qr":{"jornada":"JORNADA_3","pix_copia_e_cola":"00020101..."}}

# 5. O pagador lê o QR: paga a primeira mensalidade E autoriza a recorrência.
# 6. O C6 notifica /webhooks/c6/{tenantRef}; nós conciliamos e o mandato vira APROVADA.
#    Confirme quando quiser:
curl "$BASE/v1/pix/rec/RR..." -H "Authorization: Bearer <TENANT_TOKEN>"
# → {"status": "APROVADA", ...}

# 7. A partir daí, uma cobrança por ciclo (createCobR).
curl -X POST "$BASE/v1/pix/cobr" \
  -H "Authorization: Bearer <TENANT_TOKEN>" \
  -H "Idempotency-Key: assinatura-4712-ciclo-2026-11" \
  -d '{"id_rec": "RR...", "txid": "ASSIN4712-2026-11",
       "due_date": "2026-11-01", "amount_cents": 9900}'
```

**Amarrar o valor.** `amount_cents` no mandato é o **teto** que o pagador
autorizou. Uma cobrança acima dele é recusada com `409` antes de chegar ao banco.
Se a mensalidade for variável, omita o campo — mas então nada limita o valor de
cada ciclo além do seu próprio código.

**Os dois 409.** `mandate is not approved` = o pagador ainda não autorizou (espere,
ou reenvie a solicitação). `charge exceeds the authorized mandate value` = cobre
menos, ou crie um novo mandato. Nenhum dos dois se resolve mexendo no payload —
por isso não são `400`.

**Sem QR? (Jornada 1).** Se você já combinou o Pix Automático com o cliente por
fora, pule os passos 1–4 e mande a solicitação direto para o banco dele
(`createSolicRec`); ele aprova no app e o passo 6 acontece igual. `expires_at`
precisa estar no futuro e a menos de 30 dias.

```bash
curl -X POST "$BASE/v1/pix/solicrec" \
  -H "Authorization: Bearer <TENANT_TOKEN>" \
  -H "Idempotency-Key: assinatura-4712-solic" \
  -d '{"id_rec": "RR...", "tax_id": "02989131415", "agencia": "0001",
       "conta": "123456", "ispb_participante": "12345678",
       "expires_at": "2026-09-10T23:59:59Z"}'
```

**Encerrar.** `DELETE /v1/pix/rec/{idRec}` revoga o mandato no banco: nenhum débito
futuro pode ser originado. É idempotente, e a location pode ser reaproveitada com
`DELETE /v1/pix/locrec/{id}/idrec`.

**Cobrança falhou.** `POST /v1/pix/cobr/{txid}/retentativa/{data}` agenda a
retentativa conforme a política do mandato — desde que o mandato ainda esteja
aprovado.

**Pular ou corrigir uma parcela.** `DELETE /v1/pix/cobr/{txid}` cancela **uma**
cobrança do ciclo sem mexer no mandato: a autorização continua de pé e o mês
seguinte cobra normalmente. É a única alteração que o BACEN admite numa cobrança
recorrente — **não existe** como mudar valor ou vencimento de uma parcela já
criada. Para cobrar outro valor, cancele e crie uma nova:

```bash
curl -X DELETE "$BASE/v1/pix/cobr/ASSIN4712-2026-11" -H "Authorization: Bearer <TENANT_TOKEN>"
curl -X POST "$BASE/v1/pix/cobr" -H "Authorization: Bearer <TENANT_TOKEN>" \
  -H "Idempotency-Key: assinatura-4712-ciclo-2026-11-v2" \
  -d '{"id_rec":"RR...","txid":"ASSIN4712-2026-11-v2",
       "due_date":"2026-11-05","amount_cents":12900}'
```

Note o `txid` novo: cada débito fica rastreável à cobrança que o autorizou, em vez
de um mesmo identificador significar dois valores diferentes em momentos distintos.

**Status da cobrança.** O vocabulário é o do BACEN e a distinção importa na
operação: `CONCLUIDA` = paga; `REJEITADA` = o banco do pagador recusou (sem saldo,
débito bloqueado) — vale falar com o cliente; `EXPIRADA` = a janela passou sem
pagamento; `CANCELADA` = você cancelou.

## 5. Consulta e agendamento de pagamentos (DDA)

**Quando:** pagar boletos que caíram no DDA da empresa-cliente, ou agendar
pagamentos — de boleto **e de PIX**. Fluxo: listar → criar grupo → revisar itens →
aparar → submeter.

A API **não paga**: ela submete os pagamentos para aprovação de alguém com alçada
dentro do banco. Até a aprovação, o lote existe e não se moveu.

```bash
# Listar títulos abertos no DDA (listDDABoletos)
curl "$BASE/v1/dda/boletos" -H "Authorization: Bearer <TENANT_TOKEN>"

# Criar grupo de pagamento (createDDAGroup)
curl -X POST "$BASE/v1/dda/payment-groups" \
  -H "Authorization: Bearer <TENANT_TOKEN>" \
  -H "Idempotency-Key: dda-lote-014" \
  -H "Content-Type: application/json" \
  -d '{ "payments": [
        { "content": "3419...", "amount_cents": 12345,
          "description": "Boleto do aluguel", "transaction_date": "2026-10-02" },
        { "content": "fornecedor@exemplo.com", "amount_cents": 2500 }
      ] }'
```

`content` é a referência do pagamento: linha digitável, **chave PIX** ou BR Code.
`amount_cents` é obrigatório junto com ela. `transaction_date` é a data de execução
(`YYYY-MM-DD`); vazia agenda para hoje.

`201 Created` → `{ "txid": "grp_..." }`, **e nada mais**: o banco responde a criação
só com o identificador. Os itens, com os ids que a remoção usa, aparecem na leitura:

```bash
# Revisar itens do grupo (getDDAGroupItems)
curl "$BASE/v1/dda/payment-groups/grp_.../items" -H "Authorization: Bearer <TENANT_TOKEN>"

# Remover um item (removeDDAGroupItem) ou uma lista (removeDDAGroupItems)
curl -X DELETE "$BASE/v1/dda/payment-groups/grp_.../items/item_1" -H "Authorization: Bearer <TENANT_TOKEN>"

# Submeter o grupo para aprovação/pagamento (submitDDAGroup)
curl -X POST "$BASE/v1/dda/payment-groups/grp_.../submit" \
  -H "Authorization: Bearer <TENANT_TOKEN>" -H "Idempotency-Key: dda-submit-014" \
  -H "Content-Type: application/json" \
  -d '{ "uploader_name": "Zé da Silva" }'
```

`uploader_name` é obrigatório: é o operador que o banco exibe na tela de aprovação.

Cada item tem o seu próprio `status`, vindo do banco: `READ_DATA` (cadastrado),
`DECODE_ERROR` (não deu para ler os dados — veja `error_message`), `ERROR`,
`SCHEDULED` (agendado), `PROCESSING`, `PROCESSED` (pago), `SCHEDULING_CANCELLED`.
**Não existe status de grupo.** O lote está congelado quando qualquer item saiu de
`READ_DATA`/`DECODE_ERROR`/`ERROR` — aparar um lote congelado responde `409`.

Um grupo de outra empresa-cliente responde `404` (nunca oráculo cross-tenant).

---

## 5.1 Superfícies BACEN do PIX: location, recebidos, devolução e lote

Quatro coisas que a cobrança (`cob`/`cobv`) não cobre. Nenhuma delas é faturada: preço
por rota é decisão comercial, e ligar bilhetagem numa rota nova sem alguém decidir o
preço criaria fatura silenciosa para todo integrador.

### 5.1.1 Location de payload (`createPixLoc`, `getPixLoc`, `unlinkPixLocTxid`)

A location é o QR endereçável que o PSP serve, e existe **independentemente** da
cobrança. É isso que permite imprimir um QR antes de a cobrança que será servida por ele
existir — e trocar a cobrança por trás de um QR já impresso.

```bash
curl -X POST "$BASE/v1/pix/loc" \
  -H "Authorization: Bearer <TENANT_TOKEN>" -H "Content-Type: application/json" \
  -d '{ "tipo_cob": "cobv" }'
# → {"id": 108, "location": "pix.example.com/qr/v2/...", "tipo_cob": "cobv"}

# Desvincular a cobrança do QR:
curl -X DELETE "$BASE/v1/pix/loc/108/txid" -H "Authorization: Bearer <TENANT_TOKEN>"
```

O desvinculamento **não cancela nada**: o status da cobrança fica como está, ela só
deixa de ser servida por aquele QR. Quem quer cancelar usa o caminho da cobrança. Na
resposta o campo `txid` some, em vez de voltar vazio, para ninguém ler `""` como um txid.

### 5.1.2 PIX recebidos (`listReceivedPix`, `getReceivedPix`)

```bash
curl "$BASE/v1/pix/received?start=2026-09-01T00:00:00Z&end=2026-09-30T00:00:00Z&refund_present=true" \
  -H "Authorization: Bearer <TENANT_TOKEN>"
```

Duas coisas para não tropeçar:

- **`txid` é vazio num PIX pago contra chave estática.** A conciliação tem de lidar com
  isso em vez de supor que há cobrança por trás.
- **A resposta não traz a identidade do pagador.** O objeto do PSP carrega CPF/CNPJ e
  nome de quem pagou; nós não os transportamos, e é assim que eles nunca chegam a log,
  erro ou resposta (ADR-0008). `payer_info` é a mensagem livre que o próprio pagador
  escolheu mandar.

Os filtros booleanos (`txid_present`, `refund_present`) ausentes querem dizer "não filtre
por isto" — que é diferente de `false`.

### 5.1.3 Devolução (`requestPixRefund`, `getPixRefund`)

```bash
curl -X PUT "$BASE/v1/pix/received/E1234.../refunds/dev-pedido-771" \
  -H "Authorization: Bearer <TENANT_TOKEN>" -H "Content-Type: application/json" \
  -d '{ "amount_cents": 1500, "nature": "ORIGINAL", "description": "devolução parcial" }'
```

**O `refundID` está no caminho e é seu.** O par (`e2eid`, `refundID`) endereça sempre a
mesma devolução, então um reenvio não devolve duas vezes — por isso esta rota não pede
`Idempotency-Key`: o próprio endereço já é a chave. Gerar um id aleatório por tentativa
desfaz exatamente essa garantia.

O valor é obrigatório: não existe "devolve tudo" por omissão, porque devolver a mais é
tão errado quanto devolver a menos.

O `201` diz que o PSP **aceitou** o pedido. Se o dinheiro saiu, quem responde é a
leitura: o status pode continuar `EM_PROCESSAMENTO` depois do aceite, e um
`NAO_REALIZADO` só explica o porquê no campo `reason`.

### 5.1.4 Lote de cobranças com vencimento (`createPixBatch`, `getPixBatch`)

Até 200 cobv sob um id de lote escolhido por você.

```bash
curl -X PUT "$BASE/v1/pix/lotecobv/mensalidades-2026-09" \
  -H "Authorization: Bearer <TENANT_TOKEN>" \
  -H "Idempotency-Key: lote-mensalidades-2026-09" \
  -H "Content-Type: application/json" \
  -d '{ "description": "Mensalidades setembro",
        "charges": [ { "txid": "TXALUNO001", "amount_cents": 15000, "currency": "BRL",
                       "due_date": "2026-09-10T00:00:00-03:00", "validity_days": 30,
                       "fine_bps": 200, "monthly_interest_bps": 100,
                       "creditor_key": "escola@pix.example",
                       "devedor": { "tax_id": "12345678901", "name": "Maria",
                                    "street": "Rua A, 10", "city": "SP",
                                    "state": "SP", "zip_code": "01000000" } } ] }'
```

**Responde `202`, sem corpo — não `201`.** O PSP aceita o lote e o processa depois: as
cobranças ainda não existem, e tratar o aceite como "as cobranças estão registradas" é a
forma de errar aqui. O resultado de cada uma só sai da leitura:

```bash
curl "$BASE/v1/pix/lotecobv/mensalidades-2026-09" -H "Authorization: Bearer <TENANT_TOKEN>"
# → {"charges": [{"txid":"TXALUNO001","status":"CRIADA"},
#                {"txid":"TXALUNO002","status":"NEGADA","problem":"..."}]}
```

O `txid` é explícito **só no lote**: numa cobv avulsa ele é derivado da âncora de
idempotência, mas aqui o PSP endereça cada cobrança pelo txid do corpo, e é por ele que o
resultado dela volta. Uma cobrança sem txid derruba o lote inteiro, porque ela sumiria em
silêncio.

`PATCH` no mesmo caminho revisa cobranças do lote, e só pode **manter** o conjunto
original: acrescentar ou remover uma não é revisão, e o PSP recusa.

---

## 5.2 Boleto simples (`/v1/bank-slips`) — não é o BolePix

São **dois produtos**, ainda que os dois se chamem "boleto". O boleto simples aceita até
**três** faixas de desconto (o BolePix expõe uma só), a multa e os juros têm forma
própria, o endereço do pagador tem rua e número separados, a referência externa cabe em
10 caracteres em vez de 26 — e ele **não emite QR**.

> **Ele não cria cobrança no razão deste gateway.** É a superfície crua do banco: emite,
> lê, altera, baixa e renderiza. Um boleto emitido por `/v1/bank-slips` **não liquida
> sozinho** pelo webhook de liquidação. Quem precisa de liquidação usa `/v1/boletos`.

```bash
curl -X POST "$BASE/v1/bank-slips" \
  -H "Authorization: Bearer <TENANT_TOKEN>" \
  -H "Idempotency-Key: slip-pedido-771" \
  -H "Content-Type: application/json" \
  -d '{ "slip_id": "pedido-771", "amount_cents": 25000, "currency": "BRL",
        "due_date": "2026-10-15T00:00:00-03:00",
        "fine_bps": 200, "monthly_interest_bps": 100,
        "discounts": [ { "days_before_due": 10, "bps": 500 },
                       { "days_before_due": 5,  "bps": 300 },
                       { "days_before_due": 1,  "bps": 100 } ],
        "payer": { "name": "Cliente XPTO", "tax_id": "12345678000199",
                   "street": "Rua A", "number": 100,
                   "city": "SP", "state": "SP", "zip_code": "01000000" } }'
```

O escalonamento tem regra própria, conferida antes de ir ao banco: no máximo três faixas,
em prazos **estritamente decrescentes**, e todas na mesma forma (todas percentuais ou
todas em valor). Misturar as formas é `400` — o banco não recusa de forma clara, ele
aplica o tipo errado a alguma faixa, e o pagador paga a diferença. Multa percentual e
multa fixa também são mutuamente exclusivas.

`GET`, `PATCH` e `DELETE` em `/v1/bank-slips/{id}` endereçam pelo id **forte do banco**,
devolvido na emissão — não pelo `slip_id` que você mandou. O `PATCH` é parcial: campo
ausente é "deixa como está", nunca "zera". Tocar em **qualquer** encargo exige declarar o
quadro completo de encargos, porque o banco substitui o objeto inteiro em vez de mesclar
nele — deixar um de fora o apagaria, mudando em silêncio o que o pagador deve.

`GET /v1/bank-slips/{id}/pdf` renderiza o documento. Ele carrega PII do pagador, então
sai com `Cache-Control: no-store`: nenhum intermediário pode guardá-lo em cache.

---

## 5.3 Extrato de adquirência (`/v1/acquirer/*`)

Duas leituras sobre a mesma janela, e **não são o mesmo dinheiro**:

| rota | o que é |
|---|---|
| `GET /v1/acquirer/transactions` | a autorização: o BRUTO, de uma vez |
| `GET /v1/acquirer/receivables` | a parcela LÍQUIDA que o adquirente paga, em data futura |

```bash
curl "$BASE/v1/acquirer/receivables?start_date=2026-09-01&end_date=2026-09-30" \
  -H "Authorization: Bearer <TENANT_TOKEN>"
```

R$ 30,00 autorizados chegam à conta como R$ 28,39, já descontados MDR e tarifa por venda.
As cobranças deste gateway liquidam no **bruto**; a conta do lojista recebe o **líquido**.
É nessa diferença que uma conciliação deixa de fechar, e por isso as duas leituras existem
separadas em vez de uma só.

Três detalhes de leitura:

- **`fee_cents` e `discount_cents` chegam negativos e assim ficam.** São deduções;
  inverter o sinal esconderia a direção do dinheiro.
- **`items` é a contagem DESTA página**, não um total geral. Lê-lo como total subdeclara
  um extrato paginado — use `last_page` para saber quando parar.
- **`mdr` vem escalado por 100 e é transportado sem interpretação.** O contrato do
  adquirente não diz se é percentual ou valor, e o exemplo dele serve para os dois; nada
  aqui o usa para calcular nada, e você também não deveria sem confirmar com o banco.

`end_date` ausente é "o mesmo dia de `start_date`", que é o padrão do próprio adquirente.
Janela máxima de 60 dias.

O C6 Pay é produto com **habilitação à parte**: a conta que não o tem responde `503` nesta
superfície (e, em produção, `403` do lado do banco).

---

## 6. Reconciliação: extrato e webhook de liquidação

### 6.1 Extrato por período (`getStatement`)

Janela máxima de 30 dias; `fim >= inicio`; datas `YYYY-MM-DD`. O tenant vem da
credencial — nenhum parâmetro escolhe de quem é o extrato (ameaça H1/P1).

```bash
curl "$BASE/v1/statement?inicio=2026-08-01&fim=2026-08-30" \
  -H "Authorization: Bearer <TENANT_TOKEN>"
```

`200 OK`:

```json
{ "entries": [ { "id": "e1", "date": "2026-08-16", "amount_cents": 4990, "kind": "credit", "description": "PIX E1234..." } ] }
```

### 6.2 Webhook inbound de liquidação do C6 (`c6Webhook`)

> Do ponto de vista do integrador: o C6 chama **a Sindireceita** — você não
> chama esta rota. A empresa-cliente reconcilia via extrato (§6.1) e/ou pelas
> consultas de cada cobrança. Esta seção existe para o modelo de reconciliação
> ficar transparente.

`POST /webhooks/c6/{tenantRef}`:

- **Autenticidade:** o C6 não assina (ADR-0002/F4); a `tenantRef` opaca no path é
  a credencial (capability secret). Ref ausente/desconhecida/malformada → `401`
  uniforme (sem oráculo). **A ref nunca deve ir para log de proxy** — o ingress
  mascara o segmento; o app só loga o tenant resolvido.
- **Corpo:** cap de 64 KiB (acima → `413`); campos desconhecidos → `400`. O
  tenant vem sempre da ref (canal), nunca do corpo; `client_id` divergente do
  canal → `401`. `external_id` vazio → `400`.
- **Dedup + reconcile-before-settle:** `event_key = external_id|service|status`;
  redeliveries exatas são suprimidas. `service` seleciona o que reconciliar
  (`checkout`, `rec`, `cobr`, ou PIX/charge por padrão). `status` é **advisory** —
  a liquidação é decidida pela reconciliação autoritativa, nunca pelo corpo.
- **Sucesso:** `202 Accepted` → `{ "status": "accepted" }`.

Corpo típico enviado pelo C6:

```json
{ "external_id": "E1234...", "client_id": "c6-merchant-id", "service": "pix", "status": "CONCLUIDA" }
```

### 6.3 Webhook **de saída** — a notificação que chega até você

Enquanto §6.2 é o banco chamando a Sindireceita, este é o elo que fecha a
reconciliação **do seu lado**: quando a cobrança de uma empresa-cliente liquida,
nós entregamos uma notificação assinada no endpoint HTTPS cadastrado **por
Conta** (um só, para todas as suas empresas-clientes).

É o único componente do fluxo que você precisa escrever. O contrato completo —
validação passo a passo, política de retry, requisitos do endpoint — está no
[`integration-guide.md`](./integration-guide.md) §12. Resumo operacional:

```
POST <seu endpoint>
Content-Type: application/json
X-Webhook-Signature: sha256=<hex HMAC-SHA256 de "<timestamp>.<corpo bruto>">
X-Webhook-Timestamp: 1755561600
X-Webhook-Idempotency-Key: E1234...|pix|CONCLUIDA

{"event_key":"E1234...|pix|CONCLUIDA","event_type":"payment.paid",
 "tx_id":"E1234...","account_id":"<sua Conta>","timestamp":1755561600}
```

Três regras que decidem se a integração funciona:

1. **Valide antes de processar** — janela de frescor de 300 s sobre
   `X-Webhook-Timestamp`, depois HMAC em tempo constante sobre o **corpo bruto**
   (reserializar o JSON quebra o MAC).
2. **Deduplique** por `X-Webhook-Idempotency-Key`: a mesma notificação pode
   chegar mais de uma vez (retry nosso ou reentrega do banco).
3. **Responda 2xx rápido** e processe de forma assíncrona. São 3 tentativas com
   backoff curto; esgotadas, o evento vai para dead-letter e não volta sozinho.

O corpo **não traz valor, pagador nem PII** — só o suficiente para você saber o
que mudou. Para o detalhe da cobrança, chame nossa API de volta com a
chave-de-Conta e o `X-Client-Tenant` da empresa-cliente (§2), o que mantém dado
pessoal fora de um canal que atravessa a internet.

Para testar a verificação sem esperar uma liquidação, reproduza a assinatura
localmente com o segredo cadastrado:

```bash
TS=$(date +%s)
BODY='{"event_key":"teste|pix|CONCLUIDA","event_type":"payment.paid","tx_id":"teste","account_id":"<sua Conta>","timestamp":'"$TS"'}'
SIG="sha256=$(printf '%s.%s' "$TS" "$BODY" | openssl dgst -sha256 -hmac "$WEBHOOK_SECRET" -hex | awk '{print $2}')"

curl -sS -X POST "$SEU_ENDPOINT" \
  -H "Content-Type: application/json" \
  -H "X-Webhook-Signature: $SIG" \
  -H "X-Webhook-Timestamp: $TS" \
  -H "X-Webhook-Idempotency-Key: teste|pix|CONCLUIDA" \
  -d "$BODY"
```

---

## 7. Área administrativa e bilhetagem

Plano `/admin/*` — **interno**, operado pela Sindireceita. Autenticado por
`<ADMIN_TOKEN>` (`adminAuth`), segregado do plano `/v1`: um token de
empresa-cliente/chave-de-Conta nunca resolve papel de admin (deny-by-default).
Mutações exigem papel `admin`; `operator` é somente-leitura (`403` numa mutação).

### 7.1 Cadastrar empresa-cliente (`adminCreateTenant`)

```bash
curl -X POST "$BASE/admin/tenants" \
  -H "Authorization: Bearer <ADMIN_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{ "name": "Loja Beta Ltda" }'
```

`201 Created` → `{ "id": "tnt-loja-beta", "name": "Loja Beta Ltda", "active": true }`.

> No modelo (b) a **Conta** provisiona as próprias empresas-clientes via
> `POST /v1/clients` (§2). Este endpoint é o caminho admin/bootstrap.

### 7.2 Preço por rota — bilhetagem (`adminSetPrice`)

Define o custo em centavos de uma rota (`endpoint`) para uma empresa-cliente. O
consumo é medido no plano `/v1` e consolidado em faturas.

```bash
curl -X POST "$BASE/admin/tenants/tnt-loja-beta/pricing" \
  -H "Authorization: Bearer <ADMIN_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{ "endpoint": "pix.create", "price_cents": 15 }'
```

`200 OK` → `{ "tenant_id": "tnt-loja-beta", "endpoint": "pix.create", "price_cents": 15 }`.

### 7.3 Material bancário via admin (`adminSetBankCredential` / `adminSetBankCertificate`)

Equivalentes admin do intake self-serve (§3), para operação assistida. Mesmas
regras de segurança: `secret` e `key_pem` write-only, banco desconhecido → `400`.

```bash
curl -X PUT "$BASE/admin/tenants/tnt-loja-beta/bank-credential" \
  -H "Authorization: Bearer <ADMIN_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{ "bank": "c6", "client_id": "c6-client-uuid", "secret": "<C6_CLIENT_SECRET>" }'
```

### 7.4 Consulta de uso e geração de faturas (console HTMX)

Uso e faturas são operados pelo **console web** em `/console` (server-rendered
HTMX, autenticado por sessão + CSRF), não por JSON público. Principais telas:

- **Uso por Conta / por empresa-cliente:** `/console/accounts/{acctId}/consumption`
  e `/console/tenants/{id}/consumption` (com export `.csv` e janela de datas).
- **Faturas:** listar em `/console/tenants/{id}/invoices`, baixar CSV em
  `/console/tenants/{id}/invoices/{invId}.csv`; gerar por empresa-cliente
  (`POST /console/tenants/{id}/invoices`) ou em lote por Conta
  (`POST /console/accounts/{acctId}/invoices`).
- **Gerenciar Contas/empresas-clientes:** criar, renomear (PATCH), suspender/
  reativar, e remover configuração de banco (`ADR-0012`).

> As rotas `/console/*` são superfície de UI (HTML/HTMX) e não fazem parte do
> contrato `/v1` vendável; ficam fora do `openapi.yaml` de propósito.

---

## 8. Multi-empresa (uma Conta, várias empresas-clientes)

Uma Conta (ex.: Verz) atende N empresas-clientes com **uma** chave-de-Conta,
trocando só o seletor por chamada:

```bash
curl -X POST "$BASE/v1/pix" \
  -H "Authorization: Bearer ak_4b81…" \
  -H "X-Client-Tenant: tnt-loja-alfa" \
  -H "Idempotency-Key: pix-alfa-1" -H "Content-Type: application/json" \
  -d '{ "amount_cents": 1990, "currency": "BRL", "expires_in_seconds": 3600 }'

curl -X POST "$BASE/v1/pix" \
  -H "Authorization: Bearer ak_4b81…" \
  -H "X-Client-Tenant: tnt-loja-beta" \
  -H "Idempotency-Key: pix-beta-1" -H "Content-Type: application/json" \
  -d '{ "amount_cents": 2990, "currency": "BRL", "expires_in_seconds": 3600 }'
```

**Blast radius e boas práticas:**

- A chave-de-Conta é de **alto valor** — se vazar, expõe todas as
  empresas-clientes da Conta. Guarde em cofre; rotacione (§1.2) na menor
  suspeita; nunca a coloque em URL, log ou repositório.
- O guard §2 garante que a chave só alcança empresas-clientes da **própria**
  Conta; um `X-Client-Tenant` de outra Conta → `404`.
- Prefira uma `Idempotency-Key` **por empresa-cliente + intenção** para que um
  retry num tenant nunca colida com outro.
- Considere emitir tokens de empresa-cliente (modelo a) para integrações que
  operam uma única empresa — menor blast radius que compartilhar a chave-de-Conta.

---

## 9. Transversais (referência rápida)

### 9.1 Autenticação e autorização

| Situação | Resposta |
|---|---|
| Bearer ausente/inválido | `401` |
| Token de empresa-cliente + `X-Client-Tenant` | `400` (token não seleciona) |
| Chave-de-Conta sem `X-Client-Tenant` | `400` |
| Empresa-cliente de outra Conta / inexistente | `404` (sem oráculo) |
| Token admin `operator` numa mutação | `403` |
| Recurso de outra empresa-cliente | `404` (não `403`) |

### 9.2 Idempotência

Rotas de escrita de recurso exigem `Idempotency-Key`. Reenvio com a mesma chave
devolve o efeito original (não duplica). Para chave-de-Conta e mint admin, o
replay devolve `409` **sem** reexibir o segredo (display-once).

### 9.3 Erros comuns

| Código | Significado |
|---|---|
| `400` | Validação falhou, JSON malformado, campo desconhecido ou header obrigatório ausente |
| `401` | Não autenticado |
| `403` | Autenticado sem papel suficiente (plano admin) |
| `404` | Recurso inexistente ou de outra empresa (mesma resposta) |
| `409` | Conflito de estado / `Idempotency-Key` já usada (segredo não reexibido) |
| `413` | Corpo acima do limite (1 MiB no `/v1`; 64 KiB no webhook) |
| `429` | Rate limit — faça backoff (respeite `Retry-After` quando presente) |
| `500` | Erro interno transitório |
| `503` | O banco desta empresa-cliente não fala esta superfície, ou o produto não está habilitado na conta dele. Falha FECHADA de propósito — é melhor do que rotear para um banco que a implementa por acaso |

### 9.4 Rate limiting

Plano `/v1`: token-bucket por empresa (burst 20, 10 req/s). Intakes self-serve
(credencial/certificado) e as rotas de chave-de-Conta têm limiters **dedicados**
(burst baixo, ~1 req/min) que emitem `Retry-After` no `429`. Trate `429` com
backoff exponencial.

### 9.5 Versionamento e ambientes

A versão do contrato está em `info.version` do `openapi.yaml`. Mudanças de
comportamento passam por flags (`PAYMENT_ACCOUNT_KEY_SELECTOR`,
`PAYMENT_SELFSERVE_CRED_INTAKE`) com rollback = flip de config. Homologue em
`homolog.` antes de produção.

---

## Índice de operações (manual ↔ openapi.yaml)

| Caso | operationId(s) |
|---|---|
| §1 Chave-de-Conta | `adminMintAccountKey`, `rotateAccountKey` |
| §2 Empresa-cliente + seletor | `provisionClient`, parâmetro `ClientSelector` |
| §3 Intake self-serve | `setSelfServeBankCredential`, `setSelfServeBankCertificate` |
| §4 Cobrança | `createCheckout`, `getCheckout`, `cancelCheckout`, `createPix`, `getPix`, `listPix`, `createCobV`, `getCobV`, `updateCobV`, `createBoleto`, `getBoleto`, `updateBoleto`, `deleteBoleto` |
| §4.1 PIX Automático | `createLocRec`, `getLocRec`, `unlinkLocRec`, `createRec`, `getRec`, `cancelRec`, `createSolicRec`, `getSolicRec`, `createCobR`, `getCobR`, `cancelCobR`, `retryCobR` |
| §5 DDA | `listDDABoletos`, `createDDAGroup`, `getDDAGroupItems`, `removeDDAGroupItem`, `removeDDAGroupItems`, `submitDDAGroup` |
| §6 Reconciliação | `getStatement`, `c6Webhook`, `outboundPaymentPaid` (webhook de saída — você implementa o receptor) |
| §7 Admin / bilhetagem | `adminCreateTenant`, `adminSetPrice`, `adminSetBankCredential`, `adminSetBankCertificate` |
| §0 Health | `healthCheck` |
</content>
</invoke>

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

---

### 4.5 BolePix: campos obrigatórios e o que o banco não faz

Duas exigências do banco que recusam o registro quando ausentes:

- **`description`** — descrição impressa no boleto, vista pelo pagador. Máximo 100
  caracteres.
- **`payer.address.neighborhood`** — o bairro. O endereço do pagador é validado
  integralmente na emissão.

O QR Code do PIX vem **na própria resposta do registro**, não numa consulta posterior:
uma cobrança BolePix é pagável por boleto ou por PIX desde o momento em que é criada.
Ele é gerado a partir da chave aleatória registrada da empresa-cliente — sem chave, a
cobrança é criada normalmente, só que sem QR.

**Alteração não existe.** O banco expõe emissão, consulta, PDF, listagem e baixa; não há
endpoint de alteração. `PUT /v1/boletos/{id}` responde `400` em vez de fingir que alterou
uma cobrança já registrada. Para mudar algo: cancele e emita outra.

## 5. Consulta e pagamento DDA

**Quando:** pagar boletos que caíram no DDA da empresa-cliente. Fluxo: listar →
criar grupo → revisar itens → aparar → submeter.

```bash
# Listar boletos abertos no DDA (listDDABoletos)
curl "$BASE/v1/dda/boletos" -H "Authorization: Bearer <TENANT_TOKEN>"

# Criar grupo de pagamento a partir de linhas digitáveis (createDDAGroup)
curl -X POST "$BASE/v1/dda/payment-groups" \
  -H "Authorization: Bearer <TENANT_TOKEN>" \
  -H "Idempotency-Key: dda-lote-014" \
  -H "Content-Type: application/json" \
  -d '{ "barcodes": ["3419...","2379..."] }'
```

`201 Created` → `{ "txid": "grp_...", "status": "...", "items": [...] }`. Depois:

```bash
# Revisar itens do grupo (getDDAGroupItems)
curl "$BASE/v1/dda/payment-groups/grp_.../items" -H "Authorization: Bearer <TENANT_TOKEN>"

# Remover um item (removeDDAGroupItem) ou uma lista (removeDDAGroupItems)
curl -X DELETE "$BASE/v1/dda/payment-groups/grp_.../items/item_1" -H "Authorization: Bearer <TENANT_TOKEN>"

# Submeter o grupo para aprovação/pagamento (submitDDAGroup)
curl -X POST "$BASE/v1/dda/payment-groups/grp_.../submit" \
  -H "Authorization: Bearer <TENANT_TOKEN>" -H "Idempotency-Key: dda-submit-014"
```

Um grupo de outra empresa-cliente responde `404` (nunca oráculo cross-tenant).

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
| §5 DDA | `listDDABoletos`, `createDDAGroup`, `getDDAGroupItems`, `removeDDAGroupItem`, `removeDDAGroupItems`, `submitDDAGroup` |
| §6 Reconciliação | `getStatement`, `c6Webhook`, `outboundPaymentPaid` (webhook de saída — você implementa o receptor) |
| §7 Admin / bilhetagem | `adminCreateTenant`, `adminSetPrice`, `adminSetBankCredential`, `adminSetBankCertificate` |
| §0 Health | `healthCheck` |
</content>
</invoke>

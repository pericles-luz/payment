# Runbook — smoke E2E do fluxo PIX C6 (modo stub)

- **Escopo:** validar o fluxo PIX ponta-a-ponta da aplicação de pagamentos
  **sem o C6 real**, usando o stub bancário in-memory. Cobre provisionamento de
  tenant, criação de cobrança PIX, recebimento de webhook, **reconcile-before-settle**
  e dedup de replay.
- **Origem:** [SIN-65346](/SIN/issues/SIN-65346) (pai [SIN-65345](/SIN/issues/SIN-65345)).
  Quando as credenciais de homologação do C6 chegarem ([SIN-65344](/SIN/issues/SIN-65344)),
  os mesmos passos rodam contra o C6 real preenchendo `PAYMENT_C6_BASE_URL`/`PAYMENT_C6_TOKEN_URL`
  no lugar do stub.
- **Lentes:** secure-by-default API · observability before optimization · test pyramid.
- **Config:** ver [`../../.env.example`](../../.env.example) para a lista completa de env vars.

> ⚠️ **Sem conhecimento tribal.** Todos os comandos abaixo foram **executados e
> verificados** contra o binário em modo stub. Copie-cole literalmente; os únicos
> valores que mudam entre execuções são o `tenantID` (gerado) e o `tenantRef`
> (sorteado), capturados em variáveis de shell.

## 0. Por que stub

`cmd/api/main.go` (`newBankProvider`) escolhe o adaptador bancário por config:
quando `PAYMENT_C6_BASE_URL` está **vazio**, sobe com `bank.NewStubProvider` —
um BankProvider in-memory determinístico. Isso permite exercer todo o wiring
(rotas, auth, idempotência, unidade de trabalho transacional, anti-replay) sem
dependência externa. O stub satisfaz também os ports de produto C6-C (consent /
boleto / checkout).

## 1. Build

```bash
go build -o ./payment-api ./cmd/api
```

## 2. Limitação importante do modo stub (leia antes de rodar)

O stub **nunca liquida uma cobrança sozinho**: `StubProvider.GetCharge` retorna
sempre `status=pending` até que o hook de teste `MarkSettled` seja chamado — e
esse hook **não tem rota HTTP**. Consequência para este smoke HTTP:

- **Provável por HTTP (este runbook):** criação de cobrança PIX, leitura,
  idempotência, recebimento de webhook, **reconcile-before-settle no sentido
  NEGATIVO** (o webhook afirma `paid`, mas como o estado autoritativo do banco é
  `pending`, a cobrança **NÃO** é liquidada — exatamente a garantia W2/W3), dedup
  de replay, anti-enumeração e limites de corpo.
- **Provável apenas por teste Go (sem superfície HTTP no stub):** o caminho
  **positivo** de liquidação, a **recusa por divergência de valor**, e os **3
  produtos C6-C**. Esses são cobertos pelo suite — ver §6.

Isto é uma propriedade do stub, não uma lacuna do produto: em homologação/produção
o C6 real reporta `paid` na reconciliação e o caminho positivo fecha por HTTP.

## 3. Variáveis comuns

```bash
API=./payment-api
DB=/tmp/smoke-c6.db ; rm -f "$DB"
ADMIN="admin-smoke-token"      # placeholder dev; em prod vem do secret manager
TNT="tenant-smoke-token"
ENDPOINT="/v1/notify"          # endpoint tarifado de exemplo
```

## 4. Fase 1 — bootstrap (somente admin): criar tenant + preço

O `tenantID` é gerado por `POST /admin/tenants` (32 hex). Tenant e preço são
persistidos no SQLite, então sobrevivem ao restart da fase 2. Suba com o token
de admin apenas:

```bash
PAYMENT_C6_BASE_URL= PAYMENT_SECURE_COOKIES=false \
  PAYMENT_ADMIN_TOKENS="$ADMIN" PAYMENT_DB_PATH="$DB" PAYMENT_HTTP_ADDR=":18080" \
  "$API" & P1=$!
until curl -s http://127.0.0.1:18080/healthz >/dev/null; do sleep 0.1; done

# cria o tenant e captura o id gerado
TID=$(curl -s -X POST http://127.0.0.1:18080/admin/tenants \
  -H "Authorization: Bearer $ADMIN" -H "Content-Type: application/json" \
  -d '{"name":"smoke-tenant"}' | sed -n 's/.*"id":"\([0-9a-f]*\)".*/\1/p')
echo "tenantID=$TID"

# define o preço por-endpoint (ledger de billing)
curl -s -X POST "http://127.0.0.1:18080/admin/tenants/$TID/pricing" \
  -H "Authorization: Bearer $ADMIN" -H "Content-Type: application/json" \
  -d "{\"endpoint\":\"$ENDPOINT\",\"price_cents\":5}"

kill $P1; wait $P1 2>/dev/null
```

Saída verificada:

```
{"id":"f156fd81fafedf9cfc4c7828fdb56cdb","name":"smoke-tenant","active":true}
{"tenant_id":"f156fd81fafedf9cfc4c7828fdb56cdb","endpoint":"/v1/notify","price_cents":5}
```

## 5. Fase 2 — run: fluxo PIX completo

Agora suba ligando o `tenantID` capturado às credenciais. A `tenantRef` opaca é a
credencial do webhook (256 bits); o `client_id` no `PAYMENT_BANK_CREDS` é
cross-checado contra o corpo do webhook.

```bash
REF=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')   # 43 chars base64url
CLIENT="c6-client-smoke"

PAYMENT_C6_BASE_URL= PAYMENT_SECURE_COOKIES=false \
  PAYMENT_ADMIN_TOKENS="$ADMIN" \
  PAYMENT_TENANT_TOKENS="$TNT:$TID" \
  PAYMENT_WEBHOOK_REFS="$REF:$TID" \
  PAYMENT_BANK_CREDS="$TID:$CLIENT:c6-secret-smoke" \
  PAYMENT_DB_PATH="$DB" PAYMENT_HTTP_ADDR=":18080" \
  "$API" & P2=$!
until curl -s http://127.0.0.1:18080/healthz >/dev/null; do sleep 0.1; done
```

> A URL a registrar no portal C6 é `https://<dominio>/webhooks/c6/$REF`. **Nunca**
> logue `$REF` nem a URL completa — o edge mascara o path `/webhooks/c6/*`
> (ver [`ingress-runbook.md`](./ingress-runbook.md) §6/§7).

### 5.1 Criar cobrança PIX (bearer do tenant + Idempotency-Key obrigatório)

```bash
RESP=$(curl -s -X POST http://127.0.0.1:18080/v1/charges \
  -H "Authorization: Bearer $TNT" -H "Idempotency-Key: smoke-key-001" \
  -H "Content-Type: application/json" \
  -d "{\"endpoint\":\"$ENDPOINT\",\"amount_cents\":1500,\"currency\":\"BRL\"}")
echo "$RESP"
PID=$(echo "$RESP"  | sed -n 's/.*"id":"\([0-9a-f]*\)".*/\1/p')
TXID=$(echo "$RESP" | sed -n 's/.*"tx_id":"\([^"]*\)".*/\1/p')
```

`HTTP 201`, saída verificada (`status=pending`, `tx_id=tx_<paymentID>`):

```json
{"id":"37a544d0dec05baaa117cea15f319bd8","tenant_id":"f156fd81fafedf9cfc4c7828fdb56cdb","endpoint":"/v1/notify","amount_cents":1500,"currency":"BRL","status":"pending","tx_id":"tx_37a544d0dec05baaa117cea15f319bd8"}
```

### 5.2 Ler a cobrança

```bash
curl -s http://127.0.0.1:18080/v1/charges/$PID -H "Authorization: Bearer $TNT"
```

→ mesmo corpo, `status:"pending"`.

### 5.3 Idempotência (mesma key ⇒ mesma cobrança, sem dupla cobrança)

```bash
curl -s -X POST http://127.0.0.1:18080/v1/charges \
  -H "Authorization: Bearer $TNT" -H "Idempotency-Key: smoke-key-001" \
  -H "Content-Type: application/json" \
  -d "{\"endpoint\":\"$ENDPOINT\",\"amount_cents\":1500,\"currency\":\"BRL\"}"
```

→ retorna o **mesmo `id`/`tx_id`** da 5.1 (nenhuma cobrança nova).

### 5.4 Receber webhook C6 — reconcile-before-settle (caminho negativo)

O corpo afirma `status:"paid"`, mas o webhook é **não-confiável**:

```bash
curl -s -o /dev/null -w "HTTP %{http_code}\n" -X POST "http://127.0.0.1:18080/webhooks/c6/$REF" \
  -H "Content-Type: application/json" \
  -d "{\"external_id\":\"$TXID\",\"client_id\":\"$CLIENT\",\"service\":\"pix\",\"status\":\"paid\"}"
# → HTTP 202

curl -s http://127.0.0.1:18080/v1/charges/$PID -H "Authorization: Bearer $TNT"
# → status AINDA "pending"
```

✅ **Reconcile-before-settle provado:** o handler reconcilia com o estado
autoritativo do banco (`GetCharge`), que reporta `pending`; portanto **não
liquida** apesar do webhook afirmar `paid`. O `202` é "notificação aceita e
registrada", não "liquidado".

### 5.5 Replay/dedup (mesmo `event_key` ⇒ no-op)

Reenvie o **mesmo** corpo (o `event_key` é `external_id|service|status`):

```bash
curl -s -o /dev/null -w "HTTP %{http_code}\n" -X POST "http://127.0.0.1:18080/webhooks/c6/$REF" \
  -H "Content-Type: application/json" \
  -d "{\"external_id\":\"$TXID\",\"client_id\":\"$CLIENT\",\"service\":\"pix\",\"status\":\"paid\"}"
# → HTTP 202 (dedup: MarkProcessed reconhece a redelivery, no-op)
```

### 5.6 Guardas de segurança (verificados)

```bash
# ref inválida/desconhecida ⇒ MESMO 401 (sem oráculo de enumeração)
BADREF=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')
curl -s -o /dev/null -w "HTTP %{http_code}\n" -X POST "http://127.0.0.1:18080/webhooks/c6/$BADREF" \
  -H "Content-Type: application/json" -d '{"external_id":"x","service":"pix","status":"paid"}'
# → HTTP 401

# corpo > 64 KiB ⇒ 413 (cap pré-auth contra DoS)
python3 -c "print('{\"external_id\":\"'+'A'*70000+'\"}')" > /tmp/big.json
curl -s -o /dev/null -w "HTTP %{http_code}\n" -X POST "http://127.0.0.1:18080/webhooks/c6/$REF" \
  -H "Content-Type: application/json" --data-binary @/tmp/big.json
# → HTTP 413

# /v1 sem token ⇒ 401 (deny-by-default)
curl -s -o /dev/null -w "HTTP %{http_code}\n" http://127.0.0.1:18080/v1/charges/$PID
# → HTTP 401
```

### 5.7 Encerrar

```bash
kill $P2; wait $P2 2>/dev/null
```

**Observabilidade:** o log do serviço **não** contém a `tenantRef` nem o secret —
apenas `api: PAYMENT_C6_BASE_URL not set — using in-memory bank stub`. A
aplicação só loga o `tenant id` resolvido, nunca a ref (o mascaramento do path no
edge é responsabilidade do ingress).

## 6. Cobertura que o smoke HTTP não alcança (suite Go)

O caminho **positivo** de liquidação, a **recusa por divergência de valor** e os
**3 produtos C6-C** não têm gatilho HTTP no stub (§2); são provados pelo suite:

```bash
go test ./internal/app/  -run 'Webhook' -v        # settle + divergência
go test ./internal/adapters/bank/ -run 'Consent|Boleto|Checkout' -v
```

| Garantia | Teste (verificado PASS) |
| --- | --- |
| Liquidação positiva + reconcile | `TestWebhookReconciliationAndReplay`, `TestWebhookFullPaymentStillSettlesAndDoesNotAudit` |
| Recusa por subpagamento | `TestWebhookRefusesSettlementOnPartialPayment` |
| Recusa por sobrepagamento | `TestWebhookRefusesSettlementOnOverpayment` |
| Reconcile transiente não perde liquidação | `TestWebhookTransientReconcileErrorDoesNotSuppressSettlement` |
| PIX Automático (consent) — ciclo + isolamento | `TestStubConsentLifecycle`, `TestStubConsentNotFoundAndIsolation` |
| BolePix (boleto) | `TestStubBoleto` |
| Checkout unificado | `TestStubCheckout` |

## 7. Transição para o C6 real (homologação)

Quando as credenciais chegarem ([SIN-65344](/SIN/issues/SIN-65344)):

1. Preencha `PAYMENT_C6_BASE_URL`, `PAYMENT_C6_TOKEN_URL`, `PAYMENT_C6_SCOPE`
   (HTTPS; URL `http://` falha o startup por design).
2. Forneça o **certificado de cliente mTLS** (ver §8): `PAYMENT_C6_CLIENT_CERT` e
   `PAYMENT_C6_CLIENT_KEY` apontando para os arquivos PEM montados pelo secret
   manager.
3. Forneça `PAYMENT_BANK_CREDS` com o `client_id`/`secret` reais do tenant (via
   secret manager), ou escreva via `PUT /admin/tenants/{id}/bank-credential`.
4. Registre a URL `https://<dominio>/webhooks/c6/$REF` no portal C6.
5. Rode a §5 idêntica: agora o caminho **positivo** de liquidação fecha por HTTP
   (o C6 reporta `paid` na reconciliação) e a §5.4 vira o caso de liquidação real.

## 8. mTLS do C6 — certificado de cliente ([SIN-65805](/SIN/issues/SIN-65805))

O C6 exige um **certificado de cliente (mutual TLS)** na conexão, **além** do
bearer OAuth2. Sem o cert, o handshake TLS é recusado pelo C6 antes de qualquer
request HTTP — o OAuth2 sozinho não basta.

### 8.1 Como ligar

Duas env vars novas, ambas **caminhos** para arquivos PEM (o segredo — a chave
privada — vive só no arquivo, nunca em código/env/URL; threat C1):

| Var | Conteúdo |
| --- | --- |
| `PAYMENT_C6_CLIENT_CERT` | caminho do PEM do **certificado** do cliente |
| `PAYMENT_C6_CLIENT_KEY`  | caminho do PEM da **chave privada** do cliente |

Comportamento (`cmd/api/main.go` `newBankProvider` → `c6.MTLSHTTPClient`):

- **Ambas vazias** ⇒ sem cert de cliente — comportamento atual preservado (stub/dev
  e qualquer endpoint que não exija mTLS).
- **Setadas** ⇒ o par é carregado com `tls.LoadX509KeyPair` e injetado no
  transporte do adapter C6 via `c6.Config.HTTPClient`, mantendo **TLS >= 1.2** e
  **redirects desabilitados** (anti-SSRF) idênticos ao transporte default.
- **Falha ao carregar o par** (arquivo ausente, PEM inválido, só uma das duas
  setada) ⇒ **erro explícito de boot (fail-closed)** — o processo NÃO sobe sem o
  cert quando ele foi pedido, em vez de degradar silenciosamente para sem-mTLS.

Em homologação/produção os arquivos vêm do secret manager, montados read-only no
FS do processo (não do repositório). Permissões `0600`; nunca commitar PEM.

### 8.2 Endpoints do sandbox — status (BLOQUEADO no portal, NÃO bloqueia o cert)

`PAYMENT_C6_BASE_URL` / `PAYMENT_C6_TOKEN_URL` do **sandbox de homologação** não
vieram no e-mail de onboarding e o Portal do Desenvolvedor C6
(<https://developers.c6bank.com.br/>) é **login-walled** — a referência de API,
os hostnames de sandbox e o material do mTLS ficam atrás do login/onboarding e
**não são alcançáveis sem credencial do portal**. Confirmação pública também não
existe (busca aberta não retorna os hosts).

> **PLACEHOLDER — preencher na obtenção dos endpoints (rotear via SIN-65805 / SIN-65344):**
>
> ```
> PAYMENT_C6_BASE_URL=https://<sandbox-base-host-do-portal>      # ex.: baseapi homologação
> PAYMENT_C6_TOKEN_URL=https://<sandbox-token-host-do-portal>/oauth/token
> PAYMENT_C6_SCOPE=<scope-se-exigido-pelo-portal>
> PAYMENT_C6_CLIENT_CERT=/etc/payment/c6/client.crt   # PEM emitido/registrado no portal
> PAYMENT_C6_CLIENT_KEY=/etc/payment/c6/client.key
> ```

O **plumbing do cert (entregáveis 2–3) está completo e testado** independentemente
desses valores: assim que o portal liberar base/token URLs + o PEM do cliente,
basta preencher as cinco vars acima e rodar a §5/§7 — nenhuma mudança de código é
necessária.

## 9. Contrato REAL do C6 — descoberto ao vivo ([SIN-65856](/SIN/issues/SIN-65856))

O smoke contra o sandbox real ([SIN-65804](/SIN/issues/SIN-65804)) provou mTLS+OAuth2
mas revelou que os paths do adapter eram **placeholders** (404). Iterando ao vivo
(mTLS + bearer) descobriu-se o contrato real abaixo. Base do sandbox:
`https://baas-api-sandbox.c6bank.info`; token em `/v1/auth/` (Basic auth + mTLS).
Janela: seg–sex 7h–23h BRT. Erros = **RFC7807 problem+json** (BACEN PIX:
`https://pix.bcb.gov.br/api/v2/error/...`; C6 próprio:
`https://developers.c6bank.com.br/v1/error/...`).

| Superfície | Path real | Status |
| --- | --- | --- |
| PIX cob (imediata) | `PUT`/`GET /v2/pix/cob/{txid}` · lista `GET /v2/pix/cob?inicio=&fim=` | ✅ remapeado + **positivo provado (HTTP 200)** |
| PIX cobv (com venc.) | `/v2/pix/cobv/{txid}` | ⏳ DTO real pendente (follow-up) |
| PIX recebidos / recorrência | `/v2/pix/pix` · `/v2/pix/rec` | ⏳ follow-up |
| Extrato | `GET /v1/statement?start_date=&end_date=` (yyyy-MM-dd) | ✅ params remapeados |
| Boleto | `POST /v1/bank_slips` | ⏳ path descoberto; DTO real pendente (follow-up) |
| Checkout | `POST /v1/checkouts` | ⏳ path descoberto; schema `payment` portal-gated (follow-up) |
| Webhook mgmt | `/v1/webhooks` (req: `service`,`url`) | ⏳ follow-up |

### 9.1 PIX cob — caminho positivo confirmado (HTTP 200)

`PUT /v2/pix/cob/{txid}` (txid BACEN `[a-zA-Z0-9]{26,35}`; o adapter usa
`sha256(anchor)[:32]`) com corpo BACEN — **inclui `chave`** (a chave do recebedor;
sem ela a cob não roteia):

```bash
curl --cert /etc/payment/c6/client.crt --key /etc/payment/c6/client.key \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -X PUT "https://baas-api-sandbox.c6bank.info/v2/pix/cob/<txid>" \
  -d '{"calendario":{"expiracao":3600},"valor":{"original":"10.00"},"chave":"<chave>"}'
# → HTTP 200: {"txid":...,"status":"ATIVA","location":"qrcode-h.c6pix.com/...","pixCopiaECola":"00020101...","calendario":{"criacao":...,"expiracao":3600}}
```

Notas de DTO já aplicadas no adapter (este PR): o `location` vem **top-level**
(não `loc.location`); o request precisa de `chave` (port `ChargeRequest.CreditorKey`,
encaminhado como `chave` omitempty). Detalhes completos no documento
**"Descoberta ao vivo — contrato real C6 sandbox"** da SIN-65856.

> **Pendente (follow-ups da SIN-65856):** fonte da `chave` no app (por-tenant vs
> request — decisão de design), DTO real de cobv (spec BACEN pública), DTO de
> boleto `/v1/bank_slips` (resposta 201 não capturada) e schema `payment` do
> checkout `/v1/checkouts` (portal login-walled).

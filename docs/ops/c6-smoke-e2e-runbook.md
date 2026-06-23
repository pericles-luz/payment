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
2. Forneça `PAYMENT_BANK_CREDS` com o `client_id`/`secret` reais do tenant (via
   secret manager), ou escreva via `PUT /admin/tenants/{id}/bank-credential`.
3. Registre a URL `https://<dominio>/webhooks/c6/$REF` no portal C6.
4. Rode a §5 idêntica: agora o caminho **positivo** de liquidação fecha por HTTP
   (o C6 reporta `paid` na reconciliação) e a §5.4 vira o caso de liquidação real.

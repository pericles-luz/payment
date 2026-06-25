# PIX cobv + Checkout — Camada A (stub mode) — matriz de rastreabilidade

Homologação C6, F3 ([SIN-65722](/SIN/issues/SIN-65722), umbrella
[SIN-65683](/SIN/issues/SIN-65683)).

Camada A exercita PIX **cobrança com vencimento** (cobv, grupos 7.5–7.8) e Checkout
(grupos 10–12) **em modo stub** (`PAYMENT_C6_BASE_URL` vazio → in-memory bank,
`cmd/api/main.go`) — sem tocar o C6 real. Cada subitem do roteiro mapeia para um teste
automatizado e a evidência observável (status code / corpo de resposta). Esta matriz
alimenta a Camada B (`.docx` para o C6).

## Cobertura por PR

- **PR-A ([SIN-65724](/SIN/issues/SIN-65724), esta entrega):** domínio `pixcobv`
  (multa/juros pro-rata-die/desconto, devedor PF/PJ, chave do recebedor), port
  `PixDueChargeProvider`, adapter C6 (`CreateDueCharge`/`GetDueCharge`/`UpdateDueCharge`),
  use-case `PixDueChargeService`, rotas `POST/GET/PUT /v1/pix/cobv/{txid}` e webhook
  cobv (grupo 7.8, **reusa** o endpoint C6-D `/webhooks/c6/{tenantRef}`). **Grupos
  7.5–7.8 completos.**
- **PR-B ([SIN-65726](/SIN/issues/SIN-65726), bloqueada por PR-A):** Checkout
  `GET`/`DELETE /v1/checkout/{id}` + webhook de checkout (grupos 10–12). _Esta matriz
  será estendida nessa entrega._

## Endpoints PR-A (multi-tenant, deny-by-default, idempotency obrigatória nos writes)

| Método | Rota                      | Sucesso | Grupos   |
| ------ | ------------------------- | ------- | -------- |
| POST   | `/v1/pix/cobv`            | 201     | 7.5      |
| GET    | `/v1/pix/cobv/{txid}`     | 200     | 7.6      |
| PUT    | `/v1/pix/cobv/{txid}`     | 200     | 7.7      |
| POST   | `/webhooks/c6/{tenantRef}`| 202     | 7.8      |

## Postura de segurança (herdada do imediato + C6-D)

- **Auth deny-by-default** em todas as rotas `/v1/pix/cobv` (grupo autenticado do
  router); tenant derivado do credential autenticado, nunca do input do cliente
  (threat H1/P1). Isolamento cross-tenant testado (`http.TestCobvCrossTenantIsolationHTTP`).
- **Validação no boundary**: `Idempotency-Key` obrigatório nos writes, `due_date`
  RFC3339, `decodeJSON` rejeita campos desconhecidos (anti mass-assignment), invariantes
  cobv (tetos multa 2% / juros 1% a.m., desconto < principal, devedor CPF/CNPJ, chave
  obrigatória, vencimento no futuro) validadas no core antes do banco.
- **Reconcile-before-settle / money** (threat W3): a liquidação lê o estado
  autoritativo do banco; cobv reconcilia via `BankProvider.GetCharge` no mesmo webhook
  C6-D (dedup por `event_key`, mesma-401 anti-enumeração, path não logado em claro).
- **Reserve-before-bank**: cobrança reservada (idempotência) ANTES da chamada ao banco;
  txid + ledger persistidos atomicamente — erro de banco nunca bilheta
  (`app.TestCobvBankErrorDoesNotBill`, `app.TestCobvInvalidDoesNotReserve`).

## Matriz subitem → teste → evidência (PR-A)

| Subitem | Descrição                                       | Teste (camada)                                                                                                  | Evidência |
| ------- | ----------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------- |
| 7.5     | Criar cobrança com vencimento (`cobv`)          | `app.TestCobvCreateSuccess`, `app.TestCobvCreateIdempotent`, `http.TestCobvCreateGetUpdateHTTP`, `bank.TestStubCobvCreateAndGet`, `c6.TestCreateDueChargeSuccess` | 201, `status` + QR (copia-e-cola/location) + parâmetros echo; re-submit com mesma chave resolve a mesma cobrança (sem duplicar) |
| 7.5†    | Multa/juros pro-rata-die/desconto (regras core) | `pixcobv.TestFineAndInterest`, `pixcobv.TestDiscount`, `pixcobv.TestDiscountFixed`, `pixcobv.TestExpired`        | multa cobrada integral no 1º dia de atraso; juros = principal×taxa/30×dias; desconto até o vencimento; expira após validade |
| 7.5‡    | Validação de input + devedor PF/PJ + chave      | `app.TestCobvCreateValidation`, `pixcobv.TestNewValidationErrors`, `pixcobv.TestDebtorPJ`, `bank.TestStubCobvRejectsBadInput`, `c6.TestCreateDueChargeRejectsBadInput` | 400/ErrValidation em vencimento passado, valores inválidos, devedor/chave ausentes; CPF→PF, CNPJ→PJ |
| 7.6     | Consultar cobv por `txid`                       | `app.TestCobvGet`, `http.TestCobvGetUnknownTxid`, `bank.TestStubCobvGetUnknown`, `c6.TestGetDueChargeSuccess`, `c6.TestGetDueChargeNotFoundMapping` | 200 com parâmetros reconciliados; txid desconhecido → 404 (tenant-scoped, sem disclosure cross-tenant) |
| 7.7     | Alterar (PUT) cobv                              | `app.TestCobvUpdate`, `app.TestCobvUpdateValidation`, `bank.TestStubCobvUpdate`, `bank.TestStubCobvUpdateUnknown`, `c6.TestUpdateDueChargeSuccess`, `c6.TestUpdateDueChargeNotFoundMapping` | 200 com parâmetros novos; txid desconhecido → 404; não re-bilheta (cobrança já bilhetada na criação) |
| 7.8     | Webhook PIX recebido (cobv)                     | `http.TestCobvWebhookSettlesAndDedups`, `bank.TestStubCobvReconcilableForWebhook`                              | cobv liquida via endpoint C6-D existente `/webhooks/c6/{tenantRef}` (reconcile via `GetCharge`), 202; replay deduplicado por `event_key` |

† regras de domínio puro (sem rede). ‡ guardas de boundary + core.

## Isolamento de tenant

`http.TestCobvCrossTenantIsolationHTTP` e `bank.TestStubCobvIsolation` provam que um
tenant nunca lê/altera a cobv de outro (credencial por-tenant, leitura tenant-scoped).

## Decisões de escopo ([SIN-65746](/SIN/issues/SIN-65746))

- **`cobv` é a vocabulário canônico do grupo 7 com vencimento**, não `scheduled`
  (cob=imediata / cobv=com-vencimento, ubiquitous language BACEN/PIX e termo do
  roteiro). A trilha paralela `/v1/pix/scheduled` + `POST /v1/pix/webhook` (registrar
  URL), que havia entrado em `main` via [PR #31](https://github.com/ia-dev-sindireceita/payment/pull/31)
  ([SIN-65729](/SIN/issues/SIN-65729)), foi **removida** nesta entrega — o repositório
  expõe **uma única** superfície para PIX com vencimento: `/v1/pix/cobv`.
- **`listar cobv` (GET por intervalo) está fora de escopo** e não foi portado. Os
  subitens enumerados do grupo 7 com vencimento são **7.5 criar / 7.6 consultar (por
  txid) / 7.7 alterar / 7.8 webhook** — listagem não é um subitem cobv (a listagem por
  data do imediato é o subitem 7.4 da superfície `cob`, distinta). A trilha `scheduled`
  removida incluía um `GET /v1/pix/scheduled` (listar); como não corresponde a um
  subitem do roteiro cobv, foi descartado em vez de portado. **Se a homologação exigir
  listar cobv**, portar `GET /v1/pix/cobv` espelhando o filtro do imediato
  (`?start&end`, janela ≤ `maxPixListRange`, paginação) é um follow-up trivial.
- **7.8 (webhook PIX recebido)** padroniza no modelo C6-D: a notificação de liquidação
  é reconciliada pelo webhook compartilhado `/webhooks/c6/{tenantRef}` (reconcile via
  `GetCharge`), não por um endpoint de registro de URL por-chave.

## Reversibilidade / rollout

- Modo stub é o default de dev/teste; o C6 real só é exercido quando
  `PAYMENT_C6_BASE_URL` é configurado (Camada B / homologação). Sem migração de schema
  nesta entrega.
- Rollback: reverter o PR. A remoção de `scheduled` é zero-blast-radius hoje (Camada B
  bloqueada por creds, sem consumidor externo); as rotas `cobv` são aditivas e não
  alteram o imediato/boleto.

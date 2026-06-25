# Checkout — Camada A (stub mode) — matriz de rastreabilidade

Homologação C6, F3 Checkout consultar/cancelar/webhook
([SIN-65726](/SIN/issues/SIN-65726), pai [SIN-65722](/SIN/issues/SIN-65722),
umbrella [SIN-65683](/SIN/issues/SIN-65683)).

Camada A exercita os grupos 10–12 do checkout **em modo stub**
(`PAYMENT_C6_BASE_URL` vazio → in-memory bank, `cmd/api/main.go`) — sem tocar o C6
real. Cada subitem do roteiro mapeia para um teste automatizado e a evidência
observável (status code / corpo). Esta matriz alimenta a Camada B (`.docx` para o C6).

## Cobertura por PR

- **Checkout criar (merged, PR #27, [SIN-65689](/SIN/issues/SIN-65689)):** domínio da
  sessão + `POST /v1/checkout` (roteiro 9.a–9.c).
- **PR-B (esta entrega, grupos 10–12):** `GET /v1/checkout/{id}` (consultar, 10),
  `DELETE /v1/checkout/{id}` (cancelar, 11) e o **webhook de checkout** (12) — novo
  event type (`service=checkout`) no handler compartilhado `/webhooks/c6/{tenantRef}`,
  reusando dispatch por-tenant + dedup `event_key` + reconcile-before-settle da C6-D
  ([SIN-64753](/SIN/issues/SIN-64753)). Adapter `GetCheckoutSession`/
  `CancelCheckoutSession`; use-cases `CheckoutService.GetSession`/`CancelSession`;
  `WebhookService.HandleCheckoutEvent`.

## Endpoints (multi-tenant, deny-by-default)

| Método | Rota                          | Sucesso | Grupo |
| ------ | ----------------------------- | ------- | ----- |
| POST   | `/v1/checkout`                | 201     | 9     |
| GET    | `/v1/checkout/{id}`           | 200     | 10    |
| DELETE | `/v1/checkout/{id}`           | 200     | 11    |
| POST   | `/webhooks/c6/{tenantRef}`    | 202     | 12    |

## Matriz subitem → teste → evidência (PR-B — grupos 10–12)

| Grupo | Descrição                                   | Teste (camada)                                                                                              | Evidência |
| ----- | ------------------------------------------- | ----------------------------------------------------------------------------------------------------------- | --------- |
| 10    | Consultar sessão de checkout                | `http.TestCheckoutGetHTTP`, `app.TestCheckoutGetSession`, `bank.TestStubCheckoutCreateGetCancel`, `c6.TestGetCheckoutSessionSuccess` | **200**; `status`/`amount_cents` reconciliados do banco (source of truth) |
| 11    | Cancelar sessão de checkout                 | `http.TestCheckoutCancelHTTP`, `app.TestCheckoutCancelSession`, `bank.TestStubCheckoutCreateGetCancel`, `c6.TestCancelCheckoutSessionSuccess` | **200**; `status=CANCELLED`; cancelamento idempotente (repetir → 200, mesmo estado) |
| 12    | Webhook de checkout (status de pagamento)   | `http.TestCheckoutWebhookHTTP`, `app.TestCheckoutWebhookSettlement`, `app.TestCheckoutWebhookAmountDivergenceRefusesSettle` | **202**; só liquida após reconciliar a sessão no banco; dedup de replay; divergência de valor recusada e auditada |

## Lentes de segurança (não-negociáveis) — evidência

| Lente                                              | Teste                                                                                       | Evidência |
| -------------------------------------------------- | ------------------------------------------------------------------------------------------- | --------- |
| Auth deny-by-default (GET/DELETE checkout)         | `http.TestCheckoutGetHTTP` (no-auth → 401)                                                  | 401 sem token |
| OWASP A01 — isolamento cross-tenant (sem oráculo)  | `app.TestCheckoutGetSession` (cross-tenant → ErrNotFound), `app.TestCheckoutCancelSession`, `http.TestCheckoutGetHTTP`/`TestCheckoutCancelHTTP` (id desconhecido → 404) | id de outro tenant ou inexistente → 404, indistinguíveis |
| Reconcile-before-settle (threat W3) — valor, não só status | `app.TestCheckoutWebhookSettlement` (OPEN→não liquida; capturado→liquida), `app.TestCheckoutWebhookAmountDivergenceRefusesSettle` | captura parcial/divergente → 202 mas **não** liquida |
| Anti-replay / dedup por `event_key`                | `http.TestCheckoutWebhookHTTP` (entrega dupla → 1 liquidação)                                | exatamente 1 `payment.paid` após 2 entregas |
| Webhook compartilhado — mesma-401, body-cap, tenant-do-canal | herdado da C6-D: `http.TestWebhookMalformedRefSame401`, `TestWebhookOversizeBody`, `TestWebhookBodyTenantMismatchRejected` | dispatch de checkout reusa o handler já endurecido (sem 2º endpoint) |
| Open-redirect — recusa redirect_url não-https      | `c6.TestGetCheckoutSessionRejectsUntrustedRedirect`                                         | reconcile com redirect não-https → `ErrUnavailable`, resultado vazio |
| Erros como valores, sem vazar status C6            | `c6.TestGetCheckoutSessionNotFound`, `c6.TestCancelCheckoutSessionError` (404→`ErrNotFound`, 409→`ErrConflict`) | sentinela de domínio, sem corpo upstream |
| Falha-fechado se webhook não configurado           | `app.TestCheckoutWebhookNotConfigured`                                                      | port de checkout nil → `ErrUnavailable` (nunca drop silencioso) |
| Per-tenant isolation no adapter (token por tenant) | `c6.TestCheckoutRWMissingCredential`, `bank.TestStubCheckoutMissingCredential`              | credencial ausente → ErrNotFound, token endpoint não tocado |

## Arquitetura

- **Hexagonal:** domínio puro em `internal/domain/checkout` (sessão + total derivado
  dos itens). I/O C6 atrás do port `ports.CheckoutProvider` (adapter
  `internal/adapters/bank/c6` + stub in-memory `internal/adapters/bank`). Use-case
  `app.CheckoutService` (consultar/cancelar) e `app.WebhookService` (liquidação via
  reconcile). O webhook depende do port estreito `ports.CheckoutReconciler` (ISP).
- **Webhook reuso:** o handler `/webhooks/c6/{tenantRef}` despacha por `service`:
  `checkout` → `HandleCheckoutEvent` (reconcilia a sessão), demais → `HandlePaymentEvent`
  (charge PIX). Mesma unidade de trabalho (dedup + reconcile-before-settle + auditoria);
  o `event_key` carrega o `service`, então checkout e charge do mesmo id não colidem.
- **Gate:** `scripts/coverage.sh` > 85%; `-race`, `go vet`, `staticcheck` limpos.

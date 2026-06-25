# Boleto — Camada A (stub mode) — matriz de rastreabilidade

Homologação C6, F2 Boleto ([SIN-65710](/SIN/issues/SIN-65710), pai
[SIN-65708](/SIN/issues/SIN-65708), umbrella [SIN-65683](/SIN/issues/SIN-65683)).

Camada A exercita o ciclo de Boleto **em modo stub** (`PAYMENT_C6_BASE_URL` vazio →
in-memory bank, `cmd/api/main.go`) — sem tocar o C6 real. Cada subitem do roteiro de
homologação mapeia para um teste automatizado e a evidência observável (status code /
corpo de resposta). Esta matriz alimenta a Camada B (`.docx` para o C6).

## Cobertura por PR

- **PR-A (merged, PR #29):** domínio (multa fixa + desconto), `POST /v1/boletos`
  (grupos 1–3) e `GET /v1/boletos/{id}` (grupo 6).
- **PR-B (esta entrega):** `DELETE /v1/boletos/{id}` (baixa/cancelamento, grupo 4) e
  `PUT /v1/boletos/{id}` (alteração, grupo 5) + adapter `CancelBoleto`/`UpdateBoleto` +
  domínio `WithValidUntil` (data limite de pagamento, 5.b). **Ciclo 1–6 completo.**

## Endpoints (multi-tenant, deny-by-default, idempotency obrigatória nos writes)

| Método | Rota                  | Sucesso | Grupos      |
| ------ | --------------------- | ------- | ----------- |
| POST   | `/v1/boletos`         | 201     | 1, 2, 3     |
| GET    | `/v1/boletos/{id}`    | 200     | 6.a         |
| DELETE | `/v1/boletos/{id}`    | 204     | 4.a, 4.b    |
| PUT    | `/v1/boletos/{id}`    | 200     | 5.a–5.c     |

## Matriz subitem → teste → evidência (PR-A)

| Subitem | Descrição                                   | Teste (camada)                                                       | Evidência |
| ------- | ------------------------------------------- | ------------------------------------------------------------------- | --------- |
| 1.a     | Emissão: juros diários + multa por atraso   | `app.TestRegisterBoletoVariants/1a_fine_and_interest`               | 201, `status=REGISTERED`, principal echo |
| 1.b     | Emissão sem juros/multa, com data limite    | `app.TestRegisterBoletoVariants/1b_no_fine_no_interest`            | 201; domínio: `FineCents=InterestCents=0` em `boleto.TestFineAndInterestAndTotal` |
| 2.a     | Variável: só juros                          | `app.TestRegisterBoletoVariants/2a_interest_only`                  | 201; juros pro-rata-die `boleto.TestFineAndInterestAndTotal` |
| 2.b     | Variável: só multa                          | `app.TestRegisterBoletoVariants/2b_fine_only`                      | 201; multa percentual `boleto.TestFineRoundsHalfUp` |
| 2.c     | Multa percentual **ou valor fixo**          | `app.TestRegisterBoletoVariants/2c_fine_fixed`, `boleto.TestFixedFine`, `boleto.TestFixedFineValidation` | 201; multa fixa cobrada quando vencido, teto 2% (Lei 9.298/96) validado no core |
| 3.a     | Desconto até o vencimento                   | `boleto.TestDiscountUntilDue`, `boleto.TestDiscountFixedCents`, `app.../3a_discount_until_due`, `app.../3a_discount_fixed` | desconto (% ou fixo) aplicado até a data de vencimento, zera quando vencido |
| 3.b     | Descontos escalonados por dias antes do vto | `boleto.TestDiscountTieredByDays`, `app.TestRegisterBoletoVariants/3b_discount_tiered` | tier mais generoso entre os qualificados; ordenação validada no core |
| 6.a     | Consulta por ID                             | `app.TestRegisterBoletoVariants` (get final), `http.TestBoletoCreateAndGetHTTP`, `bank.TestStubGetBoleto`, `c6.TestGetBoletoSuccess` | 200; parâmetros registrados (multa/juros/desconto) reconciliados |

## Matriz subitem → teste → evidência (PR-B — grupos 4–5)

| Subitem | Descrição                                   | Teste (camada)                                                       | Evidência |
| ------- | ------------------------------------------- | ------------------------------------------------------------------- | --------- |
| 4.a/4.b | Baixa/cancelamento (a-vencer e vencido)     | `http.TestBoletoDeleteHTTP`, `app.TestCancelBoleto`, `bank.TestStubCancelBoleto`, `c6.TestCancelBoletoSuccess` | **204**; `GET` depois → `status=CANCELLED`; baixa idempotente (mesma resposta — a-vencer e vencido tratados igual) |
| 5.a     | Alteração de vencimento                     | `app.TestUpdateBoletoVariants/5a_due_date`, `http.TestBoletoUpdateHTTP` | **200**; `due_date` amendado reconciliado no `GET` |
| 5.b     | Alteração de validade (data limite)         | `app.TestUpdateBoletoVariants/5b_validity`, `boleto.TestWithValidUntil` | **200**; `valid_until` amendado; invariante `validade ≥ vencimento` no core |
| 5.c     | Alteração de valor/multa/juros              | `app.TestUpdateBoletoVariants/5c_amount_fine_interest`, `c6.TestUpdateBoletoSuccess` | **200**; valor/multa-fixa/juros amendados; identidade (id/txid) preservada |

## Lentes de segurança (não-negociáveis) — evidência

| Lente                                        | Teste                                                      | Evidência |
| -------------------------------------------- | ---------------------------------------------------------- | --------- |
| Auth deny-by-default (toda rota)             | `http.TestBoletoHTTPErrors/requires_auth`, `/get_requires_auth`, `http.TestBoletoWriteAuthAndValidation/delete_requires_auth`, `/put_requires_auth` | 401 sem token |
| Idempotency key obrigatória nos writes       | `http.TestBoletoHTTPErrors/missing_idempotency_key` (POST), `http.TestBoletoWriteAuthAndValidation/put_missing_idempotency_key` (PUT) | 400 sem header |
| Idempotência (sem cobrança dupla)            | `app.TestRegisterBoletoIdempotent`, `app.TestRegisterBoletoConcurrentSameKey`; amend não re-cobra `app.TestUpdateBoletoVariants` | 1 ledger entry; mesmo id em N concorrentes |
| OWASP A01 — isolamento cross-tenant (sem oráculo) | `http.TestBoletoCrossTenantGetIsolation`, `http.TestBoletoCrossTenantWriteIsolation` (DELETE/PUT), `bank.TestStubGetBoletoIsolation`, `bank.TestStubCancelBoleto`, `bank.TestStubUpdateBoleto` | tenant B → 404 em GET/DELETE/PUT do boleto de A |
| Validação no boundary + anti mass-assignment | `http.TestBoletoHTTPErrors/unknown_field`, `/bad_due_date`, `/fine_over_cap`, `http.TestBoletoWriteAuthAndValidation/put_unknown_field`, `/put_bad_due_date` | 400 |
| Erros como valores, sem vazar status C6      | `c6.TestGetBoletoNotFoundMapping`, `c6.TestCancelBoletoNotFoundMapping`, `c6.TestUpdateBoletoNotFoundMapping` (404→`ErrNotFound`) | sentinela de domínio, sem corpo upstream |
| Falha do provider não cobra                  | `app.TestRegisterBoletoBankError`, `app.TestRegisterBoletoInvalidDoesNotReserve` | 0 ledger entries |

## Arquitetura

- **Hexagonal:** domínio puro em `internal/domain/boleto` (multa fixa/percentual,
  juros pro-rata-die, desconto escalonado — invariantes no core). I/O C6 atrás do
  port `ports.BoletoProvider` (adapter `internal/adapters/bank/c6` + stub
  in-memory `internal/adapters/bank`). Use-case `app.BoletoService` orquestra
  reserva-antes-do-banco + ledger atômico (mesma ordem financeira de PIX/checkout).
- **Gate:** `scripts/coverage.sh` > 85%; `-race`, `go vet`, `staticcheck` limpos.

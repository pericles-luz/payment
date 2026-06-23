# ADR-0002 — Reconciliação de liquidação do C6 via leitura PIX (não `/charges`)

- **Status:** Aceito — decisão do CTO em 2026-06-13 ([SIN-64791](/SIN/issues/SIN-64791), gate [SIN-64780](/SIN/issues/SIN-64780)).
- **Autor:** Coder. **Decisor:** CTO.

## Contexto

O caminho LIVE de liquidação por webhook (`internal/app/webhook.go`) reconcilia a
verdade autoritativa de uma cobrança antes de liquidar (reconcile-before-settle,
ameaça W3) chamando `BankProvider.GetCharge` → C6 `GET /charges/{txid}`. O corpo
de *create* genérico (`chargeRequestBody = {payment_id, amount_cents, currency}`)
é proprietário e inventado — **não** é BACEN — logo a forma de *resposta* assumida
por `chargeResponseBody`/`toChargeResult` (`valor.original` + `pix[]`) é igualmente
especulativa, sem contrato real, sandbox, fixture ou OpenAPI no repositório. Esse
é o gap do AC#1 do SIN-64780: ler a liquidação de uma forma não verificada poderia
recusar falsamente uma cobrança legitimamente paga (liquidações silenciosamente
bloqueadas no launch).

## Decisão

A reconciliação de liquidação do C6 passa a ler pela **leitura imediata PIX
verificada por BACEN** (`PixProvider.GetImmediateCharge` → `GET …/v1/pix/{txid}`,
com `valor.original` + recibos `pix[]`), **não** pelo genérico `GET /charges/{txid}`.
O `PAYMENT_C6_BASE_URL` **não** pode ir settlement-live contra `/charges` — passa a
ser invariante de launch. O port genérico `/charges` sobrevive como abstração para
um futuro trilho não-PIX, mas não é a fonte de reconciliação de liquidação do C6.

Implementação adapter-only atrás da flag: `bank.PixSettlementProvider` embute o
`BankProvider` genérico (criação intacta) e sobrescreve só `GetCharge` — a leitura
de reconciliação — delegando a `GetImmediateCharge` e traduzindo o status terminal
BACEN `CONCLUIDA` para o status genérico `paid`. `parseAmountCents` e a soma de
recibos permanecem compartilhados e fail-secure (valor ausente/zero → 0 → recusa).

## Lentes

Secure-by-default/reconcile-before-settle (lemos a forma cujo contrato é confiável
hoje); boring-technology (a API Pix cob é o padrão BACEN que todo PSP, incl. C6,
implementa); reversibilidade/blast-radius (adapter-only, atrás de flag ainda
desligada); DRY/idiomático (um único parser compartilhado, sem duplicar mapeador
especulativo).

## Residual (informativo, não bloqueador — CEO/roadmap)

Se um produto C6 *não-PIX* (boleto/cartão via um `/charges` real) for para
settlement-live, este gate reaplica por-produto: capturar o contrato real daquele
produto antes de habilitar.

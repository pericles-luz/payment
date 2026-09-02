# API de Recebíveis C6 Pay — o que foi medido no fio

Contrato oficial em [`c6pay-recebiveis-oas.yaml`](c6pay-recebiveis-oas.yaml)
("Transações e Recebíveis C6 Pay", v1.0.7, OAS 3.1.1).

Este arquivo registra o que **difere** do contrato, medido em 02/09/2026. Existe
porque o extrato comum (`/v1/statement`) passou meses devolvendo 400 em produção por
ler uma forma que o banco nunca mandou — e o mesmo erro está armado aqui.

## ⚠️ O envelope da resposta não bate com o spec

O spec declara a lista sob `receivables`:

```yaml
properties: [page, last_page, items, receivables]
```

O fio devolve sob **`content`**:

```json
{"content":[],"page":1,"last_page":0,"items":0}
```

Os outros três campos batem. Quem implementar lendo `receivables` recebe lista vazia
para sempre, sem erro nenhum — exatamente o formato do defeito do SIN-65856.

**A forma dos ITENS continua não verificada.** A resposta medida veio vazia, então só o
envelope foi confirmado. Antes de mapear os itens, capturar uma resposta populada: se o
spec errou o nome da lista, pode ter errado outros.

## Autorização: sandbox sim, produção não

| ambiente | conta | resultado |
|---|---|---|
| sandbox | `fa6d5713…` | **200** |
| produção | LM Host (`cb2d535f…`) | **403** `acess_denied` |

Mesma chamada, mesmos cabeçalhos, mesmo código. O token de produção traz
`statement.read`, que faz o `/v1/statement` comum funcionar, mas o C6 Pay é outro
produto e exige autorização própria.

O spec **não documenta escopos** — só `bearerAuth` —, e nenhum dos outros specs do C6
documenta. Qual escopo pedir é pergunta para o gerente, junto do pedido de habilitação.

## O que a API resolve

O extrato traz **uma linha agregada** por crédito. O de 02/09/2026, de R$ 37,29, juntava
cinco recebíveis de três vendas, e duas dessas vendas tinham o mesmo valor no mesmo dia
— casar por valor e data era impossível.

Os recebíveis dão o que falta: `receivable_id`, `transaction_id`, `installment_number`
de `installments`, e a tarifa aberta em `fee` (fixa) + `mdr` (percentual) = `discount`,
com `gross_amount` e `net_amount`.

Isso confirma no contrato o que tinha sido inferido dos cinco lançamentos do relatório:
**4,2% por parcela + R$ 0,35 fixo por venda**, cobrado só no primeiro recebível.

## Por que isso importa para o nosso modelo

Nosso sistema liquida pelo **bruto**; a empresa recebe o **líquido**. Uma venda de
R$ 30,00 marcada como paga vira R$ 28,39 na conta. A diferença é o MDR da adquirente,
que o nosso modelo de dados não carrega em campo nenhum — e nenhuma configuração muda
isso, porque MDR é custo do lojista, diferente do juro de parcelamento que já resolvemos
com `interest_type: BY_ISSUER`.

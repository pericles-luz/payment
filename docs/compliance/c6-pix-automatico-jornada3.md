# PIX Automático C6 — Jornada 3 (QR composto: pagamento imediato + recorrência)

- **Escopo:** registrar qual jornada de ativação do Pix Automático a plataforma
  implementa, e ancorar o contrato do C6 contra o qual o adapter foi escrito.
- **Contrato vendorizado:** [`c6-pix-automatico-oas.yaml`](c6-pix-automatico-oas.yaml)
  — cópia **byte a byte** de `https://developers.c6bank.com.br/yamls/pix-automatico.yaml`
  (OAS 3.0.3, `PIX Automático v1.0.0`), capturada em 2026-08-26. Documento público,
  não é segredo. Não editar à mão: recapturar e substituir.
- **Servidores:** produção `https://baas-api.c6bank.info/v2/pix`,
  sandbox `https://baas-api-sandbox.c6bank.info/v2/pix`.
- **Monitoramento:** o portal já é diffado mensalmente contra
  [`c6-portal-baseline.json`](c6-portal-baseline.json) (SIN-68746). Quando
  `apis/pix-automatico` mudar, recapturar este YAML no mesmo passo.

## Por que a Jornada 3

O C6 expõe quatro jornadas de autorização definidas pelo BACEN. Elas diferem em
**como o pagador autoriza** a recorrência, não no que acontece depois:

| Jornada | Como o pagador autoriza | QR |
|---|---|---|
| 1 | Notificação no app do PSP do pagador (via `solicrec`) | sem QR |
| 2 | QR Code só com os dados da recorrência | QR de recorrência |
| **3** | **QR composto: cobrança imediata + recorrência** | **QR composto** |
| 4 | QR composto: cobrança com vencimento + oferta de recorrência | QR composto |

A Jornada 3 é a de assinatura com liberação imediata (academia, escola, SaaS): o
pagador lê **um** QR que liquida a primeira mensalidade e, no mesmo gesto, autoriza
os débitos futuros. É a única jornada em que o primeiro pagamento e a adesão
acontecem na mesma interação — o que dispensa a loja de orquestrar dois momentos.

Ela torna **obrigatório** o campo `ativacao.dadosJornada.txid` na criação da
recorrência: o `txid` ali é o da cobrança imediata já criada, e é o que amarra os
dois lados do QR composto.

## Sequência de chamadas (contrato C6)

```
POST /v2/pix/cob/{txid}       cobrança imediata          (já implementado — pix.go)
POST /v2/pix/locrec           location do payload rec    → { id, location }
POST /v2/pix/rec              { loc, ativacao.dadosJornada.txid, ... } → { idRec }
GET  /v2/pix/rec/{idRec}?txid={txid}   → dadosQR { jornada: JORNADA_3, pixCopiaECola }
      ── pagador lê o QR composto: paga + autoriza ──
PUT  /v2/pix/webhookrec       (singleton por recebedor, já implementado)
PUT  /v2/pix/cobr/{txid}      CRIAR a cobrança de cada ciclo (txid definido por nós)
GET  /v2/pix/cobr/{txid}      conciliação
PATCH /v2/pix/cobr/{txid}     única revisão admitida: {"status":"CANCELADA"}
```

`POST /locrec` **não tem corpo de requisição** — devolve `{id, location, criacao}`.

## Jornadas 2 e 4

Ficam alcançáveis sem código novo de adapter: são o mesmo
`GET /rec/{idRec}` com o `txid` ausente (→ `JORNADA_2`) ou com o `txid` de uma
cobrança com vencimento (→ `JORNADA_4`). O campo `dadosQR.jornada` da resposta é
quem informa qual foi composta.

## Divergências conhecidas contra o adapter

1. ~~**Content-type das leituras.**~~ **Resolvido por medição em 28/08/2026.** O OAS
   declara `application/json`, e o sandbox confirmou de forma direta
   (`cmd/c6-rec-probe`):

   ```
   Accept: application/json  → 200, Content-Type: application/json
   Accept: application/jose  → 400 "does not match any defined response types"
   ```

   O adapter mandava `application/jose`, então **toda** leitura de recorrência
   falhava — e nenhum valor de `PAYMENT_C6_REC_JWKS_URL` teria consertado, porque a
   requisição era recusada antes de existir assinatura a verificar. As leituras hoje
   são JSON, autenticadas pelo canal (OAuth2 sobre mTLS por tenant). O único JWS do
   contrato está em `GET /rec/{recUrlAccessToken}` — endpoint público noutro host,
   sob `jku` do BACEN, validado pelo PSP do pagador. Registro em
   [`../ops/c6-recurrence-jws-obsoleto.md`](../ops/c6-recurrence-jws-obsoleto.md).
2. ~~**Verbo de revisão da cobrança recorrente.**~~ **Resolvido.** O contrato define
   `PUT /cobr/{txid}` = *criar* (201, corpo completo, txid do cliente),
   `POST /cobr` = *criar* (txid do PSP) e `PATCH /cobr/{txid}` = *revisar*, cujo único
   campo revisável é `status` e cujo único valor admitido é `CANCELADA`
   (schema `CobRStatusRevisada`). O adapter mandava o corpo de criação via `PUT` sob o
   nome `ReviseCobR` — ou seja, era a chamada de criar com outro nome: não alterava
   nada e, contra um txid existente, no melhor caso era no-op. Hoje é
   `CancelCobR` (PATCH + `{"status":"CANCELADA"}`), exposto como
   `DELETE /v1/pix/cobr/{txid}`.

   **Não existe amenda de parcela.** Valor e vencimento de uma cobrança já criada são
   imutáveis no contrato. Mudar de ideia = cancelar a parcela e originar outra, com
   `txid` novo.

3. **Vocabulário de status da cobrança recorrente.** O enum real é
   `CRIADA/ATIVA/CONCLUIDA/EXPIRADA/REJEITADA/CANCELADA` (schema `CobRStatus`). O
   domínio espelhava o de cob/cobv (`CRIADA/ATRASADA/LIQUIDADA/REMOVIDA`), um palpite
   anterior à captura. Alinhado ao contrato: a tradução vira um cast sem perda, e a
   distinção operacional entre "o banco do pagador recusou" (`REJEITADA`) e "nós
   cancelamos" (`CANCELADA`) — que colapsaria em `REMOVIDA` — fica preservada.

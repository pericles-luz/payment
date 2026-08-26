# PIX Automático — Jornada 3 — Camada A (stub mode) — matriz de rastreabilidade

Exposição da superfície de **pagamento recorrente** do PIX Automático, jornada de
autorização **3** (QR Code composto: pagamento imediato + recorrência), contra o
contrato do C6 vendorizado em
[`../compliance/c6-pix-automatico-oas.yaml`](../compliance/c6-pix-automatico-oas.yaml)
(ver [a nota da jornada](../compliance/c6-pix-automatico-jornada3.md)).

Camada A exercita a jornada **em modo stub** (`PAYMENT_C6_BASE_URL` vazio →
in-memory bank) — sem tocar o C6 real. Cada passo mapeia para um teste automatizado
e a evidência observável. Esta matriz alimenta a Camada B (`.docx` para o C6).

## O que já existia e o que esta entrega acrescenta

Domínio, portas, adapter C6, repositórios (sqlite/postgres/inmemory) e o despacho do
webhook de recorrência já existiam (F0–F4, SIN-66030 e derivadas) — **sem nenhuma rota
HTTP**. Esta entrega acrescenta:

1. `locrec` (porta, adapter C6, stub) — inexistente em qualquer camada até aqui.
2. Os campos da Jornada 3 no mandato: `loc`, `ativacao.dadosJornada.txid` e
   `valor.valorRec`, mais a leitura `GET /rec/{idRec}?txid=` que devolve `dadosQR`
   (o QR composto). Sem ela **não havia como obter o QR**, que é o artefato central
   da jornada.
3. **A gravação durável do mandato conciliado no webhook.** Até aqui o webhook
   conciliava com o C6 e descartava o resultado, então o mandato nunca saía de CRIADA
   e o portão recusava *toda* cobrança recorrente. Sem esse elo a jornada não fecha.
4. A superfície HTTP `/v1/pix/{rec,solicrec,cobr,locrec}`, flag-gated.
5. Tarifação de `pix.rec.create` e `pix.cobr.create` (a originação de cobrança
   recorrente não escrevia no ledger).

## Fluxo e evidência

| # | Passo | Rota | Sucesso | Teste |
|---|---|---|---|---|
| 1 | Cobrança imediata (o QR liquida esta) | `POST /v1/pix` | 201 | `TestJornada3EndToEnd` |
| 2 | Location do payload | `POST /v1/pix/locrec` | 201 | `TestJornada3EndToEnd`, `TestCreateLocRecSendsNoBody` |
| 3 | Mandato ligado a `loc_id` + `journey_txid` | `POST /v1/pix/rec` | 201 (status `CRIADA`) | `TestJornada3EndToEnd`, `TestCreateRecSendsJornada3Fields` |
| 4 | QR composto | `GET /v1/pix/rec/{idRec}?qr=true` | 200 (`jornada: JORNADA_3`) | `TestJornada3EndToEnd`, `TestGetRecForQRComposesJornada3` |
| 5 | Pagador lê o QR (fora da API) | — | — | — |
| 6 | Aprovação conciliada | `POST /webhooks/c6/{tenantRef}` | 202 → mandato `APROVADA` | `TestRecWebhookRecordsApproval` |
| 7 | Cobrança de cada ciclo | `POST /v1/pix/cobr` | 201 | `TestJornada3EndToEnd` |
| — | Consulta / retentativa / cancelamento de parcela | `GET`,`DELETE /v1/pix/cobr/{txid}`, `POST .../retentativa/{data}` | 200 | `TestCobRLifecycleRoutes` |
| — | Solicitação de confirmação (Jornada 1) | `POST`,`GET /v1/pix/solicrec` | 201/200 | `TestSolicRecExpiryBoundary`, `TestGetSolicRecRoute` |
| — | Cancelar mandato | `DELETE /v1/pix/rec/{idRec}` | 200 | `TestCancelMandateStopsFurtherCharges` |
| — | Liberar location | `DELETE /v1/pix/locrec/{id}/idrec` | 200 | `TestLocRecReadAndUnlinkRoutes` |

## Invariantes de dinheiro

| Invariante | Evidência |
|---|---|
| Um mandato recém-criado **não é cobrável** (`CRIADA` ⇒ 409) | `TestCreateMandateIsBornUnchargeable`, `TestJornada3EndToEnd` passo 5 |
| Só o webhook conciliado torna o mandato cobrável — o corpo do aviso nunca é confiado | `TestRecWebhookRecordsApproval` |
| Cobrança acima do teto autorizado é recusada **antes** do banco | `TestChargeAboveMandateIsRefused`, `app.TestReviseCobRReappliesTheGates` |
| Não há rota que aceite um valor novo numa parcela já criada | `TestCobRHasNoAmendRoute` |
| Cancelar uma parcela é permitido mesmo com o mandato revogado (cancelar débito é sempre a direção segura) | `app.TestCancelCobRStopsOneInstalmentNotTheMandate` |
| Cancelar parcela é tenant-scoped antes de tocar o banco | `app.TestCancelCobRIsTenantScoped`, `TestCancelCobRCrossTenantIsNotFound` |
| Mandato cancelado não volta a debitar (nem por retentativa) | `TestCancelMandateStopsFurtherCharges`, `TestRetryAfterCancelIsRefused` |
| Originação idempotente por `txid`: sem segundo débito, sem segunda tarifa | `TestJornada3EndToEnd` passo 8 |
| Registro de mandato idempotente: sem segundo mandato, sem segunda tarifa | `app.TestCreateMandateIsIdempotent` |
| Valor cruza como centavos inteiros e vira decimal BACEN no fio (`"99.00"`) | `TestCreateRecSendsJornada3Fields` |
| Evento fora de ordem não anda o mandato para trás | `app.TestRecWebhookOutOfOrderIsAckedAndDropped` |
| Redelivery não infla a trilha de auditoria | `app.TestRecWebhookRedeliveryDoesNotReAudit` |

## Postura de segurança

- **Auth deny-by-default** em todas as rotas (grupo autenticado do router); tenant
  derivado da credencial, nunca do input (threat H1/P1) —
  `TestRecurrenceRequiresAuth`, `TestCreateMandateRejectsUnknownField`.
- **Sem oráculo cross-tenant**: o mandato de outra empresa responde 404 com corpo
  idêntico ao de um mandato inexistente — `TestGetMandateCrossTenantIsNotFound`,
  `TestLocRecReadAndUnlinkRoutes`, `app.TestRecWebhookIsTenantScoped`.
- **Validação no boundary**: `Idempotency-Key` obrigatório nos writes, `decodeJSON`
  rejeita campo desconhecido (anti mass-assignment), CPF/CNPJ validado no core antes
  de qualquer PII cruzar para o banco (`app.TestCreateMandateRejectsBadPayer`), janela
  de `expires_at` do solicrec validada aqui (BACEN CMT-APR-SOLI-016).
- **PII minimizada**: a resposta do mandato **não** ecoa documento nem nome do pagador
  — são a única PII de titular persistida (ADR-0008) e nada na resposta precisa deles
  (`TestMandateResponseDoesNotEchoPayerPII`).
- **Fail-secure na leitura**: sem `PAYMENT_C6_REC_JWKS_URL` a leitura do mandato —
  inclusive a que compõe o QR — recusa em vez de confiar em documento não-verificado
  (`c6.TestGetRecForQRFailsSecureWithoutVerifier`), e a API responde **503**, não 500.
- **Dark-ship**: com `PAYMENT_PIX_RECURRENCE` desligada as rotas não existem
  (`TestRecurrenceRoutesAbsentWhenFlagOff`); com a flag ligada e o serviço não wired,
  degrada em 503 sem panic (`TestRecurrenceServiceUnwiredIs503`).
- **Ordem de rotas**: os segmentos literais de recorrência são registrados antes de
  `/v1/pix/{txid}`, e isso é testado (`TestPixTxidRouteStillReachable`).

## Persistência

Migration `0019_pix_rec_jornada` acrescenta `loc_id BIGINT` e `jornada_txid TEXT` a
`pix_rec` (nuláveis; um mandato da Jornada 1 legitimamente não tem nenhum dos dois).
O round-trip é testado nos dois engines —
`sqlite.TestSQLiteRecJourneyBindingRoundTrips` e
`postgres.TestPostgresRecJourneyBindingRoundTrips`, este último com um id acima de
2³¹ para provar que a coluna é `BIGINT` e não `INTEGER` (`int4` no Postgres).

## Ressalvas conhecidas

1. **Content-type das leituras.** O OAS público do C6 declara `application/json` em
   todas as leituras de recorrência; o adapter exige JWS (`application/jose`), postura
   capturada ao vivo em SIN-66034. Confirmar no sandbox antes do go-live.
2. ~~**Verbo de revisão da cobrança.**~~ **Corrigido nesta entrega.** O adapter mandava
   o corpo de criação via `PUT` sob o nome `ReviseCobR` — que é a chamada de *criar*, não
   revisa nada. O contrato define `PATCH /cobr/{txid}` com corpo
   `{"status":"CANCELADA"}` como a única revisão admitida. Virou `CancelCobR` e
   `DELETE /v1/pix/cobr/{txid}`. Junto veio o vocabulário de status da cobrança, que no
   domínio espelhava cob/cobv (`ATRASADA/LIQUIDADA/REMOVIDA`) em vez do enum real
   (`CRIADA/ATIVA/CONCLUIDA/EXPIRADA/REJEITADA/CANCELADA`) — o que fazia uma liquidação
   conciliada ser descartada em silêncio.
3. **Jornadas 2 e 4** ficam alcançáveis sem código novo de adapter (mesma leitura, com
   `txid` ausente ou de uma cobv), mas não têm cobertura de teste nesta matriz.

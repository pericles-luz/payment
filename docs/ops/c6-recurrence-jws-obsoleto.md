# Runbook — verificador JWS de Recorrência (PIX Automático C6) — **OBSOLETO**

> **Este runbook descrevia um ato de go-live que não existe.** Ele mandava capturar a
> fonte do JWKS do C6 e ligar `PAYMENT_C6_REC_JWKS_URL` para destravar as leituras de
> recorrência. Sondado contra o sandbox do C6 em 28/08/2026 (`cmd/c6-rec-probe`), o
> banco respondeu que **não serve JWS nessas leituras**:
>
> ```
> GET /v2/pix/rec   Accept: application/json  → 200, Content-Type: application/json
> GET /v2/pix/rec   Accept: application/jose  → 400
>   "Request Accept header '[application/jose]' does not match any defined response
>    types. Must be one of: [application/json, application/problem+json]"
> ```
>
> Não havia JWKS a capturar e a variável não tinha valor correto possível. Pior: o
> adapter mandava `Accept: application/jose`, então **toda leitura de recorrência
> falhava com 400** — o "fail-secure" não estava protegendo uma leitura arriscada,
> estava escondendo uma leitura quebrada.
>
> Mantido no repositório como registro de uma decisão revertida. Não execute nada aqui.

## O que era, e onde estava o erro

A premissa vinha de SIN-66034 (F0), registrada como captura ao vivo: "reads são
JWS-assinados (Accept: application/jose)". O contrato público do C6, vendorizado em
[`../compliance/c6-pix-automatico-oas.yaml`](../compliance/c6-pix-automatico-oas.yaml),
diz outra coisa — e explica de onde a confusão provavelmente veio.

O Pix Automático **tem** um JWS, e ele é real. Só que não é nosso:

| | leitura do recebedor (nós) | `GET /rec/{recUrlAccessToken}` |
|---|---|---|
| host | `baas-api.c6bank.info` | `qrcode.c6pix.com` (público) |
| autenticação | OAuth2 + mTLS por tenant | nenhuma — é público |
| corpo | `application/json` | **JWS compacto** |
| chave de verificação | — | `jku` do **BACEN** (`qr-h.sandbox.pix.bcb.gov.br/rest/jwks.json`) |
| quem consome | o recebedor | o **PSP do pagador**, ao ler o QR |

O documento assinado é o payload da recorrência que o app do pagador busca para
mostrar os termos antes do aceite. Quem valida aquela assinatura é a instituição do
pagador. Nós somos o recebedor: nunca pedimos esse endpoint, e não temos o que
verificar.

## O que passou a valer

As leituras `rec`/`solicrec`/`cobr` vão com `Accept: application/json` e são
autenticadas **pelo canal** — OAuth2 `client_credentials` sobre o transporte mTLS por
tenant — exatamente como `cob`, `cobv`, `boleto` e `checkout` sempre foram.

O resíduo é honesto e vale nomear: sem JWS, não há não-repúdio criptográfico do
documento de mandato. A garantia é a do canal. Isso não é uma regressão em relação a
nada que funcionasse — o caminho JWS nunca completou uma leitura sequer — mas é uma
propriedade a menos do que o desenho original imaginava ter, e fica registrada aqui
caso o C6 venha a publicar assinatura nessas leituras.

## Como reconferir

`cmd/c6-rec-probe <tenantID>` faz exatamente a sonda acima: só leitura, não cria
mandato nem cobrança, e imprime apenas metadados (status, Content-Type, forma do
corpo) — o corpo carrega CPF/nome do devedor e não é impresso. É a forma mais rápida
de reabrir a questão se o contrato do C6 mudar.

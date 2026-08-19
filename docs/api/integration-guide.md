# Guia de Integração — API de Pagamentos Sindireceita

> Público: empresas que integram a API de Pagamentos como meio de cobrança
> (PIX, boleto, checkout hospedado, DDA) sobre seus próprios bancos. Primeiro
> banco suportado em produção: **C6**. Primeiro cliente: **Verz**.
>
> Referência técnica completa (contratos de request/response, códigos de erro):
> [`openapi.yaml`](./openapi.yaml) (OpenAPI 3.1). Este guia é a leitura de
> onboarding; a spec é a fonte da verdade máquina-a-máquina.

## 1. Visão geral

A API expõe, sob o prefixo `/v1`, as operações de cobrança e conciliação que
você aciona a partir do seu backend. Você **nunca** custodia fundos nossos nem
do banco: cada empresa integra a **sua própria** credencial bancária (modelo
PSP-Indireto) e o dinheiro liquida direto na conta dela. Nós fornecemos o acesso
à API, a orquestração das cobranças e a conciliação, faturados por uso.

Superfícies disponíveis em `/v1`:

| Superfície | Rotas | Uso |
|---|---|---|
| PIX imediato | `POST/GET /v1/pix`, `GET /v1/pix/{txid}` | Cobrança PIX imediata (cobrança dinâmica) |
| PIX com vencimento (cobv) | `POST /v1/pix/cobv`, `GET/PUT /v1/pix/cobv/{txid}` | Cobrança PIX com data de vencimento |
| Checkout hospedado | `POST/GET/DELETE /v1/checkout/{id}` | Página de pagamento hospedada (venda online) |
| Boleto (BolePix) | `POST/GET/PUT/DELETE /v1/boletos/{id}` | Boleto registrado com multa/juros/desconto |
| DDA / agendamento | `/v1/dda/*` | Consulta e pagamento de boletos no DDA |
| Extrato | `GET /v1/statement` | Extrato da conta por período |
| Cobranças genéricas | `POST/GET /v1/charges/{id}` | Cobrança abstrata (compat) |

Todas as rotas são autenticadas (deny-by-default). A única rota pública é
`GET /healthz` (health check, sem segredos).

## 2. Autenticação

A autenticação é por **token Bearer** no header HTTP:

```
Authorization: Bearer <seu-token-de-API>
```

- O token é **emitido por nós** para a sua empresa-cliente e a identifica de
  forma única. **A empresa-cliente é derivada do token, nunca de um parâmetro
  da requisição.** Nesse modelo (o **modelo a**, default) não existe seletor de
  empresa no corpo, na query ou em header — o isolamento entre empresas é
  garantido pelo escopo do token.
- Um token inválido, ausente ou malformado retorna **`401 Unauthorized`** com
  corpo `{"error":"unauthorized"}`. A resposta é uniforme (não confirma se um
  recurso existe em outra empresa).
- O token é um **segredo**: transmita apenas via TLS, guarde em cofre, nunca o
  registre em logs nem o coloque em URLs. Rotacione sob suspeita de vazamento
  (fale com o suporte para reemissão).

> **Modelo de revenda (2 níveis) — dois caminhos.** Um usuário-API revendedor
> (ex.: **Verz**) possui N empresas-clientes e uma **Conta** que as agrupa
> (bilhetagem consolidada na Conta). Há dois modos de acesso, ambos com o mesmo
> isolamento cross-empresa:
>
> - **Modelo (a) — token por empresa-cliente (default):** cada empresa-cliente
>   recebe o seu próprio token escopado; não há troca de contexto dentro de uma
>   sessão. Uma empresa nunca enxerga dados de outra.
> - **Modelo (b) — 1 chave-de-Conta + seletor por chamada (ADR-0011,
>   flag-gated):** a Conta tem **uma** chave rotacionável e escolhe a
>   empresa-cliente-alvo **a cada chamada** com o header `X-Client-Tenant`. É o
>   caminho adotado pela Verz. Detalhado na **§11**. A chave só opera sobre
>   empresas-clientes da **própria Conta** — o guard nega (com `404`) qualquer
>   seletor de outra Conta.
>
> Ver ADR de tenancy de 2 níveis (ADR-0009) e ADR-0011 (chave-de-Conta).

## 3. Onboarding (checklist)

1. **Contrato & cadastro.** Sua empresa-cliente é cadastrada e recebe um token
   de API escopado.
2. **Credencial bancária.** Você provisiona a **sua** credencial C6 de produção
   (client_id/secret + certificado mTLS) no console administrativo, por banco.
   O dinheiro liquida direto na sua conta C6.
3. **Chave PIX / dados de recebedor.** Configurados por banco no console.
4. **Webhook (opcional, recomendado).** Registramos por você uma URL de callback
   por-empresa (capability-URL) para notificação de liquidação; você não precisa
   fazer polling. Ver §7.
5. **Smoke em produção.** Faça uma cobrança de baixo valor em cada superfície que
   for usar e confirme a conciliação.

## 4. Convenções gerais

- **Base URL:** definida no seu ambiente (produção vs. homologação). Ver
  `servers` na spec.
- **Content-Type:** `application/json; charset=utf-8` em request e response.
- **Valores monetários:** expressos em **centavos** (inteiro) nas rotas `/v1`
  desta API. Ex.: `R$ 10,00` → `1000`. (Internamente convertemos para o formato
  que cada banco exige; você sempre fala em centavos conosco.)
- **Datas:** formato **RFC 3339** (ex.: `2026-08-20T00:00:00-03:00`), salvo
  onde a spec indicar outro formato para uma query de período.
- **Identificadores:** `txid`/`id` de cobrança são gerados pelo servidor na
  criação e retornados na resposta; use-os para consultar/alterar.

## 5. Idempotência

As rotas de **escrita que disparam cobrança/efeito externo** exigem o header:

```
Idempotency-Key: <chave-única-por-operação>
```

Obrigatório em: `POST /v1/pix`, `POST /v1/pix/cobv`, `POST /v1/checkout`,
`POST /v1/boletos`, `PUT /v1/boletos/{id}`, `POST /v1/charges`,
`POST /v1/dda/payment-groups`, `POST /v1/dda/payment-groups/{id}/submit`.
A ausência retorna `400` com `{"error":"missing Idempotency-Key header"}`.

Reenviar a mesma requisição com a **mesma** `Idempotency-Key` colapsa numa única
operação (a retentativa retorna o resultado original, sem dupla cobrança). Use um
valor estável por intenção de negócio (ex.: id do pedido), não um valor aleatório
por tentativa.

## 6. Erros

Toda resposta de erro usa um envelope JSON **simples e uniforme**:

```json
{ "error": "mensagem curta e segura" }
```

O envelope nunca vaza detalhe interno (stack, SQL, segredo). Mapeamento de
status:

| Status | Significado | `error` típico |
|---|---|---|
| `400 Bad Request` | Validação de entrada falhou / header obrigatório ausente | `invalid request`, `missing Idempotency-Key header` |
| `401 Unauthorized` | Token ausente/ inválido | `unauthorized` |
| `404 Not Found` | Recurso inexistente **ou** pertencente a outra empresa | `not found` |
| `409 Conflict` | Conflito de estado (ex.: cancelar algo já cancelado, alterar grupo aprovado) | `conflict` |
| `413 Payload Too Large` | Corpo acima do limite | — |
| `429 Too Many Requests` | Rate limit excedido (ver §7) | — |
| `500 Internal Server Error` | Erro interno (transitório) | `internal error` |

> **Nota sobre RFC 7807.** O padrão `application/problem+json` (RFC 7807) é o
> formato dos erros **do C6 upstream**, que conciliamos internamente. A superfície
> `/v1` desta API expõe o envelope simplificado `{"error":...}` acima. Se o seu
> contrato exigir `application/problem+json` na nossa borda, trata-se de mudança
> de contrato — fale com o suporte (há follow-up técnico registrado). Programe
> seu cliente para tratar o corpo `{"error":...}` e, principalmente, o **código
> HTTP**, que é estável.

### Cross-tenant retorna 404, não 403

Consultar/alterar um recurso que pertence a outra empresa retorna `404 not
found` (não `403`). Isso é intencional: evita confirmar a existência de recursos
fora do seu escopo. Trate `404` como "não existe para você".

## 7. Rate limiting e webhooks

**Rate limit (plano tenant).** Token-bucket por empresa-cliente: **burst de 20**
requisições, reposição de **10 req/s** sustentadas. Exceder retorna
`429 Too Many Requests`; faça backoff exponencial e reenvie (com a mesma
`Idempotency-Key` nas rotas de escrita, para não duplicar).

**Webhooks — são dois, e só um é seu.** Vale separar, porque confundi-los é a
causa mais comum de integração parada:

| | Quem chama quem | Você faz o quê |
|---|---|---|
| **Entrada (banco → nós)** | O banco notifica a **Sindireceita** numa URL secreta por empresa-cliente | **Nada.** Nós registramos essa URL no banco automaticamente quando a credencial e a chave PIX da empresa-cliente ficam completas. Você não vê nem configura essa URL. |
| **Saída (nós → você)** | Nós notificamos **o seu endpoint**, assinado | **Tudo.** É o que você implementa — contrato completo na §12. |

Não faça polling agressivo do `GET` de status: consuma o webhook de saída e
consulte sob demanda.

## 8. Faturamento por uso

Cada chamada **bem-sucedida e faturável** registra uma entrada de consumo
imutável `(empresa-cliente × endpoint)` ao preço vigente daquela rota para você.
O faturamento é **por rota** (o preço pode variar por rota e por empresa). Você
acompanha o consumo e as faturas na área administrativa. Chamadas que falham na
validação de entrada (`4xx` antes do efeito) não são faturadas.

## 9. Fluxo de venda online (exemplo — checkout hospedado)

O caminho mais comum para "vender online via C6":

1. **Abrir sessão de checkout** — `POST /v1/checkout` (com `Idempotency-Key`),
   informando os itens (valores em centavos), expiração (`expires_at` **ou**
   `expires_in_seconds`) e opções de cartão. A resposta traz o `session_id` e o
   `redirect_url` (a URL hospedada) para redirecionar o comprador.
2. **Redirecionar o comprador** para a URL hospedada; ele paga (PIX/cartão
   conforme o banco).
3. **Receber o webhook** de mudança de status na sua capability-URL, ou
   **consultar** `GET /v1/checkout/{id}` para conciliar.
4. **Cancelar** (se necessário, antes do pagamento) — `DELETE /v1/checkout/{id}`
   (idempotente: cancelar de novo retorna o estado cancelado).

Para cobrança direta sem página hospedada, use PIX imediato (`POST /v1/pix`) e
apresente o QR/copia-e-cola retornado, ou boleto (`POST /v1/boletos`).

> Os contratos exatos de cada corpo (campos, tipos, obrigatoriedade, status de
> sucesso) estão em [`openapi.yaml`](./openapi.yaml). Exemplos `curl` prontos por
> rota estão na seção de exemplos da spec.

## 10. Ambientes e versionamento

- **Versão da API:** `v1` (no path). Mudanças incompatíveis abrem um novo
  prefixo; adições retrocompatíveis permanecem em `v1`.
- **Health/provisionamento:** `GET /healthz` retorna `status`, `version`,
  `commit`, `built_at` — útil para o seu smoke de cutover confirmar qual build
  está no ar.
- **Homologação vs. produção:** use a base URL do ambiente correspondente; nunca
  aponte credenciais de produção para homologação.

## 11. Modelo (b): 1 chave-de-Conta + seletor por chamada (revendedor Verz)

> **Disponibilidade.** O modelo (b) é **flag-gated** (`PAYMENT_ACCOUNT_KEY_SELECTOR`),
> habilitado **por Conta** quando o board confirma. Com a flag desligada valem
> apenas os tokens de empresa-cliente do modelo (a). Contrato de referência:
> `openapi.yaml` (esquema `accountKeyAuth`, parâmetro `X-Client-Tenant`, rotas
> `POST /v1/account-key` e `POST /v1/clients`). Base normativa: ADR-0011.

Neste modelo a **Conta** revendedora (ex.: Verz) opera todas as suas
empresas-clientes com **uma única chave-de-Conta**, escolhendo o alvo a cada
chamada. É o padrão "Stripe-Connect" (`Stripe-Account`).

### 11.1 A chave-de-Conta

- Segredo opaco `ak_…` (≥256-bit) que identifica a **Conta**, não uma
  empresa-cliente. É um **segredo** — TLS, cofre, nunca em log/URL.
- A **1ª chave** é emitida pelo board no cadastro da Conta e entregue por canal
  seguro. Depois a Conta **rotaciona sozinha** via `POST /v1/account-key`.
- **Rotação (`POST /v1/account-key`):** emite uma nova chave e **invalida a
  anterior** (create==rotate idempotente). O segredo em claro aparece **uma
  única vez** na resposta (`account_key`) — guarde no ato; não há como relê-lo.
  Requer `Idempotency-Key`.

### 11.2 Provisionar empresas-clientes (`POST /v1/clients`)

- Autenticada **pela chave-de-Conta**. Cria uma empresa-cliente e devolve o
  `tenant_id` — é esse valor que você usa no seletor.
- O vínculo com a Conta é **server-side**: você **não** informa `account_id` no
  corpo; ele vem da chave. Uma Conta nunca cria empresa-cliente sob outra Conta.
- A credencial bancária da nova empresa-cliente vai por `PUT /v1/bank-credential`
  e o certificado mTLS por `PUT /v1/bank-certificate`, ambos self-serve e
  endereçados pelo mesmo seletor (§11.3). Requerem `Idempotency-Key`.
- **Assim que a credencial e a chave PIX daquela empresa-cliente ficam
  completas, registramos os webhooks dela no banco automaticamente** — você não
  registra nada no PSP. O que você implementa é o endpoint de saída (§12).

### 11.3 O seletor `X-Client-Tenant` (a cada chamada de negócio)

Toda chamada `/v1` de negócio (PIX, boleto, checkout, extrato, credencial…)
feita com a chave-de-Conta **deve** trazer:

```
Authorization: Bearer ak_...           # chave-de-Conta
X-Client-Tenant: <tenant_id da empresa-cliente-alvo>
```

O choke-point autentica a chave, valida que a empresa-cliente-alvo **pertence à
Conta da chave** e só então executa a operação no escopo dela. Os handlers são
os mesmos do modelo (a) — muda só quem seleciona o escopo.

### 11.4 Códigos de erro específicos do seletor

| Situação | Status | `error` |
|---|---|---|
| Chave-de-Conta **sem** `X-Client-Tenant` | `400` | `client selector required` |
| `X-Client-Tenant` enviado com **token de empresa-cliente** (modelo a) | `400` | `client selector not permitted for tenant token` |
| Chave-de-Conta inválida/ausente | `401` | `unauthorized` |
| `X-Client-Tenant` aponta empresa-cliente de **outra Conta** ou **inexistente** | `404` | `not found` |

> **Sem oráculo (segurança).** "Empresa de outra Conta" e "empresa inexistente"
> retornam a **mesma `404`** — uma chave-de-Conta válida **não** consegue
> enumerar empresas-clientes de outras Contas. Nunca é `403` (um `403`
> confirmaria a existência). O guard é **fail-closed**: qualquer falha de leitura
> ou seletor inválido **nega**.

### 11.5 Blast radius e boa prática

Uma chave-de-Conta dá acesso a **todas** as empresas-clientes **daquela Conta**
(nunca além). Trate-a como credencial de alto valor: rotacione periodicamente e
sob qualquer suspeita de vazamento (a rotação invalida a anterior de imediato).
A bilhetagem de todas as chamadas é consolidada **na Conta**.

Runbook operacional (bootstrap da 1ª chave, rotação, provisionamento e uso do
seletor): `docs/ops/runbook-verz-account-key-selector.md`.

## 12. Webhook de saída — o endpoint que **você** implementa

Quando uma cobrança de uma das suas empresas-clientes liquida, nós entregamos
uma notificação assinada no endpoint HTTPS que você cadastrar **por Conta** (um
endpoint só, para todas as suas empresas-clientes). É a peça que você precisa
escrever para integrar.

O cadastro (URL + segredo de assinatura) é feito na área administrativa. O
segredo é exibido **uma única vez** na criação/rotação — guarde no ato.

### 12.1 O que chega

`POST <seu endpoint>` com `Content-Type: application/json` e três cabeçalhos:

| Cabeçalho | Conteúdo |
|---|---|
| `X-Webhook-Signature` | `sha256=<hex>` — HMAC-SHA256 sobre `"<timestamp>.<corpo>"` |
| `X-Webhook-Timestamp` | unix-seconds do envio, **incluído na assinatura** |
| `X-Webhook-Idempotency-Key` | o `event_key` do evento — estável entre reentregas |

Corpo:

```json
{
  "event_key": "E1234...|pix|CONCLUIDA",
  "event_type": "payment.paid",
  "tx_id": "E1234...",
  "account_id": "<sua Conta>",
  "timestamp": 1755561600
}
```

> **O corpo não traz dado de pagador, valor nem PII — de propósito.** Ele
> carrega o mínimo para você saber *o que* mudou. Precisando do detalhe da
> cobrança, chame nossa API de volta com sua chave-de-Conta e o
> `X-Client-Tenant` da empresa-cliente. Isso mantém PII fora de um canal que
> atravessa a internet até um endpoint que não controlamos.

### 12.2 Como validar (obrigatório)

Na ordem, e **antes** de processar:

1. **Frescor:** rejeite se `|agora − X-Webhook-Timestamp| > 300s`. Como o
   timestamp entra na assinatura, isso derruba replay de um corpo capturado.
2. **Assinatura:** recalcule `HMAC-SHA256(segredo, timestamp + "." + corpo_bruto)`
   e compare em **tempo constante** com o valor após `sha256=`.
3. **Idempotência:** deduplique por `X-Webhook-Idempotency-Key`. A mesma
   notificação pode chegar mais de uma vez (retry nosso ou reentrega do banco);
   processar duas vezes é erro seu, não nosso.

Assine sobre o **corpo bruto recebido**, byte a byte — não sobre um JSON
reserializado. Reserializar reordena campos e quebra o MAC.

```python
# referência — Python
import hmac, hashlib, time

def verificar(corpo_bruto: bytes, assinatura: str, ts: str, segredo: str) -> bool:
    if abs(time.time() - int(ts)) > 300:
        return False
    esperado = "sha256=" + hmac.new(
        segredo.encode(), ts.encode() + b"." + corpo_bruto, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(esperado, assinatura)
```

### 12.3 O que responder, e o que acontece se você cair

Responda **2xx** assim que aceitar o evento. Qualquer outra coisa (ou timeout)
conta como falha.

- Fazemos até **3 tentativas** por evento, com backoff exponencial curto
  (250 ms até 5 s). É deliberadamente pequeno: um receptor degradado não é
  martelado.
- Cada tentativa **re-assina com um timestamp novo** — então não guarde a
  assinatura da tentativa anterior esperando que se repita.
- Esgotadas as tentativas, o evento vai para nosso **dead-letter** e não é
  reentregue automaticamente. Ele fica registrado do nosso lado para
  reprocessamento manual — mas o caminho barato é seu endpoint responder 2xx
  rápido e processar de forma assíncrona.

Processe fora do ciclo da requisição: responda 2xx, enfileire, trabalhe depois.

### 12.4 Requisitos do endpoint

- **HTTPS obrigatório** — `http://` é recusado no cadastro.
- Precisa ser alcançável pela internet pública. Endereços privados, loopback e
  metadados de nuvem são bloqueados no momento da entrega (proteção anti-SSRF).
- Um endpoint por Conta. Use `account_id` do corpo se você operar mais de uma.

## 13. Suporte

Dúvidas de integração, reemissão de token, provisionamento de credencial/cert e
registro de webhook: canal de suporte técnico Sindireceita (a definir no contrato
de cada cliente).

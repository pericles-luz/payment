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

**Webhooks (conciliação).** A liquidação é notificada de forma assíncrona pelo
banco e conciliada por nós; você recebe a atualização de status na sua
capability-URL registrada. O webhook do C6 não é assinado — a autenticidade vem
do segredo não-adivinhável embutido na própria URL de callback (uma por
empresa). Não faça polling agressivo do `GET` de status; use o webhook e
consulte sob demanda. A borda de ingress mascara o path do webhook nos logs (o
path carrega o segredo).

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
  self-serve, endereçada pelo mesmo seletor (§11.3). Requer `Idempotency-Key`.

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

## 12. Suporte

Dúvidas de integração, reemissão de token, provisionamento de credencial/cert e
registro de webhook: canal de suporte técnico Sindireceita (a definir no contrato
de cada cliente).

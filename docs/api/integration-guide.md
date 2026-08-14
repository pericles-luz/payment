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
  da requisição.** Não existe seletor de empresa no corpo, na query ou em
  header — o isolamento entre empresas é garantido pelo escopo do token.
- Um token inválido, ausente ou malformado retorna **`401 Unauthorized`** com
  corpo `{"error":"unauthorized"}`. A resposta é uniforme (não confirma se um
  recurso existe em outra empresa).
- O token é um **segredo**: transmita apenas via TLS, guarde em cofre, nunca o
  registre em logs nem o coloque em URLs. Rotacione sob suspeita de vazamento
  (fale com o suporte para reemissão).

> **Modelo de revenda (2 níveis).** Um usuário-API revendedor (ex.: Verz) possui
> N empresas-clientes. Cada empresa-cliente recebe o seu próprio token escopado;
> não há troca de contexto dentro de uma sessão. Uma empresa nunca enxerga dados
> (cobranças, extrato, credenciais) de outra. Ver ADR de tenancy de 2 níveis.

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

## 11. Suporte

Dúvidas de integração, reemissão de token, provisionamento de credencial/cert e
registro de webhook: canal de suporte técnico Sindireceita (a definir no contrato
de cada cliente).

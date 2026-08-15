# Runbook — Verz = 1 chave-de-Conta + seletor por chamada (modelo b)

> **Escopo.** Operar o modelo (b) do ADR-0011 para a Conta revendedora **Verz**:
> bootstrap da 1ª chave-de-Conta, rotação, provisionamento de empresas-clientes
> e uso do seletor `X-Client-Tenant`. Doc operacional — pareia com o contrato em
> [`../api/openapi.yaml`](../api/openapi.yaml) e o guia de integração
> [`../api/integration-guide.md`](../api/integration-guide.md) §11.
>
> **Base normativa:** [`../security/adr-0011-account-key-client-selector.md`](../security/adr-0011-account-key-client-selector.md).
> **Fases de build:** B1 (domínio/store, SIN-69278) · B2 (auth+guard, SIN-69279)
> · B3 (emissão/rotação, SIN-69280) · B4 (provisionamento, SIN-69281) ·
> B5 (este doc, SIN-69282).

## 0. Pré-condições

- **Flag ligada para a Conta:** `PAYMENT_ACCOUNT_KEY_SELECTOR` truthy no ambiente
  onde a Verz opera. **Default é off** — com a flag desligada o caminho
  chave-de-Conta não existe (só valem tokens de empresa-cliente do modelo a) e
  todos os passos abaixo são inertes.
- **Conta Verz cadastrada** (nível Account, acima do tenant — ADR-0009).
- Acesso ao **admin-plane / console** para o bootstrap da 1ª chave (passo 1).

Verificação rápida da flag (no host do serviço):

```
echo "$PAYMENT_ACCOUNT_KEY_SELECTOR"     # precisa ser truthy (1/true) para a Verz
```

## 1. Bootstrap da 1ª chave-de-Conta (admin-plane, uma vez)

A **1ª** chave não pode ser emitida pela própria chave (ainda não existe). Ela é
emitida no cadastro da Conta pelo admin-plane, com a **mesma disciplina** do
`PAYMENT_CONSOLE_BOOTSTRAP_TOKEN` (SIN-69261):

1. No admin/console, emitir a chave-de-Conta inicial da Verz.
2. O segredo em claro (`ak_…`) é exibido **uma única vez**. Copie no ato.
3. **Entregue por canal seguro** (cofre de senhas / mensagem cifrada) — **nunca**
   em comentário de issue, e-mail em claro, log ou URL.
4. Registre apenas o **fato** da emissão (data, operador, `account_id`) — nunca o
   segredo — para trilha de auditoria.

> A partir daqui a Verz **rotaciona sozinha** via `POST /v1/account-key` (passo 2);
> o admin-plane não precisa ser reusado, salvo perda total da chave.

## 2. Rotação da chave-de-Conta (self-serve)

`POST /v1/account-key` autenticada pela **chave atual**. Emite uma nova e
**invalida a anterior de imediato** (create==rotate idempotente). O segredo novo
aparece **uma vez** no corpo (`account_key`).

```
curl -sS -X POST https://<base>/v1/account-key \
  -H "Authorization: Bearer $AK_ATUAL" \
  -H "Idempotency-Key: rotate-2026-08-14-001" \
  -H "Content-Type: application/json"
# 201 → { "account_key": "ak_novo…", "account_id": "...", "rotated": true }
```

Operação:

- **Guarde o segredo novo no ato** e atualize o cofre/segredo dos integradores da
  Verz **antes** de descartar o antigo (a chave antiga para de funcionar assim que
  a rotação conclui).
- `Idempotency-Key` obrigatório: um retry com a mesma chave **não** gera um
  segredo diferente (devolve a operação original).
- **Quando rotacionar:** periodicamente e **imediatamente** sob suspeita de
  vazamento. Como a chave dá acesso a **todas** as empresas-clientes da Conta, o
  blast radius justifica rotação agressiva.
- Rate limit inbound: em `429`, respeite `Retry-After` e faça backoff.

### Recuperação (chave perdida sem chave válida para rotacionar)

Se a Verz perdeu a chave e não tem uma válida para chamar `POST /v1/account-key`,
volte ao **passo 1** (re-bootstrap admin-plane) para emitir uma nova 1ª chave.

## 3. Provisionar uma empresa-cliente (self-serve)

`POST /v1/clients` autenticada pela **chave-de-Conta**. Cria a empresa-cliente já
vinculada à Conta e devolve o `tenant_id` para o seletor.

```
curl -sS -X POST https://<base>/v1/clients \
  -H "Authorization: Bearer $AK_ATUAL" \
  -H "Idempotency-Key: create-cliente-loja-x-001" \
  -H "Content-Type: application/json" \
  -d '{"name":"Loja X"}'
# 201 → { "tenant_id": "...", "account_id": "<conta-verz>", "name": "Loja X" }
```

- **NUNCA** envie `account_id` no corpo — a Conta vem da chave (server-side,
  imutável). O corpo aceita, no máximo, um `name` opcional.
- `Idempotency-Key` obrigatório (dedup em retry — não cria empresa-cliente
  duplicada).
- **Credencial bancária** da nova empresa-cliente: em seguida, via
  `PUT /v1/bank-credential` self-serve (SIN-69196), endereçada pelo seletor do
  passo 4. O dinheiro liquida direto na conta da empresa-cliente (PSP-Indireto).

## 4. Usar o seletor em cada chamada de negócio

Toda chamada `/v1` de negócio feita com a chave-de-Conta leva o header
`X-Client-Tenant` com o `tenant_id` da empresa-cliente-alvo:

```
curl -sS -X POST https://<base>/v1/pix \
  -H "Authorization: Bearer $AK_ATUAL" \
  -H "X-Client-Tenant: <tenant_id da empresa-cliente>" \
  -H "Idempotency-Key: pedido-42" \
  -H "Content-Type: application/json" \
  -d '{"amount_cents":1000,"currency":"BRL","expires_in_seconds":3600}'
```

O choke-point valida que a empresa-cliente **pertence à Conta da chave** e só
então executa. A bilhetagem é consolidada **na Conta da Verz**.

## 5. Matriz de erros (troubleshooting)

| Sintoma | Status | Causa | Ação |
|---|---|---|---|
| `client selector required` | `400` | Chamada com chave-de-Conta **sem** `X-Client-Tenant` | Adicione o header com o `tenant_id` alvo. |
| `client selector not permitted for tenant token` | `400` | `X-Client-Tenant` enviado com **token de empresa-cliente** (modelo a) | Remova o header, ou use a chave-de-Conta. |
| `unauthorized` | `401` | Chave inválida/ausente/rotacionada | Confirme que está usando a chave **atual**; se rotacionou, atualize o segredo. |
| `not found` | `404` | Empresa-cliente de **outra Conta** ou **inexistente** | Confirme o `tenant_id` (só empresas-clientes da própria Conta). **Mesma 404** para os dois casos — sem oráculo. |
| `429` | `429` | Rate limit inbound | Respeite `Retry-After`, backoff exponencial. |

> **Segurança — sem oráculo.** "Empresa de outra Conta" e "empresa inexistente"
> retornam a **mesma `404`** de propósito: uma chave válida não consegue enumerar
> empresas-clientes de outras Contas (A01/IDOR). O guard é **fail-closed** — na
> dúvida, nega. Nunca é `403`.

## 6. Rollback / desligar o modelo (b)

Reversão é **flag + fiação**, sem migração destrutiva (ADR-0011 §Reversibilidade):

1. Desligue `PAYMENT_ACCOUNT_KEY_SELECTOR` (unset ou falsy) e faça o deploy.
2. O choke-point passa a **ignorar** o seletor e a aceitar apenas tokens de
   empresa-cliente (modelo a). As chaves-de-Conta emitidas ficam **inertes**
   (não são apagadas; a coluna/tabela permanecem — migração `0011`).
3. Empresas-clientes já provisionadas continuam válidas (são tenants normais);
   para operá-las com a flag off, use tokens de empresa-cliente do modelo (a).

Nenhum segredo é logado em nenhum passo; a rotação (passo 2) invalida a chave
anterior, então um vazamento é contido rotacionando.

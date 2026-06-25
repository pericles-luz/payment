# ADR-0004 — Chave (recebedor) da cob/cobv vem de config por-tenant, injetada pelo adapter (opção (a))

- **Status:** Proposto — aguardando ratificação do CTO ([SIN-65862](/SIN/issues/SIN-65862)).
- **Decisão de design pai:** [SIN-65861](/SIN/issues/SIN-65861). Implementação: [SIN-65862](/SIN/issues/SIN-65862).
- **Autor:** Coder. **Decisor:** CTO.
- **Contexto de contrato:** depende do remap do contrato real C6 ([SIN-65856](/SIN/issues/SIN-65856), PR #40) que provou o HTTP da cob (`PUT /v2/pix/cob/{txid}` com `chave`).

## Contexto

A cob/cobv real do C6 (BACEN PIX v2) exige o campo **`chave`** — a chave PIX do
**recebedor** (a conta do tenant que recebe os fundos) — para rotear os fundos e
emitir o QR. O port já expõe `ports.ChargeRequest.CreditorKey` e
`ports.PixDueChargeRequest.CreditorKey`, e o adapter já os encaminha como a
`chave` BACEN.

A lacuna real: **nenhum input do app populava esse campo**. Nenhuma superfície do
cliente (DTO HTTP / form HTMX) carrega a chave, então o caminho positivo da cob
**pelo app** ainda devolvia 400 (`chave` ausente) em homologação, mesmo com o
contrato HTTP provado por SIN-65856.

A pergunta de design (SIN-65861): **de onde vem a `chave`?**

- **(a)** Config **por-tenant**, injetada pelo adapter — o boundary do cliente
  **não** carrega a chave.
- **(b)** Input **por-request** — uma superfície do app popula a chave.

## Decisão

Adotamos **(a)**. A `chave` do recebedor é modelada no agregado de identidade
bancária do tenant (`ports.BankCredential.CreditorKey`, junto de `ClientID`),
carregada de config por-tenant e **injetada pelo adapter** ao montar o corpo da
cob/cobv. Nenhuma superfície do app popula a chave; o boundary do cliente fica
inalterado.

### Resolução no adapter (atrás do port)

`Provider.resolveCreditorKey(ctx, tenantID, reqKey)` (`internal/adapters/bank/c6`):

1. Se `reqKey` (após trim) **não** for vazio → usa-o (override por-request,
   **apenas** no nível do port; ver abaixo).
2. Senão → resolve `BankCredential.CreditorKey` pelo **mesmo store per-tenant**
   já usado para o OAuth2 (`creds.GetBankCredential(ctx, tenantID)`), de modo que
   uma cobrança **nunca** roteia fundos sob a identidade de outro tenant
   (ameaça H1/P1). Falha do store (ex.: tenant desconhecido) é propagada verbatim
   (mesmo erro tipado de sempre).
3. Se ambos vazios → a `chave` resolvida é `""` e o campo de wire (`omitempty`) é
   **omitido** (comportamento atual preservado).

Aplicado em `CreateCharge`, `CreateImmediateCharge`, `CreateDueCharge` e
`UpdateDueCharge`.

### Override por-request fica só no port

O campo `CreditorKey` permanece **opcional** no port; um valor não-vazio sobrepõe a
config (gancho futuro multi-chave). **Nenhuma superfície do app** o popula hoje.

### Formato de config — variável dedicada `PAYMENT_BANK_CREDITOR_KEYS`

SIN-65861 sugeriu anexar a chave **antes** do secret na tupla
`PAYMENT_BANK_CREDS` (`tenant:clientID:creditorKey:secret`, secret = cauda
greedy). **Rejeitamos** esse formato e escolhemos uma **variável de ambiente
paralela**:

```
PAYMENT_BANK_CREDITOR_KEYS="tenant:creditorKey,tenant2:creditorKey2"
```

`mergeCreditorKeys` faz `SplitN(item, ":", 2)` (uma chave PIX — e-mail, telefone,
CPF/CNPJ ou EVP UUID — nunca contém `:`) e funde cada chave no
`BankCredential` do tenant correspondente.

**Razão decisiva:** `parseBankCreds` trata o secret como **cauda greedy
`:`-tolerante** (`SplitN(item, ":", 3)`) para permitir secret com `:` no corpo.
Um teste existente, protegido (regra-3 da CTO), pina exatamente esse
comportamento — `tenantA:cidA:p4ss:w0rd:with:colons` ⇒ `Secret =
"p4ss:w0rd:with:colons"` (`bankcreds_internal_test.go`). Mover para a tupla de 4
campos reinterpretaria esse secret com `:` (passaria a `creditorKey="p4ss"`,
`secret="w0rd:with:colons"`), **quebrando** um teste que não posso modificar sem
autorização escrita da CTO. A variável paralela contorna a ambiguidade, preserva
o contrato de parsing do secret (e seus testes) e é aditiva/reversível (a var
ausente ⇒ nenhuma chave injetada; comportamento atual).

Entradas malformadas (sem `:`, tenant/chave vazios, ou chave para um tenant **sem**
credencial bancária) continuam **logando warn e sendo descartadas**. O valor da
chave **nunca** é logado — apenas o `tenant_id` não-sensível e a posição da entrada.

### Não-segredo, porém sensível a roteamento

A `chave` **não é segredo** (é o identificador PIX público da conta), mas **é
sensível a roteamento de fundos**. Por isso é **redigida** em `BankCredential.String()`
e `LogValue()` (`creditor_key=[REDACTED]`), e nunca aparece em logs de info nem em
paths de erro que possam vazar dados da conta (ameaça C1/C4).

## Consequências

- **Caminho positivo cob/cobv pelo app** deixa de 400 por `chave` ausente em
  homologação quando o tenant tem chave configurada (AC primário — atendido).
- **Boundary do cliente inalterado:** Cliente/DTO/HTMX não recebem campo `chave`.
- **Override por-request preservado** apenas no nível do port (sem breaking
  change; blast radius pequeno).
- **Boring technology:** estende o mecanismo `PAYMENT_BANK_CREDS` existente; sem
  infra nova.
- **Reversibilidade:** `PAYMENT_BANK_CREDITOR_KEYS` ausente ⇒ comportamento atual.
  Rollback = remover a variável.

## Pendência aberta — fail-fast quando ambos vazios (gated em regra-3)

SIN-65862 pede um **erro tipado no boundary do adapter (fail-fast)** quando a
`chave` está ausente num path real, em vez de deixar o C6 devolver 400.

Esse fail-fast **conflita com testes existentes protegidos**: ~15 testes do
adapter C6 (`oneTenant(...)` é usado 105×) criam cobranças **sem** `CreditorKey`
e esperam **sucesso** (ex.: `TestCreateChargeSuccess`,
`TestCreateChargeForwardsIdempotencyKey`). Um fail-fast incondicional os tornaria
`ErrValidation` — uma modificação de teste que exige **autorização escrita da
CTO** (regra-3 do quality bar).

**Estado entregue:** injeção por config (AC primário) + override por-request +
redação + ADR, com o ramo "ambos vazios" preservando o comportamento atual
(omitir). `TestCreateChargeBothEmptyOmitsChave` pina esse comportamento para que
a virada para fail-fast seja uma mudança deliberada.

**Próximo passo:** ao obter autorização da CTO, atualizar os testes que omitem a
chave (passar `CreditorKey`/cred com chave) e trocar o ramo "ambos vazios" por um
`*c6.Error{sentinel: shared.ErrValidation}`. O modo stub (`PAYMENT_C6_BASE_URL`
vazio ⇒ adapter de banco em memória, outro tipo) permanece tolerante por
construção.

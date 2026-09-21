# Roteiro de Testes — C6 Developers v3.0 (Camada B, captura ao vivo)

**Data da corrida:** 21/09/2026 · **Ambiente:** sandbox
(`baas-api-sandbox.c6bank.info`) · **Conta:** `REGRESSIVOTESTE57798242000190`
**Certificado:** `20260921.crt` (válido 21/09/2026 → 21/09/2027) ·
**client_id:** `cc07c5db-…` · **chave PIX:** `b95ddc05-…` (EVP)

Documento preenchido: `/mnt/x/parceiros/LMHost/c6bank/20260921_testes.docx`
Evidências brutas: `/mnt/x/parceiros/LMHost/c6bank/20260921_evidencias.json`

## O que isto é, e o que não é

Camada **B**: chamadas REAIS ao C6, com o status e o corpo que ele devolveu, um por
caso. Diferente das quatro matrizes de Camada A deste diretório, que exercitam o
domínio em modo stub e não tocam o banco.

Produzido por `cmd/c6-roteiro` e gravado no .docx por `scripts/preencher-roteiro.py`:

```sh
c6-roteiro --cert 20260921.crt --key 20260921.key \
  --client-id cc07c5db-… --pix-key b95ddc05-… \
  --webhook-url https://payment.lmhost.com.br/webhooks/c6/<ref> \
  --out 20260921_evidencias.json

python3 scripts/preencher-roteiro.py \
  --modelo "Roteiro de Testes - C6 Developers v3.0.docx" \
  --evidencias 20260921_evidencias.json \
  --saida 20260921_testes.docx
python3 scripts/preencher-roteiro.py --verificar 20260921_testes.docx
```

**Toda captura é de sandbox e está rotulada como não-produtiva** no documento, como a
cláusula 2.4-iii do Termo de APIs exige. O rótulo é posto pelo script, não pela
disciplina de quem preenche.

## Escopos concedidos

Os 34 escopos do token cobrem os nove blocos do roteiro — inclusive
`schedulepayments.*`. Faltam `checkout.capture` e `recpayload.write`, nenhum exigido
pelos casos listados. Lista completa na §9.0 do `docs/ops/c6-smoke-e2e-runbook.md`.

## O que ficou sem 2xx, e por quê

Nenhum dos itens abaixo é defeito do nosso lado. Todos têm a resposta do banco gravada
na evidência.

### Depende de habilitação na conta

| Casos | Retorno | Leitura |
|---|---|---|
| `C_01`–`C_03` | **401** | O produto **Checkout não está habilitado** nesta conta. O token traz `checkout.write`; o gateway valida o corpo primeiro e a habilitação depois, então todo corpo VÁLIDO dá 401 e todo corpo inválido dá 400 (medição em `internal/adapters/bank/c6/checkout.go`). Escopo concedido ≠ produto contratado. **Pedido ao gerente.** |

### Depende de o C6 consertar o sandbox

| Casos | Retorno | Leitura |
|---|---|---|
| `P_03_01`–`P_03_04` | **502** | `origin_bad_gateway` do Cloudflare em TODAS as operações de `/v2/pix/lotecobv`, persistente, com `"retryable": true`. Nenhum `Accept` muda. A origem do banco erra. |
| `BP_06` | **404** | `GET /v2/bank_slips/list` não existe no sandbox. Com parâmetros, ele antes reclama que os quatro que o contrato Bolepix 1.1.1 declara são "unexpected". O contrato publicado está à frente do ambiente. |
| `B_04`, `B_08`, `BP_02`, `BP_05` | **400 / 422** | "Evento não pode ser realizado, pois já existe uma requisição à CIP sujeita a aprovação." **Não é pressa:** um boleto emitido quarenta minutos antes continuava recusando. No sandbox a requisição à CIP não se resolve, então alterar e baixar uma cobrança emitida não são exercitáveis. |

### Não é resposta a uma requisição nossa

| Casos | Leitura |
|---|---|
| `C_0501`, `C_0502` | Pedem o RECEBIMENTO de um evento no nosso webhook. Nenhuma chamada de saída produz isso: a evidência é a entrega que o banco faz, e ela aparece no log do receptor. `C_0502` ainda exige PAGAR o link com cartão, e não há cartão de teste documentado para o sandbox. |
| `B_07`, `C_04` | Registro de webhook **por serviço**. Pulados por segurança: diferente do webhook PIX — que é chaveado pela chave, e que o próprio roteiro apaga em `P_06_03` —, estes valem para a CONTA de sandbox inteira, substituem o destino de quem já a usa e **não têm DELETE**. Rodar com `--webhook-servico`, em janela combinada. |

## O que a corrida ensinou, e que virou código

Cada um destes derrubava casos, e nenhum estava escrito em lugar nenhum antes:

1. **A credencial vai no corpo do `/v1/auth/`**, não em Basic — e o endpoint responde
   500 em cerca de metade das chamadas, de qualquer jeito. `token.go` repete em 5xx.
2. **Ler UMA recorrência com `Accept: application/json` dá 400.** Ela exige dois tipos
   que então recusa com 406, e atende `*/*` devolvendo JSON. `recurrenceRead` usa `*/*`.
3. **`POST /rec` não aceita `idRec` nem `retentativa`** e exige `politicaRetentativa` no
   topo. Quem escolhe o `idRec` é o PSP, e ele volta embrulhado em `{"data":{…}}` — só o
   PIX Automático embrulha.
4. **Valor entre R$ 5,00 e R$ 10,00.** Boleto, BolePix e checkout recusam abaixo de 5; a
   autoconfirmação de PIX do sandbox só dispara até 10.
5. **O agendamento decodifica em segundo plano.** Ler cedo dá 422 "ainda no processo de
   decodificação" — é pressa, não erro, e cede relendo.
6. **`/v1/schedule_payments/` existe e funciona.** O 404 que a ADR-0013 atribuía à falta
   do produto era caminho errado nosso.

## Pendências para a próxima janela

- Pedir ao gerente: habilitar **Checkout**, e um **cartão de teste** para `C_0502`.
- Pedir ao C6: o **502 do `lotecobv`** e a **CIP que não libera** alteração/baixa.
- Combinar uma janela para rodar com `--webhook-servico` e colher `B_07`, `C_04` e as
  entregas de `C_0501`.
- **Liquidação** continua sem nunca ter sido observada nesta conta (ADR-0013) — exceto
  o PIX, que o sandbox autoconfirma e que rendeu `P_05_01`, `P_05_03` e `P_05_04`.

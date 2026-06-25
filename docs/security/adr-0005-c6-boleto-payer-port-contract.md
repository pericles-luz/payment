# ADR-0005 — `ports.BoletoRequest` carrega o pagador completo (`Payer{Name, TaxID, Address{...}}`) para o contrato real C6 `POST /v1/bank_slips`

- **Status:** Aceito — decisão de arquitetura do CTO.
- **Decisão de design pai:** [SIN-65860](/SIN/issues/SIN-65860). Split de implementação: [SIN-65882](/SIN/issues/SIN-65882).
- **Autor e decisor:** CTO.
- **Contexto de contrato:** segue o padrão de remap do contrato real C6 já provado para PIX cob ([SIN-65856](/SIN/issues/SIN-65856), PR #40) e creditor key ([SIN-65862](/SIN/issues/SIN-65862), [ADR-0004](adr-0004-c6-creditor-key-per-tenant.md)). O boleto ainda postava num DTO inventado (`/boletos`, `payer_tax_id` plano), não no contrato real.

## Contexto

O contrato real do C6 para registrar boleto é **`POST /v1/bank_slips`** e exige um
objeto **`payer`** completo:

```jsonc
{
  "amount": 1234,                       // valor
  "due_date": "2026-07-01",             // yyyy-MM-dd (NÃO RFC3339)
  "external_reference_id": "abc123",    // ^[a-zA-Z0-9]{1,10}$
  "payer": {
    "name": "Fulano de Tal",
    "tax_id": "12345678901",
    "address": {
      "street":   "Rua das Flores",
      "number":   123,                  // inteiro
      "city":     "Brasília",
      "state":    "DF",
      "zip_code": "70000000"
    }
  }
}
```

O port atual **não carrega** essa informação. `ports.BoletoRequest` só tem
`PayerTaxID string` (linha ~556 de `internal/ports/ports.go`) — falta **nome do
pagador** e o **endereço inteiro**. O adapter C6 (`internal/adapters/bank/c6/boleto.go`)
serializa um DTO inventado (`amount_cents`, `boleto_id`, `payer_tax_id`) para um
endpoint inventado (`/boletos`).

Como nome e endereço do pagador são **obrigatórios** no contrato C6, eles **têm que
fluir do boundary** (não há como derivá-los no adapter). Isso é uma **mudança de
contrato de port**, que por regra é decisão de arquitetura do CTO antes da
implementação — daí este ADR.

A pergunta de design (SIN-65860): **qual a forma do port?**

- **(a)** Estender `BoletoRequest` com um agregado de pagador estruturado
  (`Payer{Name, TaxID, Address{...}}`), tipos Go puros, sem vazar HTTP/JSON.
- **(b)** Achatar os campos no `BoletoRequest` (`PayerName`, `PayerStreet`,
  `PayerNumber`, …) — sem sub-struct.
- **(c)** Deixar o adapter buscar nome/endereço de um store por-tenant (como a
  creditor key da ADR-0004).

## Decisão

Adotamos **(a)**: estender `ports.BoletoRequest` com um sub-agregado de pagador
estruturado, em **tipos Go puros**, mantendo Hexagonal.

### Forma do port (decisão normativa)

```go
// BoletoPayer identifica o sacado/pagador do boleto. É o espelho de domínio do
// objeto `payer` exigido pelo C6 em POST /v1/bank_slips; tipos Go puros, sem tags
// de transporte (a serialização vive no adapter).
type BoletoPayer struct {
    Name    string
    TaxID   string        // CPF/CNPJ só dígitos
    Address BoletoAddress
}

// BoletoAddress é o endereço do pagador. Number é inteiro porque o contrato C6 o
// exige como inteiro (ver "Riscos conhecidos" sobre "S/N").
type BoletoAddress struct {
    Street  string
    Number  int
    City    string
    State   string // UF 2 letras
    ZipCode string // CEP só dígitos
}
```

E em `BoletoRequest`, **substituir** o campo plano:

```go
// antes
PayerTaxID string
// depois
Payer BoletoPayer
```

**Substituir, não coexistir.** `PayerTaxID` é greenfield (o adapter C6 boleto
ainda não passou homologação — nenhum 201 real capturado), então não há contrato de
produção a preservar. Manter os dois campos seria dívida imediata e ambiguidade de
"qual tax_id vence". O `TaxID` passa a viver dentro de `Payer`.

### Por que (a) e não (b)/(c)

- **(b) achatado — rejeitado.** Seis campos `Payer*` soltos em `BoletoRequest`
  poluem a assinatura, não têm coesão (DDD-lite: o pagador é um value object) e
  espalham a mesma decisão por `RegisterBoletoInput`/DTO HTTP sem agrupar. O
  sub-struct é o mesmo padrão já usado por `BoletoDiscountTier`.
- **(c) store por-tenant — rejeitado.** A creditor key (ADR-0004) é config
  **do recebedor** (o tenant), estável, então faz sentido injetar pelo adapter. O
  pagador é **por-cobrança** (cada boleto tem um sacado diferente) — não é config,
  é dado de request. Tem que vir do boundary.

### Hexagonal — o que NÃO entra no port

Estas três continuam sendo **responsabilidade exclusiva do adapter** (`internal/adapters/bank/c6`),
nunca do port nem do domínio:

1. **Formato `due_date` `yyyy-MM-dd`.** O port carrega `time.Time`. O adapter
   formata como `due.Format("2006-01-02")` ao montar o `bank_slips` body. (Hoje o
   DTO manda `time.Time` cru — RFC3339; muda no adapter.)
2. **`external_reference_id` `^[a-zA-Z0-9]{1,10}$`.** Derivado **no adapter** a
   partir de `BoletoID` (um UUID, >10 chars), de forma **determinística e idempotente**
   (mesmo boleto ⇒ mesma ref, para o C6 colapsar retries). O port **não** ganha
   campo novo para isso — é mapeamento de transporte. O Coder escolhe o mecanismo
   (ex.: encode base36/hex de um hash estável truncado a 10 chars alfanuméricos) e
   o documenta no código. Requisito: colisão-resistente o suficiente para o
   universo de boletos de um tenant e estável entre processos.
3. **Endpoint e nomes de campo wire.** `POST /v1/bank_slips`, `amount`,
   `payer.address.zip_code`, etc. vivem só no `boletoRequestBody`/mapeamento do
   adapter.

### Validação — no adapter C6, não no app (preserva o stub)

Nome, tax_id e endereço do pagador são **obrigatórios para o C6**, mas a validação
de completude do pagador deve ficar no **mapeamento do adapter C6**
(`toBoletoRequestBody` retornando `*c6.Error{sentinel: shared.ErrValidation}` quando
faltar campo obrigatório), **não** no app/`validateBoletoPayer`.

**Razão (blast radius + "não quebrar stub"):** o adapter stub
(`internal/adapters/bank/stub*`) e seus testes registram boletos **sem** pagador
completo e esperam sucesso. Mover a obrigatoriedade para o app tornaria esses
testes `ErrValidation` — modificação de teste existente que exige autorização
escrita do CTO (regra-3 do quality bar) e quebra o stub. Mantendo a regra no
adapter C6, o stub permanece leniente por construção e só o caminho real C6 exige
o pagador completo. A validação **estrutural** barata do boundary (CPF só dígitos,
UF 2 letras, CEP 8 dígitos) pode ficar no DTO HTTP, mas a **obrigatoriedade** é do
adapter C6.

### Thread completo a estender (do boundary ao wire)

O Coder estende as quatro camadas, mantendo cada uma com seus próprios tipos:

| Camada | Arquivo | Mudança |
|---|---|---|
| HTTP DTO | `internal/adapters/http/boleto_handlers.go` | `createBoletoRequest` ganha `payer` aninhado (`name`, `tax_id`, `address{...}`); `unknown fields` continua rejeitado |
| App input | `internal/app/boleto.go` | `RegisterBoletoInput` troca `PayerTaxID` por `Payer app.BoletoPayerInput` (ou equivalente); `toBoletoRequest` mapeia |
| Port | `internal/ports/ports.go` | `BoletoRequest.PayerTaxID` → `Payer BoletoPayer`; novos tipos `BoletoPayer`/`BoletoAddress` |
| Adapter C6 | `internal/adapters/bank/c6/boleto.go` | `boletoRequestBody` vira o shape real `bank_slips`; endpoint `/v1/bank_slips`; `due_date` yyyy-MM-dd; `external_reference_id` derivado; validação de pagador obrigatório |

`UpdateBoleto` compartilha `toBoletoRequestBody` — o Coder decide se a alteração
(grupo 5) também exige pagador no contrato real; se sim, `updateBoletoRequest`
também ganha o pagador. Documentar a escolha no PR.

## Consequências

- **Caminho real C6 boleto** passa a montar o contrato verdadeiro `POST /v1/bank_slips`,
  destravando a captura do 201 real em janela de sandbox (AC do SIN-65882, passo 3).
- **Breaking change de port assumido e contido:** greenfield, sem contrato de
  produção; blast radius = as quatro camadas acima + seus testes httptest. O stub
  permanece leniente (validação só no adapter C6).
- **Hexagonal preservado:** port em tipos Go puros; formato de data, regex de
  referência e nomes de wire ficam no adapter.
- **DDD-lite:** o pagador é um value object coeso, não seis campos soltos.
- **Reversibilidade:** mudança aditiva no boundary/app; rollback = reverter o PR
  (nada em produção depende do shape antigo).

## Riscos conhecidos (para homologação)

- **`number` inteiro vs "S/N"/"123A".** O contrato C6 modela o número do endereço
  como inteiro. Endereços sem número ("S/N") ou alfanuméricos ("123A") não mapeiam
  para `int`. O port usa `int Number`; **o Coder deve registrar** como pergunta de
  homologação ao Pericles/C6 qual o valor canônico para "sem número" (ex.: `0`) e o
  comportamento esperado — **não** inventar. Capturar a resposta no PR ou num
  follow-up antes de assumir produção.
- **201 real ainda não capturado.** Até um 201 do sandbox C6 confirmar o shape,
  os nomes de campo wire são best-effort do roteiro. O httptest pina o shape
  esperado; o 201 real é a prova final (passo 3 do SIN-65882, janela seg–sex
  7h–23h BRT).

## Bar de qualidade (herdado para a implementação SIN-65882)

httptest cobrindo o novo shape `bank_slips` (request body + 201 mapeado) ·
coverage >85% · `-race` · `go vet` + `staticcheck` limpos · stub intacto · PR no
fork `ia-dev-sindireceita/payment`, **CTO mergeia** (ver memória _go-mei-das/payment
fork = CTO merges_).

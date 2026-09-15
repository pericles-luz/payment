# ADR-0013 — Liquidação de boleto reconcilia por `/v2/bank_slips`, e a modalidade (boleto | BolePix) é escolha do chamador

- **Status:** Aceito — decisão de arquitetura.
- **Data:** 15/09/2026.
- **Contexto de contrato:** especificações oficiais do C6 baixadas do portal e versionadas
  em `docs/compliance/c6-bolepix-oas.yaml` (Bolepix v1.1.0) e
  `docs/compliance/c6-bankslip-v1-oas.yaml` (Boleto bancário v1.7.2).
- **Relação com ADR anteriores:** estende [ADR-0005](adr-0005-c6-boleto-payer-port-contract.md)
  (contrato do pagador) e exercita a cláusula residual de
  [ADR-0002](adr-0002-c6-settlement-reconcile-via-pix.md), que manda o portão de liquidação
  ser reavaliado por produto.

## Contexto

Faltava a boleto e BolePix serem **opções de cobrança**, como PIX e cartão já são. Ao abrir
o código para isso, três defeitos apareceram — e cada um deles, sozinho, já impedia
qualquer boleto de funcionar contra o banco real:

1. **`external_reference_id` com o formato errado.** A derivação produzia até 10 caracteres
   minúsculos, mirando `^[a-zA-Z0-9]{1,10}$` — o padrão da API **v1**. O adapter posta na
   **v2**, que exige `^[A-Z0-9]{26}$`, exatamente 26. Toda emissão seria recusada.
2. **`boleto_id` não fazia round-trip.** A criação devolvia ao chamador o `id` do C6, e toda
   operação posterior deriva a referência a partir do id que recebeu — derivando, portanto,
   de um id que nunca foi registrado. Consulta, PDF, alteração e baixa dariam 404. Passava
   despercebido porque o stub ecoa o id que recebe.
3. **`CancelBoleto` não podia ter sucesso.** O contrato responde `204` sem corpo; o código
   usava `do()`, que faz `json.Unmarshal` em todo 2xx e mapeia a falha para
   `ErrUnavailable` — uma baixa bem-sucedida reportada como indisponibilidade do provedor.

Some-se a isso que os limites de tamanho eram medidos em **bytes**, não em caracteres, e
recusavam localmente descrições legítimas em português antes de chegarem ao banco.

A consequência prática é a premissa deste ADR: **nenhum boleto jamais foi registrado com
sucesso contra o C6 real.** Não há dado legado a preservar, então a derivação e o contrato
de porta podem mudar agora — e só agora — sem órfãos.

## Decisões

### 1. `external_reference_id` é uma bijeção do id local, não um digest

O id do boleto é o id do pagamento: 16 bytes aleatórios em hexadecimal. 16 bytes são 128
bits; 26 símbolos de base32 Crockford carregam 130. O alfabeto Crockford é todo `[A-Z0-9]`.
Logo a referência é o próprio id **reencodificado**, não um resumo dele.

Isso vale mais do que um hash truncado por três razões independentes:

- **Idempotente e determinística entre processos**, que é o que faz o colapso de retry
  funcionar — o contrato diz que uma referência repetida "retornará os dados da cobrança já
  existente", e isso só vale se a derivação nunca variar.
- **Sem colisão alguma**, por ser invertível — não uma probabilidade pequena, uma
  impossibilidade.
- **Reversível**, o que resolve metade do problema de mapeamento do webhook sem tabela de
  correspondência nenhuma.

A derivação passa a ser parte do contrato de fio, porque a referência é a **única** chave
que o banco expõe para ler, alterar, cancelar e baixar uma cobrança: trocá-la em silêncio
orfanaria todo boleto já registrado, sem endpoint de recuperação. Um vetor-ouro em teste
existe para fazer essa troca falhar alto.

### 2. A modalidade é do chamador, e `bolepix` sem chave EVP falha fechado

`ports.BoletoRequest.Modality` (`boleto` | `bolepix`), com o vazio valendo `boleto`.

Antes, o sub-objeto `payment_method.pix` era anexado sempre que a empresa tinha chave
aleatória registrada. Isso não é uma escolha, é um efeito colateral da configuração — e
tornava indistinguíveis "pediram boleto simples" e "pediram BolePix, mas a empresa está mal
configurada". Tornar a escolha explícita é o que permite **recusar** o segundo caso.

**A recusa é a parte que importa.** O banco documenta, duas vezes, que uma chave ausente ou
inválida cria a cobrança normalmente, apenas com `payment_method.pix: null`. Não existe
caminho de erro: se não recusarmos aqui, ninguém recusa. E o estrago não aparece para quem
integra — aparece para quem paga, na forma de um boleto anunciando um QR que não existe,
descoberto na hora do pagamento.

O padrão é `boleto`, não `bolepix`, porque **o default deve prometer o menos**: um padrão que
promete QR falha para toda empresa sem chave, e um padrão que não promete nada nunca mente.

### 3. Liquidação de boleto reconcilia por `/v2/bank_slips`, não pela leitura PIX

ADR-0002 fixou que a liquidação reconcilia pela leitura da cobrança PIX imediata. Para
boleto isso está **errado por construção**: `BANK_SLIP`/`BANK_SLIP_PIX` caíam no ramo
default do receptor, que lê `GET /v2/pix/cob/{txid}` — e um id de bank slip não é um txid de
cob. O resultado era 404, e um boleto pago que nunca liquidava.

Passa a existir `webhookKindBoleto`, com reconciliação por `GET /v2/bank_slips/{ref}`.

**A ordem do `switch` é carga estrutural.** O caso PIX dispara com `len(note.Pix) > 0`
sozinho, porque o webhook BACEN real não manda discriminador. Mas o QR de um BolePix é
gerado da **mesma chave** contra a qual o webhook BACEN está registrado, então um BolePix
pago por QR pode chegar com um array `pix`. Resolvido ali, seria reconciliado contra a
leitura PIX — o mesmo 404, reintroduzido por uma porta lateral. O discriminador explícito e
documentado vem **antes** da heurística.

### 4. Os dois trilhos compartilham UM rótulo de dedupe

`eventKey = objectID|label|status`. Dar rótulos distintos a `BANK_SLIP` e `BANK_SLIP_PIX`
não causaria dupla liquidação de dinheiro (`MarkPaid` é idempotente), mas **publicaria dois
`payment.paid` e dois webhooks de saída para a Conta** por um único pagamento. Uma cobrança
BolePix só pode ser paga uma vez — o banco fecha o outro trilho —, então os dois avisos são
a *mesma* liquidação e têm de colidir. Qual trilho pagou vai no log e na mensagem de
liquidação, não na chave de deduplicação.

### 5. `WAITING_CONFIRMATION` pede reentrega, não confirmação

Status novo da v2, sem equivalente em PIX ou cartão: pagamento confirmado, **recursos ainda
não creditados**.

- Não liquida: nosso contrato com a Conta é "o dinheiro chegou". PIX liquida em `CONCLUIDA`,
  que já é dinheiro creditado; manter o mesmo significado nos dois trilhos vale mais do que
  algumas horas de latência.
- Não é confirmado (`errSettlementLag`, não `errNotYetPayable`): a marca de anti-replay é
  desfeita **e** o aviso volta. Confirmá-lo dependeria de o banco mandar um segundo aviso
  quando o dinheiro cair — o que **não foi medido**. Se essa premissa estiver errada e
  confirmarmos, o pagamento se perde para sempre, que é exatamente o modo de falha que este
  código já pagou uma vez.

`CANCELED` (um L na v2; `CANCELLED` na v1 legada — as duas grafias são aceitas) é terminal e
não pago: confirmado, sem liquidar, sem reentrega.

### 6. A conferência de valor do boleto é mais fraca, e isso está escrito

`ChargeResult.AmountReconciled` exige igualdade estrita. Mas a leitura de cobrança única do
Bolepix devolve `amount` (o principal registrado) e `status` — **e não devolve `payments[]`**,
que só existe na listagem. Então, para uma cobrança liquidada, esperado e recebido são ambos
o valor registrado, e o portão de dinheiro degenera para "o banco, relido, diz que esta
cobrança de valor X está PAGA".

É mais fraco que PIX e cartão, onde um valor recebido é de fato comparado. Aceito porque
(a) o banco não faz baixa parcial de boleto e (b) um boleto pago em atraso credita
legitimamente **mais** que o principal (multa + mora pro-rata-die) — igualdade estrita
contra o valor creditado recusaria pagamento legítimo em vez de pegar fraude.

**Isto é uma redução deliberada da defesa W3 e está comentada como tal no código**, não
escondida numa atribuição. Restaurar uma comparação de verdade exige `GET /v2/bank_slips/list`
e o array `payments[]` — follow-up registrado.

### 7. Capacidade de boleto é tri-estado

`ports.Capability`: `Unknown` | `Granted` | `Denied`, serializado como `null` | `true` | `false`.

O nome do escopo C6 que autoriza emissão de boleto **não é conhecido**: não está na OpenAPI
publicada (que documenta só `bearerAuth`) nem em lugar nenhum do repositório. Responder
`false` afirmaria à empresa que a conta dela não pode emitir boleto, com base num nome que
ninguém conferiu. `null` é a resposta honesta, e não custa nada: esta rota é de exibição,
nunca um portão de autorização.

O nome vem por configuração (`PAYMENT_C6_SCOPE_BANK_SLIP_WRITE`), vazio por padrão, a ser
preenchido depois de lido num token real.

`Bolepix` é um bit **separado** de `Boleto` porque carrega uma pré-condição que não é escopo:
a chave EVP registrada. Uma conta pode estar perfeitamente autorizada a emitir boleto e
ainda assim ser incapaz de emitir um BolePix.

## Consequências

- **Desconto escalonado (grupo 3.b) fica limitado a uma faixa.** A v2 expõe só
  `first_discount_*`; a v1 legada é que tem `first`/`second`/`third`. O adapter já recusa
  duas faixas com `ErrValidation`, que é a atitude certa — descartar faixa em silêncio
  mudaria o que o pagador deve. Se a homologação exigir 3.b completo, a decisão "tudo pela
  v2" precisa ser revista **antes** da janela.
- **O receptor é forward-only.** A superfície proprietária não expõe DELETE, então um canal
  registrado fica registrado. Reverter o commit do receptor **depois** de registrar devolve
  os avisos ao ramo PIX — 404 e 500 para sempre. Reverter emissão, sim; receptor, não.
- **Registrar um canal novo rotaciona a ref do tenant** (`PutWebhookRef` revoga as outras
  refs ativas), então ligar `BANK_SLIP` reescreve todos os canais e um aviso em voo sob a ref
  antiga leva 401. Janela de baixo tráfego, e `cmd/c6-webhook-sync` precisa dos dois canais
  novos — com a varredura de renovação desligada, ele é o único que converge um tenant.

## O que ainda não foi medido

> **Addendum (PR #53).** O registro dos serviços `BANK_SLIP`/`BANK_SLIP_PIX` foi **ligado**,
> antes das medições abaixo. Este ADR dizia originalmente que não seria, e a inversão é
> deliberada e do dono do produto, não um descuido — fica registrada aqui em vez de a
> decisão sumir no histórico.
>
> O que a torna defensável é o comportamento do receptor no caso não medido, não o
> desaparecimento da incerteza: ele resolve a cobrança tentando a linha local primeiro e a
> referência do banco depois — correto qualquer que seja o identificador que chegue — e,
> quando nenhum resolve, devolve **erro** em vez de confirmação, de modo que o aviso é
> reentregue e o corpo bruto fica no log verbatim. O pior caso vira "repetido e registrado
> alto", não "dinheiro perdido em silêncio". E é esse log que responde ao item 1.
>
> O que **não** muda: nada disto substitui as medições, e o registro é de mão única (sem
> DELETE na superfície proprietária). Os cinco itens abaixo continuam abertos.

### Medido em 15/09/2026 contra o C6 sandbox

Emissão ponta a ponta pela nossa API: **HTTP 201**. O que isso fechou:

- **A referência de 26 chars é aceita E endereçável.** `POST /v2/bank_slips` aceitou a
  derivação Crockford, e `GET /v2/bank_slips/552S2QFD8D61V3BZGWXK27SDQT` — a referência
  derivada do id local `a5164577b50d307635fe1cecc47cb6fa` — devolveu **200** com a cobrança
  certa. A bijeção da decisão 1 funciona contra o banco real, não só em teste.
- **O shape da resposta bate com `bankSlipResponseBody`**: artefatos aninhados em
  `payment_method.bank_slip` (`bar_code`, `digitable_line`, `our_number`, `originator_id`,
  `billing_type`) e o QR em `payment_method.pix` (`qr_code`, `image_content`, `mime_type`,
  `reference`). O QR vem **na criação**, como o ADR-0005 dizia.
- **`amount` é decimal em reais**: `12.34` ↔ 1234 centavos. `brlDecimal` correto.
- **`status` é ausente na criação e `CREATED` na leitura** — vocabulário v2 confirmado.
- **O `id` do C6 é um ULID** (`01M2KEFNXH680SBM714RX13CJT`): 26 chars `[A-Z0-9]`, ou seja
  **indistinguível em forma** da nossa referência. A premissa da decisão 2 (§"o problema dos
  três identificadores") está confirmada: forma não decide, só o store decide.
- **A correção do `boleto_id` está validada ao vivo**: a resposta trouxe o id **local** em
  `boleto_id` e o id do C6 em `txid`, então as operações seguintes endereçam o que existe.
- **Escopos concedidos** (medição 4, fechada): `v2.bankslip.write`, `v2.bankslip.read` e
  **`v2.bankslip.pix.write`**. A perna PIX tem escopo **próprio** — confirmação independente
  de que `boleto` e `bolepix` deviam ser bits separados (decisão 7).
  `PAYMENT_C6_SCOPE_BANK_SLIP_WRITE=v2.bankslip.write`.

#### Dois achados que pedem correção

1. **O C6 recusa erro semântico com `422`, não `400`**, em `application/problem+json`, e o
   `detail` embrulha um erro do Matera:

   ```
   HTTP 422
   detail: Error generating boleto: {"type":"MATERA_CLIENT_ERROR_400",
           "message":"Valor informado no campo <cnpjCpf do grupo pagador> não pertence ao Domínio."}
   ```

   Pela nossa API isso chega como `400 {"error":"invalid request"}` — **sem detalhe e sem
   log**, porque `writeDomainError` mapeia `ErrValidation` para uma mensagem genérica e não
   registra nada. O motivo fica invisível, exatamente o buraco do incidente do extrato
   (PR #49). Um CPF inválido custou uma ida ao banco e uma hora de diagnóstico que só a sonda
   resolveu.

   **Corrigido — mas não como eu havia proposto.** A recomendação original aqui era
   registrar o `detail` do PSP em log. Ao implementar, ficou claro que era a decisão errada:
   o `detail` é texto livre que o PSP compõe, e na superfície de boleto o request **é feito
   de** dados pessoais do pagador (nome, CPF/CNPJ, endereço). Um `detail` que ecoe um valor
   recusado colocaria PII no log justamente da superfície onde isso é menos aceitável
   (ameaça C1/C4) — e a decisão de `errorEnvelope` de nunca ler `title`/`detail` estava
   certa.

   O que entrou: `mapError` passa a registrar em WARN (`c6.psp_rejected`) a operação, o
   status, o código de máquina, os **nomes** dos campos recusados e o
   **`correlation_id`** do PSP. O correlation id é o equivalente seguro — não carrega dado
   nenhum e ainda assim deixa o suporte do C6 localizar a chamada exata. Para o texto livre,
   a sonda continua sendo a porta sancionada, de uso pontual e por operador. Test-locked nas
   duas direções: o correlation id aparece, o `detail` nunca.

2. **Não validávamos dígito verificador de CPF/CNPJ**, só a largura (11 ou 14) — então um
   CPF sintaticamente correto mas inválido só era recusado pelo banco, como acima.
   **Corrigido:** `validTaxIDDigits` passa a conferir os dois dígitos por módulo 11 (CPF e
   CNPJ têm pesos diferentes) e recusa dígitos repetidos, que satisfazem a aritmética mas não
   são emissíveis. Um CPF errado volta agora como erro de campo nomeado, sem ida ao banco.

   Isso tornou visível que as próprias fixtures de teste usavam o `12345678901` — o valor
   que o banco recusa. Trocadas por um CPF com DV válido.

#### Por que a liquidação NÃO foi medida

Não há como liquidar um boleto no sandbox do C6 a partir daqui:

- o catálogo de APIs do portal não expõe **nenhum simulador** de pagamento;
- `Agendamento de Pagamentos` (DDA) responde **404** para esta conta — ela não tem DDA, e de
  todo modo o DDA lista boletos em que a conta é *pagadora*, não cedente;
- pagar o QR PIX exige um PSP pagador, que não temos.

Então as medições 1, 2, 3 e 5 continuam abertas e dependem de o C6 liquidar uma cobrança de
sandbox — pedido para o gerente de contas, não trabalho de código. A cobrança emitida está de
pé e pode ser usada para isso:

    external_reference_id  552S2QFD8D61V3BZGWXK27SDQT
    id (C6)                01M2KEFNXH680SBM714RX13CJT
    linha digitável        33690.00009 65729.430010 04489.482135 9 15770000001234

Pendente de uma janela de sandbox:

1. **Qual identificador o C6 põe em `external_id`** do aviso: o `id` dele ou a nossa
   referência. Mitigado, não resolvido: a resolução tenta a leitura local primeiro e a
   leitura por referência depois, e falha alto se nenhuma casar — correto sob as duas
   hipóteses, mas só uma delas é a real.
2. **Se `WAITING_CONFIRMATION` chega mesmo como aviso**, e se há um segundo aviso quando o
   dinheiro cai. Decide se a política da decisão 5 pode ser relaxada.
3. **Por qual envelope chega um BolePix pago por QR** — proprietário, BACEN, ou os dois.
   Decide se a ordenação da decisão 3 basta ou se falta dedupe entre canais.
4. **O nome do escopo de bank slip** (`./c6-webhook-probe <tenantID> --token-only` imprime o
   `scope` concedido no corpo bruto do token).
5. **Se `PAID` pode ser alcançado com pagamento divergente.** Se puder, a decisão 6 deixa de
   ser aceitável e a listagem vira bloqueante, não follow-up.

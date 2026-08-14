# ADR-0008 — Caminho de escrita da chave do recebedor: port próprio `CreditorKeyWriter`, bankless, RMW preservando segredo

- **Status:** Proposto — aguardando ratificação do CTO + LGTM do SecurityEngineer ([SIN-66092](/SIN/issues/SIN-66092)).
- **Decisão de design pai:** [SIN-66017](/SIN/issues/SIN-66017) (port-shape vinculante do CTO). Pai do épico: [SIN-66091](/SIN/issues/SIN-66091).
- **Autor:** Coder. **Decisor:** CTO (merge gate) + SecurityEngineer (hard gate de fund-routing).
- **Referências:** ADR-0004 (chave por-tenant injetada pelo adapter, [SIN-65862](/SIN/issues/SIN-65862)); ADR-0007 (credencial multi-banco por-tenant, [SIN-66022](/SIN/issues/SIN-66022)); UI Bancos do console ([SIN-66086](/SIN/issues/SIN-66086), PR #72).

## Contexto

ADR-0004 estabeleceu que a `chave` do recebedor (chave do recebedor PIX) é
modelada no agregado de identidade bancária do tenant
(`ports.BankCredential.CreditorKey`) e injetada pelo adapter ao montar a
cob/cobv. Até aqui **não havia caminho de escrita administrativo** para essa
chave: só podia ser semeada via config/env no boot (`PAYMENT_BANK_CREDITOR_KEYS`,
SIN-65862). A UI Bancos (SIN-66086, PR #72) exibe um card **somente-leitura** da
chave no detalhe do banco e registra explicitamente: "A edição pela console será
habilitada em uma próxima entrega (depende do port de escrita da chave)" — esse
follow-up é **este** ticket.

A decisão de port-shape do CTO em SIN-66017 foi **ancorada em `origin/main`
`e51d59b`**, quando a `secret.Store` ainda era single-bank (keyed por `tenantID`).
Desde então, ADR-0007/SIN-66022 reescreveu a store para chavear pelo par composto
`(tenantID, bankID)`, e SIN-66086 construiu o console em torno de superfícies
**por-banco** (`/console/tenants/{id}/banks/{bankId}`). Esta ADR reconcilia a
decisão vinculante do CTO com essa realidade.

## Decisão

### 1. Port próprio, separado de `CredentialWriter` (ISP / menor privilégio)

Novo `ports.CreditorKeyWriter` com um único método
`SetCreditorKey(ctx, tenantID, creditorKey string) error`. **Não** é uma extensão
de `CredentialWriter`: a capacidade de **rotacionar o segredo OAuth** e a de
**apontar o roteamento de fundos** são concedidas de forma independente. O handler
do console depende **apenas** de `CreditorKeyWriter`; o handler de credencial
continua dependendo **apenas** de `CredentialWriter` (OWASP A01, confused-deputy).

### 2. Bankless — segue a decisão vinculante do CTO, reconciliada com #72

A assinatura do port segue **exatamente** o que o CTO fixou em SIN-66017:
`SetCreditorKey(ctx, tenantID, creditorKey)` — **sem** `bankID`. O CTO
explicitamente classificou a rota `/banks/{bankId}/creditor-key` como **phantom a
descartar** e escolheu a rota bankless `/console/tenants/{id}/creditor-key`.
Mantemos **ambas** as escolhas vinculantes do CTO (assinatura do port + rota).

O adapter resolve a chave sobre a credencial do **banco padrão** do tenant
(`BankIDC6`), reutilizando o caminho retro-compatível `defaultBankID("")` da
store. Hoje **`c6` é o único banco na allow-list** (`ports.knownBankIDs`), então o
port bankless escreve o único banco que existe — a tensão "bankless vs por-banco"
é teórica enquanto a allow-list tiver um único membro.

> **Flag para revisão CTO/SecEng:** a premissa original do CTO ("o serviço modela
> exatamente UMA credencial por tenant") foi superada por ADR-0007 (multi-banco) e
> SIN-66086 (UI por-banco). Honramos a letra da decisão (port + rota bankless) e
> renderizamos o card editável **apenas no banco padrão** (`BankIDC6`); bancos não
> padrão mantêm a chave somente-leitura. Se o produto quiser chave de recebedor
> **por banco**, isso é uma evolução **aditiva** do port (`SetCreditorKey` ganha
> `bankID`) + rota por-banco — não uma reescrita deste caminho.

### 3. Adapter `*secret.Store.SetCreditorKey` — read-modify-write

Sob `s.mu.Lock()`: carrega a `BankCredential` existente de `(tenantID, BankIDC6)`,
seta `CreditorKey` e regrava — **preservando `Secret` e `ClientID`**. Tenant sem
credencial existente → `shared.ErrNotFound` (uma chave sem identidade bancária é
sem sentido e uma meia-credencial convida o gap de confused-deputy;
SecurityEngineer a confirmar). Validação no boundary: `tenantID`/`creditorKey`
vazios rejeitados via `shared.NewValidationError` (sem o valor na mensagem) e um
**validador de shape de chave PIX** explícito (EVP/UUID, e-mail, telefone E.164,
CPF/CNPJ) — não apenas não-vazio.

### 4. Correção do wipe-bug latente (mesmo PR)

`Store.SetBankCredential` regravava a struct inteira, **destruindo
silenciosamente qualquer `CreditorKey`** quando um admin rotacionava o segredo.
Trocado para read-modify-write preservando `CreditorKey`. Regressão coberta:
setar chave → rotacionar segredo → a chave sobrevive. Os dois escritores
(`CredentialWriter`, `CreditorKeyWriter`) compartilham `s.mu`, então não podem se
sobrescrever.

### 5. Auditoria (OWASP A09)

Nova `audit.ActionSetCreditorKey` e `audit.NewCreditorKeySetEntry` (irmã de
`NewCredentialSetEntry`), emitindo uma entrada com o operador autenticado
(derivado do contexto, nunca do cliente) em toda escrita bem-sucedida. A entrada
registra quem/qual-tenant/qual-banco — **nunca** o valor da chave. **Sem**
invalidação de cache de token (`CredentialInvalidator`): a chave do recebedor não
faz parte da identidade OAuth, então um bearer em cache continua válido
(SecurityEngineer a confirmar).

### 6. Console — card editável no detalhe do banco padrão, swap só do card

Rota `POST /console/tenants/{id}/creditor-key` adicionada ao grupo de mutação
Admin-only existente (RBAC `RoleAdmin` + CSRF double-submit **herdados** do spine,
não reimplementados). O card somente-leitura de #72 no `bank_detail.html` passa a
ser **editável** no banco padrão: mantém a **exibição de leitura** da chave atual
(a chave é o identificador PIX público, já exibido por #72) e adiciona um form que
posta na rota bankless, com swap HTMX **apenas do card** (`hx-target="#creditor-card"`).
O valor digitado **nunca** é reexibido em erro (roteamento-sensível, threat C1/C4).

## Consequências

- **Positivas:** caminho de escrita administrativo para a chave sem editar
  config/env e reiniciar; capacidade separada do segredo (menor privilégio);
  wipe-bug fechado com regressão; toda mudança de roteamento de fundos fica
  atribuível na trilha append-only; superfície do port mínima; integra a UI Bancos
  de #72 (substitui o placeholder somente-leitura).
- **Negativas / trade-offs:** o port resolve sempre o banco padrão (`BankIDC6`) e
  o card só é editável nesse banco; chave por-banco exige evolução aditiva. A UI
  reexibe a chave atual (não é segredo) mas nunca o valor recém-digitado em erro.
- **Reversibilidade:** mudança aditiva. Sem migração de schema (a coluna
  `CreditorKey` já existe). Rollback = remover rota/handler/port e restaurar o card
  somente-leitura de #72; a correção do wipe-bug é estritamente mais segura e não
  precisa de rollback.

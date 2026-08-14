# ADR-0008 — Inventário de acesso a dados pessoais no plano de dados (registro art.13 / B10-v)

- **Status:** Proposto — aguardando ratificação do CTO.
- **Fonte da obrigação:** Termo de Uso de APIs C6, cláusula 7.12 (regra **B10**) replicando a **LGPD** e o **Decreto 8.771/2016, art.13** (registro de acesso a dados pessoais: momento, duração, identidade do responsável, dado/titular acessado). Ver `docs/compliance/c6-termo-apis-regras.md` ([SIN-68740](/SIN/issues/SIN-68740)).
- **Design:** SecurityEngineer ([SIN-68744](/SIN/issues/SIN-68744)). **Implementação:** Coder ([SIN-68748](/SIN/issues/SIN-68748)). **Aprovação:** CTO.
- **Lentes:** OWASP A09 (Security Logging & Monitoring Failures), Least Privilege, Complete Mediation, LGPD (minimização / retenção / direito ao esquecimento), Observability.

## Contexto

O Termo C6 (B10) obriga o parceiro a manter dois registros distintos:

- **B10-(iv)** — *individualização do responsável* por **ações privilegiadas** (mutações do plano administrativo).
- **B10-(v)** — *inventário de acesso* (**leitura**) a **dados pessoais** no plano de dados: quem leu quais dados de qual titular, quando e por quanto tempo.

### Estado atual validado (2026-08-06)

**B10-(iv) — COBERTO.** O audit log durável (`audit_log`, migrations 0002/0003; SIN-66016/66025/66044) registra `operatorID + action + tenantID + at` server-side para o vocabulário **fechado de mutações privilegiadas** (`credential.set`, `tenant.create`, `pricing.set`, `settlement.amount_mismatch`, `recurrence.*`). É append-only, sem segredo, atômico no `dbtx`. Por construção (`internal/domain/audit/audit.go`) é um registro de **ações que ocorreram**, não de leituras.

**B10-(v) — NÃO COBERTO (obrigação latente).** Levantamento do plano de dados:

| Superfície de leitura | Retorna PII de titular? | Onde |
|---|---|---|
| `GET /boletos/{id}` (`BoletoResult`) | **Não** — barcode/linha digitável/status/valores; **não** ecoa `Payer{Name,TaxID,Address}` | `ports.go:687` |
| `GET /pix/cobv/{txid}` (`PixDueChargeResult`) | **Não** — QR/status/valores; **não** ecoa devedor | `ports.go:509` |
| `GET /pix/{txid}`, `GET /pix`, `GET /charges/{id}` | **Não** — status/valores | — |
| `GET /checkout/{id}` (`CheckoutResult`) | **Não** — status/redirect/valores | `ports.go:764` |
| `GET /dda/boletos` (`DDABoleto`) | **Parcial** — `BeneficiaryName` (nome do beneficiário; PII se pessoa natural) | `ports.go:817` |
| `GET /statement` (`StatementEntry`) | **Parcial** — `Description` texto-livre pode conter contraparte (não-estruturado) | `ports.go:897` |
| **`pix_rec` (PIX Automático)** | **SIM — PII em repouso**: `devedor_doc` (CPF/CNPJ) + `devedor_nome` | `migrations/0004` |
| Leitura de `pix_rec` → `FindRecByID` | Reidrata devedor da store | `internal/adapters/persistence/sqlite/recurrence.go:54` |

**Fato-chave:** a **única** PII de titular **persistida em repouso** neste serviço é o **devedor da recorrência** (`pix_rec.devedor_doc`/`devedor_nome`, SIN-66037). O comentário da migration 0004 afirma *"No secret/credential/PII is stored"* — isso está **incorreto** e deve ser corrigido: a tabela armazena PII. O único caminho de leitura dessa PII é `FindRecByID`, que hoje **não tem chamador de produção** (só testes/plumbing). As leituras do plano de dados hoje em produção (boleto/pix/cobv/checkout) **passam** a PII no *write* (inbound → C6, que é o repositório autoritativo) e devolvem **projeções sem PID de titular**.

**Conclusão:** a obrigação art.13 de *registro de leitura* torna-se **efetiva no momento** em que um endpoint do plano de dados **retornar PII de titular** — p.ex. um futuro `GET /recurrence/{idRec}` que ecoe o devedor, uma tela de console que exiba o devedor, ou o wiring de settle/reconcile que carregue `FindRecByID` para uma superfície observável. Portanto o desenho precisa (a) fixar o mecanismo e a política **agora**, e (b) tornar o caminho **seguro-por-padrão**, de modo que uma nova leitura de PII **não consiga** ser adicionada sem passar pelo registro.

## Decisão

### 1. O que precisa de registro (escopo art.13)

Registra-se **toda leitura que resolva e exponha PII de um titular pessoa natural**, a saber:

- **Obrigatório (tier 1 — PII estruturada em repouso):** qualquer leitura de `pix_rec` que reidrate/retorne `devedor_doc`/`devedor_nome` (hoje: `FindRecByID`). Este é o gatilho concreto e imediato.
- **Obrigatório quando a superfície existir (tier 1):** qualquer novo endpoint/handler que retorne devedor/pagador/sacado (`Name`, `TaxID/CPF/CNPJ`, `Address`) ao chamador ou a uma tela.
- **Condicional (tier 2 — PII não-estruturada / de terceiro):** `DDABoleto.BeneficiaryName` e `StatementEntry.Description`. Registram-se como **acesso ao objeto** (id do boleto / janela do extrato), sem tentar extrair a PII do texto — evita parser-differential e duplicação de PII.

**Não** se registra: leituras que retornam apenas status/valores/QR/barcode (não são dados pessoais de titular). Registrar tudo violaria minimização e inundaria o log (A09 ao contrário: ruído mata sinal).

### 2. Campos do registro (art.13 §… — momento, duração, responsável, objeto)

Cada evento de acesso grava:

- **`at`** — momento do início da leitura (RFC3339-UTC), como no `audit_log`.
- **`duration_ms`** — duração da operação de leitura (art.13 exige "duração"). Medida no choke-point.
- **`responsavel`** — identidade do responsável **derivada server-side**. No plano de dados o responsável é o **tenant autenticado** (não há sub-identidade humana por-request hoje): grava-se `tenant_id` + o **id da credencial/`client_id`** usada (não o segredo). Para leituras disparadas pelo plano admin/console, grava-se também o `operator_id` (mesma proveniência do `audit_log`). Nunca confiar em identidade fornecida pelo cliente.
- **`subject_ref`** — **referência não-reversível ao titular**, **não** a PII em claro. Grava-se um pseudônimo estável: `HMAC-SHA256(chave_do_serviço, doc_normalizado)` **ou** o id de negócio já-opaco (`id_rec`/`tx_id`). **É proibido copiar `devedor_doc`/`devedor_nome` para o log de acesso** (ver §4).
- **`object`** — o objeto acessado: tipo + id (`rec:{id_rec}`, `cobr:{tx_id}`, `dda_boleto:{id}`, `statement:{start..end}`).
- **`purpose`/`action`** — vocabulário fechado do tipo de leitura (`pii.read.rec`, `pii.read.dda`, `pii.read.statement`), deny-by-default como no `audit_log`.

### 3. Mecanismo: **access-log dedicado**, NÃO estender o `audit_log`

Adota-se uma tabela/porta **separada** (`pii_access_log` + `ports.PIIAccessRecorder`), não a extensão do `audit_log`. Razões:

- **Cardinalidade/custo.** Leituras são ordens de magnitude mais frequentes que mutações privilegiadas. Misturá-las inunda o `audit_log` forense e muda seu perfil de custo/retenção.
- **Semântica.** `audit_log` é vocabulário fechado de **mutações**; overloadar `Action` e a coluna `tx_id` para eventos de **leitura** (com titular + duração) borra as duas trilhas e enfraquece a tamper-evidence de ambas (Economy of Mechanism ao contrário).
- **Retenção divergente.** O registro art.13 tem política de retenção própria (minimização LGPD: janela curta e bounded, p.ex. 6–12 meses configurável) — tabela separada permite TTL/expurgo independentes sem tocar a trilha forense de mutações.
- **Direito ao esquecimento.** Com `subject_ref` pseudônimo, o expurgo do titular no `pix_rec` e a expiração do log de acesso são políticas independentes e o log **não** vira uma segunda cópia de PII a apagar.

Convenções idênticas às demais (0001/0004): TEXT opaco, TEXT RFC3339-UTC, INTEGER, `IF NOT EXISTS`, portável a Postgres. Append-only, sem `UPDATE`/`DELETE` fora do expurgo por retenção.

### 4. Minimização — o log de acesso não pode virar cópia de PII

**Requisito de aceite não-negociável:** `pii_access_log` **nunca** grava `devedor_doc`/`devedor_nome`/nome/endereço em claro. Grava `subject_ref` (HMAC/id opaco) + `object`. Isso impede que a mitigação de A09 crie uma nova superfície de vazamento LGPD (dobrar o footprint e a superfície de erasure). A `LogValue()` de qualquer struct de acesso é write-only para campos sensíveis, como já se faz para segredos.

### 5. Choke-point seguro-por-padrão (Complete Mediation)

Introduz-se um **único ponto de mediação**: a porta `PIIAccessRecorder` injetada num **decorator/middleware** por onde **toda** leitura tier-1 de PII **deve** passar. O objetivo é que o **caminho de leitura de PII seguro seja o caminho fácil**: adicionar um novo endpoint que retorne devedor sem passar pelo recorder deve **falhar na revisão** (checklist do `pr-review-policy.md`) e, onde viável, ser barrado por um gate de CI (grep por retorno de campos `Devedor*`/`Payer` fora do decorator). Hoje o wiring concreto é: decorar `FindRecByID` (ou o serviço que o consome) para emitir o evento.

### 6. Disponibilidade (fail-open vs fail-closed)

- **PII em repouso local (`pix_rec`, mesma store):** o append do acesso ocorre **na mesma transação** da leitura (atômico, como as transições de recorrência já fazem via `ports.Repository` bundled). Se o append falhar, a leitura falha — não há leitura não-registrada de PII local (Complete Mediation).
- **Leituras pass-through do banco (GetRec JWS-verificado):** não há transação cross-boundary com o C6; o append é **best-effort com alerta** em falha (não bloquear a leitura por falha de logging seria DoS auto-infligido; mas monitorar a taxa de falha). Risco residual explicitado abaixo.

## Consequências

**Positivas:** obrigação B10-(v)/art.13 atendida com trilha própria, minimizada e com retenção independente; caminho seguro-por-padrão impede regressão silenciosa quando um endpoint de PII for adicionado; separação de trilhas preserva a tamper-evidence do `audit_log` forense.

**Custo:** uma tabela + porta + decorator; um append por leitura tier-1 (baixo volume hoje — só `pix_rec`). Sem impacto nas leituras que não retornam PII.

**Risco residual:**
1. Leituras pass-through do C6 usam append best-effort → uma falha de logging pode perder um evento de acesso (mitigação: alerta na taxa de falha; a leitura autoritativa vem do banco, e o titular está no C6, não em repouso local).
2. `StatementEntry.Description` (texto-livre) pode conter PII de contraparte que registramos apenas como acesso ao objeto (janela), não ao titular — cobertura tier-2 deliberadamente grosseira para evitar parser-differential.
3. Enquanto o gate de CI (grep anti-bypass) não existir, a mediação depende do checklist de revisão humano.

## Implementação (SIN-68748 — entregue)

Implementado por Coder em SIN-68748 (revisão SecurityEngineer; aprovação CTO):

1. Migration `0006_pii_access_log` (`id`, `at`, `duration_ms`, `tenant_id`, `client_id`, `operator_id`, `subject_ref`, `object`, `action`), append-only, portável, com índices `(tenant_id, at)`, `(subject_ref, at)` e `(at)`.
2. Domínio `internal/domain/access` — `Entry` imutável (sem campo de PII em claro por construção), vocabulário fechado `Action` (deny-by-default), `Pseudonymizer` HMAC-SHA256 com chave ≥16 bytes (`LogValue` redige a chave), `RetentionPolicy` configurável (`DefaultRetention` = 6 meses).
3. Portas `ports.PIIAccessRecorder` (bundled no `Repository` — mesma tx da leitura) + `ports.PIIAccessPurger`; adapters SQLite e in-memory.
4. Choke-point `app.PIIAccessService.ReadRec` — carrega o mandato e grava o acesso na **mesma** transação (Complete Mediation: append falho → leitura revertida). Duração medida no choke-point. Responsável derivado server-side. **Wiring HTTP fica com o primeiro endpoint que retornar devedor** (nenhum existe hoje).
5. Comentário incorreto da migration 0004 corrigido (declara `devedor_doc`/`devedor_nome` como PII do titular; aponta este ADR).
6. Retenção configurável + rotina de expurgo append-safe (`app.PIIAccessRetentionService.Purge`, único DELETE permitido).
7. `pr-review-policy.md`: nova leitura que retorne `Devedor*`/`Payer` DEVE passar pelo recorder (gate de revisão + gate de CI por grep). ADR indexado em `docs/security/README.md`.
8. Testes de regressão: leitura de PII sem registro **falha**; `pii_access_log` **nunca** contém `devedor_doc`/`devedor_nome` em claro; cobertura de pacote >85% nos pacotes tocados.

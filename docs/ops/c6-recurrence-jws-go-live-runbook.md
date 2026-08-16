# Runbook — go-live do verificador JWS de Recorrência (PIX Automático C6, F4)

- **Escopo:** o ato operacional que **liga** a recorrência (PIX Automático) em um
  ambiente — confirmar a fonte do JWKS do C6, fixar a allowlist de algoritmo e ligar
  `PAYMENT_C6_REC_JWKS_URL` — fechando os **3 residuais de segurança** que o
  SecurityEngineer levantou no review do PR #65
  ([SIN-66061](/SIN/issues/SIN-66061), merged `5819f226`).
- **Origem:** [SIN-66066](/SIN/issues/SIN-66066) (F4), residuais de
  [SIN-66061](/SIN/issues/SIN-66061); barra de segurança em
  [SIN-66038](/SIN/issues/SIN-66038) §1; F0 (`SIN-66034`) já `done`.
- **Lentes:** secure-by-default API · least privilege · reconcile-before-settle.
- **Código de referência:** `internal/adapters/bank/c6/jws_verifier.go` (verificador),
  `internal/adapters/bank/c6/recurrence.go` (`signedRead`), `cmd/api/main.go` (wiring),
  [`../../.env.example`](../../.env.example) (`PAYMENT_C6_REC_JWKS_URL`).

> ⚠️ **Invariante de fail-secure.** Enquanto `PAYMENT_C6_REC_JWKS_URL` estiver
> **vazio**, o verificador permanece `nil` e **toda** leitura de recorrência
> (`GetRec` / `GetSolicRec` / `GetCobR`) falha fechado com `shared.ErrUnavailable`
> (`signedRead`, `recurrence.go:460`). Ligar a env var é **o único ato** que ativa a
> recorrência — e ele só deve ocorrer **depois** do item 1 abaixo. Não há caminho de
> recorrência que confie em documento não verificado.

---

## 0. Pré-condições (gate de entrada)

| # | Pré-condição | Verificação |
|---|---|---|
| 1 | F1 (seam fail-secure) e F4 (verificador concreto) em `main` | `5819f226` mergeado |
| 2 | mTLS do C6 provisionado (cert/chave de cliente) | `PAYMENT_C6_CLIENT_CERT`/`_KEY` setados; log `C6 mTLS client certificate loaded` |
| 3 | Captura de homologação no sandbox C6 disponível | **bloqueia itens 1 e 2** — ver abaixo |

A captura de homologação (item 3 da tabela) é a entrada externa de que os itens 1 e 2
dependem: ela revela **como** o C6 distribui a chave pública e **qual** algoritmo
emite. Sem ela, mantenha a recorrência **desligada** (env var vazia, fail-secure).

---

## 1. Confirmar a fonte viva do JWKS do C6 (residual 1)

O verificador hoje busca o JWKS de uma **URL https** (`httpJWKSFetcher`): `GET` com
`Accept: application/json`, TLS 1.2+, **redirects desabilitados** (anti-SSRF —
`jws_verifier.go:241`), corpo limitado a 1 MiB. Esse é o modelo **endpoint JWKS**.

Na captura de homologação, confirme **qual dos dois modelos** o C6 usa:

### Árvore de decisão

```
O C6 publica as chaves públicas de assinatura de Recorrência em…
├── (A) endpoint JWKS https (ex.: .well-known/jwks.json) ──► caminho atual, SEM mudança de código.
│        Ação: setar PAYMENT_C6_REC_JWKS_URL com a URL real capturada (passo 1.A).
│
└── (B) chave/cert PINADO fora de banda (.pem entregue, não servido por endpoint)
         ──► a estratégia de fetch PRECISA mudar: o httpJWKSFetcher pressupõe um
             endpoint. Abrir issue de follow-up para um fetcher de chave estática
             (ler o JWKS/PEM de um caminho/secret local em vez de HTTP). NÃO ligar a
             env var de URL nesse caso (passo 1.B).
```

> O verificador foi desenhado contra o modelo (A) porque é o que o `.env.example`
> documenta como exemplo (`…/.well-known/jwks.json`). O `jwksFetcher` é uma interface
> interna (`jws_verifier.go:53`) **justamente** para que o modelo (B) seja um novo
> adaptador de fetcher, sem tocar a lógica de seleção-por-`kid`/rotação/verificação.

### 1.A — Modelo endpoint (A): ligar a env var

1. Capturar a URL **real** do JWKS do sandbox/produção de homologação do C6.
2. Confirmar que ela é **https** e que responde um JWKS com ≥1 chave **pública**
   (`json` com `keys[]`). Uma URL `http://` falha o boot por design.
3. Setar no ambiente (NUNCA commitar valor real — é config de ambiente, não segredo,
   mas mora no `.env` do ambiente / secret manager):

   ```bash
   PAYMENT_C6_REC_JWKS_URL=https://<host-real-do-c6>/<caminho-jwks-capturado>
   ```

   `<host-real-do-c6>` / `<caminho-jwks-capturado>` **só são conhecidos após a
   captura** — preencher aqui é o ato de go-live.
4. Subir o binário e confirmar o log `api: C6 recurrence JWS verifier configured`
   (`cmd/api/main.go:273`).
5. Smoke: uma leitura `GetRec`/`GetCobR` válida retorna corpo verificado (não
   `ErrUnavailable`); um `kid` desconhecido / assinatura inválida falha fechado.

> Se o JWKS é servido **atrás do mesmo mTLS** da API C6, o cliente mTLS já é
> reutilizado pelo verificador (`main.go`, `c6cfg.HTTPClient`) — nenhum passo
> extra. Se for um host TLS público distinto, o verificador constrói o próprio
> cliente TLS-1.2+.
>
> ⚠️ **Carimbo de tenant no fetch do JWKS (SIN-69375).** O fetch do JWKS é
> **process-wide** e não tem tenant natural, então ele não carimba tenant. Com o
> transporte mTLS **baseado no cofre por tenant** (SIN-69368), um request sem tenant
> cai no slot de **cert bootstrap §8** (`PAYMENT_C6_CLIENT_CERT`/`_KEY`). Numa
> implantação **vault-only** (Verz — sem cert §8 configurado, cada cert vem do cofre),
> esse fetch apresentaria **cert de cliente vazio** e o handshake mTLS do JWKS
> **falha fechado** — quebrando a verificação de assinatura de TODA leitura de
> recorrência. Não é brecha (fail-closed), mas quebra a funcionalidade. Duas
> resoluções (qualquer uma basta):
>
> - **(a) operacional:** manter o cert bootstrap §8 (`PAYMENT_C6_CLIENT_CERT`/`_KEY`)
>   configurado enquanto a recorrência estiver ligada — o fetch tenantless usa esse
>   cert.
> - **(b) código (preferida em vault-only):** setar `PAYMENT_C6_REC_JWKS_MTLS_TENANT`
>   com o **tenant designado** cujo certificado no cofre satisfaz o mTLS do endpoint
>   JWKS. O verificador carimba esse tenant no fetch (`WithMTLSTenant`) e apresenta o
>   cert desse tenant — sem depender do cert §8. Vazio (default) mantém o
>   comportamento anterior (tenantless → cert §8, ou nenhum). Só tem efeito quando o
>   JWKS está atrás de mTLS; num JWKS público o carimbo é inerte.
>
> Se o JWKS for um **host TLS público** (sem client cert), nada disso se aplica —
> deixe `PAYMENT_C6_REC_JWKS_MTLS_TENANT` vazio.

### 1.B — Modelo cert-pinado (B): NÃO ligar a URL

Se a captura mostrar entrega out-of-band, **parar aqui**, manter a env var **vazia**
(recorrência fica fail-secure) e abrir follow-up para o fetcher de chave estática.
Ligar uma URL inexistente só produziria boot-fail ou fetch-fail — ambos fail-secure,
mas sem habilitar a recorrência.

---

## 2. Allowlist de algoritmo (residual 2)

**Estado atual (justificado — manter os dois até a captura):** o verificador aceita
`{PS256, ES256}` (`defaultRecVerifierAlgs`, `jws_verifier.go:41`) — **apenas**
assinaturas de chave pública. `alg:none` (não assinado) e `HS*` (MAC simétrico) estão
**ausentes** da allowlist, logo são rejeitados no `ParseSigned` **antes** de qualquer
chave ser consultada (defesa key-confusion: o atacante não pode apresentar a chave
pública como segredo HMAC). Os dois algoritmos restantes são ambos seguros e
assimétricos; a superfície de ataque que sobra é mínima.

**Justificativa para NÃO estreitar agora:** o algoritmo único que o C6/BACEN emite só
é conhecido com certeza **na captura de homologação** (residual 1). Estreitar antes da
captura corre o risco de rejeitar a assinatura legítima do C6 no go-live (recorrência
falharia fechada por allowlist, não por ataque). A postura segura pré-captura é
**aceitar os dois algoritmos seguros** e estreitar assim que a captura confirmar o
emissor — o custo de manter os dois é desprezível, o custo de estreitar errado é um
go-live quebrado.

**Procedimento de estreitamento (executar quando a captura confirmar o alg único):**
sem mudança de código de produto — o wiring já expõe a opção. Em `cmd/api/main.go`,
passar `WithAlgorithms` ao construir o verificador:

```go
// exemplo: C6 confirmado emitindo apenas ES256
verifier, err := c6.NewJWSVerifier(cfg.C6.RecJWKSURL, c6cfg.HTTPClient,
    c6.WithAlgorithms(jose.ES256))
```

`WithAlgorithms` ignora slice vazio/nil (o default seguro permanece) e **nunca** deve
receber `HS*`/`none` (`jws_verifier.go:81`). Acompanhar com um teste que trave a
allowlist estreitada (RED se um JWS no outro algoritmo passar).

> Decisão de fechamento: **manter `{PS256, ES256}` até a captura**; estreitar é um
> follow-up barato gated pela confirmação do emissor, não um bloqueador de go-live.

---

## 3. Fronteira de frescor / replay (residual 3)

**O que o verificador valida e o que NÃO valida.** `VerifyJWS`
(`jws_verifier.go:139`) valida **assinatura**: o documento foi assinado por uma chave
pública conhecida do C6 (selecionada pelo `kid` do header **protegido**), com um
algoritmo da allowlist. Ele **NÃO** valida **frescor**: não inspeciona `iat`/`exp`
nem qualquer carimbo temporal. Uma leitura assinada **válida-mas-velha** verifica com
sucesso.

**Por que isso é seguro — onde o frescor é de fato garantido.** O replay de uma
leitura de recorrência assinada-mas-velha é limitado pela camada de
**reconcile-before-settle**, não pelo verificador:

- As leituras `GetRec`/`GetSolicRec`/`GetCobR` são **reconciliação**: o consumidor
  (`internal/app/webhook_recurrence.go`) **relê a verdade autoritativa do C6** antes
  de confiar em qualquer notificação de status, e **compara o status** terminal
  corrente. Um documento assinado velho que reflita um estado já superado é
  reconciliado contra o estado atual; ele não consegue "ressuscitar" uma transição.
- O webhook que dispara a reconciliação é **deduplicado** por `event_key` na mesma
  unidade de trabalho transacional (reconcile-before-settle, ameaça W3) — um replay de
  entrega é descartado (`reconcileRecurrence`, `webhook_recurrence.go:112`). Um corpo que referencie um
  mandato/cobrança que o banco não reconhece é `ack`ado e **dropado** (sem settle).
- A liquidação efetiva (quando existir) lê pela **leitura imediata PIX verificada por
  BACEN**, não pelo genérico `/charges` ([ADR-0002](../security/adr-0002-c6-settlement-reconcile-via-pix.md)).

**Conclusão de conformidade.** A não-validação de frescor no verificador é uma
**decisão consciente**: frescor de mandato é responsabilidade do reconcile-before-settle
(comparação de status na releitura autoritativa), não do verificador de assinatura.
Adicionar checagem de `iat`/`exp` no verificador seria defesa-em-profundidade
**opcional**, mas exigiria que o C6 garantisse contratualmente carimbos temporais nos
documentos assinados (a confirmar na captura — residual 1). Sem esse contrato,
impor `exp` arriscaria recusar leituras legítimas. A fronteira fica registrada aqui
como invariante de go-live: **assinatura no verificador, frescor no reconcile**.

---

## 4. Checklist de go-live (operador)

- [ ] Captura de homologação do C6 disponível (pré-condição 0.3).
- [ ] Item 1: fonte do JWKS confirmada — modelo (A) endpoint **ou** (B) cert-pinado.
  - [ ] (A) `PAYMENT_C6_REC_JWKS_URL` setada com a URL https real; log
    `recurrence JWS verifier configured`; smoke de leitura verificada OK.
  - [ ] (B) follow-up de fetcher estático aberto; env var **mantida vazia**.
- [ ] Item 2: allowlist estreitada ao alg confirmado **ou** justificativa
  ({PS256, ES256}) mantida e registrada (§2).
- [ ] Item 3: fronteira frescor/replay registrada (este runbook §3) e referenciada no
  roteiro de conformidade.
- [ ] SecurityEngineer re-review dos 3 residuais.

## 5. Rollback

Recorrência é ligada por **uma** env var. Para desligar em qualquer incidente: limpar
`PAYMENT_C6_REC_JWKS_URL` (vazio) e reiniciar — o verificador volta a `nil` e todas as
leituras de recorrência voltam a falhar fechado (`ErrUnavailable`). Sem migração, sem
estado a reverter; o desligamento é fail-secure por construção.

# Monitoramento recorrente do Termo / API C6 (F21)

**Fonte contratual:** Termo de Uso de APIs C6, cláusulas **2.8 / 2.9 / 11.5** (item **F21** da gap-analysis — ver [`c6-termo-apis-regras.md`](./c6-termo-apis-regras.md), SIN-68740).

> É **nossa responsabilidade** verificar atualizações no site `developers.c6bank.com.br`. Mudanças podem afetar adversamente a Solução; em conflito, **prevalece o Termo**. (SIN-68746)

**Lentes:** boring technology, reversibility. Nada de scraper JS frágil; sinais públicos, estáveis e diffáveis. Baseline versionado em git → toda mudança é auditável e reversível.

---

## 1. O que é automatizável (público, sem login, sem JS)

O portal `developers.c6bank.com.br` é **publicamente acessível** (sem autenticação para a documentação). É uma SPA React que renderiza a referência de API via **Scalar** a partir de specs OpenAPI. Isso dá dois sinais robustos que **não exigem renderizar JS**:

| Sinal | Fonte | O que uma mudança significa | Força |
|-------|-------|-----------------------------|-------|
| **Conjunto de URLs do sitemap** | `GET /sitemap.xml` → set de `<loc>` | Página de API **adicionada/removida** (ex.: novo produto, endpoint depreciado) = mudança **material** de contrato | Alta — significativo e de baixo ruído |
| **Hash de assets estáticos** | `index.html` → `static/js/main.<hash>.js`, `static/css/main.<hash>.css` | Portal **republicado** (qualquer edição de conteúdo, inclusive release-notes) | Média — captura tudo, porém ruidoso (todo redeploy dispara) |

O baseline destes sinais vive em [`c6-portal-baseline.json`](./c6-portal-baseline.json).

> **Por que o `lastmod` do sitemap sozinho não basta:** todas as 17 URLs compartilham o mesmo `lastmod` (timestamp de build) — bump em todo deploy, sem granularidade por página. Por isso usamos o **conjunto de URLs** (materialmente significativo) + **hash de assets** (catch-all), não o `lastmod`.

## 2. O que é operator-gated (NÃO agent-doable — exceção documentada)

| Item | Por quê | Dono nomeado |
|------|---------|--------------|
| **Prosa das release-notes** (`/apis/release-notes`) | Renderizada por JS (Scalar/OpenAPI) — não diffável via `curl` | Revisão manual pelo **CTO** quando um sinal §1 dispara |
| **Termo de Uso de APIs (PDF, cláusulas 2.8/2.9/11.5)** | **Não publicado no portal público** — entregue pelo C6 ao titular da conta via canal autenticado (conta/e-mail) | **CTO** (impacto técnico) + **CEO** (relação comercial / canal com o C6) |

Estes itens **não têm issue-blocker Paperclip apontável** — são ações de operador/humano. A routine **não** tenta automatizá-los; ela emite um **lembrete mensal de revisão manual** e nomeia o dono acima. (Exceção legítima à regra "todo trabalho tem blocker de 1ª classe" — o wake-path é humano.)

---

## 3. Procedimento de triagem (executado pela routine a cada fire)

A routine Paperclip **`C6 Termo/API monitor (F21)`** (mensal, dia 3, 09:11 America/Sao_Paulo, assignee **CTO**) cria uma run-issue a cada disparo. Ao acordar nessa run-issue, o CTO executa:

1. **Buscar sinais atuais** (público, sem auth):
   ```sh
   curl -s https://developers.c6bank.com.br/sitemap.xml
   curl -s https://developers.c6bank.com.br            # extrair static/js|css/main.<hash>
   ```
2. **Comparar com o baseline** `docs/compliance/c6-portal-baseline.json`:
   - `url_set_sha256` diferente **ou** `urls[]` com item novo/removido → **mudança material candidata**.
   - `static_assets` com hash diferente → **portal republicado** → revisar release-notes manualmente.
3. **Classificar:**
   - **Sem diff** → logar `no-change` na run-issue → `done`. Fim.
   - **Só assets mudaram** (URLs iguais) → abrir `/apis/release-notes` e demais páginas `/apis/*` relevantes, avaliar se há mudança que afete a Solução (Auth, PIX, PIX Automático, Boleto, Checkout, Webhook, Extrato, Erros). Se material → passo 4. Se cosmético → logar + atualizar só o hash no baseline.
   - **URLs mudaram** → **sempre** tratar como material → passo 4.
4. **Ao detectar mudança material:**
   1. **Abrir issue de impacto** (child de SIN-68740 ou da umbrella C6 vigente), prioridade conforme risco, descrevendo: página(s) afetada(s), diff observado, cláusula do Termo potencialmente impactada, e ação (revisar adapter em `internal/adapters/bank/c6/`, atualizar DTOs/contrato, etc.).
   2. **Atualizar** `docs/compliance/c6-termo-apis-regras.md` com a mudança e a data.
   3. **Atualizar o baseline** `docs/compliance/c6-portal-baseline.json` (novo `url_set_sha256`/`urls`/hashes + `captured_at`) via PR docs-only — isso "reconhece" a mudança e evita re-disparo no mês seguinte.
5. **Lembrete operator-gated (sempre):** na run-issue, registrar o lembrete de que o **Termo de Uso (PDF)** deve ser conferido pelo canal de conta/e-mail do C6 (dono: CTO+CEO), já que não é observável no portal público.
6. **Encerrar** a run-issue: `done` com resumo (`no-change` | `material-change → SIN-XXXXX aberta` | `assets-only cosmetic`).

> **Regra de higiene:** o baseline só é atualizado **junto** com a issue de impacto (ou com a nota de "cosmético"). Nunca atualizar o baseline silenciosamente sem triar — isso apagaria o sinal.

---

## 4. Reversibilidade / blast radius

- **Reversível:** baseline e docs são versionados; reverter é um `git revert`.
- **Blast radius nulo:** a routine só **lê** o portal público e **abre issues/PRs de docs** — não toca produção, credenciais nem o adapter em runtime.
- **Boring:** `curl` + diff de JSON + cron mensal. Sem dependência nova, sem headless browser.

## 5. Manutenção da routine

- Routine id: ver `GET /api/companies/{companyId}/routines` (título `C6 Termo/API monitor (F21)`).
- Pausar: `PATCH /api/routines/{id} {"status":"paused"}`.
- Mudar cadência: `PATCH /api/routine-triggers/{triggerId} {"cronExpression":"<novo>"}`.
- Se o portal migrar de tecnologia (deixar de expor sitemap/assets hashados), esta §1 precisa ser refeita — registrar como follow-up e cair no modo operator-gated (revisão manual mensal) até re-automatizar.

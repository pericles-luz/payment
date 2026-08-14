# ADR-0001 — Transporte de autenticação do console HTML no browser

> ⚠️ **SUPERSEDED por [ADR-0010](adr-0010-console-self-contained-login.md) (2026-08-14, SIN-69265).**
> O board reverteu a decisão: adotou-se a **Opção B** (login self-contained na
> aplicação — usuário + senha + TOTP + cookie de sessão) no lugar da Opção A
> (proxy de borda injeta `Authorization: Bearer`). Este ADR fica como **registro
> histórico**; os três requisitos de CSRF que ele antecipava para a Opção B estão
> **atendidos** no ADR-0010. A Opção A permanece como fallback documentado.

- **Status:** Superseded por ADR-0010 (Opção B) em 2026-08-14 — originalmente Aceito (Opção A), ratificado pelo CTO em 2026-06-13 (L2 de [SIN-64741](/SIN/issues/SIN-64741)).
- **Contexto da review:** follow-up de defense-in-depth da review de segurança do PR #6 ([SIN-64740](/SIN/issues/SIN-64740)). Não bloqueou merge; aceite de risco do estado atual já registrado na review.
- **Autor:** Coder. **Decisor:** CTO.

## Contexto

O console HTML (`/console`, SIN-64727) é renderizado server-side com HTMX sobre o
plano admin. Hoje ele autentica **exclusivamente** via header
`Authorization: Bearer <admin-token>` — não há session cookie de primeira parte
emitido pela aplicação.

Em paralelo, o grupo `/console` já está protegido por CSRF double-submit
(`csrf.go`): em requisições seguras um token aleatório é semeado num cookie
`HttpOnly` e ecoado no HTML; em mutações o valor submetido (header `X-CSRF-Token`
ou campo de formulário) precisa bater com o cookie, comparado em tempo constante.

Os comentários de `csrf.go` descrevem a proteção como sendo para páginas
"cookie-authenticated". Isso gera uma ambiguidade: **se a autenticação é só por
bearer header (não-ambiente), o CSRF é estritamente belt-and-suspenders** — um
atacante cross-origin não consegue forjar o header `Authorization`, então não há
superfície CSRF clássica. O CSRF está correto de qualquer forma; a questão é
documentar qual transporte de auth no browser é o pretendido, porque isso decide
se o modelo CSRF é redundante (opção A) ou *load-bearing* (opção B).

## Opções

### Opção A — Header `Authorization` injetado por proxy reverso (recomendada)

O ingress/edge autentica a sessão do operador (SSO corporativo, mTLS de cliente,
ou portal interno) e injeta `Authorization: Bearer <admin-token>` na requisição
upstream. A aplicação permanece *stateless* quanto a sessão: nenhum cookie de
sessão de primeira parte é emitido.

- **Prós:** mantém o transporte de auth idêntico entre o plano JSON `/admin` e o
  HTML `/console` (um só mecanismo a auditar); a aplicação não gerencia ciclo de
  vida de sessão; não há superfície CSRF dependente de cookie ambiente — o
  double-submit existente fica como defesa redundante, sem custo.
- **Contras:** depende de configuração correta do edge (o token nunca pode
  vazar para o browser nem aparecer em URL/log); exige que o proxy seja confiável
  e o app só seja alcançável através dele.
- **Impacto no CSRF:** nenhuma mudança necessária. O double-submit continua
  válido e barato; mantê-lo é defense-in-depth.

### Opção B — Session cookie de primeira parte (futuro)

A aplicação passa a emitir um cookie de sessão (`HttpOnly`, `Secure`,
`SameSite`) após login, e o console passa a autenticar por esse cookie ambiente.

- **Prós:** login self-contained sem depender do edge para injetar header;
  experiência de browser idiomática.
- **Contras:** introduz superfície CSRF **real** (cookie ambiente é enviado pelo
  browser automaticamente em requisições cross-origin); o double-submit de
  `csrf.go` deixa de ser redundante e passa a ser **obrigatório e load-bearing**;
  a aplicação assume gestão de sessão (expiração, revogação, rotação).
- **Impacto no CSRF:** o modelo double-submit existente **continua válido** para
  cobrir esse caso — foi desenhado exatamente para páginas cookie-authenticated.
  Requisitos ao adotar B: (1) garantir `SameSite=Lax|Strict` no cookie de sessão;
  (2) confirmar que toda mutação passa pelo `CSRFProtect`; (3) o cookie de CSRF e
  o de sessão devem compartilhar a política `Secure` dirigida por config
  (`SecureCookies`, já implementado — TLS termina no proxy, então `r.TLS` é nil).

## Decisão (ratificada pelo CTO)

Adotar a **Opção A** como transporte pretendido no browser para o estado atual:
o `Authorization: Bearer` é injetado pelo proxy reverso a partir de uma sessão
autenticada no edge. Manter o CSRF double-submit como defense-in-depth.

**Justificativa por lente (CTO):**
- **Secure-by-default API / Least privilege:** o bearer não é credencial ambiente
  e nunca alcança o browser; o token vive entre edge e app. Não há superfície CSRF
  clássica e o app não custodia ciclo de vida de sessão — menor escopo de risco.
- **Boring technology / Reversibilidade:** mantém um único mecanismo de auth entre
  `/admin` (JSON) e `/console` (HTML); zero gestão de sessão a construir agora.
  Blast radius mínimo — a única mudança decorrente é comentário, sem runtime.
- **Defense in depth:** o double-submit permanece wired mesmo sendo redundante hoje,
  então a adoção futura da Opção B não exige redesign.

**Condição de operação (não-negociável para a Opção A):** o app só pode ser
alcançável através do proxy confiável, e o proxy deve garantir que o token nunca
vaze para o browser nem apareça em URL/log. Essa premissa de deploy deve constar
do runbook de ingress antes do go-live; registro como follow-up de infra.

Quando/se a Opção B for adotada no futuro, o modelo CSRF existente já cobre o
caso — abrir issue dedicada para a gestão de sessão e tornar os três requisitos
acima parte do aceite.

**Ação de documentação concluída por este ADR:** atualizar o comentário de
`csrf.go` para refletir que o transporte atual é bearer-via-proxy (não cookie de
sessão), mantendo a explicação de por que o double-submit permanece.

## Consequências

- O comentário-cabeçalho de `csrf.go` foi ajustado para nomear o transporte atual
  (bearer injetado por proxy) e deixar claro que o double-submit é redundante hoje
  e load-bearing sob a Opção B.
- Nenhuma mudança de código de runtime decorre desta decisão (A) além do
  comentário; a Opção B, se escolhida, vira issue própria.
- **Ratificado:** CTO confirmou a Opção A em 2026-06-13; ADR marcado `Aceito`.
- **Follow-up de infra (concluído):** a premissa de deploy está documentada como
  pré-requisito de go-live em [`../ops/ingress-runbook.md`](../ops/ingress-runbook.md)
  (app só acessível via proxy confiável; token nunca vaza para browser/URL/log;
  sessão do operador autenticada no edge antes da injeção do bearer) — [SIN-64744](/SIN/issues/SIN-64744).

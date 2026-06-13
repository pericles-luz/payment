# Runbook de ingress — premissa de deploy do console (Opção A)

- **Escopo:** ingress/edge em frente à aplicação de pagamentos (plano admin `/admin` JSON
  e console HTML `/console`).
- **Origem:** follow-up de infra de [SIN-64741](/SIN/issues/SIN-64741) ([SIN-64744](/SIN/issues/SIN-64744)).
  Decisão arquitetural em [`../security/adr-0001-console-browser-auth-transport.md`](../security/adr-0001-console-browser-auth-transport.md)
  (Aceito — **Opção A**).
- **Lentes:** secure-by-default, least privilege, defense-in-depth.

> ⚠️ **Bloqueio de go-live.** As três premissas abaixo são **pré-requisito
> não-negociável** para colocar o console em produção. A Opção A do ADR-0001 só é
> segura sob elas. Se qualquer uma não puder ser garantida pelo edge, **o go-live
> não acontece** até ser resolvida ou até o ADR ser revisto (ver §4).

## 0. Por que isto importa

O console HTML autentica **exclusivamente** via header `Authorization: Bearer
<admin-token>` — a aplicação é *stateless* quanto a sessão e **não** emite cookie
de sessão de primeira parte. Esse bearer **não é uma credencial de ambiente do
browser**: ele só existe no salto entre o proxy confiável e a aplicação. Quem
autentica o operador é o **edge** (SSO/mTLS/portal), que então injeta o bearer
upstream.

Esse modelo elimina a superfície CSRF clássica (um atacante cross-origin não forja
o header `Authorization`) e dispensa gestão de sessão na app — mas **transfere a
fronteira de confiança inteira para o edge**. Se o edge for mal configurado, não há
segunda barreira na aplicação. Daí as três premissas serem duras.

## 1. Premissa A — App só acessível através do proxy confiável

A aplicação **nunca** pode ser alcançável diretamente; todo tráfego de produção
passa pelo proxy reverso confiável.

**Por quê (least privilege / defense-in-depth):** a app confia no header
`Authorization` injetado pelo edge. Se a app for acessível por fora do proxy, um
cliente pode injetar o próprio header `Authorization: Bearer` e contornar a
autenticação de borda (SSO/mTLS) inteiramente — *bypass* total do controle de
acesso (OWASP A01).

**Como garantir (escolher pelo menos uma, preferir camadas):**
- A app escuta apenas em rede privada / loopback / socket interno; só o proxy
  alcança o upstream (network-level).
- Política de rede / security group / firewall que só admite a origem do proxy na
  porta do upstream.
- mTLS entre proxy e app (o upstream exige cert de cliente que só o proxy possui).

**Verificação de go-live:**
- [ ] A partir de uma rede externa (fora do segmento do proxy), uma tentativa de
      conexão direta ao host:porta da app **falha** (connection refused / timeout /
      403), não responde com página do console.
- [ ] `curl` direto ao upstream com `Authorization: Bearer <token-de-teste>` a
      partir de fora do proxy **não** autentica.
- [ ] A binding address do processo da app está documentada e **não** é `0.0.0.0`
      em interface pública sem firewall na frente.

## 2. Premissa B — Token nunca vaza para o browser, URL ou log

O `admin-token` injetado pelo proxy **nunca** pode chegar ao browser, aparecer em
URL/query string, nem ser persistido em log (do proxy, da app, ou de
observabilidade).

**Por quê (least privilege / cryptographic failures – OWASP A02/A09):** o token é
uma credencial de alto privilégio do plano admin. Se vaza para o browser
(DevTools, histórico, extensão), para a URL (referer header, log de acesso,
analytics) ou para log (agregadores, SIEM, telas de suporte), o blast radius é
comprometimento administrativo completo do tenant/plataforma.

**Como garantir:**
- O proxy injeta o header **apenas no salto upstream**; a resposta ao browser
  **nunca** ecoa o `Authorization`.
- O token vai em **header**, nunca em URL/query string (regra do secure-baseline:
  "no secrets in URLs").
- **Scrubbing de log obrigatório** no proxy e na app: o header `Authorization`
  (e o token) é redigido/omitido em access logs e logs de aplicação.
- Em mTLS de cliente como mecanismo de borda, não há token em trânsito ao browser —
  preferível quando viável.

**Verificação de go-live:**
- [ ] Inspecionar uma resposta real do `/console` no browser (DevTools → Network):
      nenhum header/cabeçalho de resposta nem corpo contém o admin-token.
- [ ] Access log do proxy de uma requisição autenticada **não** contém o valor do
      `Authorization`/token (redação ativa).
- [ ] Log da aplicação de uma requisição autenticada **não** contém o token.
- [ ] Nenhuma rota do console recebe o token via query string (grep de
      `?...token=` / `?...authorization=` nos logs de acesso retorna vazio).
- [ ] Pipeline de observabilidade (SIEM/agregador) tem regra de scrubbing para
      `Authorization` confirmada.

## 3. Premissa C — Sessão do operador autenticada no edge; proxy injeta o bearer

A identidade do operador é estabelecida **no edge** (SSO corporativo, mTLS de
cliente, ou portal interno). Só após autenticar o operador o proxy injeta o
`Authorization: Bearer <admin-token>` na requisição upstream.

**Por quê (secure-by-default / deny-by-default):** a app não autentica o humano —
ela confia que quem chega via proxy já foi autenticado. Se o proxy injeta o bearer
**incondicionalmente** (sem antes validar a sessão do operador), qualquer um que
alcance o proxy vira admin. A injeção do bearer tem de ser **consequência** da
autenticação de borda, nunca anterior a ela.

**Como garantir:**
- O proxy só injeta o `Authorization` **depois** de validar a sessão de edge
  (cookie de SSO válido / cert mTLS válido / sessão de portal ativa).
- Requisições sem sessão de edge válida são **negadas no edge** (302 para login /
  401 / 403) — nunca passam ao upstream com bearer injetado.
- Mapeamento operador→token (ou token único de serviço) documentado, com rotação
  de token definida.

**Verificação de go-live:**
- [ ] Requisição ao `/console` **sem** sessão de edge válida é barrada no proxy
      (redirect para login / 401), **não** chega ao upstream autenticada.
- [ ] Requisição **com** sessão de edge válida recebe o bearer injetado e
      autentica no upstream.
- [ ] Expiração/revogação da sessão de edge corta o acesso ao console na próxima
      requisição (não há sessão residual na app, que é stateless).
- [ ] Política de rotação do admin-token documentada.

## 4. Se uma premissa não puder ser garantida

Não force a Opção A num edge que não a sustenta. Caminhos:

- **Reabrir o ADR-0001** e avaliar a **Opção B** (session cookie de primeira parte
  emitido pela app). A Opção B move a autenticação para a aplicação e torna o CSRF
  double-submit (`csrf.go`) **load-bearing** em vez de redundante — abrir issue
  dedicada de gestão de sessão, com os requisitos do ADR §"Opção B" como aceite.
- Até a divergência ser resolvida, o console **não** vai a produção.

## 5. Checklist consolidado de go-live

Todos os itens abaixo verdadeiros antes de liberar o console em produção:

- [ ] **A** — App inacessível diretamente; só o proxy confiável alcança o upstream.
- [ ] **B** — Token não vaza para browser, URL ou log (scrubbing confirmado nos
      três pontos: browser, proxy, app + observabilidade).
- [ ] **C** — Sessão do operador autenticada no edge **antes** da injeção do bearer;
      sem sessão de edge → negado no proxy.
- [ ] **D** — Path `/webhooks/c6/*` mascarado em todo log (proxy, CDN, WAF, APM,
      mirroring); no máximo `/webhooks/c6/***`. Rotação/revogação de ref ensaiada (§7).
- [ ] ADR-0001 referenciado e premissa de deploy revisada pelo responsável de infra
      e pelo CTO.

## 6. Premissa D — Caminho do webhook C6 mascarado no log (segredo de capacidade)

> **Escopo distinto.** As premissas A–C cobrem o plano admin/console. A premissa D
> cobre o **ingress do webhook C6** (`/webhooks/c6/{tenantRef}`). Origem: gate de
> go-live levantado na review de segurança de [SIN-64753](/SIN/issues/SIN-64753)
> (PR #14, C6-D webhook), rastreado em [SIN-64773](/SIN/issues/SIN-64773) /
> [SIN-64774](/SIN/issues/SIN-64774).

O webhook C6 é **não-assinado**; a autenticidade por-tenant é um `tenantRef`
opaco de 256 bits carregado **no path da URL** (`/webhooks/c6/{tenantRef}`). Esse
ref É a credencial (ADR-0002/F4). A aplicação já está correta — resolve o ref para
o tenant id e loga apenas o tenant id resolvido, nunca o ref (ver a nota de ingress
em `internal/adapters/http/server.go` e o parsing de `config.WebhookRefs` em
`internal/platform/config/config.go`). Mas
**qualquer intermediário que registre o path completo** (access log de
nginx/Envoy/ALB, CDN, WAF, tracing/APM, request mirroring) persiste o segredo em
texto claro → disclosure de credencial → impersonação total do webhook daquele
tenant (OWASP A02/A09).

**Por quê é premissa dura:** assim como o admin-token (Premissa B), o blast radius
de um vazamento é comprometimento por-tenant. O path NUNCA pode aparecer em log.
Logar no máximo `/webhooks/c6/***`.

**Como garantir (mascarar/dropar o segmento de path para `/webhooks/c6/*`):**

- **nginx** — não logar `$request`/`$request_uri` crus nesse path; substituir por
  um literal mascarado:
  ```nginx
  map $uri $webhook_safe_uri {
      default          $request_uri;
      ~^/webhooks/c6/  "/webhooks/c6/***";
  }
  log_format masked '$remote_addr [$time_local] "$request_method $webhook_safe_uri $server_protocol" '
                    '$status $body_bytes_sent "$http_user_agent"';
  access_log /var/log/nginx/access.log masked;
  ```
  Atenção: `$request` contém o path cru — não usá-lo no formato. Validar que
  nenhum `log_format` ativo nesse path emite `$request` ou `$request_uri`.

- **Envoy** — `%REQ(:PATH)%` (e `%REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%`) loga o path
  cru. Para a rota do webhook: usar um access log dedicado que **omite** o path ou
  emite literal (`text_format` sem `%REQ(:PATH)%`), ou um filtro Lua/Wasm que
  reescreve o path logado para `/webhooks/c6/***`. Não herdar o formato default.

- **AWS ALB / CloudFront / AWS WAF** — access logs do ALB (`request`), logs padrão
  do CloudFront (`cs-uri-stem`) e logs do WAF (`uri`) gravam o path completo e
  **não permitem mascaramento seletivo por path**. Mitigações (escolher uma):
  (a) terminar o webhook num proxy próprio (nginx/Envoy) que mascara **antes** de
  qualquer hop logado; (b) desabilitar access logging para a rota/distribuição do
  webhook (listener/behavior dedicado); (c) se o log for inevitável, tratar esses
  logs como **portadores de segredo** (cripto em repouso, acesso restrito,
  retenção curta) **e** adotar rotação periódica de ref (§7). Para WAF, excluir o
  path do logging ou redigir via transform do Kinesis Firehose.

- **APM / tracing (OpenTelemetry, Datadog, New Relic)** — atributos `url.path` /
  `http.target` / `http.url` capturam o path. Configurar span processor / regra de
  obfuscação de URL que redige o path para `/webhooks/c6/***` nesse endpoint.

- **Request mirroring / traffic shadowing** (Envoy mirror, nginx `mirror`, service
  mesh) — duplica o path cru para o destino espelho e seus logs. **Desabilitar**
  mirroring para `/webhooks/c6/*`.

**Verificação de go-live:**
- [ ] Access log de um `POST /webhooks/c6/<ref>` real mostra `/webhooks/c6/***`,
      nunca o ref cru.
- [ ] Nenhum `log_format`/formatter ativo nesse path emite `$request`/`%REQ(:PATH)%`.
- [ ] Nenhum CDN/WAF/ALB captura o path cru (ou o webhook os contorna / logging
      desabilitado / logs tratados como portadores de segredo).
- [ ] APM/tracing redige `url.path` para o webhook.
- [ ] Nenhum request mirroring duplica o path.
- [ ] `grep -E '/webhooks/c6/[A-Za-z0-9_-]{43}' <access logs>` retorna **vazio**.
- [ ] Procedimento de rotação + revogação (§7) ensaiado uma vez em staging.

## 7. Rotação e revogação de tenantRef

O mapa `PAYMENT_WEBHOOK_REFS` (`ref -> tenantID`, parseado em
`config.WebhookRefs`) admite **múltiplos refs apontando para o mesmo tenant** —
isso habilita rotação sem downtime.

**Rotação (higiene periódica / suspeita leve):**
1. Cunhar um ref novo com `httpadapter.GenerateTenantRef()` (32 bytes CSPRNG,
   base64url, 43 chars).
2. Adicionar a entrada nova **ao lado** da antiga em `PAYMENT_WEBHOOK_REFS`
   (ex.: `refAntigo:tenantA,refNovo:tenantA`) e recarregar/redeployar config.
3. Atualizar a URL de callback no portal C6 para o ref novo.
4. Confirmar tráfego de entrada chegando pelo ref novo (tenant id resolvido no
   log da app).
5. Remover a entrada antiga de `PAYMENT_WEBHOOK_REFS` e redeployar. A URL antiga
   passa a 401 (failure-closed). Janela de overlap = zero downtime.

**Revogação (comprometimento / descomissionamento):**
- Remover a entrada do ref de `PAYMENT_WEBHOOK_REFS` e redeployar. O ref deixa de
  resolver → 401 uniforme; a capacidade de impersonação é revogada imediatamente.
- Se o tenant continua ativo, cunhar+registrar um ref novo e atualizar o C6
  (rotação acima). O ref nunca é logado em nenhuma etapa.

## Referências

- ADR-0001 — [`../security/adr-0001-console-browser-auth-transport.md`](../security/adr-0001-console-browser-auth-transport.md)
- Baseline de segurança — [`../security/secure-baseline.md`](../security/secure-baseline.md)
  (segredos, "no secrets in URLs", logging)
- Cookie `Secure` proxy-aware / TLS termina no proxy — [SIN-64731](/SIN/issues/SIN-64731)
- Webhook C6 / `tenantRef` como credencial (ADR-0002/F4) — nota de ingress em
  `internal/adapters/http/server.go`, parsing em `internal/platform/config/config.go`
  (`WebhookRefs`), geração em `internal/adapters/http/auth.go` (`GenerateTenantRef`).
- Premissa D — origem em [SIN-64753](/SIN/issues/SIN-64753) (PR #14, C6-D webhook),
  gate em [SIN-64773](/SIN/issues/SIN-64773) / [SIN-64774](/SIN/issues/SIN-64774).

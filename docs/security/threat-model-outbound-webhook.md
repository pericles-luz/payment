# Threat Model — Webhook de saída por Conta (outbound forward)

- **Issue:** [SIN-69489](/SIN/issues/SIN-69489) ([SIN-69486·TM], filho de [SIN-69485](/SIN/issues/SIN-69485)).
- **Status:** **GATE BLOQUEANTE DA F2 (forward).** Nenhum código de forward outbound
  merge antes do LGTM do SecurityEngineer neste documento. Este é o artefato de aceite.
- **Autor / dono do threat model:** SecurityEngineer.
  **Impl (após aceite):** Coder (F2). **Aprovação de PR:** review = SecEng → approval = CTO.
- **Modelo:** STRIDE sobre o caminho de forward + trust boundaries. Foco: viramos
  **provedor de entrega best-effort** para a Conta-revenda (ex. Verz) → a **URL de
  destino é user-supplied** → superfície **SSRF (OWASP A10)** de primeira classe.
- **Lentes:** OWASP **A10 (SSRF)** · **A01 (Broken Access Control / isolamento de
  Conta)** · Defense-in-depth · Least-privilege · **Fail-securely (failure-closed)**
  · Secure-by-default · Hexagonal (guard fora do domínio).
- **Referências:** ADR-0011 (account-key / modelo b); plano CTO em SIN-69486
  (decisões de produto do CEO ratificadas 2026-08-17); cofre AAD row-binding
  (`internal/adapters/secret/crypto.go:47` `SealWithAAD`/`OpenWithAAD`, migr 0012);
  limiter/backoff outbound (`internal/adapters/bank/c6/ratelimit.go`); inbound
  capability URL (`internal/adapters/http/handlers.go:307` `handleC6Webhook`);
  `AccountResolver` (`cmd/api/main.go:255`); `threat-model.md` (modelo-mãe);
  `threat-model-self-serve-credential-intake.md` (padrão de cofre write-only + audit).

---

## 1. Contexto e delta de superfície

Hoje todo webhook do sistema é **inbound**: o C6 chama a nossa capability URL
`POST /webhooks/c6/{tenantRef}` (`handleC6Webhook`). Essa superfície já é hardenada
(mesma-401 anti-enum, dedup por `event_key`, reconcile-before-settle, isolamento por
`tenantRef` CSPRNG hash-at-rest) — **não é o escopo deste TM**.

O delta da F2 inverte o fluxo: a cada evento inbound atribuído a uma Conta, nós
**originamos uma requisição HTTP de saída** para uma URL **configurada pela própria
Conta-revenda**. Isso introduz, pela primeira vez no serviço, um **cliente HTTP
server-side que disca para um destino escolhido por um ator semi-confiável**. Essa é
a definição canônica da superfície **SSRF (OWASP A10)**: o atacante controla o
destino da conexão que o NOSSO servidor abre, de dentro da NOSSA rede.

> **Princípio load-bearing (deriva o desenho inteiro):** a URL de destino é **dado
> hostil**. O forwarder deve tratá-la como não-confiável em **todo** acesso
> (complete mediation) — na escrita da config **e** no momento do dial de **cada**
> tentativa/hop — e falhar-fechado quando não puder provar que o IP de destino é
> público. Um destino não-provado-público é um destino recusado, não um destino
> tolerado.

### 1.1 Por que a validação no parse NÃO basta (TOCTOU / DNS-rebinding)

Validar o host na hora de **salvar** a config (`evil.com` resolve para `1.2.3.4`
público) e depois discar por hostname deixa uma janela clássica: entre a validação
e o dial, o dono de `evil.com` reaponta o DNS para `169.254.169.254` (metadata) ou
`127.0.0.1`. O nome continua "válido", mas o socket abre contra a rede interna. Por
isso o controle **obrigatório** é validar o **IP efetivamente discado**, no
`DialContext`/`Control` do `net.Dialer`, **depois** da resolução e **imediatamente
antes** de conectar — resolver → checar cada IP resolvido → discar **no IP validado**
(não re-resolver). Ver checklist §7 controle **SSRF-3**.

---

## 2. Ativos, atores, trust boundaries

| Ativo | Classe | Nota |
|---|---|---|
| **Posição de rede do servidor** (capacidade de originar conexões de dentro do perímetro) | **Crítico** | O alvo real do SSRF. Blast radius = tudo que o box alcança: metadata cloud, serviços internos, o próprio `payment` em `localhost`, DB, plano admin. |
| **Payload do evento** (dados de cobrança/recorrência de UMA Conta) | Confidencial | Vaza cross-Conta se atribuição falhar (A01). Contém, no pior caso, PII do devedor (`devedor_doc/nome`, ver `sin-68744`). |
| **Segredo HMAC de assinatura por Conta** | Confidencial (segredo) | Mesmo tier de credencial de banco. Write-only, cofre cifrado. |

**Atores:**
- **Conta-revenda (Verz e futuras):** configura a URL e detém o segredo HMAC.
  Semi-confiável — autenticada no `/console` (sessão + CSRF), mas **hostil-potencial**:
  pode apontar a URL para dentro da nossa rede de propósito. É o **atacante SSRF primário**.
- **C6 (upstream inbound):** dispara os eventos. Não deve **nunca** receber erro
  causado por falha de forward (senão vira canal de repúdio/DoS reflexivo — ver D3).
- **Rede interna / metadata endpoint:** vítima do SSRF. Sem credencial própria de
  defesa contra um cliente que fala de `localhost` — por isso o guard é a única barreira.

**Trust boundaries cruzadas no forward:**
1. `Conta (config)` → `OutboundEndpointStore` (escrita de URL+segredo). Validação SSRF #1.
2. `WebhookService (inbound, já atribuído à Conta)` → `OutboundForwarder` (fan-out).
   Boundary de **isolamento de Conta** (A01).
3. `OutboundForwarder` → **Internet pública** (o dial). Validação SSRF #2 (dial-time),
   a load-bearing.

**Hexagonal:** todo o forward vive em **adapters de saída**, fora do domínio.
Portas novas (do plano CTO §3): `OutboundEndpointStore`, `OutboundForwarder`,
`SSRFGuard`, `DeadLetterSink`. O domínio `outboundwebhook` só conhece
`OutboundEndpoint{accountID, url, secretRef, active}` — invariante `url https-only`;
o segredo **nunca** entra no agregado (só `secretRef` ao cofre). O `net/http.Client`
e o `net.Dialer` com o guard são detalhe de adapter.

---

## 3. STRIDE do caminho de forward

| # | Categoria | Ameaça | Sev. | Mitigação obrigatória na F2 |
|---|-----------|--------|------|------------------------------|
| **S1** | Spoofing | Forjar um evento de forward para uma Conta que o atacante não controla | Alta | Forward é disparado **só** pelo choke-point do `WebhookService` após atribuição server-side à Conta (F1). Não há endpoint que aceite "entregue X para a Conta Y" de fora. |
| **S2** | Spoofing (do NOSSO callback) | O receptor da Conta não consegue distinguir um POST nosso de um forjado por terceiro | Alta | **HMAC por Conta** (§5): o receptor verifica a assinatura. Sem assinatura válida ⇒ receptor descarta. |
| **T1** | Tampering | Adulterar a URL de destino em trânsito/repouso para redirecionar eventos | Alta | URL em repouso no store cifrado (mesmo cofre AAD row-binding). Config só via `/console` (sessão+CSRF, account-scoped). |
| **T2** | Tampering | Man-in-the-middle no forward lê/edita o payload | Alta | **https-only** (SSRF-1). TLS valida cert do destino (sem `InsecureSkipVerify`). |
| **R1** | Repudiation | Conta nega ter recebido / nós negamos ter tentado entregar | Média | `audit_log` append-only por tentativa: `account_id`, `endpoint_id`, `event_key`, resultado (`delivered`/`retry`/`dead_letter`), status HTTP, timestamp. **Nunca** o payload nem o segredo. |
| **I1** | **Info disclosure (SSRF read)** | URL aponta para `http(s)://169.254.169.254/…`, `localhost:PORT`, serviço interno → resposta interna volta ou side-channel (timing/erro) revela topologia/segredos internos | **Crítica** | **SSRF guard dial-time** (§4, SSRF-1..7). Além disso: a **resposta** do destino **nunca** é ecoada de volta em nenhum lugar; corpo da resposta é lido só p/ status e descartado (limite de bytes). Erros de forward **não** distinguem "conexão recusada" de "host bloqueado" para o operador externo. |
| **I2** | **Info disclosure (cross-Conta)** | Evento da Conta A entregue ao endpoint da Conta B → vazamento de PII/cobrança cross-tenant | **Crítica (A01)** | Atribuição fail-closed (F1): `endpoint` é carregado **por `accountID` resolvido server-side** do evento. `owner==""` ⇒ **dead-letter**, nunca fallback para outro endpoint. Ver §6. |
| **I3** | Info disclosure | Segredo HMAC vaza em log/URL/response/dead-letter | **Crítica** | Segredo **write-only** no cofre; `LogValue()`/redação (padrão C1/C4). Nunca em URL (é HTTP header de assinatura, computado server-side). Dead-letter grava metadados, não o segredo. |
| **D1** | DoS (outbound amplification) | Um flood de eventos inbound, ou um destino lento/caído, satura goroutines/conexões nossas | Alta | Limiter de saída **por Conta** + timeout curto por tentativa + teto de tentativas com backoff+jitter (reusa `ratelimit.go`) + fila/worker-pool limitada. Falha terminal ⇒ dead-letter, não retry infinito. |
| **D2** | DoS (SSRF-as-portscan / internal amplification) | Atacante usa o forwarder como proxy para varrer/martelar a rede interna variando a URL | Alta | SSRF guard bloqueia destinos internos **antes** do dial ⇒ não há alvo interno para varrer. Limiter por Conta limita a taxa de sondagem externa também. |
| **D3** | DoS (reflexão para o C6) | Falha de forward propaga erro para a resposta do webhook inbound ⇒ C6 re-tenta ⇒ tempestade | Alta | **Forward é best-effort e assíncrono ao ACK do inbound.** O handler inbound responde 2xx ao C6 **independente** do resultado do forward (reconcile-before-settle já garante a consistência interna). Falha de forward ⇒ retry interno/dead-letter, **nunca** status de erro ao C6. |
| **E1** | Elevation | Via SSRF, alcançar o plano admin/metadata e obter credencial de instância / escalar | **Crítica** | Igual I1: guard dial-time fecha o acesso à rede interna e ao metadata. Least-privilege do processo (sem role de nuvem ampla) é defesa em profundidade. |
| **E2** | Elevation (replay) | Reenviar um forward antigo capturado para o endpoint da Conta | Média | HMAC inclui **timestamp**; receptor rejeita fora da janela (§5). Do nosso lado, dedup por `event_key` evita re-forward do mesmo evento. |

**Conclusão STRIDE:** o risco está concentrado, como o CEO/CTO anteciparam, em
**I1/E1 (SSRF)** e **I2 (isolamento de Conta / A01)** — ambos **Críticos**. Os dois
são mitigados **por construção** (guard dial-time fail-closed + atribuição
server-side fail-closed), não por check espalhado. O resto é higiene de entrega
(HMAC, best-effort, limiter, redação) já com padrões existentes no repo para reusar.

---

## 4. SSRF — controles detalhados (A10, bloqueante F2)

O modelo já foi **aprovado pelo CEO** (SIN-69486 decisão 2). Aqui ratifico e detalho
os controles obrigatórios. **Todos são bloqueantes** salvo marcação explícita.

### 4.1 Onde vive (arquitetura hexagonal)
Adapter de saída `OutboundForwarder` + porta `SSRFGuard`. O guard é injetado no
`net.Dialer.Control` (ou `DialContext`) do `http.Transport` usado **exclusivamente**
para forwards. **Não** reusar o transport do C6 (que legitimamente fala com um host
externo fixo) — transport dedicado, sem proxy, sem cache de conexão cross-Conta que
possa mascarar re-resolução.

### 4.2 Controles (referenciados no checklist §7)

- **SSRF-1 — Scheme allowlist:** só `https`. `http`, `file`, `gopher`, `ftp`, `data`,
  etc. ⇒ rejeitado na escrita **e** no dial. Sem downgrade.
- **SSRF-2 — Bloqueio de destinos não-públicos (allowlist de "público", não denylist
  frágil).** Recusar se o IP resolvido cair em qualquer:
  - loopback `127.0.0.0/8`, `::1`
  - RFC1918 `10/8`, `172.16/12`, `192.168/16`
  - link-local `169.254.0.0/16` (**inclui metadata `169.254.169.254`**) e `fe80::/10`
  - **ULA IPv6 `fc00::/7`** (cobre `fd00::/8`)
  - `0.0.0.0/8`, unspecified `::`, broadcast `255.255.255.255`
  - multicast `224/4`, `ff00::/8`
  - **IPv4-mapped/compat IPv6** (`::ffff:127.0.0.1`, `::ffff:169.254.169.254`) — normalizar para o IPv4 subjacente **antes** de checar, senão o bypass clássico passa
  - `NAT64 64:ff9b::/96` (mapeia IPv4 privado em IPv6) — recomendado bloquear.
  Regra positiva: **só IP global-unicast público** passa. `net.IP.IsPrivate() ||
  IsLoopback() || IsLinkLocalUnicast() || IsLinkLocalMulticast() || IsMulticast() ||
  IsUnspecified()` cobre a maioria; ULA e mapped-IPv6 exigem checagem explícita.
- **SSRF-3 — Validação no DIAL, não só no parse (anti-TOCTOU/rebind).** No
  `Control`/`DialContext`: a resolução já ocorreu, o `address` recebido é
  `ip:port` **concreto**; validar **esse IP** contra SSRF-2 e recusar antes de
  conectar. Como o dialer disca no IP que ele mesmo resolveu (e nós validamos esse
  mesmo IP no `Control`), não há janela de re-resolução. **Este é o controle
  load-bearing** — validação só-no-parse é insuficiente (§1.1).
- **SSRF-4 — Sem redirects para rede interna.** `CheckRedirect` do client: por
  padrão **recusar TODO redirect** (`return http.ErrUseLastResponse` / erro). Se
  redirects forem necessários no futuro, **re-validar cada hop** pelo mesmo guard
  (SSRF-1..3) — nunca seguir um `Location` sem passar pelo dial-guard. Para v1,
  recomendo **zero redirects** (economia de mecanismo).
- **SSRF-5 — Porta:** só `443` (https implica). Recusar portas arbitrárias que
  facilitem port-probing interno. *(Recomendado; bloqueante se o custo for baixo.)*
- **SSRF-6 — Timeouts agressivos:** `DialTimeout`, `TLSHandshakeTimeout`,
  `ResponseHeaderTimeout`, timeout total por tentativa. Evita que um destino que
  "engole" a conexão vire vetor de DoS/timing-oracle (D1).
- **SSRF-7 — Resposta não-refletida + corpo limitado:** ler no máximo N KB da
  resposta (`io.LimitReader`) só para status; **nunca** ecoar corpo/headers do
  destino em log, audit, UI ou erro devolvido. Fecha o lado "read" do SSRF (I1).
- **SSRF-8 — Erro opaco ao configurador:** ao rejeitar uma URL (na escrita) ou uma
  tentativa (no dial), a mensagem ao operador da Conta é genérica
  ("destino não permitido"); **não** revela se o IP era interno, qual faixa bateu,
  nem se o host respondeu — para não virar oráculo de mapeamento interno.

### 4.3 Residual risk (SSRF)
- **DNS-rebinding com TTL 0 entre a resolução do dialer e o `Control`:** fechado
  porque validamos o **IP concreto** que o dialer resolveu, não o hostname; o Go
  resolve uma vez por dial e passa o IP ao `Control`. Se um futuro custom resolver
  reintroduzir gap, o teste **T-SSRF-rebind** (§8) pega.
- **Serviço público que é proxy aberto para rede interna do atacante:** fora do
  nosso modelo — só destinos públicos são alcançados; o que o destino faz com o
  POST é responsabilidade da Conta. HMAC garante autenticidade da origem.
- **IPv6 exótico/novas faixas reservadas:** mitigado pela regra positiva
  (só global-unicast público passa); manter a lista de bloqueio como defesa 2.

---

## 5. Assinatura HMAC por Conta

- **Algoritmo:** **HMAC-SHA256** (stdlib `crypto/hmac` + `crypto/sha256`). Sem
  algoritmo negociável no header (evita alg-confusion). Sem assinatura assimétrica
  (não precisamos — é MAC simétrico entre nós e a Conta).
- **Segredo:** por Conta, ≥256-bit CSPRNG, gerado por nós no provisionamento do
  endpoint, **write-only** no cofre cifrado (KEK vault + AAD row-binding), exibido
  **display-once** na criação/rotação (padrão account-key SIN-69278). Nunca lido de
  volta, nunca em log/URL.
- **O que entra no MAC:** `HMAC(secret, timestamp || "." || raw_body)` — o corpo
  **exato em bytes** que enviamos + o timestamp, ligados. Assinar o corpo cru (não
  um re-serialize) evita parser-differential entre o que assinamos e o que enviamos.
- **Headers:** `X-Webhook-Signature: sha256=<hex>` e `X-Webhook-Timestamp:
  <unix_seconds>`. (Nomes finais podem seguir convenção que a doc Verz publicar.)
- **Anti-replay:** o `X-Webhook-Timestamp` entra no MAC; a Conta receptora rejeita
  se `|now - timestamp|` > janela (recomendar 300s na doc). Do nosso lado, dedup por
  `event_key` impede re-forward do mesmo evento. O timestamp assinado impede que um
  atacante replaye um corpo capturado com timestamp novo (mudaria o MAC).
- **Rotação:** rotação de segredo é last-write-wins + auditada; durante a rotação a
  Conta pode aceitar as duas assinaturas por uma janela (detalhe de doc, não nosso).

---

## 6. Isolamento de Conta / A01 (Crítico)

Regra invariante da F2, herdada da F1:

> O endpoint de destino é **sempre** derivado do `accountID` **resolvido
> server-side** do evento inbound (`AccountResolver.ResolveAccountID(ctx,
> tenantID)`, `cmd/api/main.go:255`, sobre o `tenantRef` da capability URL). **Nunca**
> de nada no payload, header ou config do evento.

- **Fail-closed:** se a resolução Conta não retorna dono (`owner==""` / conta
  suspensa / endpoint inativo) ⇒ **dead-letter**, **sem** forward, **sem** fallback
  para qualquer outro endpoint (ADR-0011 T7). Um evento não-atribuível **nunca** é
  entregue "no melhor palpite".
- **Sem cross-Conta:** carregar o endpoint por `accountID` exato; um teste de
  isolamento (§8 T-ISO) prova que evento da Conta A **nunca** resolve o endpoint da
  Conta B, mesmo com IDs adjacentes/adivinháveis.
- **Sem erro pro C6:** falha de atribuição/entrega é registrada e dead-lettered; o
  ACK ao C6 permanece 2xx (D3). Repúdio coberto por `audit_log` (R1).
- **Dead-letter:** grava `event_key`, `tenantRef`-hash, motivo (`unassigned` /
  `delivery_exhausted` / `endpoint_inactive`), timestamp — **sem** payload PII em
  claro e **sem** segredo. Retenção segue política LGPD (`sin-68744`); se precisar
  guardar payload para replay manual, cifrar em repouso (cofre) e escopar por Conta.

---

## 7. Checklist de controles obrigatórios (o que a F2 DEVE satisfazer)

**Bloqueantes (merge-gate — sem estes o PR da F2 não passa no meu review):**

| ✔ | Controle | Classe | Verificação (teste em §8) |
|---|----------|--------|----------------------------|
| ☐ | SSRF-1 https-only (escrita **e** dial) | A10 | T-SSRF-scheme |
| ☐ | SSRF-2 bloqueio de loopback/RFC1918/link-local(+metadata)/ULA/mapped-IPv6/unspecified/multicast | A10 | T-SSRF-ranges (table-driven, um caso por faixa) |
| ☐ | SSRF-3 **validação no dial-time (Control/DialContext) sobre o IP concreto** | A10 | T-SSRF-rebind |
| ☐ | SSRF-4 sem redirects para rede interna (v1: zero redirects) | A10 | T-SSRF-redirect |
| ☐ | SSRF-7 resposta não-refletida + corpo limitado (`io.LimitReader`) | A10 (read) | T-SSRF-noecho |
| ☐ | A01 endpoint derivado de `accountID` server-side; **nunca** do payload | A01 | T-ISO-crossaccount |
| ☐ | Fail-closed: não-atribuível ⇒ dead-letter, sem fallback, sem forward | A01/Fail-secure | T-ISO-unassigned |
| ☐ | Best-effort: falha de forward **nunca** vira erro de resposta ao C6 (ACK 2xx) | DoS/D3 | T-ACK-independent |
| ☐ | HMAC-SHA256 por Conta, timestamp assinado no MAC, segredo write-only | Crypto/A02 | T-HMAC-sign, T-HMAC-tamper |
| ☐ | Segredo/URL: nunca em log/URL/response/dead-letter (redação `LogValue`) | Info-disc | T-REDACT |
| ☐ | Timeouts (dial/TLS/response/total) + teto de tentativas com backoff+jitter | DoS/D1 | T-TIMEOUT, T-RETRY-cap |
| ☐ | Limiter de saída **por Conta** (reusa `ratelimit.go`) | DoS/D1-D2 | T-LIMITER-peraccount |
| ☐ | Segredo em repouso no cofre cifrado (KEK + AAD row-binding, migr do store) | A02 | T-VAULT-aad |
| ☐ | `audit_log` por tentativa (account-scoped), sem payload/segredo | Logging/R1 | T-AUDIT |
| ☐ | Flag `PAYMENT_OUTBOUND_WEBHOOK` default-off; forward dark até ligar | Reversib. | T-FLAG-off |

**Recomendados (não-bloqueantes; documentar decisão se omitidos):**

| ✔ | Controle | Nota |
|---|----------|------|
| ☐ | SSRF-5 porta restrita a 443 | baixo custo; recomendo bloqueante |
| ☐ | SSRF-8 erro opaco ao configurador (anti-oráculo de topologia) | evita mapeamento interno |
| ☐ | NAT64 `64:ff9b::/96` na denylist | defesa 2 além da regra positiva |
| ☐ | Transport HTTP **dedicado** ao forward (não reusar o do C6) | isolamento de conexão |
| ☐ | Dead-letter com payload cifrado p/ replay manual escopado por Conta | operabilidade |
| ☐ | Métrica/alerta de taxa de dead-letter por Conta | detecção de abuso/config quebrada |

---

## 8. Casos de teste de abuso (obrigatórios no PR da F2)

Cada teste deve **falhar contra código sem o controle** e passar com ele
(regressão que encoda a vulnerabilidade). Cobertura >85% no pacote `outboundwebhook`.

1. **T-SSRF-ranges** (table-driven): para cada destino em
   `{127.0.0.1, 10.0.0.5, 172.16.0.1, 192.168.1.1, 169.254.169.254, ::1, fe80::1,
   fd00::1, ::ffff:127.0.0.1, ::ffff:169.254.169.254, 0.0.0.0, 224.0.0.1}` →
   forward **recusado no dial**, endpoint jamais conectado. Usar um resolver/dialer
   fake que devolve o IP alvo.
2. **T-SSRF-rebind:** hostname resolve para IP público na escrita da config, mas o
   dialer resolve para `169.254.169.254` no dial → **recusado** (prova que a
   validação é no dial-time, não no parse).
3. **T-SSRF-scheme:** `http://`, `file://`, `gopher://` na config → rejeitados na escrita.
4. **T-SSRF-redirect:** destino público responde `302 Location:
   http://169.254.169.254/…` → forwarder **não segue** (v1 zero-redirect).
5. **T-SSRF-noecho:** destino devolve corpo grande/secreto → nosso audit/log/erro
   **não** contém o corpo; leitura limitada por `io.LimitReader`.
6. **T-ISO-crossaccount:** evento resolvido para Conta A **nunca** carrega o endpoint
   da Conta B (IDs adjacentes). Prova A01.
7. **T-ISO-unassigned:** evento com `owner==""` → **dead-letter**, zero forward, zero
   fallback.
8. **T-ACK-independent:** forward falha (destino 500/timeout) → resposta ao inbound
   C6 permanece **2xx** (best-effort; sem reflexão de erro).
9. **T-HMAC-sign / T-HMAC-tamper:** assinatura verifica com o segredo certo;
   corpo/timestamp adulterado → assinatura inválida (o receptor rejeitaria).
10. **T-REDACT:** `LogValue()`/erros/dead-letter **nunca** contêm o segredo HMAC nem a
    URL em claro sensível; secret write-only (sem GET).
11. **T-TIMEOUT / T-RETRY-cap:** destino lento respeita timeout; nº de tentativas
    limitado com backoff; após teto → dead-letter (sem loop infinito).
12. **T-LIMITER-peraccount:** flood de eventos de uma Conta é throttled sem afetar
    entrega de outra Conta.
13. **T-VAULT-aad:** segredo selado com AAD row-binding; troca de row → `OpenWithAAD`
    falha (não deserializa cross-row).
14. **T-FLAG-off:** com `PAYMENT_OUTBOUND_WEBHOOK` off, nenhum forward é originado.

---

## 9. Decisão do gate

- **SSRF (A10):** modelo do CEO **ratificado**; controles SSRF-1..8 detalhados e
  tornados testáveis. O controle **load-bearing é SSRF-3 (dial-time)** — sem ele, o
  resto é bypassável por rebind. **Bloqueante.**
- **Isolamento de Conta (A01):** fail-closed server-side + dead-letter. **Bloqueante.**
- **Best-effort/liability:** ACK ao C6 desacoplado do forward (D3). **Bloqueante.**
- **HMAC + secret handling + limiter + audit + flag:** reusam padrões já hardenados
  no repo (account-key display-once, cofre AAD, `ratelimit.go`, audit account-scoped).

**F2 (SIN-69486·F2 / forward) está autorizada a iniciar SOB este contrato:** o PR da
F2 deve marcar todos os itens bloqueantes do §7 e incluir os testes de abuso do §8.
Meu review de segurança da F2 confere este checklist item-a-item antes do approval do
CTO. Qualquer omissão de item bloqueante = change-request.

**Residual risk pós-F2:** (a) um serviço **público** malicioso que aja como proxy
para a rede do atacante — fora do nosso modelo, mitigado por só-destinos-públicos +
HMAC; (b) novas faixas IP reservadas não listadas — mitigado pela regra positiva
"só global-unicast público passa"; (c) exfiltração via timing do dial mesmo com erro
opaco — baixo, mitigado por timeouts uniformes (SSRF-6/8). Nenhum é bloqueante.

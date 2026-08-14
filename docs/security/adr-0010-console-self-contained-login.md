# ADR-0010 — Login self-contained do console (usuário + senha + TOTP 2FA)

- **Status:** Aceito — direção do board (Pericles) em 2026-08-14 via [SIN-69261](/SIN/issues/SIN-69261) → implementado em [SIN-69265](/SIN/issues/SIN-69265). **Supersede a Opção A do [ADR-0001](adr-0001-console-browser-auth-transport.md).**
- **Autor:** Coder. **Review:** SecurityEngineer (auth/crypto/sessão/TOTP + threat model do bootstrap) → **Aprovação:** CTO.
- **Lentes:** Secure-by-default API, Least privilege, Defense in depth, OWASP A01/A02/A07, Hexagonal, HTMX-over-SPA.

## Contexto

O ADR-0001 adotou a **Opção A**: o edge autentica o operador e injeta
`Authorization: Bearer <admin-token>` upstream; a aplicação ficava *stateless*
quanto a sessão. Na prática de go-live isso exigia um proxy que injetasse o bearer
e autenticasse a sessão de borda — infraestrutura que o board tomou como atrito
(um 401 no browser ao acessar `/console` sem o proxy, [SIN-69261](/SIN/issues/SIN-69261)).

O próprio ADR-0001 já previa a **Opção B** (cookie de sessão de primeira parte) e
listava os três requisitos de CSRF a cumprir caso fosse adotada. O board decidiu
adotá-la: **login self-contained** com **usuário + senha + TOTP 2FA**, usuário
`pericles.luz`, senha e segredo TOTP obtidos no primeiro acesso.

## Decisão

Adotar a **Opção B** como transporte de auth do browser para o console:

1. **Login próprio.** `GET /console/login` (público) renderiza o formulário
   usuário/senha/TOTP; `POST /console/login` verifica e, em sucesso, cria uma
   sessão server-side e emite um cookie de sessão. `POST /console/logout` revoga.
2. **Verificação de credencial (domínio puro, atrás de porta).**
   - **Senha:** hash **argon2id** (m=64 MiB, t=3, p=4; OWASP), nunca em claro,
     nunca logada; comparação constant-time. Erro genérico `credenciais inválidas`
     (sem enumeração de usuário — A07). Timing equalizado com um argon2 dummy no
     caminho "usuário inexistente".
   - **TOTP:** RFC 6238 (HMAC-SHA1, 6 dígitos, passo 30s, skew ±1). **Replay guard**
     server-side: o passo consumido é registrado e reuso do mesmo código (ou de um
     anterior) na janela é rejeitado. Segredo base32 protegido em repouso pelo
     adapter durável (follow-up).
3. **Sessão server-side atrás de porta.** Id opaco de 256 bits; o cookie carrega
   **só o id** (`HttpOnly`, `Secure` dirigido por `PAYMENT_SECURE_COOKIES`,
   `SameSite=Lax`, escopo `/console`). Expiração **absoluta (12h) + idle (30min)**;
   **id novo a cada login** (anti-fixation, já que o id é sempre recém-gerado);
   logout revoga; expiração/idle revogam proativamente.
4. **Middleware do console aceita Bearer OU cookie.** Deny-by-default. O Bearer
   admin existente continua válido (retrocompat / fallback Opção A e o plano JSON
   `/admin` intacto); um cookie de sessão válido autoriza o operador único como
   **admin** (direção do board). Um Bearer presente-porém-inválido é negado sem
   *fallthrough* para o cookie. Só `/console/login`, `/console/bootstrap` e os
   estáticos são públicos.
5. **Bootstrap de 1º acesso gated (sem land-grab).** Sem credencial provisionada,
   `POST /console/bootstrap` gera senha + segredo TOTP aleatórios, exibe **UMA vez**
   (senha + `otpauth://` para QR) e persiste o **hash da senha + o segredo TOTP**,
   então **trava** (uso único; 409 depois). O provisionamento é gated por um
   **token de deploy** (`PAYMENT_CONSOLE_BOOTSTRAP_TOKEN`) entregue ao Pericles fora
   de banda; **sem token ⇒ bootstrap DESABILITADO** (rota 404, failure-closed) — não
   pode virar takeover anônimo.
6. **CSRF load-bearing (os 3 requisitos do ADR-0001, agora atendidos):**
   (1) cookie de sessão `SameSite=Lax`; (2) **toda** mutação do console (inclusive
   login/logout/bootstrap) passa por `CSRFProtect` double-submit; (3) cookie de
   sessão e cookie de CSRF compartilham a política `Secure` de `PAYMENT_SECURE_COOKIES`
   (o console passou a usar `Server.CSRF().Protect` em vez do guard default para
   herdar exatamente essa política).
7. **Anti-brute-force em duas camadas:** limiter por IP no `POST /console/login`
   (primeira linha) + lockout temporário por usuário no serviço (segunda linha).

## Arquitetura (hexagonal)

- **Domínio** `internal/domain/consoleauth`: `Credential`, `Session`, verificador
  TOTP (RFC 6238) e hashing argon2id — sem `database/sql`, sem HTTP, sem SDK.
- **Use-case** `internal/app` (`ConsoleAuthService`): bootstrap, login (com replay
  guard + lockout), authenticate+touch, logout. Depende só de portas estreitas
  (`ConsoleCredentialStore`, `SessionStore`, `TOTPReplayStore`).
- **Adapter** `internal/adapters/consoleauth` (in-memory): satisfaz as três portas.
- **Transporte** `internal/adapters/http/console_auth.go`: middleware sessão-ou-Bearer,
  handlers de login/logout/bootstrap, cookie de sessão; presentation em `adminweb`.

## Consequências

- A fronteira de confiança volta para a aplicação; o edge não precisa mais injetar
  bearer nem autenticar sessão. A premissa "app só via proxy" da Opção A relaxa
  (runbook §9); mantém-se TLS na borda e nunca-logar-segredo.
- O double-submit de `csrf.go`, antes redundante, torna-se **load-bearing** — sem
  redesenho, exatamente como o ADR-0001 previu.
- **Trade-off de reinício:** o store é in-memory na 1ª entrega (atrás de porta); um
  restart derruba sessões e a credencial provisionada (re-bootstrap necessário). O
  adapter durável (sqlite, cripto em repouso) atrás das MESMAS portas é o follow-up.
- **Provisionamento seguro:** a senha inicial + segredo TOTP chegam ao Pericles pela
  tela de bootstrap (exibição única), gated pelo token de deploy entregue fora de
  banda — nunca em comentário/PR público, URL ou log.

## Reversibilidade

Rollback é fiação/flag: sem `PAYMENT_CONSOLE_BOOTSTRAP_TOKEN` o bootstrap fica
desabilitado, e como o middleware ainda aceita o Bearer admin, o console volta ao
transporte Opção A (proxy injeta bearer) sem mudança de código.

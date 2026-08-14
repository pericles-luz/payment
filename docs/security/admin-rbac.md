# Admin plane — RBAC & CSRF (para o child B)

> Núcleo de segurança do admin plane ([SIN-64726](/SIN/issues/SIN-64726), child de
> [SIN-64724](/SIN/issues/SIN-64724)). Este documento descreve o **role model**, o
> guard reutilizável `requireRole`, a **port de escrita de credencial bancária** e
> o **helper de CSRF** que a UI/CRUD HTMX (child B) deve consumir.
> Postura: **deny-by-default, least privilege, defense-in-depth**.

## 1. Role model (RBAC)

A autenticação do admin plane evoluiu de binária (`bool`) para **por role**,
derivada **server-side** do token — nunca de input do cliente.

| Role           | Constante (`internal/adapters/http`) | Capacidade                       |
| -------------- | ------------------------------------ | -------------------------------- |
| `admin`        | `RoleAdmin`                          | Leitura **e** escrita (full)     |
| `operator`     | `RoleOperator`                       | Somente leitura (read-only)      |
| (desconhecido) | —                                    | Negado (deny-by-default)         |

- O middleware `adminAuthMiddleware` autentica o token, resolve a role em
  **tempo constante** (`crypto/subtle`) e a injeta no `context` (`ctxRole`),
  do mesmo modo que `ctxTenantID`.
- Tokens são mapeados a roles na configuração:
  `PAYMENT_ADMIN_TOKENS` → `RoleAdmin`, `PAYMENT_OPERATOR_TOKENS` → `RoleOperator`
  (ver `internal/platform/config`). Entradas com token vazio ou role inválida são
  **descartadas** no construtor — uma config malformada nunca concede acesso.

### Guard reutilizável — `requireRole`

```go
// Rota de escrita: exige admin pleno.
r.Group(func(r chi.Router) {
    r.Use(requireRole(RoleAdmin))
    r.Post("/tenants", s.handleCreateTenant)
})

// Rota de leitura do child B: admite admin OU operator.
r.Group(func(r chi.Router) {
    r.Use(requireRole(RoleAdmin, RoleOperator))
    r.Get("/tenants", s.handleListTenants) // exemplo do child B
})
```

Semântica do guard (já behind `adminAuthMiddleware`):

- Sem role no context (não autenticado) → **401**.
- Autenticado mas role insuficiente → **403**.
- Role na lista permitida → segue.

> O child B **não** precisa reimplementar autorização: basta envolver suas rotas
> com `requireRole(...)`. Rotas de escrita HTMX usam `requireRole(RoleAdmin)`;
> rotas de leitura podem incluir `RoleOperator`.

## 2. Credencial bancária por-tenant (write path)

A port de leitura `ports.CredentialStore` (`GetBankCredential`) ganhou uma irmã
de escrita, separada por ISP. A credencial é chaveada pelo par `(tenantID, bankID)`
(ADR-0007 / SIN-66015): um tenant pode ter credenciais independentes em mais de um
banco.

```go
type CredentialWriter interface {
    // bankID vazio é armazenado sob o banco default BankIDC6 (retro-compat).
    SetBankCredential(ctx context.Context, tenantID, bankID, clientID, secret string) error
}
```

- Adapter: `internal/adapters/secret` (`*secret.Store` implementa as duas ports).
- Use-case: `app.AdminService.SetBankCredential(ctx, tenantID, bank, clientID, secret)`
  — normaliza o `bank` (trim+lowercase; vazio → `c6`), valida que é um **banco
  conhecido** (`ports.IsKnownBankID`, deny-by-default — hoje só `c6` tem adapter),
  valida que o tenant existe e delega ao writer.
- **O secret nunca** entra em estado de domínio, log, erro ou URL (threat C1/C4):
  transita direto para o secret store. A resposta HTTP confirma a escrita
  **sem** ecoar o secret.
- **Auditoria**: a escrita grava uma entry `credential.set` com o `bank_id`
  (não-secreto, slug de roteamento). O secret e o `client_id` **nunca** entram na
  entry (`audit.NewCredentialSetEntry` não tem parâmetro de secret).
- Rota: `PUT /admin/tenants/{tenantID}/bank-credential` (guard `requireRole(RoleAdmin)`).

### Contrato do endpoint (para a UX — SIN-66017)

`PUT /admin/tenants/{tenantID}/bank-credential` · auth: Bearer admin (RoleAdmin) ·
`Content-Type: application/json` · corpo estritamente decodificado (campos
desconhecidos → 400).

Request:

```json
{ "bank": "c6", "client_id": "<id>", "secret": "<write-only>" }
```

- `bank` — **opcional**. Slug do banco; normalizado (trim + lowercase). Ausente ou
  vazio ⇒ `c6` (retro-compat). Banco desconhecido ⇒ **400**. Hoje o único slug
  aceito é `c6`; o conjunto cresce conforme novos adapters entram.
- `client_id` / `secret` — obrigatórios; `secret` é write-only (nunca lido de volta).

Response `200`:

```json
{ "tenant_id": "<id>", "bank": "c6", "client_id": "<id>", "status": "ok" }
```

- `bank` ecoado é o **resolvido/normalizado** (confirma sob qual banco gravou).
- O `secret` **nunca** aparece na resposta.

Erros: `400` (corpo inválido / banco desconhecido / `secret` ausente) · `401`
(sem role admin) · `404` (tenant inexistente — mascarado como not-found).

## 3. Isolamento de tenant no admin plane

O admin cruza tenants por design, mas:

- Um **token de tenant nunca** resolve para uma role admin → toda rota `/admin`
  retorna **401** para tokens de tenant (deny-by-default; coberto por teste).
- Toda operação admin que toca dados de um tenant recebe o `tenantID`
  **explicitamente** (path param) e o repositório continua **tenant-scoped**.

## 4. CSRF para forms HTMX (consumir no child B)

A API JSON (tenant/admin) autentica por **Bearer token** (não cookie ambiente),
logo **não** é exposta a CSRF. As **páginas HTML** do admin (child B), servidas ao
browser com cookie de sessão, **são** — e devem usar o middleware abaixo.

Estratégia: **double-submit token**. O middleware emite um token aleatório (256
bits, `crypto/rand`) em cookie `HttpOnly`/`SameSite=Lax`/`Secure`, e o expõe via
context para o template renderizar. Em requests mutantes (POST/PUT/PATCH/DELETE)
o token submetido (header ou campo de form) precisa bater com o cookie, comparado
em **tempo constante**.

### Como o child B usa

1. Envolva as rotas HTML mutantes com o middleware:

   ```go
   r.Route("/admin/ui", func(r chi.Router) {
       r.Use(adminAuthMiddleware(s.adminAuth)) // autentica + injeta role
       r.Use(httpadapter.CSRFProtect)          // CSRF para o plano HTML
       r.Get("/tenants", s.handleTenantsPage)  // GET emite/renova o token
       r.Use(requireRole(RoleAdmin))
       r.Post("/tenants", s.handleCreateTenantForm)
   })
   ```

2. No template, leia o token do context e injete-o no HTMX via `hx-headers`
   (ou num campo escondido para forms sem JS):

   ```html
   <!-- token = httpadapter.CSRFToken(r.Context()) -->
   <body hx-headers='{"X-CSRF-Token": "{{ .CSRFToken }}"}'>
     ...
     <form hx-post="/admin/ui/tenants">
       <input type="hidden" name="csrf_token" value="{{ .CSRFToken }}">
       ...
     </form>
   </body>
   ```

Constantes/símbolos exportados (`internal/adapters/http`):

| Símbolo            | Uso                                                        |
| ------------------ | ---------------------------------------------------------- |
| `CSRFProtect`      | Middleware `func(http.Handler) http.Handler`               |
| `CSRFToken(ctx)`   | Token atual para renderizar no template                    |
| `CSRFHeaderName`   | `"X-CSRF-Token"` — header que o HTMX envia                 |
| `CSRFFieldName`    | `"csrf_token"` — campo escondido (fallback sem JS)         |

Falhas (token ausente/divergente em método mutante) → **403**.

## 5. Reversibilidade / rollback

- Mudanças são **aditivas**: novas ports/rotas/middleware. As rotas admin
  existentes mantêm o comportamento (admin token → `RoleAdmin` → escrita permitida).
- Sem migração de schema; o secret store é in-process/config-driven (vault é
  drop-in). Rollback = reverter o PR; nenhum passo de dados a desfazer.
- Feature-flag não é necessária: as capacidades novas só são alcançáveis por
  tokens admin já privilegiados.

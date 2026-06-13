# Segurança — Plataforma de Pagamentos

Conjunto de documentos de segurança da plataforma de pagamentos multi-tenant
(Go, hexagonal, C6 Bank, SQLite→Postgres, RabbitMQ). Produzido para
[SIN-64706](/SIN/issues/SIN-64706) a partir do plano de
[SIN-64704](/SIN/issues/SIN-64704#document-plan).

| Documento | Conteúdo |
|-----------|----------|
| [`threat-model.md`](./threat-model.md) | Trust boundaries, DFD, STRIDE por componente (PIX, PIX Automático, BolePix, Checkout, webhooks C6, multi-tenancy, billing), riscos priorizados. |
| [`secure-baseline.md`](./secure-baseline.md) | Requisitos de segurança obrigatórios: segredos, auth/mTLS/OAuth C6, isolamento de tenant, idempotência/anti-replay de webhook, validação de entrada, cripto, logging, PIX/BCB + LGPD. |
| [`pr-review-policy.md`](./pr-review-policy.md) | Critérios objetivos de "potencial de fragilidade" + checklist de revisão de segurança (gate de merge). |
| [`adr-0001-console-browser-auth-transport.md`](./adr-0001-console-browser-auth-transport.md) | ADR (Aceito — Opção A) — transporte de auth do console HTML no browser: bearer injetado por proxy vs. futuro session cookie, e impacto no modelo CSRF. |
| [`../ops/ingress-runbook.md`](../ops/ingress-runbook.md) | Runbook de ingress — premissa de deploy não-negociável da Opção A (ADR-0001) como pré-requisito de go-live: app só via proxy confiável, token não vaza, sessão autenticada no edge. |

## Postura

**Secure by default, failure-closed, least privilege.** Se o caminho inseguro for
mais fácil que o seguro, isso é um bug a corrigir — não um tradeoff a aceitar.

## Como aplicar (CTO)

1. Mergear estes docs no repo dev como baseline de referência.
2. Codificar o que for automatizável como gates de CI (ver `pr-review-policy.md` §6)
   — não confiar só em revisão humana.
3. Tratar `secure-baseline.md` como requisitos de aceite para a fundação
   ([SIN-64705](/SIN/issues/SIN-64705)) e o adapter C6.

> ⚠️ **Verificar contra os anexos C6 de SIN-64704** (`autenticação.yaml`, `pix.yaml`,
> `pix_automatico.yaml`, `bolepix.yaml`, `checkout-c6-bank.yaml`, `notificações.yaml`).
> Onde este baseline assume o mecanismo C6 (mTLS + OAuth2 client_credentials, webhook
> via mTLS), o autor do adapter deve confirmar o detalhe exato no spec e abrir issue
> se divergir. Os **requisitos de segurança** valem independentemente do mecanismo.

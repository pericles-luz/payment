# Conformidade contratual — C6 Bank "Termos e Condições de Uso de APIs" (v. 10/03/2025)

> **Fonte autoritativa:** contrato assinado (DocuSign `8C9A0429…B32F` / `74A0B313…7BEED24`),
> anexo da issue [SIN-68738](/SIN/issues/SIN-68738), documento `regras-c6-termo-apis`.
> Este arquivo traduz as cláusulas do Termo em **regras operacionais e de engenharia**
> que valem para todo o repositório `payment` e para a operação do SaaS Super Inteligente,
> e mapeia cada regra ao controle existente (ou ao gap rastreado).
>
> Em conflito entre esta tradução e o Termo assinado, **prevalece o Termo**. Rastreamento
> de mudanças do Termo: regra F21 (rotina recorrente).

**Natureza da relação (contexto).** Somos o **"Desenvolvedor"**. O Termo é civil, sem
exclusividade, gratuito hoje (mas o C6 pode passar a cobrar — 11.10), por prazo
indeterminado, e **o C6 pode alterar o Termo/API a qualquer momento sem aviso**
(1.2, 2.8, 2.9). Foro: São Paulo/SP, lei brasileira (12.1).

---

## ⛔ A. Regras BLOQUEANTES para engenheiros (violação = rescisão imediata ou suspensão de acesso)

Estas sete regras têm consequência contratual severa e imediata. **Todo PR que toque
billing, credenciais, o cliente C6, capturas de homologação ou UI/faturas deve ser lido
contra esta lista.** Um PR que as viole não passa no gate de revisão de segurança.

| # | Regra (cláusula) | O que NÃO fazer no código/produto |
|---|---|---|
| **A1** | **NUNCA cobrar em nome do C6 (2.11)** — "a parceria será imediatamente rescindida". | Nenhuma bilhetagem/cobrança/fatura pode se apresentar como cobrança "do C6". Toda cobrança do SaaS é **inequivocamente sob a marca do Super Inteligente / do tenant**. |
| **A2** | **Chave de Acesso intransferível e confidencial (2.4-ii, 5.xv, 6.1)** | Não distribuir/divulgar/vender/ceder Chave/senha. Usar **apenas** as Chaves criadas pelo C6 para aquele Cliente e **apenas** para os serviços contratados por ele. Segredo write-only, zero-log, isolado por `(tenant, bank)`. |
| **A3** | **Sandbox ≠ real (2.4-iii)** | Não declarar a terceiros que transação de Sandbox é real / "já em vigor". Capturas e telas de homologação **rotuladas como não-produtivas**. |
| **A4** | **Sem engenharia reversa / código-fonte (2.4-i, 8.4)** | Não descompilar/desofuscar/desmontar a API do C6. Licença é só de **código-objeto**. |
| **A5** | **Não burlar segurança nem interferir na operação (2.5-i,ii,viii)** | Não desativar dispositivos de segurança; **não gerar carga tipo-DoS / tempestade de chamadas**; não acessar sistemas/redes do C6 de forma não autorizada. |
| **A6** | **Sem scraping/indexação automatizada não autorizada (2.5-vii)** | Jobs só chamam endpoints para a finalidade do serviço contratado — nunca varredura/coleta em massa. |
| **A7** | **Não usar a API para alterar score/elegibilidade de Cliente (2.5-v)** | Proibido usar a API para mudar classificação/perfil/score/elegibilidade, ou obter crédito/produto indevido. |

## B. Segurança da informação e proteção de dados (LGPD) — obrigações técnicas

- **B8 — Somos o controlador (4.i, 7.3).** Responsabilidade integral e exclusiva pelo
  tratamento de dados pessoais dos usuários, em conformidade com a LGPD e política de
  privacidade divulgada.
- **B9 — Consentimento informado é OBRIGATÓRIO coletar e ARMAZENAR (3.5).** Os termos de
  uso da Solução devem ser aprovados por consentimento informado do usuário, "colhido e
  armazenado pelo Desenvolvedor obrigatoriamente".
- **B10 — Diretrizes de segurança (7.12, replicando LGPD / Decreto 8.771/2016 art. 13):**
  (i) criptografar dados coletados em trânsito e repouso; (ii) proteger contra acesso não
  autorizado; (iii) acesso a dados pessoais só a pessoas autorizadas sob sigilo;
  (iv) **autenticação que individualize o responsável** pelo tratamento/acesso;
  (v) **manter inventário/registro** de momento, duração, identidade do responsável e
  objeto acessado.
- **B11 — Respeitar rate limits e restrições comunicadas pelo C6 (3.3).** O C6 pode limitar
  nº/frequência de chamadas; restrições "deverão ser imediatamente respeitadas". Chamadas
  não usadas **não acumulam**.

## C. Notificação e resposta a incidentes

- **C12 — Reportar imediatamente ao C6 uso abusivo/suspeito/não autorizado (5.v, 6.3).**
- **C13 — Ordem judicial de divulgar Informação Confidencial → avisar o C6 em até 48h (6.4)**,
  divulgando só a parte estritamente exigida.
- **C14 — Direitos do titular (LGPD) via `encarregado@c6bank.com` (7.10).**

## D. Confidencialidade, auditoria, encerramento

- **D15 — Confidencialidade permanente (6.1–6.2, 6.5).** No término: devolver/destruir tudo,
  proibido manter cópia; sigilo persiste após o fim.
- **D16 — Sujeição a auditoria do C6 (3.4, 11.3).** Remota ou in loco, anual ou menor.
  Manter documentação técnica e trilha de auditoria "auditáveis a qualquer momento".
- **D17 — Não obstruir saída do Cliente (5.xiv).** Não impedir contratação de outros
  Desenvolvedores nem revogação de Chaves; não cobrar multa de encerramento.
- **D18 — Sem cessão sem anuência (11.4).** C6 pode encerrar/suspender com 15 dias de aviso
  (ou imediato por descumprimento/força maior — 10.3, 10.4).

## E. Propriedade intelectual e marcas

- **E19 — Não usar marcas/logotipos/nomes do C6 (8.2).** O acesso à API não autoriza citar
  ou usar marcas do C6 além do estritamente factual/permitido.
- **E20 — Reportar violações de PI pelo canal da Cláusula 11 (8.3).**

## F. Regras operacionais contínuas

- **F21 — Monitorar mudanças do Termo/API (2.8, 2.9, 11.5)** em `developers.c6bank.com.br`.
- **F22 — Manter e-mail/celular de cadastro atualizados (11.9).** Canais: geral
  `assistentespj@c6bank.com`; encarregado/LGPD `encarregado@c6bank.com`; homologação
  `homologacaoapi@c6bank.com`.
- **F23 — Declaração PEP (5.vi)** e conformidade anticorrupção/compliance (5.xi) — governança.

---

## Gap analysis: regra → controle → status

Legenda: ✅ coberto · 🟡 parcial (controle existe, falta reforço/confirmação) · ❌ gap real (issue aberta).

| Regra | Controle existente no repo | Status | Issue de follow-up |
|---|---|---|---|
| **A1** nunca cobrar em nome do C6 | Bilhetagem/ledger sob marca do tenant; nenhuma fatura invoca a marca C6 | 🟡 sem guardrail explícito nem revisão de faturas/UI | [SIN-68741](/SIN/issues/SIN-68741) |
| **A2** chave confidencial/isolada | ADR-0007 (cofre multibanco `(tenant,bank)`), `CredentialStore` write-only, zero-log de segredo, isolamento de tenant | ✅ | — |
| **A3** sandbox ≠ real | `docs/homologacao/*` — capturas de homologação | 🟡 rotular explicitamente telas/capturas como não-produtivas | dobrado em A1 review / doc |
| **A4** sem engenharia reversa | Consumimos só a API pública (código-objeto); nenhum artefato de descompilação no repo | ✅ (política) | — |
| **A5** anti-DoS / não interferir | Cliente C6 `do()` é **single-shot** (`internal/adapters/bank/c6/c6.go`) — sem retry-storm; mas sem throttle proativo | 🟡→❌ ver B11 | [SIN-68742](/SIN/issues/SIN-68742) |
| **A6** anti-scraping | Jobs chamam endpoints só para a finalidade do serviço; sem crawler | ✅ (política) | — |
| **A7** não alterar score/elegibilidade | Nenhum uso da API para classificação/score | ✅ (política) | — |
| **B8** controlador LGPD | Política de privacidade + isolamento de dados por tenant | ✅ (produto) | — |
| **B9** consentimento coletado+armazenado | **Nenhum** registro auditável de consentimento do usuário aos termos da Solução (o domínio `consent`/`recurrence` é o mandato PIX Automático, NÃO o consentimento LGPD aos termos) | ❌ | [SIN-68743](/SIN/issues/SIN-68743) |
| **B10 (iv)** individualização do responsável | Audit log durável (SIN-66016/66025): `Entry{operatorID, action, tenantID, at}`, operator populado server-side pelo middleware admin | ✅ (plano admin) | — |
| **B10 (v)** inventário de acesso a dados pessoais (art.13) | Audit cobre ações **privilegiadas do plano admin** (cred/tenant/pricing/recorrência); **não** cobre inventário de leitura de dados pessoais no plano de dados | 🟡→❌ | [SIN-68744](/SIN/issues/SIN-68744) |
| **B11** respeitar rate limits / backoff | Rate-limit **inbound** (por tenant/IP na nossa API) existe; cliente **outbound** C6 mapeia `429→ErrUnavailable` mas **não** faz backoff/`Retry-After` nem limita a taxa de saída | ❌ | [SIN-68742](/SIN/issues/SIN-68742) |
| **C12/C13** notificação de incidente ao C6 (imediata / judicial 48h) | `docs/ops/*` tem ingress + smoke runbooks; **nenhum** runbook de resposta a incidente com canal/SLA para o C6 | ❌ | [SIN-68745](/SIN/issues/SIN-68745) |
| **C14** direitos do titular via encarregado | Canal `encarregado@c6bank.com` documentado (F22) | ✅ (doc) | — |
| **D15–D18** confidencialidade/auditoria/saída | Postura de segurança auditável (`docs/security`), sem multa de saída no produto | ✅ | — |
| **E19/E20** marcas/PI do C6 | UI/marketing sob marca própria | 🟡 revisão de UI/docs dobrada em A1 review | dobrado em A1 |
| **F21** monitorar Termo/API | **Nenhuma** rotina recorrente de acompanhamento | ❌ | [SIN-68746](/SIN/issues/SIN-68746) |
| **F22** canais de cadastro | Documentado aqui e nos runbooks | ✅ (doc) | — |
| **F23** PEP/anticorrupção | Governança (não-código) | ✅ (governança) | — |

### Resumo dos gaps convertidos em issues (filhas de [SIN-68740](/SIN/issues/SIN-68740))

1. [SIN-68741](/SIN/issues/SIN-68741) — Guardrail "nunca cobrar em nome do C6" (A1) + revisão de faturas/UI/marcas (A3/E19).
2. [SIN-68742](/SIN/issues/SIN-68742) — Rate limiting + backoff/`Retry-After` no cliente HTTP outbound do C6 (A5/B11).
3. [SIN-68743](/SIN/issues/SIN-68743) — Captura + guarda auditável de consentimento LGPD aos termos da Solução (B9 / 3.5).
4. [SIN-68744](/SIN/issues/SIN-68744) — Inventário de acesso a dados pessoais no plano de dados (B10-v / Decreto 8.771/2016 art.13).
5. [SIN-68745](/SIN/issues/SIN-68745) — Runbook de resposta a incidente com notificação ao C6 (C12 imediata / C13 judicial 48h).
6. [SIN-68746](/SIN/issues/SIN-68746) — Rotina recorrente de monitoramento do Termo/API em `developers.c6bank.com.br` (F21).

> As issues são criadas ao mesmo tempo que este documento; os números acima são preenchidos
> na abertura. Não é preciso implementar os gaps neste PR — apenas rastreá-los.

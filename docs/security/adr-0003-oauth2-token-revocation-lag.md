# ADR-0003 — Lag de revogação do token OAuth2 do C6 (evict no update de credencial)

- **Status:** Proposto — aguardando ratificação do CTO ([SIN-64764](/SIN/issues/SIN-64764)).
- **Contexto da review:** follow-up **não-bloqueante** levantado na security review de C6-A ([SIN-64750](/SIN/issues/SIN-64750), PR #11) pelo SecurityEngineer. Não bloqueou o merge de C6-A. Pai: [SIN-64723](/SIN/issues/SIN-64723).
- **Autor:** Coder. **Decisor:** CTO.
- **Nota de numeração:** o issue SIN-64764 rotulou este documento como "ADR-0073". Numerei-o **0003** para seguir a sequência local de ADRs (0001, 0002). Renomeio sob pedido se o CTO preferir o rótulo original.

## Contexto

O adapter C6 (`internal/adapters/bank/c6`) autentica via OAuth2
`client_credentials` por tenant. O `tokenManager` (`token.go`) mantém o bearer em
**cache em memória, por tenant**, e o serve até pouco antes de expirar (skew de
refresh de 30s). Quando o PSP omite `expires_in`, o TTL de fallback é de 60s.

O token nunca é persistido (ameaça C1) — vive apenas no processo. Mas, enquanto
está em cache, ele **sobrevive a uma rotação ou revogação da credencial daquele
tenant** até expirar: a credencial nova já está no secret-store, porém o
`token()` só vai resolvê-la e re-emitir o bearer no próximo (re)fetch, isto é,
quando o cache vence. Esse é o tradeoff padrão de cache de token
`client_credentials` — **não bloqueia C6-A** — mas há uma janela em que um bearer
emitido sob a credencial antiga continua válido para chamadas ao banco.

Janela máxima de lag, **sem mitigação**: `≤ TTL do token` (≤ `expires_in`), ou
≤ 60s quando o PSP omite `expires_in`.

## Decisão

Duas partes, ambas entregues em SIN-64764:

### 1. Evict imediato no write de credencial (código)

Um novo port opcional **`ports.CredentialInvalidator`** (`InvalidateToken(tenantID string)`)
é chamado pelo plano admin logo após um `CredentialWriter.SetBankCredential`
bem-sucedido (tanto `AdminService` quanto `ConsoleService`). O adapter C6
implementa o port: `Provider.InvalidateToken` zera o slot de cache daquele tenant
(`tokenManager.invalidate`), de modo que a **próxima** chamada re-emite o bearer
sob a credencial corrente. A rotação/revogação passa a valer **na hora**, em vez
de esperar o TTL.

Propriedades de design:

- **Hexagonal / ISP.** O port é separado do `CredentialWriter` (escritor) e do
  `CredentialStore` (leitor): o plano admin depende só da capacidade de evict. Um
  write path sem cache para invalidar (o stub in-memory) simplesmente não fornece
  o invalidator e o serviço admin cai num no-op.
- **Best-effort e local.** `InvalidateToken` não tem `error` nem `context`:
  derrubar uma entrada em memória não pode falhar e **nunca** pode fazer falhar o
  write de credencial que já foi commitado. O evict roda **depois** do write
  bem-sucedido (um write que falha mantém a credencial antiga em vigor, então não
  há o que evictar) e antes do registro de auditoria.
- **Por tenant e thread-safe.** O evict pega o lock externo só para localizar o
  slot e o lock do próprio slot para zerá-lo — a mesma ordem `externo→slot` que o
  `token()` usa, sem inversão. Um refresh em voo para a credencial antiga termina
  no seu slot; como a credencial nova já está persistida antes do evict, qualquer
  (re)fetch — o em voo ou o do próximo chamador — resolve o segredo novo.
- **Wrapper transparente.** O `PixSettlementProvider` (decorator de liquidação na
  frente do C6) repassa `InvalidateToken` ao provider embrulhado quando este o
  suporta, então o evict funciona mesmo com o decorator no caminho.

### 2. Documentação operacional (este ADR / runbook)

Ver "Operação — rotação e revogação" abaixo.

## Consequências

- **Lag eliminado no processo que serve o write.** Após uma rotação via plano
  admin, o bearer antigo é descartado imediatamente naquele processo.
- **Residual em deploy multi-réplica.** O cache é **por processo**. Um
  `SetBankCredential` chega a **uma** réplica e evicta apenas o cache dela; as
  demais réplicas seguem servindo o bearer antigo **até o TTL** (≤ `expires_in`;
  60s no fallback). Convergência garantida pelo TTL, não pelo evict. Hoje a app
  roda single-instance (um bus in-memory, um SQLite), então não há residual; o
  alerta vale para quando houver fan-out horizontal — nesse cenário, ou aceita-se
  o lag ≤ TTL nas outras réplicas, ou promove-se a invalidação a um canal
  cross-réplica (ex.: pub/sub), o que seria um novo ADR.
- **Revogação fora-de-banda (no próprio PSP).** Se a credencial for revogada
  direto no C6 sem passar pelo `SetBankCredential` da app, o evict não dispara —
  o lag ≤ TTL volta a valer até o próximo refresh, que então falhará a
  autenticação e propagará o erro. O caminho suportado de revogação é **rotacionar
  pela app** (que evicta), não revogar só no PSP.

## Operação — rotação e revogação de credencial de banco

1. **Rotacionar** a credencial do tenant pelo plano admin: `PUT
   /admin/tenants/{tenantID}/bank-credential` (ou a tela equivalente do console),
   com o novo `client_id`/`secret`. Isso persiste a credencial **e** evicta o
   token em cache daquele tenant no processo que atende a requisição.
2. **Efeito imediato (single-instance):** a próxima chamada ao banco para o tenant
   re-autentica sob a credencial nova. Nenhuma ação extra.
3. **Deploy multi-réplica:** as réplicas que não atenderam o write convergem
   sozinhas dentro do TTL do token (≤ `expires_in`; 60s no fallback). Se for
   preciso forçar convergência antes do TTL, faça um rolling-restart das réplicas
   (o cache é em memória, então o restart zera tudo) — ou avalie promover a
   invalidação a cross-réplica (novo ADR).
4. **Revogação de emergência:** rotacione a credencial pela app (passo 1) para um
   segredo novo válido; isso invalida o bearer antigo no processo na hora e nas
   demais dentro do TTL. Revogar **apenas** no PSP, sem rotacionar pela app, deixa
   o lag ≤ TTL ativo nas réplicas até o refresh falhar.

## Alternativas consideradas

- **Só documentar o lag (sem código).** Era a proposta mínima do follow-up.
  Rejeitada como insuficiente: o evict por write é barato, contido e fecha o lag
  no caminho normal de rotação.
- **TTL agressivo / sem cache.** Reduz o lag às custas de re-emitir token a cada
  chamada (latência + carga no endpoint OAuth do C6). Rejeitada: o cache é
  desejável; o evict mira só a janela de rotação.
- **Invalidação cross-réplica (pub/sub) agora.** Adiada: a app é single-instance
  hoje e isso adicionaria infraestrutura sem ganho atual. Fica registrada como o
  próximo passo se/quando houver fan-out horizontal.

## Referências

- [SIN-64764](/SIN/issues/SIN-64764) — este follow-up.
- [SIN-64750](/SIN/issues/SIN-64750) — security review de C6-A onde o residual foi levantado.
- [SIN-64723](/SIN/issues/SIN-64723) — umbrella C6.
- Código: `internal/ports/ports.go` (`CredentialInvalidator`),
  `internal/adapters/bank/c6/token.go` (`invalidate`),
  `internal/adapters/bank/c6/c6.go` (`InvalidateToken`),
  `internal/app/admin.go` / `internal/app/console.go` (chamada do evict),
  `internal/adapters/bank/pixsettle.go` (repasse pelo decorator),
  `cmd/api/main.go` (wiring).

# ADR-0006 — CD durável do receptor de pagamentos por rsync de binário (build → ship → restart → /healthz)

- **Status:** Aceito — Opção A escolhida pelo CEO em [SIN-65858](/SIN/issues/SIN-65858).
- **Issue de implementação:** [SIN-65900](/SIN/issues/SIN-65900).
- **Autor:** Coder (engenharia). **Decisor:** CTO (merge do fork) / CEO (promoção upstream).
- **Repos:** PR no fork `ia-dev-sindireceita/payment`; promoção para `pericles-luz/payment` pelo CEO.

## Contexto

O receptor de pagamentos é um **único binário Go** (`cmd/api`), sem Dockerfile,
servindo `/healthz` em `:8080` atrás do HAProxy em `payment.lmhost.com.br`
(VPS `143.198.66.140`). Ele precisa estar **no ar** antes que o CTO registre o
webhook do C6 e feche [SIN-65855](/SIN/issues/SIN-65855) (o remap já mergeou em
[SIN-65856](/SIN/issues/SIN-65856)).

Até aqui o start era **manual, one-shot** (o humano subia o binário na mão). O CEO
escolheu a **Opção A — CD durável** ([SIN-65858](/SIN/issues/SIN-65858)): um caminho
de deploy **owned pelo agente**, para que o CTO (e todo deploy futuro) embarque sem
um humano por-deploy.

Restrições que moldam a decisão:

- **Sem Dockerfile** — payment é um binário único. Copiar o pipeline docker/cosign/SBOM
  do crm seria over-engineering e introduziria infra que não existe.
- **Sem shell de agente no VPS** — o bootstrap do host é um passo único do CEO,
  dirigido por runbook (`docs/deploy/staging.md`); nenhum agente roda comando no VPS.
- Já existe o template **go-mei-das** (build de binário → rsync → restart systemd →
  smoke `/healthz`), provado em produção.

## Decisão

Espelhar o CD de binário do **go-mei-das**, adaptado ao payment:

1. **`.github/workflows/cd-stg.yml`** — disparado por `workflow_run` encadeado no
   sucesso do workflow `CI` em `main` (+ `workflow_dispatch` para deploy manual).
   O job é **owner-gated** (`github.repository_owner == 'pericles-luz'`): só o
   upstream deploya; o fork é no-op e não drifta (mesma razão do crm
   [SIN-63281](/SIN/issues/SIN-63281)).
2. **Build com provenance** — `-ldflags -X` carimba version/commit/build-time no
   pacote novo `internal/version`; o `/healthz` passa a reportar o SHA implantado,
   então o smoke **afirma o SHA que subiu**, não apenas que *algum* binário responde.
   Sem as flags o binário ainda builda e `/healthz` cai no fallback
   `runtime/debug.ReadBuildInfo()` (backward compatible).
3. **SSH com chave travada** — o binário é **streamado por stdin** numa única
   sessão `ssh … deploy` (sem `scp`: um `command=` intercepta toda conexão da chave,
   não há exceção scp/SFTP). O verbo `deploy` travado por `authorized_keys command=`
   invoca o wrapper VPS, que lê o stdin, valida (não-vazio + ELF), instala
   atomicamente e dá `systemctl restart`. `known_hosts` **pinado** (sem TOFU).
4. **`deploy/scripts/payment-deploy.sh`** — wrapper que valida
   `SSH_ORIGINAL_COMMAND`/argv e aceita **apenas** `deploy` (e `preflight`
   read-only); qualquer outra coisa sai não-zero. Install atômico (`rename(2)`) +
   restart via **um** sudoers NOPASSWD escopado só àquele comando.
5. **`deploy/systemd/payment-api.service`** — `User=payment` (não-root),
   `EnvironmentFile=/opt/payment/.env.stg`, `Restart=on-failure`, hardening
   defense-in-depth.

## Lente de segurança

- **Menor privilégio:** usuário `payment` dedicado não-root; chave de deploy presa
  ao wrapper via `command=`; **um** sudoers NOPASSWD (só `systemctl restart payment-api`).
- **Secure-by-default:** `known_hosts` pinado (sem TOFU); job owner-gated; `set +x`
  em torno de host/usuário/segredos — nenhum segredo em log ou URL. Cert/chave mTLS
  do C6 são **paths para arquivos 0600** owned por `payment`, provisionados por
  [SIN-65806](/SIN/issues/SIN-65806); **nunca** bytes inline em repo/thread (threat C1).
- **Reversibilidade / blast radius:** no smoke-fail o job fica vermelho e o binário
  **anterior segue rodando** (rollback manual documentado no runbook nesta fase).
- **Boring technology:** stdlib + systemd + ssh (binário por stdin); nenhuma infra nova.

## Consequências

- **Rollback é manual nesta fase** (operador reinstala o binário anterior + restart,
  per `docs/deploy/staging.md`). **Auto-rollback fica deferido** — quando houver
  retenção de binário anterior no host ou um `rollback-stg.yml` (à la go-mei-das
  `rollback-prod.yml`), abrir follow-up.
- O `/healthz` agora expõe version/commit/built_at — provenance sem segredo, seguro
  no endpoint não-autenticado.
- O bootstrap do VPS é responsabilidade **única e manual do CEO** (runbook); o agente
  nunca toca o host.
- ADR mora em `docs/security/` (convenção do repo: todos os ADRs aqui, numeração
  sequencial) em vez de `docs/adr/` citado no ticket — escolha por consistência com
  ADR-0001…0005.

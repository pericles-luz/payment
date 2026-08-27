# Corte do payment para a infra lmhost

> **EXECUTADO em 21/08/2026 00:00Z.** Janela de **38 segundos** para produção.
> As duas instâncias rodam em `pre-prod` sobre PostgreSQL, com segredos vindos do
> Vault. Contagens conferidas contra a origem, incluindo os 25 `processed_events`.
> Certificados já migrados para ACME automático (vencem 18/nov/2026, renovação
> pelo Caddy). CD apontado para o `pre-prod`, com a chave de deploy e o comando
> forçado replicados.
>
> **Pendente: desmontar o host antigo** — ver "Passo 3", deliberadamente adiado.

Sequência de corte (Fase 5 da migração, SIN-70001), com o porquê de cada ordem.
O que está escrito aqui foi medido nas máquinas, não presumido.

## O que mudou em relação ao plano original

O plano previa cortar em dois passos: primeiro trocar o backend do HAProxy antigo
para o host novo, depois virar o DNS. **O primeiro passo é impossível.**

`pre-prod` não tem IP público em interface — é NAT **por porta**, e só a 22 está
encaminhada. Medido: do HAProxy antigo, `201.23.79.48:22` conecta e
`201.23.79.48:8081` dá timeout mesmo com o ufw do `pre-prod` liberado. Não existe
caminho do balanceador antigo até a aplicação nova.

A troca inverte a ordem e fica melhor que o plano original:

1. **Ingress primeiro, com o app antigo ainda servindo.** O Caddy passa a fazer
   proxy para `payment.someu.com.br` com o certificado real copiado do HAProxy.
   A virada de DNS não muda nada para o cliente — mesmo certificado, mesma
   aplicação. **Zero indisponibilidade.**
2. **Aplicação depois, em janela própria.** Troca-se o upstream do Caddy. O
   rollback é voltar uma linha e recarregar: segundos, sem depender de TTL.

## Estado atual (passo 1 já preparado)

| | |
|---|---|
| Certificados | reais, do Let's Encrypt, em `/etc/caddy/certs/` no balanceador, `caddy:caddy` 0600 |
| Upstream do Caddy | `payment.someu.com.br:8080` e `:8081` — o app **antigo** |
| ufw do servidor antigo | libera 8080/8081 para `201.23.82.60` (balanceador) **e** `143.198.66.140` (HAProxy), para o rollback |
| DNS | ainda `143.198.66.140` |

Verificado: os dois caminhos devolvem resposta idêntica e a verificação TLS pelo
balanceador passa **sem `-k`**.

```sh
curl -sS --resolve payment.lmhost.com.br:443:201.23.82.60 https://payment.lmhost.com.br/healthz
curl -sS --resolve payment.lmhost.com.br:443:143.198.66.140 https://payment.lmhost.com.br/healthz
```

## Passo 1 — virar o DNS (sem indisponibilidade)

1. Baixar o TTL de `payment.lmhost.com.br` e `payment-sbx.lmhost.com.br` de 3600
   para 300. Esperar uma hora. *(O TTL não afeta mais o TLS — afeta a velocidade
   do rollback.)*
2. Apontar os dois `A` para **201.23.82.60**.
3. Confirmar pelos dois lados até o antigo parar de receber:
   `tail -f /var/log/caddy/payment-access.log` no balanceador.
4. Deixar assentar 24 a 48h.
5. **Remover as duas linhas `tls` explícitas do Caddyfile** e recarregar. O Caddy
   emite o próprio por HTTP-01 (agora resolvendo para si mesmo) e assume a
   renovação. Conferir `issuer` = Let's Encrypt e o novo `notAfter`.

> ⚠️ O passo 5 tem prazo, não é limpeza opcional. Enquanto o `tls` explícito
> estiver lá, **ninguém renova** esses certificados, e o de `payment` vence em
> **25/out/2026**.

## Passo 2 — mover a aplicação (janela curta)

**Pré-requisito, fora da janela: ensaio a seco. Já feito em 20/08/2026** —
snapshot consistente do `payment.db` de produção (via `Connection.backup()`, não
cópia crua: o app estava escrevendo), carga real num banco descartável e
verificação criptográfica. Resultado:

- **271 linhas** carregadas em 14 tabelas, **sem violação de FK**. O risco de linha
  órfã — o SQLite rodava `PRAGMA foreign_keys` numa conexão só de um pool
  ilimitado, então o enforcement lá era inconsistente — **não se materializou**.
- **3 credenciais e 3 certificados selados abriram** com a KEK de produção, via
  `vault-reseal` com a mesma chave nos dois campos (migração só-de-AAD). A cópia
  byte a byte preserva o vínculo AAD `(tenantID, bankID)`.
- Tempo total do ETL: **abaixo de 1 segundo**.

Repetir o ensaio só é necessário se o schema mudar. O `.db` do ensaio foi
destruído com `shred`; o corte usa um snapshot novo, tirado depois do congelamento.

O `payment.db` precisa ser copiado para o `pre-prod`: nenhum host vê os dois
lados (o servidor antigo não alcança a VLAN privada — medido).

```sh
# 1. congelar (o C6 passa a receber erro e REENTREGA; nada se perde)
ssh root@payment.someu.com.br 'systemctl stop payment-api'

# 2. copiar o .db final e rodar o ETL
#    (o alvo tem de estar VAZIO: o ETL usa ON CONFLICT DO NOTHING, que carrega
#     linha nova mas NAO atualiza linha mudada — não serve como sync incremental)
sudo -u payment PAYMENT_DB_PATH=/tmp/payment.db \
  PAYMENT_DB_DSN='postgres://payment:...@172.18.2.248:5432/payment?sslmode=require' \
  /opt/payment/bin/db-migrate

# 3. subir a instancia de producao
ssh ubuntu@pre-prod 'sudo systemctl enable --now payment-api'

# 4. trocar o upstream no Caddyfile: payment.someu.com.br:8080 -> 172.18.1.82:8080
ssh ubuntu@syndeotech-lb 'sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile && sudo systemctl reload caddy'
```

**Rollback:** voltar a linha `reverse_proxy` para `payment.someu.com.br:8080`,
recarregar o Caddy e religar o app antigo. O SQLite antigo fica intocado.

### Quanto tempo fica fora

| Etapa | |
|---|---|
| `systemctl stop` | instantâneo |
| copiar 360 KB | segundos |
| ETL de 271 linhas em 14 tabelas | **< 1 s** (medido no ensaio) |
| boot até `/healthz` responder | **0,36–0,49 s** (medido, 3 execuções) |
| reload do Caddy | ~1 s |

Soma mecânica abaixo de 30 s; com um operador conferindo entre os passos, **1 a 3
minutos**. Todos os números acima são medidos, não estimados.

Não é indisponibilidade igual para todos: os webhooks do C6 recebem 502 e são
**reentregues** (o código conta com isso — `errSettlementLag` devolve erro de
propósito para provocar reentrega). Chamadas `/v1/*` e o console tomam 502 de
verdade pelo tempo da janela.

## Passo 3 — limpeza (ADIADA de propósito)

> Nada aqui foi feito ainda, e é intencional: no dia do corte o serviço não teve
> tráfego real, então a stack nova ainda não se provou em uso. Enquanto isso, o
> host antigo é o rollback — o SQLite está lá, no estado do momento do corte, e o
> app volta a servir com `systemctl start payment-api` mais um `reverse_proxy` de
> volta para `payment.someu.com.br` no Caddy.
>
> Fazer o que está abaixo depois de alguns dias de uso real.


1. Remover `bk_payment` e `bk_payment_sbx` do `/etc/haproxy/haproxy.cfg` antigo.
   **Não desligar aquela máquina:** ela ainda serve `contador.someu.com.br`,
   `escravo.someu.com.br` e `verz.com.br`.
2. Tirar `payment.*` do certbot do host antigo — depois da virada ele não
   consegue mais responder ao HTTP-01 e as renovações passam a falhar.
3. Fechar as regras de ufw de `143.198.66.140` no servidor antigo.
4. ~~Apontar `PAYMENT_STG_HOST` / `PAYMENT_STG_HOST_KEY` no GitHub para o
   `pre-prod`.~~ **Já feito na própria janela do corte, em 21/08 00:07Z** — não é
   limpeza pendente. `PAYMENT_STG_SMOKE_URL` continua `https://payment.lmhost.com.br`.

   > **O CD ficou quebrado seis dias por causa deste passo.** Os secrets foram
   > repontados, mas a chave de deploy foi instalada em `/home/payment/.ssh/` seguindo
   > o `staging.md` §5b, que então trazia esse caminho fixo — e no `pre-prod` o home do
   > usuário `payment` é `/opt/payment`. O `sshd` procurava em `/opt/payment/.ssh/`,
   > que não existia, e toda tentativa do CD morria em `Permission denied (publickey)`.
   > Nada disso apareceu até 26/08, porque só um merge na `main` dispara o CD e não
   > houve nenhum no intervalo — o `/healthz` seguiu servindo o binário pré-corte.
   > Corrigido movendo o `authorized_keys` para o home real; diagnóstico em
   > [`staging.md` §11](staging.md).
5. Manter o host antigo intocado por ~2 semanas como rollback frio.

`PAYMENT_WEBHOOK_BASE_URL` continua `https://payment.lmhost.com.br` em todas as
fases — nenhuma ref precisa ser reemitida no C6.

# Segredos do payment no Vault (infra lmhost)

Como o `payment-api` recebe sua configuração em `pre-prod`, e o que fazer quando
ela falha. Escrito na Fase 3 da migração lmhost (SIN-70001).

## O desenho em uma frase

Nenhuma configuração vive em disco no host da aplicação: a cada boot o serviço
autentica no Vault por AppRole, materializa tudo em `/run/payment/<inst>/`
(tmpfs) e entrega o processo ao binário.

```
systemd  →  payment-run.sh <inst>
                ├─ vault-materialize.py <inst>   → /run/payment/<inst>/env  (0600)
                │      AppRole → Vault           → /run/payment/<inst>/c6/*.{crt,key} (0600)
                └─ exec payment-api
```

| Onde | O quê |
|---|---|
| `minio` 172.18.2.63:8200 | Vault. KV v2 em `payment/`, caminhos `payment/prod` e `payment/sbx` |
| `pre-prod` `/etc/payment/approle-<inst>` | `role_id` + `secret_id`, 0640 `root:payment` |
| `pre-prod` `/etc/payment/vault-ca.crt` | CA do Vault (autoassinado; SAN traz `IP:172.18.2.63`) |
| `pre-prod` `/opt/payment/bin/vault-materialize.py` | busca e materializa |
| `pre-prod` `/opt/payment/bin/payment-run.sh` | materializa, exporta, `exec` no binário |
| `pre-prod` `/run/payment/<inst>/` | tmpfs, 0700, apagado quando o serviço para |

Uma policy por instância, com `read` apenas no próprio caminho. `payment-prod`
não enxerga `payment/sbx`, e nenhuma das duas alcança `transit/` ou o que a
NFS-e usa no mesmo Vault.

## Por que um wrapper e não `ExecStartPre` + `EnvironmentFile`

Porque não funciona, e a falha é silenciosa no diagnóstico: o systemd carrega o
`EnvironmentFile` **antes** de executar o `ExecStartPre`, e se o arquivo ainda
não existe ele recusa a unit inteira com `Failed to load environment files` sem
sequer rodar o start-pre. Medido nesta máquina. Como o arquivo só passa a existir
depois de falarmos com o Vault, o carregamento precisa acontecer dentro do mesmo
processo que vira o serviço.

## Fail-closed, e o que isso custa

Vault selado, fora do ar, ou segredo sem `PAYMENT_BANK_VAULT_KEY` ⇒ o
materializador sai diferente de zero e o `payment-api` **não sobe**.

É deliberado. Subir sem a KEK é pior que não subir: os cofres caem para memória,
as credenciais bancárias configuradas em runtime somem, e isso só apareceria
quando um cliente tentasse cobrar.

O custo é uma dependência de boot entre duas máquinas: `minio` reiniciou ⇒ o
Vault volta **selado** (shamir 3 de 5) ⇒ o payment não sobe até alguém deselar.
Isso é compartilhado com a custódia A1 da NFS-e, que depende do mesmo Vault.

## `is-active` mente durante a falha

Com `Restart=on-failure`, uma unit que falha para sempre segue reportando
`active` enquanto cicla. Medido: com o Vault bloqueado, `systemctl is-active`
dizia `active` com a porta sem escuta nenhuma.

As units têm `StartLimitIntervalSec=300` / `StartLimitBurst=5` justamente para
que 5 falhas seguidas levem a unit a `failed`, que é o estado que o operador e o
alerta conseguem ver. O alerta `PaymentUnitFalhou` no Prometheus (em `rabbit`)
observa `node_systemd_unit_state{state="failed"}`.

**Não confie em `is-active` para saber se o serviço atende.** Use a porta:

```sh
ss -lnt | grep 8080          # prod
curl -sS http://172.18.1.82:8081/healthz
```

## Diagnóstico

```sh
journalctl -u payment-api-sbx | grep vault-materialize | tail -5
```

| Mensagem | Causa |
|---|---|
| `login falhou: <urlopen error timed out>` | Vault inalcançável: selado, parado, ou ufw de `minio` sem `8200` para 172.18.1.82 |
| `respondeu HTTP 403` | `secret_id` revogado/expirado, ou policy sem `read` no caminho |
| `segredo sem PAYMENT_BANK_VAULT_KEY` | o KV foi gravado incompleto — **não** contorne subindo sem KEK |
| `valor multilinha em X` | alguém gravou um PEM fora dos campos `C6_CLIENT_*_PEM` |

## Nunca materialize no diretório do serviço

`vault-materialize.py <inst>` escreve em `/run/payment/<inst>` — que é onde o
processo em execução guarda os PEMs que apresenta ao C6. Uma ferramenta de
operador que materialize ali e depois limpe leva junto os arquivos do serviço.
Aconteceu: um script de diagnóstico fez exatamente isso, e o `payment-api` só não
quebrou porque já tinha lido tudo no boot.

Passe um destino próprio, e rode como o usuário `payment` (rodando como root os
arquivos ficam 0700 do root e o serviço não os lê):

```sh
sudo install -d -o payment -g payment -m 0700 /run/payment-ops
sudo -u payment python3 /opt/payment/bin/vault-materialize.py prod /run/payment-ops/prod
# ... use ...
sudo rm -rf /run/payment-ops
```

Os caminhos dos PEMs no env são derivados do destino, não copiados do cofre, para
que o valor e o arquivo não possam divergir.

## Operações

Ver a forma do segredo (chaves, sem valores), em `minio`:

```sh
sudo bash -c 'source /root/vault-env.sh && vault kv get -format=json payment/prod' \
  | python3 -c 'import sys,json;[print(k) for k in sorted(json.load(sys.stdin)["data"]["data"])]'
```

Rotacionar o `secret_id` de uma instância (em `minio`, depois copiar para
`/etc/payment/approle-<inst>` em `pre-prod` e reiniciar a unit):

```sh
sudo bash -c 'source /root/vault-env.sh && vault write -f -field=secret_id \
  auth/approle/role/payment-prod/secret-id'
```

Trocar um valor sem reescrever o resto: leia o JSON, altere a chave, grave de
volta com `vault kv put payment/<inst> -`. `vault kv put` **substitui** o segredo
inteiro — passar só um campo apaga os outros.

Depois de qualquer alteração, `systemctl restart payment-api<-sbx>`: a
materialização só acontece no start.

## Pendências conhecidas

- **`root_token` e as 5 unseal keys estão em `/root/vault-init.json`, na própria
  máquina do Vault.** Quem tem root em `minio` deselar e lê tudo, o que anula o
  split de Shamir e enfraquece o motivo de a KEK morar aqui. Tirar da máquina.
- `secret_id` sem TTL (`secret_id_ttl=0`), para não derrubar o serviço no meio da
  noite. A rotação é manual, pelo procedimento acima.
- A materialização acontece só no start. Um segredo trocado no Vault não alcança
  um processo já rodando.

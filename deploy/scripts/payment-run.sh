#!/usr/bin/env bash
# payment-run.sh <prod|sbx> — busca a configuracao no Vault e entrega o processo
# ao payment-api.
#
# Por que um wrapper e nao ExecStartPre + EnvironmentFile: o systemd carrega o
# EnvironmentFile ANTES de rodar o ExecStartPre, e se o arquivo nao existe ele
# recusa a unit inteira ("Failed to load environment files") sem sequer executar
# o start-pre. Testado nesta maquina, nao presumido. Como o arquivo so passa a
# existir depois de falarmos com o Vault, o carregamento precisa acontecer dentro
# do mesmo processo que vira o servico — que e o que este script faz, terminando
# em exec para nao deixar um shell no meio.
#
# Fail-closed: se o materializador sair diferente de zero (Vault selado, fora do
# ar, ou segredo sem KEK), o set -e derruba aqui e o payment-api nunca roda.
set -euo pipefail

inst="${1:?uso: payment-run.sh <prod|sbx>}"
env_file="/run/payment/${inst}/env"

/usr/bin/python3 /opt/payment/bin/vault-materialize.py "$inst"

# Lido linha a linha e exportado sem passar pelo shell: um valor com espaco ou
# com aspas nao pode virar palavra solta nem ser reinterpretado.
while IFS= read -r line; do
  [ -n "$line" ] || continue
  case "$line" in \#*) continue ;; esac
  export "${line%%=*}=${line#*=}"
done < "$env_file"

exec /opt/payment/bin/payment-api

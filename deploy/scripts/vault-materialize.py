#!/usr/bin/env python3
"""vault-materialize.py <prod|sbx> — materializa a configuracao da instancia.

Roda como ExecStartPre. Autentica no Vault por AppRole, le payment/<inst> e
escreve /run/payment/<inst>/env mais os PEMs mTLS em /run/payment/<inst>/c6/.
Tudo em tmpfs: o systemd apaga o RuntimeDirectory quando o servico para, entao
nenhum segredo encosta em disco persistente.

Fail-closed em todo caminho. Vault selado, inacessivel, ou resposta sem a KEK =>
saida diferente de zero e o servico NAO sobe. Subir sem KEK seria pior que nao
subir: os cofres cairiam para memoria, as credenciais bancarias configuradas em
runtime sumiriam, e isso so apareceria quando um cliente tentasse cobrar.

Usa apenas a stdlib contra a API HTTP do Vault — sem CLI e sem jq para instalar.
"""
import json
import os
import ssl
import sys
import urllib.request

VAULT_ADDR = "https://172.18.2.63:8200"
CA_FILE = "/etc/payment/vault-ca.crt"

PEMS = {"C6_CLIENT_CERT_PEM": "c6/client.crt", "C6_CLIENT_KEY_PEM": "c6/client.key"}


def die(msg):
    sys.stderr.write("vault-materialize: %s\n" % msg)
    raise SystemExit(1)


def post(path, payload, token=None):
    req = urllib.request.Request(
        VAULT_ADDR + path,
        data=json.dumps(payload).encode() if payload is not None else None,
        method="POST" if payload is not None else "GET",
    )
    if token:
        req.add_header("X-Vault-Token", token)
    # Verificacao ligada. O certificado do Vault traz IP:172.18.2.63 no SAN, entao
    # ela funciona contra o IP. Desligar deixaria qualquer um na VLAN se passar
    # pelo Vault e servir uma KEK falsa.
    ctx = ssl.create_default_context(cafile=CA_FILE)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=5) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")[:300]
        die("%s respondeu HTTP %s: %s" % (path, e.code, body))
    except Exception as e:  # rede, TLS, Vault selado
        die("%s falhou: %s" % (path, e))


def main():
    if len(sys.argv) not in (2, 3) or sys.argv[1] not in ("prod", "sbx"):
        die("uso: vault-materialize.py <prod|sbx> [destino]")
    inst = sys.argv[1]
    # O destino e parametrizavel para que uma ferramenta de operador NAO escreva
    # nem apague o diretorio de runtime do servico em execucao. Ja aconteceu: um
    # script de diagnostico materializou em /run/payment/prod e depois fez rm -rf,
    # levando junto os PEMs do processo que estava servindo.
    dest = sys.argv[2] if len(sys.argv) == 3 else "/run/payment/%s" % inst

    creds = {}
    with open("/etc/payment/approle-%s" % inst) as f:
        for line in f:
            if "=" in line:
                k, _, v = line.strip().partition("=")
                creds[k] = v
    for k in ("VAULT_ROLE_ID", "VAULT_SECRET_ID"):
        if not creds.get(k):
            die("%s ausente em /etc/payment/approle-%s" % (k, inst))

    login = post("/v1/auth/approle/login",
                 {"role_id": creds["VAULT_ROLE_ID"], "secret_id": creds["VAULT_SECRET_ID"]})
    token = login.get("auth", {}).get("client_token")
    if not token:
        die("login AppRole nao devolveu token")

    secret = post("/v1/payment/data/%s" % inst, None, token=token)
    data = secret.get("data", {}).get("data") or {}
    if not data.get("PAYMENT_BANK_VAULT_KEY"):
        die("segredo sem PAYMENT_BANK_VAULT_KEY — recusando subir sem KEK")

    # mode= em makedirs sofre o umask; o chmod explicito e o que garante 0700.
    os.makedirs(os.path.join(dest, "c6"), mode=0o700, exist_ok=True)
    os.chmod(dest, 0o700)
    os.chmod(os.path.join(dest, "c6"), 0o700)

    n_pems = 0
    for key, rel in PEMS.items():
        if data.get(key):
            path = os.path.join(dest, rel)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(data[key])
            n_pems += 1

    # Os caminhos dos PEMs sao DERIVADOS do destino, nunca copiados do cofre: se o
    # valor gravado la divergir do lugar onde o arquivo foi mesmo escrito, o
    # processo aponta para um arquivo que nao existe.
    data["PAYMENT_C6_CLIENT_CERT"] = os.path.join(dest, PEMS["C6_CLIENT_CERT_PEM"])
    data["PAYMENT_C6_CLIENT_KEY"] = os.path.join(dest, PEMS["C6_CLIENT_KEY_PEM"])

    lines = []
    for k in sorted(data):
        if k in PEMS:
            continue
        v = str(data[k])
        # EnvironmentFile e KEY=VALUE puro. Uma quebra de linha viraria uma linha
        # solta que o systemd leria como outra variavel — recuse na origem.
        if "\n" in v:
            die("valor multilinha em %s; so PEM pode ser multilinha" % k)
        lines.append("%s=%s" % (k, v))

    path = os.path.join(dest, "env")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(lines) + "\n")

    sys.stderr.write("vault-materialize: %s — %d variaveis, %d PEMs\n" % (inst, len(lines), n_pems))


main()

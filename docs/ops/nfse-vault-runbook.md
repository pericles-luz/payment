# NFS-e: ligar a emissão no payment (Vault + env)

Procedimento para ligar `PAYMENT_NFSE_*` na instância **prod** do payment (`payment-api`,
`pre-prod`), apontando primeiro para a **produção restrita** do ADN (`tpAmb=2`). Uma instância
só, porque o A1 fica custodiado por empresa + CNPJ: se catalogo e go-mei-das falarem com a mesma
empresa na mesma instância, o certificado é importado uma vez.

Contexto e decisões: [ADR-0014](../security/adr-0014-nfse.md). Segredos do payment no Vault:
[vault-lmhost.md](../deploy/vault-lmhost.md).

## Estado em 24/11/2026

Já aplicados, e conferidos de `pre-prod`:
- **Passo 1:** feito. O AppRole loga pela CA, lê `payment-transit` e recebe 403 em `transit/`
  (go-mei-das) e no KV.
- **Passo 2:** feito, **sem** `PAYMENT_NFSE_ENABLED`, porque o binário em produção ainda não tem
  NFS-e.
- **Passo 4:** feito. Empresa LM Host `cb2d535f2911773d6d738acf641dcd15` (Conta Verz); token de
  empresa em `PAYMENT_TENANT_TOKENS` e em `/etc/mei-das/serve.env` do `syndeotech-lb`.
- **Envs fiscais:** gravadas em `/etc/mei-das/serve.env` (`LMHOST_BILLING_NFSE_*`) e em
  `/etc/catalogo/env` do `vitrine-worker-01` (`CATALOGO_NFSE_*`), com backup `*.bak-nfse-*`.

Faltam, depois do merge e do deploy:
1. Gravar `PAYMENT_NFSE_ENABLED=true` no KV e reiniciar o `payment-api` (passo 3).
2. Reiniciar o `mei-das-serve` e o catalogo com as versões novas.
3. Importar o A1 (passo 5).

## 0. Pré-requisitos

- O binário com NFS-e (branch `feat/nfse-emissao`) **já implantado**. Se os passos 1 a 3 forem
  feitos antes do deploy, deixe `PAYMENT_NFSE_ENABLED` vazio: com ele ligado e a configuração
  incompleta, o boot **falha**, por desenho.
- O Vault deselado.

## 1. Mount, política e AppRole (em `minio`)

```sh
sudo -i
source /root/vault-env.sh

# Mount Transit PRÓPRIO do payment. Nunca o "transit/" do go-mei-das: a política concede
# keys/+ (qualquer nome) no mount, então um mount compartilhado deixaria um serviço
# apagar as chaves do outro.
vault secrets enable -path=payment-transit transit

# Mesma política do go-mei-das, só que no mount e no prefixo do payment
# (custody.FiscalSignerVaultPolicyFor("payment-transit", "payment-a1")).
vault policy write payment-nfse - <<'HCL'
path "payment-transit/sign/payment-a1.*" {
  capabilities = ["update"]
}
path "payment-transit/keys/+" {
  capabilities = ["read", "delete"]
}
path "payment-transit/keys/+/config" {
  capabilities = ["update"]
  allowed_parameters = {
    "deletion_allowed" = [true]
  }
}
path "payment-transit/keys/+/import" {
  capabilities = ["update"]
}
path "payment-transit/wrapping_key" {
  capabilities = ["read"]
}
HCL

# AppRole própria para a emissão. NÃO é a payment-prod: aquela só lê o KV na
# materialização. Esta é usada pelo processo em execução para assinar.
vault write auth/approle/role/payment-nfse \
  token_policies=payment-nfse token_ttl=20m token_max_ttl=1h \
  secret_id_ttl=0 token_bound_cidrs=172.18.1.82/32 secret_id_bound_cidrs=172.18.1.82/32

vault read -field=role_id auth/approle/role/payment-nfse/role-id
vault write -f -field=secret_id auth/approle/role/payment-nfse/secret-id
```

Guarde o `role_id` e o `secret_id` só para o passo 2. Não os deixe em histórico de shell nem em
arquivo.

## 2. Variáveis no KV `payment/prod` (em `minio`)

`vault kv put` **substitui o segredo inteiro**. Leia, acrescente e grave:

```sh
vault kv get -format=json payment/prod | python3 -c '
import sys, json
d = json.load(sys.stdin)["data"]["data"]
d.update({
  "PAYMENT_NFSE_ENABLED": "true",
  "PAYMENT_NFSE_VAULT_ADDR": "https://172.18.2.63:8200",
  "PAYMENT_NFSE_VAULT_CA_FILE": "/etc/payment/vault-ca.crt",
  "PAYMENT_NFSE_VAULT_ROLE_ID": "<role_id>",
  "PAYMENT_NFSE_VAULT_SECRET_ID": "<secret_id>",
  "PAYMENT_NFSE_ADN_URL": "https://sefin.producaorestrita.nfse.gov.br/SefinNacional",
  "PAYMENT_NFSE_DANFSE_URL": "https://adn.producaorestrita.nfse.gov.br",
  "PAYMENT_NFSE_PRODUCAO": "false",
})
json.dump(d, sys.stdout)' > /root/payment-prod.json
vault kv put payment/prod @/root/payment-prod.json && shred -u /root/payment-prod.json
vault kv get -format=json payment/prod | python3 -c 'import sys,json;[print(k) for k in sorted(json.load(sys.stdin)["data"]["data"])]'
```

`PAYMENT_NFSE_VAULT_MOUNT` e `PAYMENT_NFSE_VAULT_KEY_PREFIX` ficam de fora: os padrões
(`payment-transit`, `payment-a1`) são os do passo 1.

## 3. Reiniciar e conferir (em `pre-prod`)

```sh
sudo systemctl restart payment-api
journalctl -u payment-api -n 50 | grep -E 'NFS-e|nfse|vault-materialize'
# esperado: "api: NFS-e enabled (tpAmb=2, adn=https://sefin.producaorestrita..., danfse=true)"
ss -lnt | grep 8080
```

Se o serviço não subir, a mensagem do boot diz qual variável falta ou qual URL não é https.

## 4. Empresa da LHMOST e token do go-mei-das

1. Use a empresa (tenant) da LHMOST que o catalogo já guarda em `platform_payment_settings`.
   É nela que o A1 vai ser importado.
2. O go-mei-das fala com essa mesma empresa por um **token de empresa**, nunca pela
   chave-de-Conta do catalogo, que dá acesso a todas as empresas da Conta:
   - gere um token aleatório (`openssl rand -base64 32`);
   - acrescente `token=<tenant_id>` em `PAYMENT_TENANT_TOKENS` no KV `payment/prod` (mesmo
     procedimento do passo 2) e reinicie;
   - no go-mei-das: `PAYMENT_API_URL=https://payment.lmhost.com.br`, `PAYMENT_API_TOKEN=<token>`,
     sem `PAYMENT_CLIENT_TENANT`.

## 5. Certificado A1

Depois que o `.pfx` existir:

```sh
curl -sS -X PUT https://payment.lmhost.com.br/admin/tenants/<tenant_id>/nfse-certificate \
  -H "Authorization: Bearer <token admin>" -H 'Content-Type: application/json' \
  --data-binary @- <<EOF
{"cnpj":"67188163000110","pfx_base64":"$(base64 -w0 lmhost.pfx)","password":"<senha>"}
EOF
```

A resposta traz serial e validade. A importação aparece na auditoria como `nfse.certificate.set`.

## 6. Primeira nota e virada para produção

1. Emita uma nota de teste pelo catalogo ou pelo go-mei-das. Em produção restrita ela não tem
   valor fiscal.
2. Confira `GET /v1/nfse/{id}/pdf`. Se a rota responder 404 `nfse_pdf_unavailable` com a nota
   autorizada, o endpoint de DANFSe do ADN é outro: ajuste `PAYMENT_NFSE_DANFSE_URL`.
3. Para produção, troque no KV e reinicie:
   - `PAYMENT_NFSE_ADN_URL` → a URL de produção da Sefin Nacional;
   - `PAYMENT_NFSE_DANFSE_URL` → a do ADN de produção;
   - `PAYMENT_NFSE_PRODUCAO=true`.

## Rollback

`PAYMENT_NFSE_ENABLED` vazio e reiniciar: as rotas passam a responder 503. Nada mais muda. As
chaves continuam no Vault e as notas já emitidas continuam no ADN.

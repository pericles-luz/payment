# ADR-0014 — NFS-e emitida pelo gateway, com o A1 custodiado no Vault por AppRole própria

- **Status:** Aceito.
- **Data:** 24/11/2026.
- **Relação:** a custódia do A1 veio do go-mei-das (ADR-0007 e ADR-0008 daquele repositório,
  "nfse-a1-custody-kms" e "nfse-mei-custody"). O tenancy é o do [ADR-0009](adr-0009-two-level-tenancy.md).
  O seletor de empresa é o do [ADR-0011](adr-0011-account-key-client-selector.md).

## Contexto

A LHMOST emite todo mês NFS-e para os clientes do `catalogo` (revenda) e do `go-mei-das` (API
DAS). O emissor existia só dentro do go-mei-das (`internal/nfse`), que nenhum outro módulo
consegue importar. Decidiu-se que **o gateway passa a ser o único emissor** e que os produtos
chamam `POST /v1/nfse`. O go-mei-das deixa de emitir por conta própria.

## Decisão

1. **Código copiado, não importado.** `internal/nfse/**` (DPS, XMLDSig, cliente ADN, custódia,
   import A1) foi copiado para `payment/internal/nfse`. Além disso, ganhou três coisas:
   - o tomador (`toma`) na DPS;
   - a numeração da DPS feita pelo gateway;
   - a guarda do XML autorizado.
2. **Numeração da DPS é do gateway.** Ela fica em `nfse_dps_sequences`, por (CNPJ, série), com
   upsert atômico. Vários produtos emitem pelo mesmo CNPJ. Se o número viesse do cliente, ou
   colidiria (DPS duplicada, rejeitada pela Sefin) ou exigiria coordenação entre sistemas.
   - O número é gravado na reserva (`pending`) **antes** da transmissão. Quem assume uma reserva
     órfã reenvia a mesma DPS, e a Sefin deduplica. Assim não sai uma segunda nota.
3. **Contagem no razão, atômica com o registro.** A emissão autorizada e a entrada
   `billing_ledger` (`nfse.emit`) são gravadas na mesma `WithinTx`. Sem preço configurado, a
   entrada vale R$ 0, mas existe, e por isso a operação aparece no Consumo e nas Faturas.
   - Rejeição e falha de transporte não contam.
   - Reenvio idempotente não conta de novo.
4. **Custódia do A1:**
   - A chave privada é importada como chave **não exportável** no Vault transit. O gateway só
     pede assinaturas de digest, e o mTLS com o ADN usa um `crypto.Signer` que delega ao Vault.
   - O banco guarda só a cadeia pública, o serial, o `notAfter` e o **hash** do CNPJ
     (`nfse_a1_certs`).
   - O payment usa uma **AppRole própria** e um **mount Transit próprio** (`payment-transit`,
     chaves `payment-a1.*`). Nunca usa o `transit/` do go-mei-das: a política de custódia concede
     `keys/+` (qualquer nome) no mount, por causa da prioridade de globs do Vault, então mount
     compartilhado deixaria um serviço apagar as chaves do outro. Com mounts separados, o
     comprometimento de um serviço não dá ao outro capacidade de assinar notas nem de destruir
     certificados. Procedimento em `docs/ops/nfse-vault-runbook.md`.
5. **Tenancy.** A chave da custódia é `company_id = tenant_id + "_" + CNPJ`. Uma empresa-cliente
   pode emitir por mais de um CNPJ, cada um com o seu A1. Uma empresa nunca assina com o A1 de
   outra, e toda leitura de emissão é escopada pela empresa autenticada: id de outra empresa
   responde `404`.
6. **Falha fechada na configuração.**
   - Com `PAYMENT_NFSE_ENABLED` desligado, as rotas respondem `503`.
   - Com ela ligada e a configuração incompleta, ou com Vault, ADN ou DANFSe em `http://`, o
     boot falha.
   - `PAYMENT_NFSE_PRODUCAO` começa falso, ou seja, `tpAmb=2`, produção restrita.
7. **Auditoria.** Toda importação de A1 (rota da empresa ou `/admin`) grava
   `nfse.certificate.set` com quem, qual empresa e quando. Nunca grava o arquivo, a senha nem
   o CNPJ.

## Consequências

- **Dados pessoais.** O tomador pode ser pessoa física, com CPF. O documento e o nome dele
  ficam em `nfse_emissions` e também no XML fiscal, que por natureza os contém. A leitura é
  escopada pela empresa.
  - Diferente de `pix_rec.devedor_*`, essa leitura **não** passa pelo registro de acesso a PII
    do ADR-0008. Fica como pendência, se a NFS-e para pessoa física virar uso real.
- **Certificados do go-mei-das.** Os A1 já custodiados lá não migram: as chaves não são
  exportáveis. Cada CNPJ precisa ser **reimportado** no payment.
- **Numeração.** Se um CNPJ já emitiu DPS por outro sistema (por exemplo, o emissor web
  nacional) na mesma série, o primeiro número do gateway pode colidir. Nesse caso, use outra
  série (`serie` na requisição).
- **URL do DANFSe.** O endpoint `GET /danfse/{chave}` do ADN está configurado em
  `PAYMENT_NFSE_DANFSE_URL` e precisa ser confirmado em produção restrita antes de ligar em
  produção. Sem ele, só a rota `/pdf` fica indisponível; a emissão não é afetada.

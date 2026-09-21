# Rodar o roteiro de homologação do C6

Duas ferramentas, nesta ordem. A primeira fala com o banco; a segunda escreve no
documento que vai para `homologacaoapi@c6bank.com`.

## 1. Capturar as evidências

```sh
go build -o /tmp/c6-roteiro ./cmd/c6-roteiro

C6_CLIENT_SECRET='…' C6_PIX_KEY='…' /tmp/c6-roteiro \
  --cert /mnt/x/parceiros/LMHost/c6bank/20260921.crt \
  --key  /mnt/x/parceiros/LMHost/c6bank/20260921.key \
  --client-id cc07c5db-c4be-4622-a216-58ed90caac62 \
  --webhook-url https://payment.lmhost.com.br/webhooks/c6/<ref> \
  --out /mnt/x/parceiros/LMHost/c6bank/20260921_evidencias.json
```

O segredo e a chave PIX vêm do ambiente, não da linha de comando — o histórico do shell
guarda o que se digita nela.

**A janela do sandbox é seg–sex, 7h–23h BRT.** A ferramenta avisa quando você está fora
dela, porque o que falha aí parece problema de contrato e não é.

A corrida leva de quinze a trinta minutos: são ~90 chamadas a uma a cada 1,1 s (o limite
é 60 por minuto somando TODAS as APIs), mais as esperas dos casos que dependem de
processamento do banco.

### Refazer só um bloco

```sh
… --only P_01 --merge --out <o mesmo arquivo>
```

`--merge` sobrescreve só os casos desta corrida e preserva o resto. Serve para quando um
bloco falhou por forma errada de requisição: corrigir e refazer os nove custaria a
janela inteira.

### `--webhook-servico`

Desligado por padrão, e é para deixar assim salvo em janela combinada. O webhook PIX é
chaveado pela chave — a nossa é nova, e o próprio roteiro a apaga em `P_06_03`. Os de
SERVIÇO (`B_07` BANK_SLIP, `C_04` CHECKOUT) valem para a conta de sandbox inteira,
substituem o destino de quem já a usa, e a superfície não expõe DELETE.

## 2. Preencher o documento

```sh
python3 scripts/preencher-roteiro.py \
  --modelo "/mnt/x/parceiros/LMHost/c6bank/Roteiro de Testes - C6 Developers v3.0.docx" \
  --evidencias /mnt/x/parceiros/LMHost/c6bank/20260921_evidencias.json \
  --saida      /mnt/x/parceiros/LMHost/c6bank/20260921_testes.docx

python3 scripts/preencher-roteiro.py --verificar \
  /mnt/x/parceiros/LMHost/c6bank/20260921_testes.docx
```

`--verificar` relê o arquivo gravado sem depender do Word: zip íntegro, XML bem formado,
146 campos preenchidos, 8 caixas marcadas, e todo corpo com o rótulo de sandbox que a
cláusula 2.4-iii do Termo de APIs exige.

Os dados da organização têm padrão (LMHost / Verz / CNPJ 67.188.163/0001-10) e bandeiras
para trocar: `--cnpj`, `--empresa`, `--software`, `--responsavel`, `--email`,
`--telefone`. `--blocos` escolhe quais caixas marcar.

**Abra uma vez no Word ou LibreOffice antes de enviar.** A verificação prova a estrutura;
ela não prova que o documento está legível para quem vai lê-lo.

## O que esperar da corrida

Ver [`docs/homologacao/roteiro-v3-camadaB.md`](../docs/homologacao/roteiro-v3-camadaB.md):
o que ficou sem 2xx, por quê, e o que depende do gerente da conta em vez de código.

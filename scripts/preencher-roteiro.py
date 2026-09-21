#!/usr/bin/env python3
"""Preenche o "Roteiro de Testes - C6 Developers v3.0" com as evidências capturadas.

Uso:
    preencher-roteiro.py --modelo ROTEIRO.docx --evidencias evidencias.json --saida PREENCHIDO.docx
    preencher-roteiro.py --verificar PREENCHIDO.docx

Só a biblioteca padrão. `python-docx` não está instalado em lugar nenhum deste
projeto, e um .docx é um zip com XML dentro — a dependência não se paga.

# Como o documento guarda o que se digita nele

São campos de formulário LEGADOS do Word, não controles de conteúdo modernos:

  * **8 FORMCHECKBOX**, um por bloco de API. Marcar é pôr `<w:checked w:val="1"/>`
    dentro do `<w:checkBox>`. (AUTENTICAÇÃO não tem caixa — é obrigatória.)
  * **146 FORMTEXT**. Em ordem de documento: os 6 primeiros são os dados da
    organização, e os 140 restantes são 70 pares (status, corpo), um par por tabela
    "TESTE: XX".

Um FORMTEXT é uma sequência de runs: `fldChar begin` (com o `ffData`), o `instrText`,
`fldChar separate`, **o resultado**, `fldChar end`. Preencher é trocar o resultado.

O documento vem com `<w:documentProtection w:edit="forms" w:enforcement="1"/>` e SEM
hash de senha: preencher formulário é exatamente o uso previsto, não há proteção a
contornar.

# A associação caso ↔ célula não é por posição fixa

Cada tabela de resultado é lida para descobrir de que caso ela é ("TESTE: P_01_01"), e
os campos são casados na ordem em que aparecem. Assim uma revisão do roteiro que
acrescente ou remova um caso é detectada — o script recusa o que não reconhece — em vez
de deslocar em silêncio todas as respostas seguintes, que é o erro que ninguém revisa.
"""

import argparse
import json
import re
import shutil
import sys
import zipfile
from xml.etree import ElementTree as ET

W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
DOC = "word/document.xml"

# O rótulo que abre TODO corpo de resposta.
#
# O Termo de APIs do C6, cláusula 2.4-iii, proíbe apresentar transação de sandbox como
# real e exige que capturas de homologação sejam rotuladas como não-produtivas. Fica no
# script, e não na disciplina de quem preenche, porque disciplina não sobrevive à
# terceira rodada.
ROTULO = "[SANDBOX — NÃO PRODUTIVO] "

# Os 8 checkboxes, na ordem em que aparecem no documento.
BLOCOS = [
    "AGENDAMENTO DE PAGAMENTOS",
    "BOLETO",
    "CHECKOUT",
    "EXTRATO",
    "PIX",
    "TRANSAÇÕES E RECEBÍVEIS",
    "PIX AUTOMÁTICO",
    "BOLEPIX",
]


def texto_do_paragrafo(p):
    return "".join(t.text or "" for t in p.iter(W + "t"))


def conta_formtext(el):
    return sum(1 for it in el.iter(W + "instrText") if "FORMTEXT" in (it.text or ""))


def mapear_campos(xml_bytes):
    """Devolve (campos_da_organizacao, [(caso, n_campos)]) em ordem de documento."""
    root = ET.fromstring(xml_bytes)
    body = root.find(W + "body")
    org = 0
    casos = []
    for ch in body:
        n = conta_formtext(ch)
        if not n:
            continue
        if ch.tag != W + "tbl":
            raise SystemExit("campo de formulário fora de tabela; modelo inesperado")
        linhas = [
            [" ".join(texto_do_paragrafo(p).strip() for p in c.findall(W + "p")).strip()
             for c in tr.findall(W + "tc")]
            for tr in ch.findall(W + "tr")
        ]
        titulo = linhas[0][0] if linhas and linhas[0] else ""
        if "DADOS DA ORGANIZAÇÃO" in titulo:
            org = n
            continue
        m = re.match(r"TESTE:\s*([A-Z]+_[A-Z0-9_]+)", titulo)
        if not m:
            raise SystemExit(f"tabela com campo de formulário e sem caso: {titulo!r}")
        if n != 2:
            raise SystemExit(f"{m.group(1)}: esperava 2 campos (status, corpo), há {n}")
        casos.append(m.group(1))
    return org, casos


# Começo de um run: `<w:r>` ou `<w:r ` com atributos. O padrão é explícito porque um
# `str.rindex("<w:r")` casa também com `<w:rPr`, e cortar o XML no meio de um `<w:rPr>`
# gera um documento que o Word abre como corrompido — sem nenhum erro no caminho.
INICIO_DE_RUN = re.compile(r"<w:r[ >]")


def ultimo_run_antes(xml, inicio, fim):
    """Posição do último `<w:r>` que começa em [inicio, fim)."""
    ocorrencias = [m.start() for m in INICIO_DE_RUN.finditer(xml, inicio, fim)]
    if not ocorrencias:
        raise SystemExit("campo sem run de fechamento; modelo inesperado")
    return ocorrencias[-1]


def regiao_do_resultado(xml, pos):
    """Delimita o RESULTADO do próximo FORMTEXT a partir de `pos`.

    Devolve (inicio, fim, proxima_posicao) ou None quando não há mais campos.
    """
    marca = xml.find("FORMTEXT", pos)
    if marca < 0:
        return None
    sep = xml.index('w:fldCharType="separate"', marca)
    inicio = xml.index("</w:r>", sep) + len("</w:r>")
    fim_marca = xml.index('w:fldCharType="end"', inicio)
    fim = ultimo_run_antes(xml, inicio, fim_marca)
    return inicio, fim, fim


def escapar(texto):
    """XML-escapa e converte quebra de linha em <w:br/>."""
    texto = (texto.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
    partes = texto.split("\n")
    runs = []
    for i, parte in enumerate(partes):
        if i:
            runs.append("<w:br/>")
        if parte:
            runs.append(f'<w:t xml:space="preserve">{parte}</w:t>')
    return "".join(runs) or '<w:t xml:space="preserve"></w:t>'


def preencher_campos(xml, valores):
    """Troca o RESULTADO de cada FORMTEXT, na ordem, pelos valores dados."""
    saida = []
    pos = 0
    for valor in valores:
        regiao = regiao_do_resultado(xml, pos)
        if regiao is None:
            raise SystemExit("modelo tem menos campos de texto que valores a preencher")
        inicio, fim, _ = regiao

        # Reaproveita a formatação do resultado antigo para o novo texto não destoar.
        antigo = xml[inicio:fim]
        m = re.search(r"<w:rPr>.*?</w:rPr>", antigo, re.S)
        rpr = m.group(0) if m else ""

        saida.append(xml[pos:inicio])
        saida.append(f"<w:r>{rpr}{escapar(valor)}</w:r>")
        pos = fim
    saida.append(xml[pos:])
    return "".join(saida)


def marcar_caixas(xml, marcar):
    """Marca os checkboxes cujos índices (0..7) estão em `marcar`."""
    saida = []
    pos = 0
    for i in range(len(BLOCOS)):
        cb = xml.find("<w:checkBox>", pos)
        if cb < 0:
            raise SystemExit("modelo tem menos caixas de seleção que blocos")
        fim = xml.index("</w:checkBox>", cb)
        trecho = xml[cb:fim]
        if i in marcar:
            trecho = trecho.replace('<w:checked w:val="0"/>', '<w:checked w:val="1"/>')
            if '<w:checked w:val="1"/>' not in trecho:
                trecho += '<w:checked w:val="1"/>'
        saida.append(xml[pos:cb])
        saida.append(trecho)
        pos = fim
    saida.append(xml[pos:])
    return "".join(saida)


def corpo_da_evidencia(ev):
    """Monta o texto da célula "Response Body - Retornado" de um caso."""
    partes = [ROTULO]
    if ev.get("metodo") and ev.get("url"):
        partes.append(f"{ev['metodo']} {ev['url']}\n")
    if ev.get("request"):
        partes.append(f"REQUEST: {ev['request']}\n")
    if ev.get("erro"):
        partes.append(f"ERRO DE TRANSPORTE: {ev['erro']}\n")
    partes.append(ev.get("body") or "(sem corpo)")
    if ev.get("quando"):
        partes.append(f"\n\nCapturado em {ev['quando']} (ambiente {ev.get('ambiente', '?')}).")
    return "".join(partes)


def status_da_evidencia(ev):
    """Texto da célula "Status Code - Retornado"."""
    status = ev.get("status") or 0
    if status:
        return str(status)
    # Caso sem chamada de saída (evento de entrada, pré-requisito ausente): dizer isso
    # é mais honesto do que escrever um "0" que se lê como status.
    return "— (não houve resposta HTTP; ver a descrição)"


def preencher(modelo, evidencias, saida, organizacao, blocos):
    with zipfile.ZipFile(modelo) as z:
        xml = z.read(DOC).decode("utf8")
        partes = {n: z.read(n) for n in z.namelist()}

    n_org, casos = mapear_campos(xml.encode("utf8"))
    if n_org != len(organizacao):
        raise SystemExit(f"a tabela da organização tem {n_org} campos, e há {len(organizacao)} valores")

    faltando = [c for c in casos if c not in evidencias]
    if faltando:
        raise SystemExit("sem evidência para: " + ", ".join(faltando))
    sobrando = [c for c in evidencias if c not in casos]
    if sobrando:
        raise SystemExit("evidência para casos que o modelo não tem: " + ", ".join(sobrando))

    valores = list(organizacao)
    for caso in casos:
        ev = evidencias[caso]
        valores.append(status_da_evidencia(ev))
        valores.append(corpo_da_evidencia(ev))

    xml = preencher_campos(xml, valores)
    xml = marcar_caixas(xml, {BLOCOS.index(b) for b in blocos})
    partes[DOC] = xml.encode("utf8")

    shutil.copyfile(modelo, saida)
    with zipfile.ZipFile(saida, "w", zipfile.ZIP_DEFLATED) as z:
        for nome, dados in partes.items():
            z.writestr(nome, dados)
    print(f"{len(casos)} casos e {len(blocos)} blocos gravados em {saida}")


def verificar(caminho):
    """Relê o documento gravado e confere o que ele tem, sem depender do Word."""
    with zipfile.ZipFile(caminho) as z:
        xml = z.read(DOC).decode("utf8")

    problemas = []
    marcadas = xml.count('<w:checked w:val="1"/>')
    if marcadas != len(BLOCOS):
        problemas.append(f"{marcadas} caixas marcadas, esperava {len(BLOCOS)}")

    n_org, casos = mapear_campos(xml.encode("utf8"))
    resultados = resultados_dos_campos(xml)
    esperado = n_org + 2 * len(casos)
    if len(resultados) != esperado:
        problemas.append(f"{len(resultados)} campos, esperava {esperado}")

    vazios = [i for i, v in enumerate(resultados) if not v.strip()]
    if vazios:
        problemas.append(f"{len(vazios)} campos vazios (índices {vazios[:10]})")

    for i, caso in enumerate(casos):
        status = resultados[n_org + 2 * i].strip()
        corpo = resultados[n_org + 2 * i + 1]
        if not status:
            problemas.append(f"{caso}: sem status")
        if ROTULO.strip() not in corpo:
            problemas.append(f"{caso}: corpo sem o rótulo de sandbox")

    if problemas:
        for p in problemas:
            print("FALHA:", p)
        return 1
    print(f"ok: {len(BLOCOS)} caixas marcadas, {len(casos)} casos preenchidos, "
          f"{len(resultados)} campos, todos com o rótulo de sandbox")
    return 0


def resultados_dos_campos(xml):
    """Extrai o texto do RESULTADO de cada FORMTEXT, em ordem."""
    out = []
    pos = 0
    while True:
        regiao = regiao_do_resultado(xml, pos)
        if regiao is None:
            return out
        inicio, fim, _ = regiao
        trecho = xml[inicio:fim]
        texto = "".join(re.findall(r"<w:t[^>]*>(.*?)</w:t>", trecho, re.S))
        texto = (texto.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&"))
        out.append(texto)
        pos = fim


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--verificar", metavar="DOCX")
    ap.add_argument("--modelo")
    ap.add_argument("--evidencias")
    ap.add_argument("--saida")
    ap.add_argument("--cnpj", default="67.188.163/0001-10")
    ap.add_argument("--empresa", default="LMHost")
    ap.add_argument("--software", default="Verz")
    ap.add_argument("--responsavel", default="Péricles Gomes Luz")
    ap.add_argument("--email", default="pericles.luz@gmail.com")
    ap.add_argument("--telefone", default="(31) 98605-8910")
    ap.add_argument("--blocos", default=",".join(BLOCOS),
                    help="blocos a marcar, separados por vírgula")
    args = ap.parse_args()

    if args.verificar:
        return verificar(args.verificar)
    if not (args.modelo and args.evidencias and args.saida):
        ap.error("--modelo, --evidencias e --saida são obrigatórios")

    with open(args.evidencias, encoding="utf8") as f:
        lista = json.load(f)
    evidencias = {e["caso"]: e for e in lista}

    organizacao = [args.cnpj, args.empresa, args.software,
                   args.responsavel, args.email, args.telefone]
    blocos = [b.strip() for b in args.blocos.split(",") if b.strip()]
    desconhecidos = [b for b in blocos if b not in BLOCOS]
    if desconhecidos:
        raise SystemExit("bloco desconhecido: " + ", ".join(desconhecidos))

    preencher(args.modelo, evidencias, args.saida, organizacao, blocos)
    return 0


if __name__ == "__main__":
    sys.exit(main())

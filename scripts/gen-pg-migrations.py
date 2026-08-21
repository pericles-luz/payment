#!/usr/bin/env python3
"""Deriva migrations/pg/*.sql a partir de migrations/*.sql.

Duas regras, e apenas duas:
  1. BLOB -> BYTEA                 (5 colunas seladas AES-256-GCM)
  2. <algo>_cents INTEGER -> BIGINT (no Postgres INTEGER e int32; o Go le int64)

Tudo o mais ja e SQL portavel — o DDL foi escrito assim de proposito.
Rode este script quando adicionar uma migration nova e confira o diff.
"""
import re, sys, pathlib

SRC = pathlib.Path("migrations")
DST = SRC / "pg"

HEADER = ("-- GERADO por scripts/gen-pg-migrations.py a partir de ../%s — NAO EDITE A MAO.\n"
          "-- Regras: BLOB->BYTEA; *_cents INTEGER->BIGINT. Veja o script para o porque.\n")

def convert(text):
    stats = {"blob": 0, "cents": 0}
    out_lines = []
    for line in text.split("\n"):
        # comentario de linha inteira: preserva intacto
        if line.lstrip().startswith("--"):
            out_lines.append(line); continue
        code, sep, comment = line.partition("--")
        new = code
        n_blob = len(re.findall(r"\bBLOB\b", new))
        new = re.sub(r"\bBLOB\b", "BYTEA", new)
        # so colunas de dinheiro: nome terminando em _cents
        def cents_sub(m):
            stats["cents"] += 1
            return m.group(1) + "BIGINT"
        n_before = stats["cents"]
        new = re.sub(r"(\b\w*_cents\s+)INTEGER\b", cents_sub, new)
        stats["blob"] += n_blob
        out_lines.append(new + sep + comment)
    return "\n".join(out_lines), stats

def main():
    DST.mkdir(exist_ok=True)
    total = {"blob": 0, "cents": 0}
    files = sorted(p for p in SRC.glob("*.sql"))
    for p in files:
        text = p.read_text()
        new, stats = convert(text)
        (DST / p.name).write_text(HEADER % p.name + new)
        total["blob"] += stats["blob"]; total["cents"] += stats["cents"]
        if stats["blob"] or stats["cents"]:
            print("  %-42s BLOB->BYTEA:%d  cents->BIGINT:%d" % (p.name, stats["blob"], stats["cents"]))
    print("%d arquivos; total BLOB->BYTEA:%d  cents->BIGINT:%d" % (len(files), total["blob"], total["cents"]))

main()

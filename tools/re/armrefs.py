#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Resolve PIC data references in an LLVM-objdump ARM disassembly.
Patterns: ldr rD,[pc,#imm] ... add rD,pc,rD  (pc-relative)
          ldr rD,[pc,#imm] ... add rD,rG,rD  (GOT-relative, GOT base given)
usage: armrefs.py <elf> <disasm> <gotbase-hex> <target-hex>...   -> prints referencing instruction addrs + enclosing function
"""
import re, struct, sys

elf, dis, got = sys.argv[1], sys.argv[2], int(sys.argv[3], 16)
targets = {int(t, 16) for t in sys.argv[4:]}
d = open(elf, "rb").read()
# map vaddr->file offset via program headers
phoff, = struct.unpack_from("<I", d, 0x1C)
phentsize, phnum = struct.unpack_from("<HH", d, 0x2A)
loads = []
for i in range(phnum):
    ty, off, va, pa, fsz, msz, fl, al = struct.unpack_from("<8I", d, phoff + i * phentsize)
    if ty == 1:
        loads.append((va, off, fsz))


def word(va):
    for v, o, s in loads:
        if v <= va < v + s:
            return struct.unpack_from("<I", d, o + va - v)[0]
    return None


ins = []
func = "?"
fre = re.compile(r"^([0-9a-f]+) <(.+)>:")
ire = re.compile(r"^\s+([0-9a-f]+):\s+(\S+)\s*(.*)$")
for line in open(dis):
    m = fre.match(line)
    if m:
        func = m.group(2)
        continue
    m = ire.match(line)
    if m:
        ins.append((int(m.group(1), 16), m.group(2), m.group(3), func))

ldr_re = re.compile(r"^(r\d+|lr|ip|sl|fp), \[pc, #(-?(?:0x)?[0-9a-f]+)\]")
add_re = re.compile(r"^(r\d+|ip|sl|fp), (pc|r\d+|ip|sl|fp), (r\d+|ip|sl|fp)\s*(?:@.*)?$")
for k, (a, op, args, fn) in enumerate(ins):
    if not op.startswith("add"):
        continue
    m = add_re.match(args)
    if not m or m.group(1) != m.group(3) and m.group(1) != m.group(2):
        continue
    rd = m.group(1)
    other = m.group(2) if m.group(3) == rd else m.group(3)
    for j in range(k - 1, max(0, k - 24), -1):
        a2, op2, args2, _ = ins[j]
        m2 = ldr_re.match(args2)
        if op2.startswith("ldr") and m2 and m2.group(1) == rd:
            lit = a2 + 8 + int(m2.group(2), 0)
            v = word(lit)
            if v is None:
                break
            cand = (a + 8 + v) & 0xFFFFFFFF if other == "pc" else (got + v) & 0xFFFFFFFF
            if cand in targets:
                print(f"{cand:#010x} <- {a:#x} in {fn}  ({'pcrel' if other == 'pc' else 'gotoff via ' + other})")
            break

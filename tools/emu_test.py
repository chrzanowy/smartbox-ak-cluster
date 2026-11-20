#!/usr/bin/env python3
"""Emulate libSdH.so constructor against the real sdDongle image (unicorn, ARM).
Checks: which words get written, that writes only hit pages made RWX by mprotect, and that the
redirected Setup call lands in shim_session_setup.
usage: emu_test.py <sdDongle> <libSdH.so>
"""
import struct, sys
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_INTR, UC_HOOK_MEM_WRITE, UC_HOOK_CODE, UC_PROT_ALL
from unicorn.arm_const import *

exe = open(sys.argv[1], "rb").read()
lib = open(sys.argv[2], "rb").read()
LIB = 0x40000000
STUB = 0x50000000
STACK = 0x60000000
END = 0x70000000
mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)


def phdrs(d):
    phoff, = struct.unpack_from("<I", d, 0x1C)
    n, = struct.unpack_from("<H", d, 0x2C)
    return [struct.unpack_from("<8I", d, phoff + i * 32) for i in range(n)]


def map_image(d, base):
    for t, o, va, pa, fs, ms, fl, al in phdrs(d):
        if t != 1:
            continue
        lo = (base + va) & ~0xFFF
        hi = (base + va + ms + 0xFFF) & ~0xFFF
        try:
            mu.mem_map(lo, hi - lo, UC_PROT_ALL)
        except Exception:
            pass
        # whole-page file content like the kernel does
        foff = o - ((base + va) - lo)
        mu.mem_write(lo, d[foff:foff + min(hi - lo, len(d) - foff)][: (base + va + fs) - lo + 0xFFF & ~0xFFF] if False else d[foff:foff + ((base + va + fs) - lo)])


map_image(exe, 0)
map_image(lib, LIB)
mu.mem_map(STUB, 0x1000, UC_PROT_ALL)
mu.mem_map(STACK - 0x10000, 0x10000, UC_PROT_ALL)
mu.mem_map(END, 0x1000, UC_PROT_ALL)

# dynamic relocations of the lib
dyn = [p for p in phdrs(lib) if p[0] == 2][0]
ents = {}
for j in range(dyn[5] // 8):
    tag, val = struct.unpack_from("<iI", lib, dyn[1] + j * 8)
    ents.setdefault(tag, []).append(val)
symtab, strtab = ents[6][0], ents[5][0]


def symname(i):
    nm, = struct.unpack_from("<I", lib, symtab + i * 16)
    return lib[strtab + nm:lib.index(b"\0", strtab + nm)].decode()


def symval(i):
    return struct.unpack_from("<I", lib, symtab + i * 16 + 4)[0]


stubs = {}
for tag_off, tag_sz in ((17, 18), (23, 2)):
    if tag_off not in ents:
        continue
    off = ents[tag_off][0]
    size = ents[tag_sz][0]
    for k in range(size // 8):
        r_off, r_info = struct.unpack_from("<II", lib, off + k * 8)
        typ, si = r_info & 0xFF, r_info >> 8
        addr = LIB + r_off
        if typ == 23:  # RELATIVE
            v, = struct.unpack("<I", mu.mem_read(addr, 4))
            mu.mem_write(addr, struct.pack("<I", v + LIB))
        elif typ in (21, 22):  # GLOB_DAT / JUMP_SLOT
            name = symname(si)
            sv = symval(si)
            if sv:
                tgt = LIB + sv
            else:
                tgt = STUB + 4 * len(stubs)
                stubs[tgt] = name
                mu.mem_write(tgt, struct.pack("<I", 0xE12FFF1E))  # bx lr (we intercept before)
            mu.mem_write(addr, struct.pack("<I", tgt))

writable = set()
writes = []
calls = []


def on_code(uc, addr, size, ud):
    if addr in stubs:
        name = stubs[addr]
        r0 = uc.reg_read(UC_ARM_REG_R0)
        calls.append(name)
        ret = {"open": 3, "write": uc.reg_read(UC_ARM_REG_R2), "close": 0, "mkdir": 0}.get(name, 0)
        if name == "write":
            buf = uc.mem_read(uc.reg_read(UC_ARM_REG_R1), uc.reg_read(UC_ARM_REG_R2))
            log.append(bytes(buf))
        uc.reg_write(UC_ARM_REG_R0, ret)


def on_intr(uc, intno, ud):
    r7 = uc.reg_read(UC_ARM_REG_R7)
    a = [uc.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2)]
    if r7 == 125:
        pg, ln, prot = a
        calls.append(f"mprotect({pg:#x},{ln:#x},{prot})")
        for p in range(pg, pg + ln, 0x1000):
            (writable.add if prot & 2 else writable.discard)(p)
    elif r7 == 0xF0002:
        calls.append(f"cacheflush({a[0]:#x},{a[1]:#x})")
    else:
        calls.append(f"svc {r7}")
    uc.reg_write(UC_ARM_REG_R0, 0)


def on_write(uc, access, addr, size, value, ud):
    if addr < 0x130000:  # inside sdDongle RX image
        ok = (addr & ~0xFFF) in writable
        writes.append((addr, value & 0xFFFFFFFF, ok))


log = []
mu.hook_add(UC_HOOK_CODE, on_code, begin=STUB, end=STUB + 0xFFF)
mu.hook_add(UC_HOOK_INTR, on_intr)
mu.hook_add(UC_HOOK_MEM_WRITE, on_write)


def sym_addr(name):
    n = ents[10][0] if 10 in ents else 0
    i = 0
    while True:
        try:
            if symname(i) == name:
                return LIB + symval(i)
        except Exception:
            return None
        i += 1
        if i > 200:
            return None


init = sym_addr("altscreen_ak_init")
shim = sym_addr("shim_session_setup")
mu.reg_write(UC_ARM_REG_SP, STACK - 0x100)
mu.reg_write(UC_ARM_REG_LR, END)
mu.emu_start(init, END, count=200000)
print("imports/syscalls:", calls)
print("log:", b"".join(log).decode(errors="replace"))
for a, v, ok in writes:
    print(f"  write {a:#010x} = {v:#010x}  {'OK (page RWX)' if ok else '!! PAGE NOT WRITABLE'}")
print("pages left writable:", [hex(p) for p in sorted(writable)])
# second ctor call must be a no-op
nw = len(writes)
mu.reg_write(UC_ARM_REG_LR, END)
mu.emu_start(init, END, count=200000)
print("second init writes:", len(writes) - nw)
# follow the redirected call: execute bl at 0x5ec50 and the cave
mu.reg_write(UC_ARM_REG_PC, 0x5EC50)
hit = []
h = mu.hook_add(UC_HOOK_CODE, lambda uc, a, s, u: hit.append(a), begin=0, end=0xFFFFFFFF)
mu.emu_start(0x5EC50, shim, count=3)
print("trace:", [hex(x) for x in hit], "-> pc", hex(mu.reg_read(UC_ARM_REG_PC)), "shim at", hex(shim))
# P1 effect: run the (patched) slot-3 sequence and read r1 at the CFArrayAppendValue call
mu.reg_write(UC_ARM_REG_R4, 0x1234)
mu.emu_start(0x3C3C4, 0x3C3DC, count=10)
r1 = mu.reg_read(UC_ARM_REG_R1)
print(f"slot3 object r1 = {r1:#x}", bytes(mu.mem_read(r1, 18)))

#!/usr/bin/env python3
"""Minimal ELF32 LE helper: sections, string address lookup, literal-pool xrefs.
usage: elfx.py <elf> sections | str <substring>... | xref <hexaddr>...
"""
import struct, sys


def load(p):
    d = open(p, "rb").read()
    assert d[:4] == b"\x7fELF" and d[4] == 1 and d[5] == 1
    e_shoff, = struct.unpack_from("<I", d, 0x20)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", d, 0x2E)
    secs = []
    for i in range(e_shnum):
        nm, ty, fl, addr, off, size = struct.unpack_from("<IIIIII", d, e_shoff + i * e_shentsize)
        secs.append([nm, ty, fl, addr, off, size])
    so = secs[e_shstrndx][4]
    for s in secs:
        n = s[0]
        s[0] = d[so + n:d.index(b"\0", so + n)].decode()
    return d, secs


def sec_of_off(secs, off):
    for s in secs:
        if s[3] and s[4] <= off < s[4] + s[5]:
            return s
    return None


def main():
    d, secs = load(sys.argv[1])
    cmd = sys.argv[2]
    if cmd == "sections":
        for n, ty, fl, addr, off, size in secs:
            print(f"{n:20s} addr={addr:#010x} off={off:#08x} size={size:#08x} flags={fl:#x}")
    elif cmd == "str":
        for sub in sys.argv[3:]:
            b = sub.encode()
            i = d.find(b)
            while i >= 0:
                s = sec_of_off(secs, i)
                if s:
                    st = d.rfind(b"\0", 0, i) + 1
                    end = d.index(b"\0", i)
                    va = s[3] + (st - s[4])
                    print(f"{va:#010x} [{s[0]}] {d[st:end][:100]!r}")
                i = d.find(b, i + 1)
    elif cmd == "xref":
        for h in sys.argv[3:]:
            v = struct.pack("<I", int(h, 16))
            i = d.find(v)
            while i >= 0:
                s = sec_of_off(secs, i)
                if s and i % 4 == 0:
                    print(f"{h} referenced at {s[3] + (i - s[4]):#010x} [{s[0]}]")
                i = d.find(v, i + 1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Build ak_202610081659_hook.tar for the SmartBox AK3918AN.
Static changes to sdDongle (everything else is done at runtime by the shim's constructor):
  1. one DT_NULL slot -> DT_NEEDED "/usr/data/lib/libSdH.so" (absolute: no library search path involved;
     string stored right after the trampoline, offset relative to DT_STRTAB)
  2. RX PT_LOAD filesz/memsz extended to cover the trampoline (8 zero bytes at 0x123440) + that string
The shim's PT_PHDR is turned into PT_NULL (vendor libs have none).
usage: build_ak_hook.py <vendor-extracted-dir> <libSdH.so> <outdir>
"""
import hashlib, os, struct, subprocess, sys, tarfile

LIBNAME = "libSdH.so"
NEEDED_PATH = b"/usr/data/lib/libSdH.so\0"
STR_VA = 0x123448
CAVE_VA = 0x123440
EXPECT_MD5 = {  # vendor ak_202610081659 contents
    "sdDongle": None,
}
LIBS = ["libSdAuto.so", "libSdCommon.so", "libSdSampleRate.so", "libSdUtils.so"]


def phdrs(d):
    phoff, = struct.unpack_from("<I", d, 0x1C)
    n, = struct.unpack_from("<H", d, 0x2C)
    return phoff, [list(struct.unpack_from("<8I", d, phoff + i * 32)) for i in range(n)]


def patch(src):
    d = bytearray(src)
    phoff, ph = phdrs(d)
    # dynamic section
    dyn = [p for p in ph if p[0] == 2][0]
    ents = [list(struct.unpack_from("<iI", d, dyn[1] + j * 8)) for j in range(dyn[4] // 8)]
    strtab = [v for t, v in ents if t == 5][0]
    strsz = [v for t, v in ents if t == 10][0]
    off_needed = STR_VA - strtab
    if any(t == 1 and v == off_needed for t, v in ents):
        raise SystemExit("already patched")
    nulls = [j for j, e in enumerate(ents) if e[0] == 0]
    if len(nulls) < 2:
        raise SystemExit("not enough DT_NULL")
    # insert DT_NEEDED right after the existing NEEDED entries would need shifting; using the first
    # DT_NULL keeps all original entries in place (ld.so processes NEEDED in table order).
    j = nulls[0]
    struct.pack_into("<iI", d, dyn[1] + j * 8, 1, off_needed)
    print(f"DT_NEEDED {NEEDED_PATH!r} at dyn slot {j}, strtab off {off_needed:#x} (DT_STRSZ {strsz:#x})")
    # extend RX segment
    for k, p in enumerate(ph):
        t, o, va, pa, fs, ms, fl, al = p
        if t == 1 and fl == 5:
            end_va = va + fs
            new_end = STR_VA + len(NEEDED_PATH)
            if not (end_va <= CAVE_VA and STR_VA == CAVE_VA + 8 and new_end - va <= 0x113fec - o):
                raise SystemExit("cave/string outside gap")
            if any(d[o + fs + q] for q in range(new_end - end_va)):
                raise SystemExit("gap not zero")
            so_ = o + (STR_VA - va)
            d[so_:so_ + len(NEEDED_PATH)] = NEEDED_PATH
            newsz = new_end - va
            struct.pack_into("<II", d, phoff + k * 32 + 16, newsz, newsz)
            print(f"RX PT_LOAD filesz/memsz {fs:#x} -> {newsz:#x}")
    return bytes(d)


def main():
    src_dir, shim, out = sys.argv[1], sys.argv[2], sys.argv[3]
    os.makedirs(out, exist_ok=True)
    for f in LIBS:
        open(os.path.join(out, f), "wb").write(open(os.path.join(src_dir, f), "rb").read())
    sd = patch(open(os.path.join(src_dir, "sdDongle"), "rb").read())
    open(os.path.join(out, "sdDongle"), "wb").write(sd)
    lib = bytearray(open(shim, "rb").read())
    phoff, ph = phdrs(lib)
    for k, p in enumerate(ph):
        if p[0] == 6:
            struct.pack_into("<I", lib, phoff + k * 32, 0)
            print("shim PT_PHDR -> PT_NULL")
    open(os.path.join(out, LIBNAME), "wb").write(bytes(lib))
    name = "ak_202610081659_hook"
    tar = os.path.join(out, name)
    with tarfile.open(tar, "w", format=tarfile.GNU_FORMAT) as t:
        for f in LIBS + ["sdDongle", LIBNAME]:
            p = os.path.join(out, f)
            os.chmod(p, 0o777)
            ti = t.gettarinfo(p, arcname=f)
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = ""
            ti.mtime = 1791555500
            with open(p, "rb") as fh:
                t.addfile(ti, fh)
    data = open(tar, "rb").read()
    print("tar", tar, len(data), "md5", hashlib.md5(data).hexdigest())
    for f in LIBS + ["sdDongle", LIBNAME]:
        print(f"  {f:20s} md5 {hashlib.md5(open(os.path.join(out, f), 'rb').read()).hexdigest()}")


if __name__ == "__main__":
    main()

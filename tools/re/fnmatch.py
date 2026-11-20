#!/usr/bin/env python3
"""Match functions between the AX (MIPS) and AK (ARM) sdDongle builds of the same source.
Anchors: identical sets of referenced strings. Propagation: aligned callee sequences of matched pairs.
usage: fnmatch.py <ax-afl.json> <ax-elf> <ak-afl.json> <ak-elf> <out.json> [ax-hex ...]  (query: print AK match for AX addrs)
"""
import difflib, json, struct, sys


def segs(d):
    phoff, = struct.unpack_from("<I", d, 0x1C)
    n, = struct.unpack_from("<H", d, 0x2C)
    out = []
    for i in range(n):
        t, o, va, pa, fs, ms, fl, al = struct.unpack_from("<8I", d, phoff + i * 32)
        if t == 1:
            out.append((va, o, fs))
    return out


def cstr(d, sg, va):
    for v, o, s in sg:
        if v <= va < v + s:
            off = o + va - v
            if d[off:off + 8] == b"\x56\x07\x01\x00\xff\xff\xff\x7f":
                off += 8
            end = d.find(b"\0", off, off + 200)
            if end <= off:
                return None
            s_ = d[off:end]
            if len(s_) >= 3 and all(32 <= c < 127 or c in (9, 10) for c in s_):
                return s_.decode()
    return None


def load(afl, elf):
    d = open(elf, "rb").read()
    sg = segs(d)
    fns = {}
    for f in json.load(open(afl)):
        if f["name"].startswith("sym.imp."):
            continue
        strs = set()
        for r in f.get("datarefs", []) or []:
            s = cstr(d, sg, r["to"])
            if s:
                strs.add(s)
        calls = [c["to"] for c in sorted(f.get("callrefs", []) or [], key=lambda c: c["from"]) if c["type"] in ("CALL", "CODE")]
        fns[f["offset"]] = dict(name=f["name"], size=f["size"], strs=frozenset(strs), calls=calls)
    return fns


def main():
    ax = load(sys.argv[1], sys.argv[2])
    ak = load(sys.argv[3], sys.argv[4])
    m = {}  # ax addr -> ak addr
    def index(fns):
        idx = {}
        for a, f in fns.items():
            if f["strs"]:
                idx.setdefault(f["strs"], []).append(a)
        return idx
    ia, ik = index(ax), index(ak)
    for k, al in ia.items():
        kl = ik.get(k)
        if len(al) == 1 and kl and len(kl) == 1:
            m[al[0]] = kl[0]
    # name anchors: AK exported names that exist in AX
    axn = {}
    for a, f in ax.items():
        axn.setdefault(f["name"], []).append(a)
    for b, f in ak.items():
        n = f["name"]
        if n.startswith("sym.") and n in axn and len(axn[n]) == 1 and axn[n][0] not in m:
            m[axn[n][0]] = b
    # fuzzy: Jaccard >= 0.6 on string sets with >= 3 strings, unique best both ways
    used = set(m.values())
    ua = [a for a in ax if a not in m and len(ax[a]["strs"]) >= 3]
    uk = [b for b in ak if b not in used and len(ak[b]["strs"]) >= 3]
    best = {}
    for a in ua:
        sa = ax[a]["strs"]
        sc = sorted(((len(sa & ak[b]["strs"]) / len(sa | ak[b]["strs"]), b) for b in uk if sa & ak[b]["strs"]), reverse=True)
        if sc and sc[0][0] >= 0.6 and (len(sc) == 1 or sc[0][0] - sc[1][0] >= 0.15):
            best[a] = sc[0][1]
    cnt = {}
    for a, b in best.items():
        cnt[b] = cnt.get(b, 0) + 1
    for a, b in best.items():
        if cnt[b] == 1:
            m[a] = b
    anchors = len(m)
    # propagation
    changed = True
    rounds = 0
    while changed and rounds < 30:
        changed = False
        rounds += 1
        rev = {v: k for k, v in m.items()}
        for a, b in list(m.items()):
            ca = [c for c in ax[a]["calls"] if c in ax]
            cb = [c for c in ak[b]["calls"] if c in ak]
            # dedupe consecutive while keeping order of first occurrence
            ua = list(dict.fromkeys(ca))
            ub = list(dict.fromkeys(cb))
            ka = [("M%x" % m[c]) if c in m else ("S" + str(sorted(ax[c]["strs"]))[:80] if ax[c]["strs"] else "?") for c in ua]
            kb = [("M%x" % c) if c in rev else ("S" + str(sorted(ak[c]["strs"]))[:80] if ak[c]["strs"] else "?") for c in ub]
            sm = difflib.SequenceMatcher(a=ka, b=kb, autojunk=False)
            for tag, i1, i2, j1, j2 in sm.get_opcodes():
                if tag in ("equal", "replace") and (i2 - i1) == (j2 - j1):
                    for x, y in zip(ua[i1:i2], ub[j1:j2]):
                        if x in m or y in rev:
                            continue
                        if tag == "replace" and (ka[ua.index(x)].startswith("M") or kb[ub.index(y)].startswith("M")):
                            continue
                        m[x] = y
                        rev[y] = x
                        changed = True
    json.dump({"%x" % k: "%x" % v for k, v in m.items()}, open(sys.argv[5], "w"), indent=0)
    print(f"anchors {anchors}, total matches {len(m)} after {rounds} rounds (ax fns {len(ax)}, ak fns {len(ak)})")
    for q in sys.argv[6:]:
        a = int(q, 16)
        if a in m:
            b = m[a]
            print(f"AX {a:#x} ({ax[a]['name']}, {ax[a]['size']}B) -> AK {b:#x} ({ak[b]['name']}, {ak[b]['size']}B)")
        else:
            print(f"AX {a:#x} -> no match" + ("" if a in ax else " (not a function start in AX analysis)"))


if __name__ == "__main__":
    main()

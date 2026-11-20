#!/usr/bin/env python3
"""For unmatched AX functions: list AX and AK functions between the nearest matched anchors.
If both lists have equal length, propose the index-aligned AK address.
usage: neigh.py <ax-afl.json> <ak-afl.json> <match.json> <ax-hex>...
"""
import bisect, json, sys

ax = sorted((f["offset"], f["size"], f["name"]) for f in json.load(open(sys.argv[1])) if not f["name"].startswith("sym.imp."))
ak = sorted((f["offset"], f["size"], f["name"]) for f in json.load(open(sys.argv[2])) if not f["name"].startswith("sym.imp."))
m = {int(k, 16): int(v, 16) for k, v in json.load(open(sys.argv[3])).items()}
axa = [a for a, _, _ in ax]
aka = [a for a, _, _ in ak]
for q in sys.argv[4:]:
    t = int(q, 16)
    i = bisect.bisect_left(axa, t)
    lo = next((axa[j] for j in range(i - 1, -1, -1) if axa[j] in m), None)
    hi = next((axa[j] for j in range(i + 1 if i < len(axa) and axa[i] == t else i, len(axa)) if axa[j] in m), None)
    if lo is None or hi is None or m[lo] >= m[hi]:
        print(f"{q}: anchors unusable ({lo}, {hi})")
        continue
    A = [x for x in ax if lo < x[0] < hi]
    K = [x for x in ak if m[lo] < x[0] < m[hi]]
    idx = [k for k, x in enumerate(A) if x[0] == t]
    prop = ""
    if len(A) == len(K) and idx:
        prop = f"  => AK {K[idx[0]][0]:#x} ({K[idx[0]][1]}B)"
    print(f"{q}: between AX {lo:#x}->{m[lo]:#x} and {hi:#x}->{m[hi]:#x}: AX {len(A)} fns, AK {len(K)} fns{prop}")
    if not prop and len(A) < 14 and len(K) < 14:
        for k in range(max(len(A), len(K))):
            a = A[k] if k < len(A) else None
            b = K[k] if k < len(K) else None
            print(f"     {'*' if a and a[0] == t else ' '} {a[0]:#x} {a[1]:5d} {a[2][:40]:40s}" if a else "      -" + " " * 50, end="")
            print(f" | {b[0]:#x} {b[1]:5d}" if b else " | -")

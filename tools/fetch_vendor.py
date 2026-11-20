#!/usr/bin/env python3
"""Download the vendor (stock) application package for the SmartBox AK3918AN from the vendor's
update server - the same request the dongle's own web page makes. Nothing is sent to the dongle.

usage: fetch_vendor.py [version] [outdir]      (no version: list what the server offers)
"""
import hashlib, json, os, sys, urllib.request

SERVER = "http://120.79.59.57:8080/device-web/upgrade"
PLATFORM, CUSTOM = "AK3918AN", "suding"


def post(path, payload):
    req = urllib.request.Request(SERVER + path, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read()


def main():
    listing = json.loads(post("/queryDeviceVersion", {"version": "", "platform": PLATFORM, "custom": CUSTOM}))
    offered = {d["version"]: d["md5Encryption"] for d in listing.get("data", [])}
    if len(sys.argv) < 2:
        for v, m in offered.items():
            print(v, m)
        return
    ver = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else "vendor"
    if ver not in offered:
        sys.exit(f"{ver} not offered; available: {', '.join(offered)}")
    data = post("/downLoad", {"version": ver, "platform": PLATFORM, "custom": CUSTOM})
    md5 = hashlib.md5(data).hexdigest()
    if md5 != offered[ver]:
        sys.exit(f"md5 mismatch: got {md5}, server says {offered[ver]}")
    os.makedirs(out, exist_ok=True)
    path = os.path.join(out, ver)
    open(path, "wb").write(data)
    print(f"saved {path} ({len(data)} bytes, md5 {md5})")


if __name__ == "__main__":
    main()

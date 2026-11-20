#!/usr/bin/env python3
"""Upload a suding vendor firmware tar to a SmartBox dongle (AK3918AN) via its web page protocol.

Stages (explicit, one per run):
  check    - GET getversion.cgi only, print platform/custom/versions
  upload   - POST chunks to downfile.cgi; dongle verifies md5 ("file check success"); NO install
  install  - GET submition.cgi?filename=<name>& then reboot.cgi (requires a prior successful upload)
Every run logs to build/dongle-20261120/flash-log.txt.
"""
import hashlib, os, sys, time, urllib.request, uuid

HOST = "http://192.168.200.1"
CHUNK = 10 * 1024
EXPECT = ("AK3918AN", "suding")
LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "logs", "flash-log.txt")


def log(msg):
    line = time.strftime("%Y-%m-%d %H:%M:%S ") + msg
    print(line)
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    with open(LOG, "a") as f:
        f.write(line + "\n")


def get(path, timeout=15):
    with urllib.request.urlopen(HOST + path, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def post_chunk(filename, data):
    b = uuid.uuid4().hex
    body = (f'--{b}\r\nContent-Disposition: form-data; name="chunk"; filename="{filename}"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n").encode() + data + f"\r\n--{b}--\r\n".encode()
    req = urllib.request.Request(HOST + "/cgi-bin/downfile.cgi", data=body,
                                 headers={"Content-Type": f"multipart/form-data; boundary={b}"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8", "replace")


def check():
    v = get("/cgi-bin/getversion.cgi")
    info = {k.strip(): val.strip() for k, val in (l.split(":", 1) for l in v.splitlines() if ":" in l)}
    plat, cust = info.get("platform", ""), info.get("custom", "")
    log(f"dongle platform={plat} custom={cust} system={info.get('system_version')} protocol={info.get('protocol_version')}")
    if (plat, cust) != EXPECT:
        log("ABORT: not the expected dongle")
        sys.exit(2)


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ("check", "upload", "install"):
        sys.exit(__doc__)
    stage = sys.argv[1]
    check()
    if stage == "check":
        return
    if len(sys.argv) != 4:
        sys.exit("usage: flash_vendor.py upload|install <tar> <expected-md5>")
    path, want = sys.argv[2], sys.argv[3]
    data = open(path, "rb").read()
    md5 = hashlib.md5(data).hexdigest()
    name = os.path.basename(path)
    if name.endswith(".bin"):
        name = name[:-4]
    if md5 != want:
        log(f"ABORT: {path} md5 {md5} != {want}")
        sys.exit(2)
    if stage == "upload":
        n = (len(data) + CHUNK - 1) // CHUNK
        log(f"upload {name} md5 {md5} size {len(data)} chunks {n}")
        resp = ""
        for i in range(n):
            fn = f"{name}.0" if i == 0 else f"{name}:{md5}.2" if i == n - 1 else f"{name}.1"
            resp = post_chunk(fn, data[i * CHUNK:(i + 1) * CHUNK])
            if "success" not in resp:
                log(f"ABORT: chunk {i} response: {resp.strip()!r}")
                sys.exit(3)
        log(f"last response: {resp.strip()!r}")
        if "file check success" not in resp:
            log("ABORT: dongle did not confirm checksum")
            sys.exit(3)
        log("upload OK (file check success), not installed")
    else:
        r = get("/cgi-bin/submition.cgi?filename=" + name + "&", timeout=90)
        log(f"submition response: {r.strip()!r}")
        if "success download" not in r:
            log("ABORT: submition did not report success download; NOT rebooting")
            sys.exit(4)
        time.sleep(2)
        try:
            log(f"reboot response: {get('/cgi-bin/reboot.cgi', timeout=10).strip()!r}")
        except OSError as e:
            log(f"reboot request ended: {e} (expected while rebooting)")


if __name__ == "__main__":
    main()

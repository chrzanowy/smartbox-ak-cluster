# smartbox-ak-cluster

CarPlay instrument-cluster map (second display, stream type 111) through a cheap wireless CarPlay
dongle: the **"Smart Box" with `platform:AK3918AN`, `custom:suding`** (ARM926EJ-S, uClibc).

It is an ARM port of [OMKE/wireless-carplay-virtual-cockpit](https://github.com/OMKE/wireless-carplay-virtual-cockpit),
which does the same for the MIPS `AX1800M` variant of this dongle. Both run the same vendor
code base, but the binaries, the CPU and almost all addresses differ, and the AK build exports far
fewer symbols, so every function was located again (see `docs/ADDRESSES.md`).

Target car: VW Passat B8 with MHI2 (HARMAN, AirPlay 210.81) and the
[mhi2-aid-carplay](https://github.com/chrzanowy/mhi2-aid-carplay) bridge, which shows the CarPlay cluster stream on
the AID. Any car that shows a CarPlay cluster map with a cable should behave the same.

> **Status:** confirmed in a VW Passat B8 / MHI2: CarPlay starts with low latency and the CarPlay map is shown on the AID.

## Is it my dongle?

| Check | Value |
|---|---|
| Wi-Fi | `SmartBox_XXXX`, password `12345678` |
| Web page | http://192.168.200.1 |
| http://192.168.200.1/cgi-bin/getversion.cgi | `platform:AK3918AN`, `custom:suding` |
| USB | pretends to be an iPhone (`05ac:12a8`) |

`tools/flash.py` refuses any other platform. For `AX1800M` use OMKE's project.

## What it does

The shim `libSdH.so` is loaded by the vendor app `sdDongle` (one added `DT_NEEDED`).
Its constructor checks the original instruction words and only then patches, at runtime:

- **P1** `enabledFeatures` sent to the iPhone always contains `viewAreas` + `altScreen`;
  **nostrip**: the phone-facing `/info` keeps every display the car advertises (incl. the cluster).
- **P2** `AirPlayReceiverSessionSetup` is redirected through the shim: a type-111 stream from the
  phone is taken out of the request and answered with our own socket (added to the response with the
  vendor's `_AddResponseStream`).
- **P3** a type-111 RTSP `SETUP` is sent to the car over the dongle's AirPlay client
  (cluster uuid `b7e6c5a0-2222-4000-8000-000000000002`), then a TCP stream is opened.
- **P4** frames from the phone are decrypted (ChaCha20-Poly1305 or AES-CTR) and sent to the car
  with AES-CTR, H.264 unchanged; display size / view area are taken from the phone's config header.

If any checked word does not match, nothing is patched and the dongle behaves as stock.
Static changes to `sdDongle`: 29 bytes (one `DT_NULL` → `DT_NEEDED "/usr/data/lib/libSdH.so"`,
RX segment extended over an 8-byte trampoline and that string).

## Build

Needs `zig` (compiler + `ld.lld`) and Python 3.

```sh
./build.sh          # fetches vendor ak_202610081659 from the vendor update server, builds build/out/ak_202610081659_hook
```

`tools/emu_test.py` runs the shim constructor against the real `sdDongle` image in unicorn
(`pip install unicorn`) and prints every patched word.

## Install / roll back

Connect the computer to the dongle Wi-Fi, then:

```sh
python3 tools/flash.py check
python3 tools/flash.py upload  build/out/ak_202610081659_hook <md5>   # dongle verifies, nothing installed
python3 tools/flash.py install build/out/ak_202610081659_hook <md5>   # installs and reboots
```

Roll back = install the vendor package the same way (`vendor/ak_202610081659`).
The update only replaces the application in `/usr/data/lib`; the web updater lives in the base
system. If the application fails to start, the dongle falls back to its factory copy (observed).

## Logs

`/usr/data/log/altscreen.log` (persistent flash, so it is kept short: at most 16 KB per boot,
cleared at boot when over 64 KB; repeated per-frame events are only counted). Download all dongle logs as a zip, locally:

```sh
curl -o logs.zip "http://192.168.200.1/cgi-bin/minizip.cgi?logID=mylogs&"
```

Expected sequence in a car session: `req stream type 111` → `alt connected` → `alt chacha keys rc 0`
→ `cluster SETUP sent` → `cluster car dataPort N` → `cluster ctx ready` → `alt config sent`
→ `alt idr after frames` → `alt frames pushed …` / `alt configs so far …`.

## Notes

- No vendor firmware is stored in this repository; `tools/fetch_vendor.py` downloads it from the
  vendor's own update server, as the dongle's web page does.
- `tools/re/` holds the scripts used to match functions between the AX (MIPS, with symbols) and
  AK (ARM) builds.
- Dongle logs contain MAC addresses and serial numbers; redact before sharing.

## Licence

GPL-3.0, see `LICENSE`. The shim design is derived from OMKE's project, which is MIT-licensed;
its notice is kept in `LICENSES/MIT-OMKE.txt`.

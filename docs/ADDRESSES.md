# Addresses — sdDongle `ak_202610081659` (AK3918AN) vs OMKE stock `ax_202609051445` (AX1800M)

Found by matching functions between the MIPS build (symbols) and the ARM build: identical string
sets, AK exported names, fuzzy string similarity, aligned callee sequences (`tools/re/fnmatch.py`),
1:1 layout of CF wrappers, and manual checks of call sites. Struct offsets were checked in code.

## Patch sites (applied at runtime by the constructor)

| What | AX | AK | Original → new |
|---|---|---|---|
| single call of `AirPlayReceiverSessionSetup` | 0x46c2fc | 0x5ec50 | `bl 0x6a60c` → `bl 0x123440` (trampoline `ldr pc,[pc,#-4]` + shim address) |
| enabledFeatures: create array | 0x43f46c | 0x3c308 | `beq` → `nop` |
| enabledFeatures: viewAreas | 0x43f4d0 | 0x3c364 | `beq` → `nop` |
| enabledFeatures: third slot | 0x43f540 | 0x3c3c4 | `beq` → `nop` |
| third slot object (cornerMasks → altScreen) | 0x43f558 | literal 0x3c678 | 0x000bbfc6 → 0x000b6d95 (object 0xf34ea) |
| nostrip (`delete_display_config` loop) | 0x43e4a4 | 0x3b43c | `beq` (0x0a000002) → `b` (0xea000002) |

## Functions

| Function | AX | AK |
|---|---|---|
| AirPlayReceiverSessionSetup | 0x477fd4 | 0x6a60c |
| AirPlayReceiverSessionSendCommand | 0x474fd0 | 0x673e0 |
| GetStreamSecurityKeys | 0x474254 | 0x654c0 |
| AirPlay_DeriveAESKeySHA512ForScreen | 0x481af0 | 0x73e84 |
| simAirPlayDeriveAESKeySHA512 | 0x42ce68 | 0x2b884 |
| AES_CTR_Init / AES_CTR_Update | 0x48b780 / 0x48b804 | 0x7ca74 / 0x7cab0 |
| chacha20_poly1305 init / add_aad / decrypt / verify | 0x4aa770 / 0x4aad3c / 0x4aaec0 / 0x4ab124 | 0x999e0 / 0x99e54 / 0x99f64 / 0x9a10c |
| ServerSocketOpen | 0x4cbf54 | 0xb709c |
| SockAddrCopy / SetPort / GetSize | 0x4cd2fc / 0x4cc6e0 / 0x4cbb30 | 0xb82dc / 0xb7858 / 0xb6ce8 |
| SocketSetQoS | 0x4caf40 | 0xb6128 |
| UUIDGet | 0x4ea9b0 | 0xd03a4 |
| HTTPMessageCreate / SetBodyPtr | 0x4b953c / 0x4b962c | 0xa6d08 / 0xa6dc8 |
| HTTPHeader_InitRequest / AddFieldF | 0x4bc550 / 0x4bcbf0 | 0xa9710 / 0xa9e00 |
| HTTPClientSendMessage | 0x4b90d0 | 0xa6974 |
| CFBinaryPlistV0Create / CreateWithData | 0x49d354 / 0x49e3e4 | 0x8d0a0 / 0x8e414 |
| dispatch_semaphore create / wait / signal | 0x4b30b4 / 0x4b35fc / 0x4b3208 | 0xa11d8 / 0xa15b8 / 0xa1338 |
| CFRelease / CFGetTypeID | 0x492528 / 0x4924a0 | 0x82c78 / 0x82c34 |
| CFArray GetTypeID / CreateMutable / GetCount / GetValueAtIndex / AppendValue / RemoveValueAtIndex | 0x4925ac / 0x492748 / 0x4927c0 / 0x492814 / 0x4929b4 / 0x4929cc | 0x82ca8 / 0x82e10 / 0x82e58 / 0x82e90 / 0x82fc0 / 0x82fc4 |
| CFArrayEnsureCreatedAndAppend | 0x4a4144 | 0x9327c |
| CFDictionary GetTypeID / CreateMutable / CreateMutableCopy / GetValue / SetValue | 0x493234 / 0x49324c / 0x4933c4 / 0x493438 / 0x493470 | 0x83564 / 0x83568 / 0x83678 / 0x836bc / 0x836dc |
| CFDictionary GetTypedValue / GetInt64 / SetInt64 / SetCString | 0x4a57fc / 0x4a5514 / 0x4a77d0 / 0x4a49dc | 0x945c8 / 0x943cc / 0x96b00 / 0x9397c |

## Data

| Item | AX | AK |
|---|---|---|
| kCFTypeArrayCallBacks / DictionaryKey / DictionaryValue | 0x5630e4 / 0x5630cc / 0x5630b8 | 0x134200 / 0x1341e8 / 0x1341d4 |
| gAirPlayClient / gPeerAddr / pairVerifySessionHomeKit / sessionAesKey | 0x56abf8 / 0x56c3e0 / 0x56ad70 / 0x56ad90 | 0x13bf28 / 0x13bca0 / 0x13a7e4 / 0x13a800 |
| receiver keys streams / type / dataPort / streamConnectionID | 0x52e2a8 / 0x52e300 / 0x52e450 / 0x52e388 | 0xffce1 / 0xffef3 / 0x100219 / 0x10013f |
| receiver keys params / url | 0x52e490 / 0x52e558 | 0x1002fa / 0x100452 |
| client keys streams / type / dataPort / streamConnectionID / uuid / latencyMs | 0x52105c / 0x52106c / 0x52107c / 0x521090 / 0x5210ac / 0x5210bc | 0xf63f9 / 0xf6409 / 0xf6416 / 0xf6475 / 0xf6490 / 0xf649d |
| `altScreen` CF constant | 0x51f364 | 0xf34ea |

## Struct offsets (identical in both builds)

- session: `+0x8c` peer sockaddr family, `+0x200` screen AES key material, `+0x3ec` pairVerifySession.
- HTTPMessage (CF instance, 0x900 bytes + 8): `+0x10` header, `+0x49c` body ptr, `+0x4a0` body len,
  `+0x8f4/+0x8f8/+0x8fc` context, `+0x904` completion callback.
- ARM EABI: 64-bit arguments (connection IDs, dispatch time) are passed in r2:r3; r1 is padding.

/* SPDX-License-Identifier: GPL-3.0-only */
/*
 * libSdH.so for the suding SmartBox AK3918AN (ARM926EJ-S, uClibc), firmware ak_202610081659.
 * P1: the iPhone requests the instrument-cluster stream (type 111); P2: the dongle accepts it;
 * P3: the dongle sets up a type-111 stream to the car; P4: frames are decrypted (ChaCha20-Poly1305
 * or AES-CTR) and re-encrypted AES-CTR to the car, H.264 untouched.
 *
 * Design follows OMKE/wireless-carplay-virtual-cockpit (MIT, AX1800M/MIPS), re-done for ARM.
 * Difference: ALL code patches are applied at runtime by the constructor after verifying the
 * original instruction words. If anything does not match, nothing is patched (stock behaviour).
 *
 * Built freestanding (-nostdlib); libc symbols resolve from sdDongle's libc.so.0 at load time.
 */
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;
typedef long long i64;
typedef unsigned long size_t;
typedef long ssize_t;

/* ---- libc (uClibc) imports, resolved lazily from the host process ---- */
extern int open(const char *, int, ...);
extern ssize_t write(int, const void *, size_t);
extern ssize_t read(int, void *, size_t);
extern int close(int);
extern int accept(int, void *, void *);
extern int fcntl(int, int, ...);
extern int mkdir(const char *, int);
typedef unsigned long pthread_t;
extern int pthread_create(pthread_t *, const void *, void *(*)(void *), void *);
extern int pthread_attr_init(void *);
extern int pthread_attr_setdetachstate(void *, int);
extern int pthread_attr_destroy(void *);
#define PTHREAD_CREATE_DETACHED 1

/* raw EABI syscalls: no dependency on libc exports that sdDongle does not already use */
static long sys3(long nr, long a, long b, long c) {
  register long r0 __asm__("r0") = a;
  register long r1 __asm__("r1") = b;
  register long r2 __asm__("r2") = c;
  register long r7 __asm__("r7") = nr;
  __asm__ volatile("svc #0" : "+r"(r0) : "r"(r1), "r"(r2), "r"(r7) : "memory");
  return r0;
}
#define NR_mprotect 125

#define O_WRONLY 01
#define O_CREAT 0100
#define O_APPEND 02000
#define O_TRUNC 01000
#define NR_lseek 19
#define SEEK_END 2
#define O_NONBLOCK 04000
#define F_GETFL 3
#define F_SETFL 4
#define PROT_READ 1
#define PROT_WRITE 2
#define PROT_EXEC 4
#define ARM_NR_cacheflush 0xf0002

/* ---- addresses in sdDongle ak_202610081659 (see docs/25 §8) ---- */
#define VA_SETUP            0x0006a60cu  /* AirPlayReceiverSessionSetup(session, req, resp_out) */
#define VA_SETUP_CALL       0x0005ec50u  /* the only caller: bl VA_SETUP */
#define VA_CAVE             0x00123440u  /* 8 zero bytes added at end of the RX segment */
#define VA_P1_GATE_ALL      0x0003c308u  /* beq: no flag set -> no enabledFeatures array */
#define VA_P1_GATE_VIEW     0x0003c364u  /* beq: skip viewAreas */
#define VA_P1_GATE_SLOT3    0x0003c3c4u  /* beq: skip cornerMasks slot */
#define VA_P1_LIT_SLOT3     0x0003c678u  /* literal: cornerMasks CF object, pc-relative */
#define VA_ALTSCREEN_CFOBJ  0x000f34eau  /* "altScreen" constant CF object */
#define VA_P1_ADD_PC        0x0003c3d0u
#define VA_NOSTRIP          0x0003b43cu  /* beq: skip CFArrayRemoveValueAtIndex in the /info displays loop */  /* add r1, pc, r1 using the literal (+ #892 + #1 after) */

#define W_SETUP_CALL_OLD    0xeb002e6du  /* bl 0x6a60c from 0x5ec50 */
#define W_GATE_ALL_OLD      0x0afffdcdu
#define W_GATE_VIEW_OLD     0x0a000012u
#define W_GATE_SLOT3_OLD    0x0a000005u
#define W_LIT_SLOT3_OLD     0x000bbfc6u  /* -> cornerMasks object 0xf871b */
#define W_NOSTRIP_OLD       0x0a000002u  /* beq 0x3b44c */
#define W_NOSTRIP_NEW       0xea000002u  /* b   0x3b44c : never remove displays */
#define W_NOP               0xe1a00000u  /* mov r0, r0 */
#define W_LDR_PC_PC_M4      0xe51ff004u  /* ldr pc, [pc, #-4] */

/* CF-lite functions (wrappers) */
typedef void *(*fn_dict_get_typed)(void *, void *, unsigned long, int *);
typedef i64 (*fn_dict_get_i64)(void *, void *, int *);
typedef void (*fn_dict_set_i64)(void *, void *, i64);
typedef void (*fn_dict_set_value)(void *, void *, void *);
typedef void *(*fn_dict_get_value)(void *, void *);
typedef void *(*fn_dict_mk)(void *, long, void *, void *);
typedef void *(*fn_dict_mkcopy)(void *, long, void *);
typedef void *(*fn_arr_mk)(void *, long, void *);
typedef long (*fn_arr_count)(void *);
typedef void *(*fn_arr_at)(void *, long);
typedef void (*fn_arr_append)(void *, void *);
typedef void (*fn_release)(void *);
typedef unsigned long (*fn_typeid)(void);
typedef int (*fn_setup)(void *, void *, void **);
typedef int (*fn_sso)(int, int, int, int, int *, int, int *);

static const fn_setup orig_setup = (fn_setup)VA_SETUP;
static const fn_typeid cf_array_type_id = (fn_typeid)0x00082ca8u;
static const fn_dict_get_typed cf_dict_get_typed = (fn_dict_get_typed)0x000945c8u;
static const fn_dict_get_i64 cf_dict_get_int64 = (fn_dict_get_i64)0x000943ccu;
static const fn_dict_set_i64 cf_dict_set_int64 = (fn_dict_set_i64)0x00096b00u;
static const fn_dict_set_value cf_dict_set_value = (fn_dict_set_value)0x000836dcu;
typedef int (*fn_add_resp)(void *, void *);
#define VA_ADD_RESPONSE_STREAM 0x000652d4u  /* _AddResponseStream(resp, entry): GetTyped(resp,"streams") or create+set, then append */
#define W_ADD_RESPONSE_STREAM  0xe92d43f0u  /* push {r4-r9, lr} */
static const fn_add_resp add_response_stream = (fn_add_resp)VA_ADD_RESPONSE_STREAM;
static const fn_dict_mk cf_dict_create_mutable = (fn_dict_mk)0x00083568u;
static const fn_dict_mkcopy cf_dict_create_mutable_copy = (fn_dict_mkcopy)0x00083678u;
static const fn_arr_mk cf_array_create_mutable = (fn_arr_mk)0x00082e10u;
static const fn_arr_count cf_array_count = (fn_arr_count)0x00082e58u;
static const fn_arr_at cf_array_at = (fn_arr_at)0x00082e90u;
static const fn_arr_append cf_array_append = (fn_arr_append)0x00082fc0u;
static const fn_release cf_release = (fn_release)0x00082c78u;
static const fn_sso server_socket_open = (fn_sso)0x000b709cu;

#define CB_ARRAY      ((void *)0x00134200u)  /* kCFTypeArrayCallBacks */
#define CB_DICT_KEY   ((void *)0x001341e8u)  /* kCFTypeDictionaryKeyCallBacks */
#define CB_DICT_VAL   ((void *)0x001341d4u)  /* kCFTypeDictionaryValueCallBacks */
#define K_STREAMS     ((void *)0x000ffce1u)
#define K_TYPE        ((void *)0x000ffef3u)
#define K_DATAPORT    ((void *)0x00100219u)
#define K_CONNID      ((void *)0x0010013fu)
#define SESSION_FAMILY_OFF 0x8c
#define SOCK_STREAM_ARM 1
#define IPPROTO_TCP 6
#define RCVBUF_SCREEN ((int)0xfffd4000u)
#define ALT_SCREEN_TYPE 111

/* ---- tiny helpers ---- */
static size_t slen(const char *s) { size_t n = 0; while (s[n]) n++; return n; }

static const char LOGDIR[] = "/usr/data/log";
static const char LOGF[] = "/usr/data/log/altscreen.log";

/* altscreen.log lives in persistent flash: truncate at boot when over LOG_MAX_FILE,
   and stop writing after LOG_MAX_BOOT bytes per boot (one marker line). */
#define LOG_MAX_FILE (64 * 1024)
#define LOG_MAX_BOOT (16 * 1024)
static long g_log_bytes;
static int g_log_capped;
static int log_open(void) {
  if (g_log_capped) return -1;
  int fd = open(LOGF, O_WRONLY | O_CREAT | O_APPEND, 0644);
  if (fd < 0) return -1;
  if (g_log_bytes > LOG_MAX_BOOT) {
    static const char m[] = "log cap reached for this boot\n";
    write(fd, m, sizeof m - 1);
    g_log_capped = 1;
    close(fd);
    return -1;
  }
  return fd;
}
static void log_w(int fd, const void *p, size_t n) { write(fd, p, n); g_log_bytes += (long)n; }
static void log_trim_at_boot(void) {
  int fd = open(LOGF, O_WRONLY | O_CREAT | O_APPEND, 0644);
  if (fd < 0) return;
  long sz = sys3(NR_lseek, fd, 0, SEEK_END);
  close(fd);
  if (sz > LOG_MAX_FILE) { fd = open(LOGF, O_WRONLY | O_CREAT | O_TRUNC, 0644); if (fd >= 0) close(fd); }
}

static void dbg(const char *msg, long n) {
  int fd = log_open();
  if (fd < 0) return;
  log_w(fd, msg, slen(msg));
  if (n != -1) {
    /* decimal without division (no __aeabi_uidiv dependency on ARMv5) */
    static const unsigned long p10[] = {1000000000ul, 100000000ul, 10000000ul, 1000000ul, 100000ul,
                                        10000ul, 1000ul, 100ul, 10ul, 1ul};
    char b[24]; int l = 0, started = 0;
    unsigned long m = n < 0 ? (unsigned long)(-n) : (unsigned long)n;
    b[l++] = ' ';
    if (n < 0) b[l++] = '-';
    for (int i = 0; i < 10; i++) {
      char dgt = '0';
      while (m >= p10[i]) { m -= p10[i]; dgt++; }
      if (dgt != '0' || started || i == 9) { b[l++] = dgt; started = 1; }
    }
    log_w(fd, b, l);
  }
  log_w(fd, "\n", 1);
  close(fd);
}

static void dbg_hex(const char *msg, u32 v) {
  static const char hx[] = "0123456789abcdef";
  char b[12]; b[0] = ' '; b[1] = '0'; b[2] = 'x';
  for (int i = 0; i < 8; i++) b[3 + i] = hx[(v >> (28 - 4 * i)) & 15];
  b[11] = 0;
  int fd = log_open();
  if (fd < 0) return;
  log_w(fd, msg, slen(msg)); log_w(fd, b, 11); log_w(fd, "\n", 1);
  close(fd);
}

/* ---- P2..P4: stream filter, sink, cluster SETUP to the car, frame relay ---- */
extern void *malloc(size_t);
extern void free(void *);
extern int socket(int, int, int);
extern int setsockopt(int, int, int, const void *, u32);
extern int connect(int, const void *, u32);
extern int usleep(u32);
extern ssize_t send(int, const void *, size_t, int);

#define MSG_NOSIGNAL 0x4000
#define SOL_SOCKET_ARM 1
#define SO_REUSEADDR_ARM 2
#define IPPROTO_IPV6 41
#define IPV6_V6ONLY 26
#define AF_INET6 10

/* more sdDongle functions (ak_202610081659) */
typedef int (*fn_sendcmd)(void *, void *, void *, void *);
typedef void (*fn_dict_set_cstr)(void *, void *, const char *, u32);
typedef int (*fn_streamkeys)(void *, i64, int, int, void *);
typedef void (*fn_derive_screen)(void *, int, i64, void *, void *);
typedef void (*fn_aes_init)(void *, const void *, const void *);
typedef void (*fn_aes_upd)(void *, const void *, size_t, void *);
typedef void (*fn_cc_init)(void *, const void *, const void *);
typedef void (*fn_cc_aad)(void *, const void *, size_t);
typedef int (*fn_cc_dec)(void *, const void *, size_t, void *);
typedef int (*fn_cc_ver)(void *, void *, const void *, int *);
typedef void (*fn_uuid)(void *);
typedef int (*fn_http_create)(void **);
typedef int (*fn_http_init)(void *, const char *, const char *, const char *);
typedef int (*fn_http_addf)(void *, const char *, const char *, ...);
typedef int (*fn_http_setbody)(void *, const char *, const void *, size_t);
typedef int (*fn_http_send)(void *, void *);
typedef void (*fn_arr_ensure)(void **, void *);
typedef void *(*fn_plist_create)(void *, int *, int);
typedef void *(*fn_plist_read)(const void *, size_t, int *);
typedef void *(*fn_sem_create)(long);
typedef long (*fn_sem_wait)(void *, unsigned long long);
typedef long (*fn_sem_signal)(void *);
typedef void (*fn_sock_copy)(const void *, void *);
typedef void (*fn_sock_setport)(void *, int);
typedef int (*fn_sock_getsize)(const void *);
typedef int (*fn_sock_qos)(int, int);
typedef unsigned long (*fn_gettypeid)(void *);
typedef void (*fn_simderive)(const void *, size_t, const char *, size_t, const char *, size_t, void *, void *);

static const fn_sendcmd session_send_command = (fn_sendcmd)0x000673e0u;
static const fn_dict_set_cstr cf_dict_set_cstr = (fn_dict_set_cstr)0x0009397cu;
static const fn_streamkeys get_stream_keys = (fn_streamkeys)0x000654c0u;
static const fn_derive_screen derive_screen = (fn_derive_screen)0x00073e84u;
static const fn_aes_init aes_ctr_init = (fn_aes_init)0x0007ca74u;
static const fn_aes_upd aes_ctr_update = (fn_aes_upd)0x0007cab0u;
static const fn_cc_init cc_init = (fn_cc_init)0x000999e0u;
static const fn_cc_aad cc_aad = (fn_cc_aad)0x00099e54u;
static const fn_cc_dec cc_dec = (fn_cc_dec)0x00099f64u;
static const fn_cc_ver cc_ver = (fn_cc_ver)0x0009a10cu;
static const fn_uuid uuid_get = (fn_uuid)0x000d03a4u;
static const fn_http_create http_create = (fn_http_create)0x000a6d08u;
static const fn_http_init http_init = (fn_http_init)0x000a9710u;
static const fn_http_addf http_addf = (fn_http_addf)0x000a9e00u;
static const fn_http_setbody http_setbody = (fn_http_setbody)0x000a6dc8u;
static const fn_http_send http_send = (fn_http_send)0x000a6974u;
static const fn_arr_ensure cf_arr_ensure = (fn_arr_ensure)0x0009327cu;
static const fn_plist_create cf_plist_create = (fn_plist_create)0x0008d0a0u;
static const fn_plist_read cf_plist_read = (fn_plist_read)0x0008e414u;
static const fn_sem_create d_sem_create = (fn_sem_create)0x000a11d8u;
static const fn_sem_wait d_sem_wait = (fn_sem_wait)0x000a15b8u;
static const fn_sem_signal d_sem_signal = (fn_sem_signal)0x000a1338u;
static const fn_sock_copy sock_copy = (fn_sock_copy)0x000b82dcu;
static const fn_sock_setport sock_setport = (fn_sock_setport)0x000b7858u;
static const fn_sock_getsize sock_getsize = (fn_sock_getsize)0x000b6ce8u;
static const fn_sock_qos sock_qos = (fn_sock_qos)0x000b6128u;
static const fn_gettypeid cf_get_type_id = (fn_gettypeid)0x00082c34u;
static const fn_typeid cf_dict_type_id = (fn_typeid)0x00083564u;
static const fn_simderive sim_derive = (fn_simderive)0x0002b884u;

/* globals (exported by sdDongle) */
#define G_AIRPLAY_CLIENT ((void **)0x0013bf28u)
#define G_PEER_ADDR ((void *)0x0013bca0u)
#define G_PAIRVERIFY_HK ((int *)0x0013a7e4u)
#define G_SESSION_AESKEY ((void *)0x0013a800u)
/* CF keys of the client module (same copies OMKE used in AX order) */
#define K2_STREAMS ((void *)0x000f63f9u)
#define K2_TYPE ((void *)0x000f6409u)
#define K2_DATAPORT ((void *)0x000f6416u)
#define K2_CONNID ((void *)0x000f6475u)
#define K2_UUID ((void *)0x000f6490u)
#define K2_LATENCYMS ((void *)0x000f649du)
#define K_CMD_PARAMS ((void *)0x001002fau)
#define K_CMD_URL ((void *)0x00100452u)
#define SESSION_PVS_OFF 0x3ec
#define SESSION_SCREENKEY_OFF 0x200
/* HTTPMessage fields (identical in AX and AK) */
#define MSG_HDR_OFF 0x10
#define MSG_BODYPTR_OFF 0x49c
#define MSG_BODYLEN_OFF 0x4a0
#define MSG_CTX_A 0x8f4
#define MSG_CTX_B 0x8f8
#define MSG_CTX_C 0x8fc
#define MSG_COMPLETION 0x904

#define CLUSTER_STREAM_TYPE 111
static const char CLUSTER_UUID[] = "b7e6c5a0-2222-4000-8000-000000000002";
static const char CLUSTER_MAP_URL[] = "maps:/car/instrumentcluster/map";
#define CLUSTER_W_DEFAULT 800
#define CLUSTER_H_DEFAULT 480

static void mset(void *p, int v, size_t n) { u8 *q = (u8 *)p; while (n--) *q++ = (u8)v; }
static void mcpy(void *d, const void *s, size_t n) { u8 *a = (u8 *)d; const u8 *b = (const u8 *)s; while (n--) *a++ = *b++; }
/* "<prefix><u64 decimal>" without division */
static int fmt_u64(char *out, int cap, const char *prefix, unsigned long long v) {
  int l = 0;
  while (*prefix && l < cap - 1) out[l++] = *prefix++;
  unsigned long long p = 10000000000000000000ull;
  int started = 0;
  for (int i = 0; i < 20; i++) {
    char d = '0';
    while (v >= p) { v -= p; d++; }
    if ((d != '0' || started || i == 19) && l < cap - 1) { out[l++] = d; started = 1; }
    /* p /= 10 without division: table walk */
    static const unsigned long long t[20] = {10000000000000000000ull, 1000000000000000000ull, 100000000000000000ull,
      10000000000000000ull, 1000000000000000ull, 100000000000000ull, 10000000000000ull, 1000000000000ull,
      100000000000ull, 10000000000ull, 1000000000ull, 100000000ull, 10000000ull, 1000000ull, 100000ull, 10000ull,
      1000ull, 100ull, 10ull, 1ull};
    if (i < 19) p = t[i + 1];
  }
  out[l] = 0;
  return l;
}

static void dbg_bytes(const char *msg, const u8 *p, int n) {
  static const char hx[] = "0123456789abcdef";
  int fd = log_open();
  if (fd < 0) return;
  log_w(fd, msg, slen(msg));
  if (n > 48) n = 48;
  for (int i = 0; i < n; i++) { char c[3] = {' ', hx[p[i] >> 4], hx[p[i] & 15]}; log_w(fd, c, 3); }
  log_w(fd, "\n", 1);
  close(fd);
}

/* ---- state ---- */
struct car_ctx {
  int fd;
  int data_port;
  void *sem;
  u8 key[16];
  u8 iv[16];
  u8 aes[0x400] __attribute__((aligned(8)));
};
static struct car_ctx *volatile g_car;
static void *volatile g_session;
static volatile unsigned long long g_conn111;
static volatile int g_have_conn111;
static volatile int g_cluster_started;

static int writeall(int fd, const void *buf, int n) {
  const u8 *p = (const u8 *)buf;
  while (n > 0) {
    ssize_t w = send(fd, p, n, MSG_NOSIGNAL);
    if (w <= 0) return -1;
    p += w;
    n -= (int)w;
  }
  return 0;
}
static int readn(int fd, void *buf, int n) {
  u8 *p = (u8 *)buf;
  int got = 0;
  while (got < n) {
    ssize_t r = read(fd, p + got, n - got);
    if (r <= 0) return -1;
    got += (int)r;
  }
  return 0;
}

static int send_phone_cmd(void *session, const char *type, int with_url) {
  void *req = cf_dict_create_mutable(0, 0, CB_DICT_KEY, CB_DICT_VAL);
  void *params = cf_dict_create_mutable(0, 0, CB_DICT_KEY, CB_DICT_VAL);
  if (!req || !params) return -1;
  cf_dict_set_cstr(req, K_TYPE, type, 0xffffffffu);
  cf_dict_set_cstr(params, K2_UUID, CLUSTER_UUID, 0xffffffffu);
  if (with_url) cf_dict_set_cstr(params, K_CMD_URL, CLUSTER_MAP_URL, 0xffffffffu);
  cf_dict_set_value(req, K_CMD_PARAMS, params);
  cf_release(params);
  int rc = session_send_command(session, req, 0, 0);
  cf_release(req);
  return rc;
}

static int has_idr(const u8 *b, u32 len) {
  u32 pos = 0;
  while (pos + 5 <= len) {
    u32 nlen = ((u32)b[pos] << 24) | ((u32)b[pos + 1] << 16) | ((u32)b[pos + 2] << 8) | b[pos + 3];
    if ((b[pos + 4] & 0x1f) == 5) return 1;
    if (nlen == 0 || pos + 4 + nlen > len) break;
    pos += 4 + nlen;
  }
  return 0;
}

/* frame to the car: 128-byte header (len, type; config also carries display size/viewArea) + body */
static int send_to_car(struct car_ctx *cc, int type, const u8 *phone_hdr, u8 *body, u32 len) {
  u8 hdr[128];
  mset(hdr, 0, sizeof hdr);
  *(u32 *)hdr = len;
  hdr[4] = (u8)type;
  if (type == 1) {
    /* copy display size + viewArea floats from the phone's config header when present */
    u32 w = *(const u32 *)(phone_hdr + 0x10), h = *(const u32 *)(phone_hdr + 0x14);
    if (w && h) mcpy(hdr + 0x10, phone_hdr + 0x10, 0x20);
    else {
      static const float fw = (float)CLUSTER_W_DEFAULT, fh = (float)CLUSTER_H_DEFAULT;
      mcpy(hdr + 0x10, &fw, 4); mcpy(hdr + 0x14, &fh, 4);
      mcpy(hdr + 0x28, &fw, 4); mcpy(hdr + 0x2c, &fh, 4);
    }
  }
  if (type == 0) aes_ctr_update(cc->aes, body, len, body);
  int rc = writeall(cc->fd, hdr, 128);
  if (rc == 0 && len) rc = writeall(cc->fd, body, (int)len);
  return rc;
}

static void *sink_thread(void *arg) {
  int srv = (int)(long)arg;
  dbg("alt sink thread up", -1);
  int c = accept(srv, 0, 0);
  close(srv);
  if (c < 0) { dbg("alt accept fail", -1); return 0; }
  dbg("alt connected", -1);
  void *session = g_session;
  if (session) { int sr = send_phone_cmd(session, "showUI", 1); dbg("alt showUI err", sr); }

  static u8 cctx[0x400] __attribute__((aligned(8)));
  static u8 dctx[0x400] __attribute__((aligned(8)));
  u8 cckey[32], ccnonce[8];
  int dec_ready = 0, chacha = 0;
  void *pvs = session ? *(void **)((u8 *)session + SESSION_PVS_OFF) : 0;
  dbg("alt pairVerifySession set", pvs ? 1 : 0);
  if (pvs && g_have_conn111 && g_conn111) {
    int rc = get_stream_keys((u8 *)session + SESSION_PVS_OFF, (i64)g_conn111, 0, 0, cckey);
    dbg("alt chacha keys rc", rc);
    if (rc == 0) { mset(ccnonce, 0, sizeof ccnonce); dec_ready = 1; chacha = 1; }
  } else if (g_have_conn111 && session && g_conn111) {
    u8 key[16], iv[16];
    derive_screen((u8 *)session + SESSION_SCREENKEY_OFF, 16, (i64)g_conn111, key, iv);
    aes_ctr_init(dctx, key, iv);
    dec_ready = 1;
    dbg("alt aes decrypt ready", -1);
  } else {
    dbg("alt no connID", -1);
  }

  u8 hdr[128];
  u8 *body = 0, *cfg_body = 0;
  u8 cfg_hdr[128];
  u32 bodycap = 0, cfg_len = 0;
  long frames = 0, pushed = 0;
  int cfg_sent = 0, got_idr = 0, wait_idr = 0, send_failed = 0, dumped = 0, cfg_dumped = 0;
  long cfg_count = 0, idr_log = 0;
  for (;;) {
    if (readn(c, hdr, 128) != 0) break;
    u32 bodylen = *(u32 *)hdr;
    int ftype = hdr[4];
    if (bodylen > 4000000u) { dbg("alt bad bodylen", (long)bodylen); break; }
    frames++;
    if (frames == 1) dbg("alt first frame type", ftype);
    if (bodylen == 0) continue;
    if (bodylen > bodycap) {
      free(body);
      body = (u8 *)malloc(bodylen + 16);
      if (!body) { dbg("alt malloc fail", -1); break; }
      bodycap = bodylen;
    }
    if (readn(c, body, (int)bodylen) != 0) break;
    struct car_ctx *cc = g_car;
    if (ftype == 0) {
      if (chacha) {
        if (bodylen < 16) continue;
        int err = 0;
        cc_init(cctx, cckey, ccnonce);
        cc_aad(cctx, hdr, 128);
        int n = cc_dec(cctx, body, bodylen - 16, body);
        n += cc_ver(cctx, body + n, body + bodylen - 16, &err);
        for (int k = 0; k < 8 && ++ccnonce[k] == 0; k++) {}
        if (dumped < 2) dbg("alt chacha verify err", err);
        if (err != 0 || n != (int)bodylen - 16) { if (dumped < 4) dbg("alt chacha fail", n); dumped++; continue; }
        bodylen -= 16;
      } else if (dec_ready) {
        aes_ctr_update(dctx, body, bodylen, body);
      }
      if (dumped < 2) { dbg_bytes("alt vid dec", body, 32); dumped++; }
      if (dec_ready && cc && cfg_body) {
        if (!cfg_sent) {
          if (send_to_car(cc, 1, cfg_hdr, cfg_body, cfg_len) == 0) dbg("alt config sent late", (long)cfg_len);
          cfg_sent = 1; got_idr = 0; wait_idr = 0;
        }
        if (!got_idr && has_idr(body, bodylen)) {
          got_idr = 1;
          if (wait_idr > 0 || idr_log < 3) { dbg("alt idr after frames", wait_idr); idr_log++; }
        }
        if (!got_idr) {
          if ((wait_idr++ & 127) == 0 && session) { int kr = send_phone_cmd(session, "forceKeyFrame", 0); dbg("alt force keyframe err", kr); }
          continue;
        }
        if (send_to_car(cc, 0, hdr, body, bodylen) == 0) pushed++;
        else if (!send_failed) { send_failed = 1; dbg("alt send to car fail after", pushed); }
      }
    } else if (ftype == 1) {
      if (cfg_dumped < 3) { dbg_bytes("alt config hdr", hdr, 48); dbg_bytes("alt config body", body, (int)bodylen); cfg_dumped++; }
      free(cfg_body);
      cfg_body = (u8 *)malloc(bodylen);
      if (cfg_body) { mcpy(cfg_body, body, bodylen); mcpy(cfg_hdr, hdr, 128); cfg_len = bodylen; cfg_sent = 0; }
      if (cfg_body && cc) {
        if (send_to_car(cc, 1, cfg_hdr, cfg_body, cfg_len) == 0) {
          pushed++;
          if (++cfg_count <= 3) dbg("alt config sent", (long)cfg_len);
        }
        cfg_sent = 1; got_idr = 0; wait_idr = 0;
      }
    }
    if ((frames <= 2048 && (frames & 511) == 0) || (frames & 65535) == 0) {
      dbg("alt frames pushed", pushed);
      dbg("alt configs so far", cfg_count);
    }
  }
  dbg("alt stream end, frames", frames);
  dbg("alt stream end, pushed", pushed);
  dbg("alt stream end, configs", cfg_count);
  /* allow a fresh cluster SETUP on the next session */
  struct car_ctx *old = g_car;
  g_car = 0;
  if (old && old->fd >= 0) { close(old->fd); old->fd = -1; }
  g_have_conn111 = 0;
  g_cluster_started = 0;
  free(body);
  free(cfg_body);
  close(c);
  return 0;
}

static int spawn(void *(*fn)(void *), void *arg) {
  pthread_t t;
  long attr[16];
  pthread_attr_init(attr);
  pthread_attr_setdetachstate(attr, PTHREAD_CREATE_DETACHED);
  int prc = pthread_create(&t, attr, fn, arg);
  pthread_attr_destroy(attr);
  return prc;
}

static int open_alt_sink(void *session) {
  int family = *(u16 *)((u8 *)session + SESSION_FAMILY_OFF);
  int port = 0, fd = -1;
  int rc = server_socket_open(family, SOCK_STREAM_ARM, IPPROTO_TCP, 0, &port, RCVBUF_SCREEN, &fd);
  if (rc != 0 || fd < 0) { dbg("alt ServerSocketOpen rc", rc); return 0; }
  int fl = fcntl(fd, F_GETFL, 0);
  if (fl != -1) fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
  int prc = spawn(sink_thread, (void *)(long)fd);
  if (prc != 0) { close(fd); dbg("alt thread fail", prc); return 0; }
  return port;
}

/* ---- P3: SETUP type 111 to the car over the dongle's own AirPlay client ---- */
static void cluster_response_cb(void *msg) {
  int len = *(int *)((u8 *)msg + MSG_BODYLEN_OFF);
  void *bodyp = *(void **)((u8 *)msg + MSG_BODYPTR_OFF);
  struct car_ctx *cc = *(struct car_ctx **)((u8 *)msg + MSG_CTX_C);
  dbg("cluster SETUP response bytes", len);
  int found = 0;
  if (len > 0 && bodyp) {
    int err = 0;
    void *d = cf_plist_read(bodyp, (size_t)len, &err);
    if (err == 0 && d) {
      if (cf_get_type_id(d) == cf_dict_type_id()) {
        void *streams = cf_dict_get_typed(d, K2_STREAMS, cf_array_type_id(), 0);
        long n = streams ? cf_array_count(streams) : 0;
        for (long i = 0; i < n; i++) {
          void *sd = cf_array_at(streams, i);
          if (sd && cf_dict_get_int64(sd, K2_TYPE, 0) == CLUSTER_STREAM_TYPE) {
            cc->data_port = (int)cf_dict_get_int64(sd, K2_DATAPORT, 0);
            dbg("cluster car dataPort", cc->data_port);
            found = 1;
            break;
          }
        }
      }
      cf_release(d);
    } else {
      dbg("cluster response plist err", err);
    }
  }
  if (!found) dbg("cluster response without type 111", -1);
  d_sem_signal(cc->sem);
}

static void *cluster_setup_to_car(void *unused) {
  (void)unused;
  if (*G_PAIRVERIFY_HK != 0) { dbg("cluster homekit pairing mode not supported", -1); return 0; }
  void *client = *G_AIRPLAY_CLIENT;
  if (!client) { dbg("cluster no airplay client", -1); return 0; }
  struct car_ctx *cc = (struct car_ctx *)malloc(sizeof *cc);
  if (!cc) return 0;
  mset(cc, 0, sizeof *cc);
  cc->fd = -1;
  cc->sem = d_sem_create(0);

  void *msg = 0;
  if (http_create(&msg) != 0 || !msg) { dbg("cluster http create fail", -1); return 0; }
  if (http_init((u8 *)msg + MSG_HDR_OFF, "SETUP", "/NoUse", "RTSP/1.0") != 0) { dbg("cluster http init fail", -1); return 0; }
  http_addf((u8 *)msg + MSG_HDR_OFF, "CSeq", "%d", 1);

  void *req = cf_dict_create_mutable(0, 0, CB_DICT_KEY, CB_DICT_VAL);
  void *sd = cf_dict_create_mutable(0, 0, CB_DICT_KEY, CB_DICT_VAL);
  if (!req || !sd) { dbg("cluster dict fail", -1); return 0; }
  u8 u[16];
  uuid_get(u);
  u32 hi = ((u32)u[0] << 24) | ((u32)u[1] << 16) | ((u32)u[2] << 8) | u[3];
  u32 lo = ((u32)u[4] << 24) | ((u32)u[5] << 16) | ((u32)u[6] << 8) | u[7];
  unsigned long long connid = ((unsigned long long)hi << 32) | lo;
  cf_dict_set_int64(sd, K2_CONNID, (i64)connid);
  cf_dict_set_int64(sd, K2_TYPE, CLUSTER_STREAM_TYPE);
  cf_dict_set_cstr(sd, K2_UUID, CLUSTER_UUID, 0xffffffffu);
  cf_dict_set_int64(sd, K2_LATENCYMS, 25);
  void *arr = 0;
  cf_arr_ensure(&arr, sd);
  cf_dict_set_value(req, K2_STREAMS, arr);
  int blen = 0;
  void *body = cf_plist_create(req, &blen, 0);
  if (!body) { dbg("cluster plist fail", -1); return 0; }
  if (http_setbody(msg, "application/x-apple-binary-plist", body, (size_t)blen) != 0) { dbg("cluster setbody fail", -1); return 0; }
  cf_release(arr);
  cf_release(sd);
  cf_release(req);

  *(void **)((u8 *)msg + MSG_COMPLETION) = (void *)&cluster_response_cb;
  *(int *)((u8 *)msg + MSG_CTX_A) = 0;
  *(int *)((u8 *)msg + MSG_CTX_B) = 0;
  *(void **)((u8 *)msg + MSG_CTX_C) = cc;
  dbg("cluster SETUP sent", -1);
  http_send(client, msg);
  d_sem_wait(cc->sem, ~0ull);  /* DISPATCH_TIME_FOREVER, as OMKE; own thread */
  if (cc->data_port <= 0) { dbg("cluster no dataPort", -1); return 0; }

  u8 sa[160];
  mset(sa, 0, sizeof sa);
  sock_copy(G_PEER_ADDR, sa);
  int family = *(u16 *)sa;
  int fd = socket(family, SOCK_STREAM_ARM, 0);
  if (fd < 0) { dbg("cluster socket fail", -1); return 0; }
  int one = 1;
  setsockopt(fd, SOL_SOCKET_ARM, SO_REUSEADDR_ARM, &one, 4);
  if (family == AF_INET6) setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, 4);
  sock_qos(fd, 0xc);
  sock_setport(sa, cc->data_port);
  int slen_ = sock_getsize(sa);
  int ok = 0;
  for (int tries = 0; tries < 21; tries++) {
    if (connect(fd, sa, (u32)slen_) == 0) { ok = 1; break; }
    usleep(100000);
  }
  if (!ok) { dbg("cluster connect fail", -1); close(fd); return 0; }
  dbg("cluster connected to car", cc->data_port);

  char ks[48], is[48];
  int kl = fmt_u64(ks, sizeof ks, "AirPlayStreamKey", connid);
  int il = fmt_u64(is, sizeof is, "AirPlayStreamIV", connid);
  sim_derive(G_SESSION_AESKEY, 16, ks, (size_t)kl, is, (size_t)il, cc->key, cc->iv);
  aes_ctr_init(cc->aes, cc->key, cc->iv);
  cc->fd = fd;
  g_car = cc;
  dbg("cluster ctx ready", -1);
  return 0;
}

/* ---- P2: request filter ---- */
static void *filter_streams(void *req, int *had_alt) {
  *had_alt = 0;
  void *orig = cf_dict_get_typed(req, K_STREAMS, cf_array_type_id(), 0);
  if (!orig) return 0;
  long n = cf_array_count(orig);
  void *keep = cf_array_create_mutable(0, 0, CB_ARRAY);
  if (!keep) return 0;
  for (long i = 0; i < n; i++) {
    void *sd = cf_array_at(orig, i);
    long ty = (long)cf_dict_get_int64(sd, K_TYPE, 0);
    dbg("req stream type", ty);
    if (ty == ALT_SCREEN_TYPE) {
      *had_alt = 1;
      g_conn111 = (unsigned long long)cf_dict_get_int64(sd, K_CONNID, 0);
      g_have_conn111 = 1;
      dbg_hex("alt connID lo", (u32)g_conn111);
      continue;
    }
    cf_array_append(keep, sd);
  }
  if (!*had_alt) { cf_release(keep); return 0; }
  void *req2 = cf_dict_create_mutable_copy(0, 0, req);
  if (!req2) { cf_release(keep); *had_alt = 0; return 0; }
  cf_dict_set_value(req2, K_STREAMS, keep);
  cf_release(keep);
  return req2;
}

int shim_session_setup(void *session, void *req, void **resp_out) {
  int had_alt = 0;
  g_session = session;
  void *req2 = filter_streams(req, &had_alt);
  int rc = orig_setup(session, req2 ? req2 : req, resp_out);
  if (req2) cf_release(req2);
  if (rc != 0 || !had_alt || !resp_out || !*resp_out) return rc;
  int port = open_alt_sink(session);
  if (port <= 0) { dbg("alt sink fail", -1); return rc; }
  void *entry = cf_dict_create_mutable(0, 0, CB_DICT_KEY, CB_DICT_VAL);
  if (!entry) { dbg("alt entry alloc fail", -1); return rc; }
  cf_dict_set_int64(entry, K_TYPE, ALT_SCREEN_TYPE);
  cf_dict_set_int64(entry, K_DATAPORT, port);
  int arc = add_response_stream(*resp_out, entry);
  cf_release(entry);
  if (arc != 0) { dbg("alt add response stream fail", arc); return rc; }
  dbg("alt dataPort", port);
  if (!g_cluster_started) {
    g_cluster_started = 1;
    if (spawn(cluster_setup_to_car, 0) != 0) { g_cluster_started = 0; dbg("cluster thread fail", -1); }
  }
  return rc;
}

/* ---- runtime patching ---- */
static u32 rd(u32 va) { return *(volatile u32 *)va; }
static void wr(u32 va, u32 v) { *(volatile u32 *)va = v; }
static u32 bl_to(u32 from, u32 to) { return 0xeb000000u | (((to - (from + 8)) >> 2) & 0x00ffffffu); }

static int set_prot(u32 va, int prot) {
  u32 pg = va & ~0xfffu;
  return (int)sys3(NR_mprotect, (long)pg, 0x1000, prot);
}
static void flush(u32 va, u32 len) { sys3(ARM_NR_cacheflush, (long)va, (long)(va + len), 0); }

static int g_done;

static void install(void) {
  if (g_done) return;
  g_done = 1;
  mkdir(LOGDIR, 0755);
  log_trim_at_boot();
  dbg("altscreen-ak shim loaded", -1);
  u32 lit_new = VA_ALTSCREEN_CFOBJ - (VA_P1_ADD_PC + 8) - 893;
  if (rd(VA_SETUP_CALL) != W_SETUP_CALL_OLD || rd(VA_SETUP_CALL) != bl_to(VA_SETUP_CALL, VA_SETUP) ||
      rd(VA_P1_GATE_ALL) != W_GATE_ALL_OLD || rd(VA_P1_GATE_VIEW) != W_GATE_VIEW_OLD ||
      rd(VA_P1_GATE_SLOT3) != W_GATE_SLOT3_OLD || rd(VA_P1_LIT_SLOT3) != W_LIT_SLOT3_OLD ||
      rd(VA_NOSTRIP) != W_NOSTRIP_OLD || rd(VA_CAVE) != 0 || rd(VA_CAVE + 4) != 0 ||
      rd(VA_ADD_RESPONSE_STREAM) != W_ADD_RESPONSE_STREAM) {
    dbg_hex("altscreen-ak MISMATCH, nothing patched; setup_call", rd(VA_SETUP_CALL));
    return;
  }
  const int rwx = PROT_READ | PROT_WRITE | PROT_EXEC, rx = PROT_READ | PROT_EXEC;
  /* 1. cave -> shim_session_setup ; 2. redirect the single Setup call to the cave */
  if (set_prot(VA_CAVE, rwx) != 0) { dbg("mprotect cave fail", -1); return; }
  wr(VA_CAVE, W_LDR_PC_PC_M4);
  wr(VA_CAVE + 4, (u32)&shim_session_setup);
  set_prot(VA_CAVE, rx);
  flush(VA_CAVE, 8);
  if (set_prot(VA_SETUP_CALL, rwx) != 0) { dbg("mprotect call fail", -1); return; }
  wr(VA_SETUP_CALL, bl_to(VA_SETUP_CALL, VA_CAVE));
  set_prot(VA_SETUP_CALL, rx);
  flush(VA_SETUP_CALL, 4);
  dbg("setup hook installed", -1);
  /* 3. P1: enabledFeatures always [ (uiContext?), viewAreas, altScreen, (focusTransfer?) ] */
  if (set_prot(VA_P1_GATE_ALL, rwx) != 0) { dbg("mprotect p1 fail (hook active, P1 off)", -1); return; }
  wr(VA_P1_GATE_ALL, W_NOP);
  wr(VA_P1_GATE_VIEW, W_NOP);
  wr(VA_P1_GATE_SLOT3, W_NOP);
  wr(VA_P1_LIT_SLOT3, lit_new);
  set_prot(VA_P1_GATE_ALL, rx);
  flush(VA_P1_GATE_ALL & ~0xfffu, 0x1000);
  dbg_hex("P1 altScreen patched, lit", lit_new);
  /* 4. nostrip: phone-facing /info keeps all displays the car advertises (incl. the cluster) */
  if (set_prot(VA_NOSTRIP, rwx) != 0) { dbg("mprotect nostrip fail", -1); return; }
  wr(VA_NOSTRIP, W_NOSTRIP_NEW);
  set_prot(VA_NOSTRIP, rx);
  flush(VA_NOSTRIP, 4);
  dbg("nostrip patched", -1);
}

__attribute__((constructor)) static void ctor(void) { install(); }
void altscreen_ak_init(void) { install(); }  /* also wired as DT_INIT */

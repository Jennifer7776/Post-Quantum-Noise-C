// test_pqnoise_oqs_whitebox.c
// 1) 直接 OQS_KEM_* 自测
// 2) 通过 Noise 握手（内存内）+ vtable hook，白盒验证 EKEM/SKEM 顺序 & 次数
// 构建：gcc -std=c11 -I../include test_pqnoise_oqs_whitebox.c -L../src/.libs -lnoise -loqs -o test_pqnoise_oqs_whitebox

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <oqs/oqs.h>
#include "noise/protocol.h"
#include "noise/protocol/buffer.h"
#include "noise/protocol/dhstate.h"
#include "../src/protocol/internal.h"


/* --------- 工具 --------- */
static void die(const char *where, int err) {
    noise_perror(where, err);
    fprintf(stderr, "%s: error=%d\n", where, err);
    exit(1);
}
static void hex(const char *tag, const uint8_t *b, size_t n) {
    fprintf(stderr, "[WB_TEST] %s len=%zu: ", tag, n);
    for (size_t i=0;i<n;i++) fprintf(stderr, "%02x", b[i]);
    fputc('\n', stderr);
}
static void set_empty_payload(NoiseBuffer *dst, uint8_t *scratch1) {
    noise_buffer_set_input(*dst, scratch1, 0);
}

/* --------- (A) 直接 OQS 自测 --------- */
static void oqs_selftest(const char *kem_name, size_t pk_len, size_t ct_len, size_t sh_len) {
    OQS_KEM *kem = OQS_KEM_new(kem_name);
    if (!kem) { fprintf(stderr, "OQS_KEM_new(%s) failed\n", kem_name); exit(2); }

    uint8_t *pk = malloc(pk_len), *sk = malloc(kem->length_secret_key);
    uint8_t *ct = malloc(ct_len), *ss1 = malloc(sh_len), *ss2 = malloc(sh_len);
    if (!pk||!sk||!ct||!ss1||!ss2) { fprintf(stderr,"oom\n"); exit(3); }

    if (OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS) { fprintf(stderr,"OQS keypair fail\n"); exit(4); }
    if (OQS_KEM_encaps(kem, ct, ss1, pk) != OQS_SUCCESS) { fprintf(stderr,"OQS encaps fail\n"); exit(5); }
    if (OQS_KEM_decaps(kem, ss2, ct, sk) != OQS_SUCCESS) { fprintf(stderr,"OQS decaps fail\n"); exit(6); }

    hex("OQS ss(encaps)", ss1, sh_len);
    hex("OQS ss(decaps)", ss2, sh_len);
    if (memcmp(ss1, ss2, sh_len) != 0) { fprintf(stderr,"[FAIL] OQS ss mismatch\n"); exit(7); }
    fprintf(stderr, "[WB_TEST] OQS selftest OK (%s)\n", kem_name);

    free(pk); free(sk); free(ct); free(ss1); free(ss2);
    OQS_KEM_free(kem);
}

/* --------- (B) vtable hook：统计 Noise 在握手里调用 encaps/decaps --------- */
typedef struct {
    NoiseDHState *dh;
    int (*orig_encaps)(NoiseDHState*, uint8_t*, uint8_t*);
    int (*orig_decaps)(const NoiseDHState*, const uint8_t*, uint8_t*);
    const char *label; /* "init.local_e", "resp.remote_s", ... */
} Hook;

static Hook hooks[8];
static int hooks_n = 0;
static int cnt_encaps = 0;
static int cnt_decaps = 0;

static Hook* find_hook(const NoiseDHState *dh) {
    for (int i=0;i<hooks_n;i++) if (hooks[i].dh == dh) return &hooks[i];
    return NULL;
}

static int wrap_encaps(NoiseDHState *st, uint8_t *ct, uint8_t *shared) {
    Hook *h = find_hook(st);
    cnt_encaps++;
    fprintf(stderr, "[WB_TEST] ENCAPS via %-18s  (ptr=%p)\n", h ? h->label : "?", (void*)st);
    int rc = h && h->orig_encaps ? h->orig_encaps(st, ct, shared) : NOISE_ERROR_INVALID_STATE;
    if (rc==NOISE_ERROR_NONE) hex("shared(sender)", shared, st->shared_key_len);
    return rc;
}
static int wrap_decaps(const NoiseDHState *st, const uint8_t *ct, uint8_t *shared) {
    Hook *h = find_hook(st);
    cnt_decaps++;
    fprintf(stderr, "[WB_TEST] DECAPS via %-18s  (ptr=%p)\n", h ? h->label : "?", (void*)st);
    int rc = h && h->orig_decaps ? h->orig_decaps(st, ct, shared) : NOISE_ERROR_INVALID_STATE;
    if (rc==NOISE_ERROR_NONE) hex("shared(recv)  ", shared, st->shared_key_len);
    return rc;
}

static void hook_one(NoiseDHState *dh, const char *label) {
    if (!dh) return;
    Hook *h = &hooks[hooks_n++];
    h->dh = dh;
    h->orig_encaps = dh->encaps;
    h->orig_decaps = dh->decaps;
    h->label = label;
    /* 覆盖 vtable：后续握手里 EKEM/SKEM 就会进我们的 wrapper，再转调原函数(=OQS) */
    dh->encaps = &wrap_encaps;
    dh->decaps = &wrap_decaps;
}

/* --------- (C) 用 OQS 生成静态/临时钥并注入 Noise（像你的 client/server） --------- */
static void inject_local_keypair_if_needed(NoiseHandshakeState *hs,
                                           const char *kem_name,
                                           size_t pk_len, size_t sk_len)
{
    if (!noise_handshakestate_needs_local_keypair(hs)) return;

    OQS_KEM *kem = OQS_KEM_new(kem_name);
    if (!kem) { fprintf(stderr,"OQS_KEM_new fail\n"); exit(10); }
    uint8_t *pk = malloc(pk_len);
    uint8_t *sk = malloc(sk_len);
    if (!pk||!sk) { fprintf(stderr,"oom\n"); exit(11); }
    if (OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS) { fprintf(stderr,"OQS keypair fail\n"); exit(12); }

    NoiseDHState *dh = noise_handshakestate_get_local_keypair_dh(hs);
    /* 你的后端需要提供 set_keypair；若没有，可 fallback 为 set_public_key + 私钥私有存储 */
    if (dh->set_keypair) {
        int e = dh->set_keypair(dh, sk, sk_len, pk, pk_len);
        if (e) die("set_keypair", e);
    } else {
        int e = noise_dhstate_set_public_key(dh, pk, pk_len);
        if (e) die("set_public_key", e);
        /* 注意：如果没有 set_keypair，后端必须已存有 sk（比如 generate_keypair），否则 decaps 无法进行 */
    }

    hex("LOCAL static/ephemeral PK (injected)", pk, pk_len);

    free(pk); free(sk);
    OQS_KEM_free(kem);
}

static void maybe_set_remote_static_pk(NoiseHandshakeState *dst, NoiseHandshakeState *src) {
    if (!noise_handshakestate_needs_remote_public_key(dst)) return;
    NoiseDHState *remote = noise_handshakestate_get_remote_public_key_dh(dst);
    NoiseDHState *local  = noise_handshakestate_get_local_keypair_dh(src);
    size_t plen = noise_dhstate_get_public_key_length(local);
    uint8_t *pub = (uint8_t*)malloc(plen);
    int e = noise_dhstate_get_public_key(local, pub, plen);
    if (!e) e = noise_dhstate_set_public_key(remote, pub, plen);
    free(pub);
    if (e) die("set remote pk", e);
}

/* --------- (D) 内存握手（带 hook） --------- */
static void run_handshake(const char *name, const char *kem_name,
                          size_t pk_len, size_t sk_len)
{
    NoiseHandshakeState *init=NULL, *resp=NULL;
    int err = noise_handshakestate_new_by_name(&init, name, NOISE_ROLE_INITIATOR);
    if (err != NOISE_ERROR_NONE) die("new init", err);
    err = noise_handshakestate_new_by_name(&resp, name, NOISE_ROLE_RESPONDER);
    if (err != NOISE_ERROR_NONE) die("new resp", err);

    /* 先让我们“像小程序那样”用 OQS 生成需要的本地静态/临时钥并注入 */
    inject_local_keypair_if_needed(init, kem_name, pk_len, sk_len);
    inject_local_keypair_if_needed(resp, kem_name, pk_len, sk_len);

    /* 必要时注入对端静态公钥（NK/NX/…） */
    maybe_set_remote_static_pk(init, resp);
    maybe_set_remote_static_pk(resp, init);

    /* 安装 hook（覆盖 vtable，统计 EKEM/SKEM 调用） */
    hook_one(noise_handshakestate_get_local_keypair_dh(init), "init.local");
    hook_one(noise_handshakestate_get_remote_public_key_dh(init), "init.remote");
    hook_one(noise_handshakestate_get_local_keypair_dh(resp), "resp.local");
    hook_one(noise_handshakestate_get_remote_public_key_dh(resp), "resp.remote");

    /* start */
    err = noise_handshakestate_start(init); if (err) die("start init", err);
    err = noise_handshakestate_start(resp); if (err) die("start resp", err);

    /* 驱动到 SPLIT（内存里搬运） */
    uint8_t buf[16384], scratch[1];
    NoiseBuffer nb_out, nb_in, nb_empty;

    for (int steps=0; steps<24; steps++) {
        int ia = noise_handshakestate_get_action(init);
        int ra = noise_handshakestate_get_action(resp);
        if (ia==NOISE_ACTION_SPLIT && ra==NOISE_ACTION_SPLIT) break;

        if (ia==NOISE_ACTION_WRITE_MESSAGE) {
            noise_buffer_set_output(nb_out, buf, sizeof(buf));
            set_empty_payload(&nb_empty, scratch);
            err = noise_handshakestate_write_message(init, &nb_out, &nb_empty); if (err) die("init write", err);
            size_t mlen = nb_out.size;
            noise_buffer_set_input(nb_in, buf, mlen);
            set_empty_payload(&nb_empty, scratch);
            err = noise_handshakestate_read_message(resp, &nb_in, &nb_empty); if (err) die("resp read", err);
            continue;
        }
        if (ra==NOISE_ACTION_WRITE_MESSAGE) {
            noise_buffer_set_output(nb_out, buf, sizeof(buf));
            set_empty_payload(&nb_empty, scratch);
            err = noise_handshakestate_write_message(resp, &nb_out, &nb_empty); if (err) die("resp write", err);
            size_t mlen = nb_out.size;
            noise_buffer_set_input(nb_in, buf, mlen);
            set_empty_payload(&nb_empty, scratch);
            err = noise_handshakestate_read_message(init, &nb_in, &nb_empty); if (err) die("init read", err);
            continue;
        }
        fprintf(stderr,"[WB_TEST] deadlock\n"); exit(30);
    }

    if (noise_handshakestate_get_action(init)!=NOISE_ACTION_SPLIT ||
        noise_handshakestate_get_action(resp)!=NOISE_ACTION_SPLIT) {
        fprintf(stderr,"[WB_TEST] not at SPLIT\n"); exit(31);
    }

    /* 拆分 + AEAD 验证 */
    NoiseCipherState *is, *ir, *rs, *rr;
    err = noise_handshakestate_split(init, &is, &ir); if (err) die("split init", err);
    err = noise_handshakestate_split(resp, &rs, &rr); if (err) die("split resp", err);

    static const uint8_t msg[]="hello pqnoise";
    uint8_t inout[128]; memcpy(inout, msg, sizeof(msg));
    NoiseBuffer mb;
    noise_buffer_set_inout(mb, inout, sizeof(msg), sizeof(inout));
    if (noise_cipherstate_encrypt(is, &mb)!=NOISE_ERROR_NONE) { fprintf(stderr,"encrypt fail\n"); exit(40); }
    size_t ctlen = mb.size;
    noise_buffer_set_inout(mb, inout, ctlen, sizeof(inout));
    if (noise_cipherstate_decrypt(rr, &mb)!=NOISE_ERROR_NONE) { fprintf(stderr,"decrypt fail\n"); exit(41); }
    if (mb.size != sizeof(msg) || memcmp(inout, msg, sizeof(msg))!=0) { fprintf(stderr,"AEAD mismatch\n"); exit(42); }

    noise_cipherstate_free(is); noise_cipherstate_free(ir);
    noise_cipherstate_free(rs); noise_cipherstate_free(rr);
    noise_handshakestate_free(init); noise_handshakestate_free(resp);
}

/* --------- main --------- */
int main(void) {
    /* 先做 OQS 自测（你可以换 768/1024） */
    oqs_selftest("Kyber512", 800, 768, 32);

    /* 再跑几种 pattern（按你的 patterns 列表挑几个关键的） */
    cnt_encaps = cnt_decaps = 0;
    run_handshake("Noise_pqNN_Kyber512_ChaChaPoly_BLAKE2s", "Kyber512", 800, 1632);
    fprintf(stderr, "[WB_TEST] pqNN  calls: encaps=%d decaps=%d\n", cnt_encaps, cnt_decaps);

    cnt_encaps = cnt_decaps = 0;
    run_handshake("Noise_pqNK_Kyber512_ChaChaPoly_BLAKE2s", "Kyber512", 800, 1632);
    fprintf(stderr, "[WB_TEST] pqNK  calls: encaps=%d decaps=%d\n", cnt_encaps, cnt_decaps);

    cnt_encaps = cnt_decaps = 0;
    run_handshake("Noise_pqNX_Kyber512_ChaChaPoly_BLAKE2s", "Kyber512", 800, 1632);
    fprintf(stderr, "[WB_TEST] pqNX  calls: encaps=%d decaps=%d\n", cnt_encaps, cnt_decaps);

    cnt_encaps = cnt_decaps = 0;
    run_handshake("Noise_pqXX_Kyber512_ChaChaPoly_BLAKE2s", "Kyber512", 800, 1632);
    fprintf(stderr, "[WB_TEST] pqXX  calls: encaps=%d decaps=%d\n", cnt_encaps, cnt_decaps);

    fprintf(stderr, "[WB_TEST] All done.\n");
    return 0;
}

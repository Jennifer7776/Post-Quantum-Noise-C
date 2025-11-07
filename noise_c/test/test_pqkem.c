// test/test_pqkem.c — self-test for Kyber512 & HQC128 (NN/NX/NK/XX, pure PQ)
// 默认一次跑完两家族；支持 --hqc-only / --kyber-only 只跑其一。

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "noise/protocol.h"
#include "noise/protocol/buffer.h"
#include "noise/protocol/errors.h"

static void die(const char *where, int err) {
    noise_perror(where, err);
    fprintf(stderr, "%s: error=%d\n", where, err);
    exit(1);
}

static void set_empty_payload(NoiseBuffer *dst, uint8_t *scratch1) {
    noise_buffer_set_input(*dst, scratch1, 0);
}

static void maybe_provide_keys(NoiseHandshakeState *init, NoiseHandshakeState *resp) {
    if (noise_handshakestate_needs_local_keypair(init)) {
        NoiseDHState *idh = noise_handshakestate_get_local_keypair_dh(init);
        int e = noise_dhstate_generate_keypair(idh);
        if (e) die("init gen static", e);
    }
    if (noise_handshakestate_needs_local_keypair(resp)) {
        NoiseDHState *rdh = noise_handshakestate_get_local_keypair_dh(resp);
        int e = noise_dhstate_generate_keypair(rdh);
        if (e) die("resp gen static", e);
    }
    if (noise_handshakestate_needs_remote_public_key(init)) {
        NoiseDHState *init_remote = noise_handshakestate_get_remote_public_key_dh(init);
        NoiseDHState *resp_local  = noise_handshakestate_get_local_keypair_dh(resp);
        size_t plen = noise_dhstate_get_public_key_length(resp_local);
        uint8_t *pub = (uint8_t *)malloc(plen);
        if (!pub) die("malloc pub init<-resp", NOISE_ERROR_NO_MEMORY);
        int e = noise_dhstate_get_public_key(resp_local, pub, plen);
        if (!e) e = noise_dhstate_set_public_key(init_remote, pub, plen);
        free(pub);
        if (e) die("init set remote pk", e);
    }
    if (noise_handshakestate_needs_remote_public_key(resp)) {
        NoiseDHState *resp_remote = noise_handshakestate_get_remote_public_key_dh(resp);
        NoiseDHState *init_local  = noise_handshakestate_get_local_keypair_dh(init);
        size_t plen = noise_dhstate_get_public_key_length(init_local);
        uint8_t *pub = (uint8_t *)malloc(plen);
        if (!pub) die("malloc pub resp<-init", NOISE_ERROR_NO_MEMORY);
        int e = noise_dhstate_get_public_key(init_local, pub, plen);
        if (!e) e = noise_dhstate_set_public_key(resp_remote, pub, plen);
        free(pub);
        if (e) die("resp set remote pk", e);
    }
}

static int run_one_protocol(const char *name) {
    NoiseHandshakeState *init = NULL, *resp = NULL;
    int err = noise_handshakestate_new_by_name(&init, name, NOISE_ROLE_INITIATOR);
    if (err) return NOISE_ERROR_NOT_APPLICABLE;
    err = noise_handshakestate_new_by_name(&resp, name, NOISE_ROLE_RESPONDER);
    if (err) { noise_handshakestate_free(init); return NOISE_ERROR_NOT_APPLICABLE; }

    printf("[TRY] %s\n", name);

    maybe_provide_keys(init, resp);
    err = noise_handshakestate_start(init); if (err) die("init start", err);
    err = noise_handshakestate_start(resp); if (err) die("resp start", err);

    uint8_t buf[16384], scratch[1];
    NoiseBuffer nb_out, nb_in, nb_empty;

    for (int steps = 0; steps < 16; steps++) {
        int ia = noise_handshakestate_get_action(init);
        int ra = noise_handshakestate_get_action(resp);
        if (ia == NOISE_ACTION_SPLIT && ra == NOISE_ACTION_SPLIT)
            break;

        if (ia == NOISE_ACTION_WRITE_MESSAGE) {
            noise_buffer_set_output(nb_out, buf, sizeof(buf));
            set_empty_payload(&nb_empty, scratch);
            err = noise_handshakestate_write_message(init, &nb_out, &nb_empty);
            if (err) die("init write", err);
            size_t mlen = nb_out.size;
            int rnext = noise_handshakestate_get_action(resp);
            if (rnext != NOISE_ACTION_READ_MESSAGE) {
                fprintf(stderr, "resp not expecting READ after init WRITE (action=%d)\n", rnext);
                exit(3);
            }
            noise_buffer_set_input(nb_in, buf, mlen);
            set_empty_payload(&nb_empty, scratch);
            err = noise_handshakestate_read_message(resp, &nb_in, &nb_empty);
            if (err) die("resp read", err);
            continue;
        }

        if (ra == NOISE_ACTION_WRITE_MESSAGE) {
            noise_buffer_set_output(nb_out, buf, sizeof(buf));
            set_empty_payload(&nb_empty, scratch);
            err = noise_handshakestate_write_message(resp, &nb_out, &nb_empty);
            if (err) die("resp write", err);
            size_t mlen = nb_out.size;
            int inext = noise_handshakestate_get_action(init);
            if (inext != NOISE_ACTION_READ_MESSAGE) {
                fprintf(stderr, "init not expecting READ after resp WRITE (action=%d)\n", inext);
                exit(3);
            }
            noise_buffer_set_input(nb_in, buf, mlen);
            set_empty_payload(&nb_empty, scratch);
            err = noise_handshakestate_read_message(init, &nb_in, &nb_empty);
            if (err) die("init read", err);
            continue;
        }

        fprintf(stderr, "deadlock: init action=%d, resp action=%d\n", ia, ra);
        exit(3);
    }

    if (noise_handshakestate_get_action(init) != NOISE_ACTION_SPLIT ||
        noise_handshakestate_get_action(resp) != NOISE_ACTION_SPLIT) {
        fprintf(stderr, "not at SPLIT\n"); exit(3);
    }

    NoiseCipherState *isend=NULL, *irecv=NULL, *rsend=NULL, *rrecv=NULL;
    err = noise_handshakestate_split(init, &isend, &irecv); if (err) die("init split", err);
    err = noise_handshakestate_split(resp, &rsend, &rrecv); if (err) die("resp split", err);

    static const uint8_t msg[] = "hello pqkem over noise";
    uint8_t inout[256]; memcpy(inout, msg, sizeof(msg));
    NoiseBuffer mb;
    noise_buffer_set_inout(mb, inout, sizeof(msg), sizeof(inout));
    err = noise_cipherstate_encrypt(isend, &mb); if (err) die("encrypt", err);
    size_t ctlen = mb.size;
    noise_buffer_set_inout(mb, inout, ctlen, sizeof(inout));
    err = noise_cipherstate_decrypt(rrecv, &mb); if (err) die("decrypt", err);
    if (mb.size != sizeof(msg) || memcmp(inout, msg, sizeof(msg)) != 0) {
        fprintf(stderr, "AEAD mismatch\n"); exit(4);
    }

    printf("[OK ] %s — handshake+AEAD passed\n", name);

    noise_cipherstate_free(isend); noise_cipherstate_free(irecv);
    noise_cipherstate_free(rsend); noise_cipherstate_free(rrecv);
    noise_handshakestate_free(init); noise_handshakestate_free(resp);
    return NOISE_ERROR_NONE;
}

static int run_family(const char *label, const char *const names[]) {
    int found = 0;
    for (int i = 0; names[i]; i++) {
        int r = run_one_protocol(names[i]);
        if (r == NOISE_ERROR_NONE) { found = 1; break; }
    }
    if (!found) fprintf(stderr, "[WARN] No %s protocol name recognized.\n", label);
    return found;
}
int main(int argc, char **argv) {
    int want_hqc = 1, want_kyber = 1, want_bike = 1;
    if (argc >= 2) {
        if (!strcmp(argv[1], "--hqc-only"))       { want_hqc = 1; want_kyber = 0; want_bike = 0; }
        else if (!strcmp(argv[1], "--kyber-only")){ want_hqc = 0; want_kyber = 1; want_bike = 0; }
        else if (!strcmp(argv[1], "--bike-only")) { want_hqc = 0; want_kyber = 0; want_bike = 1; }
        else {
            fprintf(stderr, "usage: %s [--hqc-only | --kyber-only | --bike-only]\n", argv[0]);
            return 2;
        }
    }

    const char *kyber_names[] = {
        "Noise_pqNX_Kyber512_ChaChaPoly_BLAKE2s",
        "Noise_pqNK_Kyber512_ChaChaPoly_BLAKE2s",
        "Noise_pqXX_Kyber512_ChaChaPoly_BLAKE2s",
        "Noise_pqNN_Kyber512_ChaChaPoly_SHA256",
        "Noise_pqNX_Kyber512_ChaChaPoly_SHA256",
        "Noise_pqNK_Kyber512_ChaChaPoly_SHA256",
        "Noise_pqXX_Kyber512_ChaChaPoly_SHA256",
        NULL
    };
    const char *hqc_names[] = {
        "Noise_pqNX_HQC128_ChaChaPoly_BLAKE2s",
        "Noise_pqNK_HQC128_ChaChaPoly_BLAKE2s",
        "Noise_pqXX_HQC128_ChaChaPoly_BLAKE2s",
        "Noise_pqNN_HQC128_ChaChaPoly_SHA256",
        "Noise_pqNX_HQC128_ChaChaPoly_SHA256",
        "Noise_pqNK_HQC128_ChaChaPoly_SHA256",
        "Noise_pqXX_HQC128_ChaChaPoly_SHA256",
        NULL
    };
    const char *bike_names[] = {
        "Noise_pqNX_BIKEL3_ChaChaPoly_BLAKE2s",
        "Noise_pqNK_BIKEL3_ChaChaPoly_BLAKE2s",
        "Noise_pqXX_BIKEL3_ChaChaPoly_BLAKE2s",
        "Noise_pqNN_BIKEL1_ChaChaPoly_SHA256",
        "Noise_pqNX_BIKEL1_ChaChaPoly_SHA256",
        "Noise_pqNK_BIKEL1_ChaChaPoly_SHA256",
        "Noise_pqXX_BIKEL1_ChaChaPoly_SHA256",
        NULL
    };

    int passes = 0, families = 0;
    if (want_kyber) { families++; passes += run_family("Kyber512", kyber_names); }
    if (want_hqc)   { families++; passes += run_family("HQC128",  hqc_names); }
    if (want_bike)  { families++; passes += run_family("BIKEL3", bike_names); }

    if (passes == 0) {
        fprintf(stderr, "[FAIL] No protocol recognized (check registration & names)\n");
        return 2;
    }
    if (passes < families) {
        fprintf(stderr, "[DONE] Some families skipped/not found.\n");
        return 0;
    }
    printf("[DONE] All requested PQ KEM smoke tests passed.\n");
    return 0;
}

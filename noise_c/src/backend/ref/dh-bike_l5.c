// src/backend/ref/dh-hqc.c
#include "internal.h"
#include <oqs/oqs.h>
#include <string.h>
#include <stdlib.h>

/* Allow these semantic error codes to be defined in 
the current Noise-C version (for compatibility with older versions) */

#ifndef NOISE_ERROR_RANDOM_FAILURE
#define NOISE_ERROR_RANDOM_FAILURE NOISE_ERROR_INVALID_STATE
#endif
#ifndef NOISE_ERROR_NOT_SUPPORTED
#define NOISE_ERROR_NOT_SUPPORTED  NOISE_ERROR_INVALID_PARAM
#endif

typedef struct {
    struct NoiseDHState_s parent;
    OQS_KEM *kem;
    uint8_t *private_key;   /* 动态分配：kem->length_secret_key */
    uint8_t *public_key;    /* 动态分配：kem->length_public_key */
} NoiseBikeL5State;

/* — Generate key pair — */
static int noise_bikel5_keypair(NoiseDHState *state, const NoiseDHState *other)
{
    NoiseBikeL5State *st = (NoiseBikeL5State *)state;
    OQS_STATUS rc = st->kem->keypair(st->public_key, st->private_key);
    return (rc == OQS_SUCCESS) ? NOISE_ERROR_NONE : NOISE_ERROR_RANDOM_FAILURE;
}

/* — Only set the private key: Most KEMs do not support restoring pk from sk — */
static int noise_bikel5_set_keypair_private(NoiseDHState *state, const uint8_t *private_key)
{
    (void)state; (void)private_key;
    return NOISE_ERROR_NOT_SUPPORTED;
}

/* — Paired configuration of pk/sk — */
static int noise_bikel5_set_keypair(NoiseDHState *state, const uint8_t *private_key, const uint8_t *public_key)
{
    NoiseBikeL5State *st = (NoiseBikeL5State *)state;
    memcpy(st->private_key, private_key, st->parent.private_key_len);
    memcpy(st->public_key,  public_key,  st->parent.public_key_len);
    return NOISE_ERROR_NONE;
}

/* — Basic public key verification: at least reject all zeros — */

static int noise_bikel5_validate_public_key(const NoiseDHState *state, const uint8_t *public_key)
{
    size_t len = state->public_key_len;
    size_t i; unsigned char nz = 0;
    for (i = 0; i < len; ++i) nz |= public_key[i];
    return nz ? NOISE_ERROR_NONE : NOISE_ERROR_INVALID_PUBLIC_KEY;
}

/* DH.calculate should not be called (KEM) —— */

static int noise_bikel5_calculate(const NoiseDHState *private_key_state,
         const NoiseDHState *public_key_state, uint8_t *shared_key)
{
    (void)private_key_state; (void)public_key_state; (void)shared_key;
    return NOISE_ERROR_INVALID_STATE;
}

/* —— Encap/Decap —— */
static int noise_bikel5_encapsulate(const NoiseDHState *state, uint8_t *cipher, uint8_t *shared)
{
    NoiseBikeL5State *st = (NoiseBikeL5State *)state;
    OQS_STATUS rc = st->kem->encaps(cipher, shared, st->public_key);
    return (rc == OQS_SUCCESS) ? NOISE_ERROR_NONE : NOISE_ERROR_INVALID_STATE;
}

static int noise_bikel5_decapsulate(const NoiseDHState *state, const uint8_t *cipher, uint8_t *shared)
{
    NoiseBikeL5State *st = (NoiseBikeL5State *)state;
    OQS_STATUS rc = st->kem->decaps(shared, cipher, st->private_key);
    return (rc == OQS_SUCCESS) ? NOISE_ERROR_NONE : NOISE_ERROR_INVALID_STATE;
}

/* —— Constructor：BIKEL5 —— */
NoiseDHState *pqnoise_bike_l5_new(void)
{
    NoiseBikeL5State *state = noise_new(NoiseBikeL5State);
    if (!state) return 0;

    state->kem = OQS_KEM_new(OQS_KEM_alg_bike_l5);
    if (!state->kem) { noise_free(state, sizeof(*state)); return 0; }

    /* Allocate pk/sk buffers based on the OQS length field */
 
    state->parent.private_key_len = state->kem->length_secret_key;
    state->parent.public_key_len  = state->kem->length_public_key;
    state->parent.shared_key_len  = state->kem->length_shared_secret;
    state->parent.cipher_len      = state->kem->length_ciphertext;

    state->private_key = (uint8_t *)malloc(state->parent.private_key_len);
    state->public_key  = (uint8_t *)malloc(state->parent.public_key_len);
    if (!state->private_key || !state->public_key) {
        if (state->private_key) free(state->private_key);
        if (state->public_key)  free(state->public_key);
        OQS_KEM_free(state->kem);
        noise_free(state, sizeof(*state));
        return 0;
    }

    state->parent.dh_id = NOISE_DH_BIKEL5;
    state->parent.nulls_allowed = 0;

    state->parent.private_key = state->private_key;
    state->parent.public_key  = state->public_key;

    state->parent.generate_keypair     = noise_bikel5_keypair;
    state->parent.set_keypair          = noise_bikel5_set_keypair;
    state->parent.set_keypair_private  = noise_bikel5_set_keypair_private;
    state->parent.validate_public_key  = noise_bikel5_validate_public_key;
    state->parent.copy                 = NULL; 
    state->parent.calculate            = noise_bikel5_calculate;
    state->parent.encaps               = noise_bikel5_encapsulate;
    state->parent.decaps               = noise_bikel5_decapsulate;

    return &(state->parent);
}



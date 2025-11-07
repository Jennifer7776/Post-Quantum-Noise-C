#include "internal.h"
#include <string.h>

#include <oqs/oqs.h>
#include <time.h>


// Create OQS_KEM object initialized with Kyber.

typedef struct
{
    struct NoiseDHState_s parent;
    OQS_KEM* kem;
    uint8_t private_key[3168];
    uint8_t public_key[1568];   
} NoiseKyberState;

static int noise_kyber_generate_keypair
        (NoiseDHState *state, const NoiseDHState *other)
{
    NoiseKyberState *st = (NoiseKyberState *)state;
    st->kem->keypair(st->public_key, st->private_key);
    return NOISE_ERROR_NONE;
}

/*No function given to generate a kyber public key from the private key*/
static int noise_kyber_set_keypair_private
        (NoiseDHState *state, const uint8_t *private_key)
{
    return NOISE_ERROR_NONE;
}

static int noise_kyber_set_keypair
        (NoiseDHState *state, const uint8_t *private_key,
         const uint8_t *public_key)
{
    NoiseKyberState *st = (NoiseKyberState *)state;
    const size_t pk_len = st->parent.public_key_len;
    const size_t sk_len = st->parent.private_key_len;
    memcpy(st->public_key,  public_key,  pk_len);
    memcpy(st->private_key, private_key, sk_len);
    return NOISE_ERROR_NONE;
}

static int noise_kyber_validate_public_key
        (const NoiseDHState *state, const uint8_t *public_key)
{
    /*No function*/
    return NOISE_ERROR_NONE;
}

static int noise_kyber_copy
        (NoiseDHState *state, const NoiseDHState *from, const NoiseDHState *other)
{
    NoiseKyberState *st = (NoiseKyberState *)state;
    const NoiseKyberState *from_st = (const NoiseKyberState *)from;

    const size_t pk_len = st->parent.public_key_len;
    const size_t sk_len = st->parent.private_key_len;

    memcpy(st->private_key, from_st->private_key, sk_len);
    memcpy(st->public_key,  from_st->public_key,  pk_len);
    return NOISE_ERROR_NONE;
}

static int noise_kyber_calculate
        (const NoiseDHState *private_key_state,
         const NoiseDHState *public_key_state,
         uint8_t *shared_key)
{
    /*This function should not be called with kyber*/
    return NOISE_ERROR_INVALID_STATE;
}

static int noise_kyber_encapsulate
        (const NoiseDHState *state, uint8_t *cipher, uint8_t *shared)
{
    NoiseKyberState *st = (NoiseKyberState *)state;
    st->kem->encaps(cipher, shared, st->public_key);
    return NOISE_ERROR_NONE;
}

static int noise_kyber_decapsulate
        (const NoiseDHState *state, const uint8_t *cipher, uint8_t *shared)
{
    NoiseKyberState *st = (NoiseKyberState *)state;
    st->kem->decaps(shared, cipher, st->private_key);
    return NOISE_ERROR_NONE;
}

/*kyber 512*/
NoiseDHState *pqnoise_kyber512_new(void)
{
    NoiseKyberState *state = noise_new(NoiseKyberState);
    if (!state)
        return 0;

    state->kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    state->parent.dh_id = NOISE_DH_KYBER512;
    state->parent.nulls_allowed = 0;

    state->parent.private_key_len = state->kem->length_secret_key;   /* 1632 */
    state->parent.public_key_len  = state->kem->length_public_key;   /* 800  */
    state->parent.shared_key_len  = state->kem->length_shared_secret;/* 32   */
    state->parent.cipher_len      = state->kem->length_ciphertext;   /* 768  */

    state->parent.private_key = state->private_key;
    state->parent.public_key = state->public_key;
    state->parent.generate_keypair = noise_kyber_generate_keypair;
    state->parent.set_keypair = noise_kyber_set_keypair;
    state->parent.set_keypair_private = noise_kyber_set_keypair_private;
    state->parent.validate_public_key = noise_kyber_validate_public_key;
    state->parent.copy = noise_kyber_copy;
    state->parent.calculate = noise_kyber_calculate;
    state->parent.encaps = noise_kyber_encapsulate;
    state->parent.decaps = noise_kyber_decapsulate;
    return &(state->parent);
}


// Kyber-768
NoiseDHState *pqnoise_kyber768_new(void)
{
    NoiseKyberState *state = noise_new(NoiseKyberState);
    if (!state)
        return 0;
    state->kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    if (!state->kem) {
        noise_free(state, sizeof(*state));
        return 0;
    }
    state->parent.dh_id = NOISE_DH_KYBER768;      
    state->parent.nulls_allowed = 0;

    state->parent.private_key_len = state->kem->length_secret_key;   /* 2400 */
    state->parent.public_key_len  = state->kem->length_public_key;   /* 1184 */
    state->parent.shared_key_len  = state->kem->length_shared_secret;/* 32   */
    state->parent.cipher_len      = state->kem->length_ciphertext;   /* 1088 */

    state->parent.private_key = state->private_key;
    state->parent.public_key  = state->public_key;
    state->parent.generate_keypair     = noise_kyber_generate_keypair;
    state->parent.set_keypair          = noise_kyber_set_keypair;
    state->parent.set_keypair_private  = noise_kyber_set_keypair_private;
    state->parent.validate_public_key  = noise_kyber_validate_public_key;
    state->parent.copy                 = noise_kyber_copy;
    state->parent.calculate            = noise_kyber_calculate;
    state->parent.encaps               = noise_kyber_encapsulate;
    state->parent.decaps               = noise_kyber_decapsulate;
    return &(state->parent);
}

// Kyber-1024
NoiseDHState *pqnoise_kyber1024_new(void)
{
    NoiseKyberState *state = noise_new(NoiseKyberState);
    if (!state)
        return 0;
    state->kem = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
    if (!state->kem) {
        noise_free(state, sizeof(*state));
        return 0;
    }
    state->parent.dh_id = NOISE_DH_KYBER1024;   
    state->parent.nulls_allowed = 0;

    state->parent.private_key_len = state->kem->length_secret_key;   /* 3168 */
    state->parent.public_key_len  = state->kem->length_public_key;   /* 1568 */
    state->parent.shared_key_len  = state->kem->length_shared_secret;/* 32   */
    state->parent.cipher_len      = state->kem->length_ciphertext;   /* 1568 */

    state->parent.private_key = state->private_key;
    state->parent.public_key  = state->public_key;
    state->parent.generate_keypair     = noise_kyber_generate_keypair;
    state->parent.set_keypair          = noise_kyber_set_keypair;
    state->parent.set_keypair_private  = noise_kyber_set_keypair_private;
    state->parent.validate_public_key  = noise_kyber_validate_public_key;
    state->parent.copy                 = noise_kyber_copy;
    state->parent.calculate            = noise_kyber_calculate;
    state->parent.encaps               = noise_kyber_encapsulate;
    state->parent.decaps               = noise_kyber_decapsulate;
    return &(state->parent);
}

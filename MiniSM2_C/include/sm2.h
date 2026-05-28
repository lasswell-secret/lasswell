#ifndef MINI_SM2_SM2_H
#define MINI_SM2_SM2_H

#include <stddef.h>
#include <stdint.h>
#include "ecc.h"

#define SM2_OK 1
#define SM2_ERR 0
#define SM2_C1_SIZE 65
#define SM2_C3_SIZE 32

typedef struct {
    U256 d;
    ECPoint public_key;
} SM2KeyPair;

void sm2_init(void);
const ECCurve *sm2_get_curve(void);

int sm2_generate_keypair(SM2KeyPair *key);

int sm2_encrypt(const uint8_t *msg, size_t msg_len,
                const ECPoint *public_key,
                uint8_t *cipher, size_t *cipher_len);

int sm2_decrypt(const uint8_t *cipher, size_t cipher_len,
                const U256 *private_key,
                uint8_t *msg, size_t *msg_len);

int sm2_sign(const uint8_t *msg, size_t msg_len,
             const uint8_t *id, size_t id_len,
             const SM2KeyPair *key,
             U256 *r, U256 *s);

int sm2_verify(const uint8_t *msg, size_t msg_len,
               const uint8_t *id, size_t id_len,
               const ECPoint *public_key,
               const U256 *r, const U256 *s);

#endif

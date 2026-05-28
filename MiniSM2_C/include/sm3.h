#ifndef MINI_SM2_SM3_H
#define MINI_SM2_SM3_H

#include <stddef.h>
#include <stdint.h>

#define SM3_DIGEST_SIZE 32

void sm3_hash(const uint8_t *msg, size_t len, uint8_t digest[SM3_DIGEST_SIZE]);
void sm3_kdf(const uint8_t *z, size_t z_len, size_t out_len, uint8_t *out);

#endif

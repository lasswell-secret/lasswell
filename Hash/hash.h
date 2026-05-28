#ifndef HASH_H
#define HASH_H

#include <stddef.h>
#include <stdint.h>

#define HASH_BLOCK_SIZE 64
#define SM3_DIGEST_SIZE 32
#define SHA256_DIGEST_SIZE 32

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t buffer[HASH_BLOCK_SIZE];
    size_t buffer_len;
} SM3_ctx;

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t buffer[HASH_BLOCK_SIZE];
    size_t buffer_len;
} SHA256_ctx;

void SM3_init(SM3_ctx *ctx);
void SM3_update(SM3_ctx *ctx, const uint8_t *data, size_t len);
void SM3_final(SM3_ctx *ctx, uint8_t digest[SM3_DIGEST_SIZE]);
void SM3_hash(const uint8_t *data, size_t len, uint8_t digest[SM3_DIGEST_SIZE]);

void SHA256_init(SHA256_ctx *ctx);
void SHA256_update(SHA256_ctx *ctx, const uint8_t *data, size_t len);
void SHA256_final(SHA256_ctx *ctx, uint8_t digest[SHA256_DIGEST_SIZE]);
void SHA256_hash(const uint8_t *data, size_t len, uint8_t digest[SHA256_DIGEST_SIZE]);

#endif

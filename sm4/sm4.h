#ifndef SM4_H
#define SM4_H

#include <stdint.h>
#include <stddef.h>

#define SM4_BLOCK_SIZE 16
#define SM4_KEY_SIZE   16
#define SM4_ROUNDS     32

typedef struct {
    uint32_t rk[SM4_ROUNDS];
} SM4_ctx;

void SM4_init(SM4_ctx *ctx, const uint8_t key[SM4_KEY_SIZE]);

void SM4_encrypt_block(const SM4_ctx *ctx,
                       const uint8_t input[SM4_BLOCK_SIZE],
                       uint8_t output[SM4_BLOCK_SIZE]);

void SM4_decrypt_block(const SM4_ctx *ctx,
                       const uint8_t input[SM4_BLOCK_SIZE],
                       uint8_t output[SM4_BLOCK_SIZE]);

void SM4_encrypt_ecb(const SM4_ctx *ctx,
                     const uint8_t *input,
                     uint8_t *output,
                     size_t length);

void SM4_decrypt_ecb(const SM4_ctx *ctx,
                     const uint8_t *input,
                     uint8_t *output,
                     size_t length);

#endif

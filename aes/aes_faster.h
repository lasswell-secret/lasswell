#ifndef AES_FASTER_H
#define AES_FASTER_H

#include <stdint.h>
#include <stddef.h>

#define AES_BLOCK_SIZE 16
#define AES_128_KEY_SIZE 16
#define AES_128_ROUND_KEY_SIZE 176

typedef struct {
    uint8_t roundKey[AES_128_ROUND_KEY_SIZE];
} AES_ctx;

void AES_init(AES_ctx *ctx, const uint8_t *key);
void AES_encrypt_block(const AES_ctx *ctx, const uint8_t *input, uint8_t *output);
void AES_decrypt_block(const AES_ctx *ctx, const uint8_t *input, uint8_t *output);
int AES_encrypt_ecb(const AES_ctx *ctx, const uint8_t *input, uint8_t *output, size_t length);
int AES_decrypt_ecb(const AES_ctx *ctx, const uint8_t *input, uint8_t *output, size_t length);

#endif

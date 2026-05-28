#include "sm4.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/*
 * SM4-128 software implementation
 * - 128-bit key
 * - 128-bit block
 * - 32 rounds
 * - ECB buffer functions for speed testing
 *
 * Compile:
 *   gcc -std=c99 -Wall -Wextra -O3 sm4.c -o sm4
 */

static const uint8_t sm4_sbox[256] = {
    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
    0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
    0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
    0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
    0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
    0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
    0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
    0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
    0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
    0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
    0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
    0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
    0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
    0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
    0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
    0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
};

static const uint32_t sm4_fk[4] = {
    0xa3b1bac6u, 0x56aa3350u, 0x677d9197u, 0xb27022dcu
};

static const uint32_t sm4_ck[32] = {
    0x00070e15u,0x1c232a31u,0x383f464du,0x545b6269u,
    0x70777e85u,0x8c939aa1u,0xa8afb6bdu,0xc4cbd2d9u,
    0xe0e7eef5u,0xfc030a11u,0x181f262du,0x343b4249u,
    0x50575e65u,0x6c737a81u,0x888f969du,0xa4abb2b9u,
    0xc0c7ced5u,0xdce3eaf1u,0xf8ff060du,0x141b2229u,
    0x30373e45u,0x4c535a61u,0x686f767du,0x848b9299u,
    0xa0a7aeb5u,0xbcc3cad1u,0xd8dfe6edu,0xf4fb0209u,
    0x10171e25u,0x2c333a41u,0x484f565du,0x646b7279u
};

static inline uint32_t rotl32(uint32_t x, unsigned int n) {
    return (x << n) | (x >> (32u - n));
}

static inline uint32_t load_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) |
           ((uint32_t)p[3]);
}

static inline void store_be32(uint8_t *p, uint32_t x) {
    p[0] = (uint8_t)(x >> 24);
    p[1] = (uint8_t)(x >> 16);
    p[2] = (uint8_t)(x >>  8);
    p[3] = (uint8_t)(x);
}

static inline uint32_t sm4_tau(uint32_t x) {
    return ((uint32_t)sm4_sbox[(x >> 24) & 0xff] << 24) |
           ((uint32_t)sm4_sbox[(x >> 16) & 0xff] << 16) |
           ((uint32_t)sm4_sbox[(x >>  8) & 0xff] <<  8) |
           ((uint32_t)sm4_sbox[(x      ) & 0xff]);
}

/* Round transform: T(x) = L(tau(x)) */
static inline uint32_t sm4_t(uint32_t x) {
    x = sm4_tau(x);
    return x ^ rotl32(x, 2) ^ rotl32(x, 10) ^ rotl32(x, 18) ^ rotl32(x, 24);
}

/* Key schedule transform: T'(x) = L'(tau(x)) */
static inline uint32_t sm4_t_key(uint32_t x) {
    x = sm4_tau(x);
    return x ^ rotl32(x, 13) ^ rotl32(x, 23);
}

void SM4_init(SM4_ctx *ctx, const uint8_t key[SM4_KEY_SIZE]) {
    uint32_t k[36];

    k[0] = load_be32(key +  0) ^ sm4_fk[0];
    k[1] = load_be32(key +  4) ^ sm4_fk[1];
    k[2] = load_be32(key +  8) ^ sm4_fk[2];
    k[3] = load_be32(key + 12) ^ sm4_fk[3];

    for (int i = 0; i < SM4_ROUNDS; i++) {
        k[i + 4] = k[i] ^ sm4_t_key(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ sm4_ck[i]);
        ctx->rk[i] = k[i + 4];
    }
}

static inline void sm4_crypt_block_with_rk(const uint32_t rk[SM4_ROUNDS],
                                           const uint8_t input[SM4_BLOCK_SIZE],
                                           uint8_t output[SM4_BLOCK_SIZE]) {
    uint32_t x0 = load_be32(input +  0);
    uint32_t x1 = load_be32(input +  4);
    uint32_t x2 = load_be32(input +  8);
    uint32_t x3 = load_be32(input + 12);
    uint32_t tmp;

    for (int i = 0; i < SM4_ROUNDS; i++) {
        tmp = x0 ^ sm4_t(x1 ^ x2 ^ x3 ^ rk[i]);
        x0 = x1;
        x1 = x2;
        x2 = x3;
        x3 = tmp;
    }

    store_be32(output +  0, x3);
    store_be32(output +  4, x2);
    store_be32(output +  8, x1);
    store_be32(output + 12, x0);
}

void SM4_encrypt_block(const SM4_ctx *ctx,
                       const uint8_t input[SM4_BLOCK_SIZE],
                       uint8_t output[SM4_BLOCK_SIZE]) {
    sm4_crypt_block_with_rk(ctx->rk, input, output);
}

void SM4_decrypt_block(const SM4_ctx *ctx,
                       const uint8_t input[SM4_BLOCK_SIZE],
                       uint8_t output[SM4_BLOCK_SIZE]) {
    uint32_t drk[SM4_ROUNDS];

    for (int i = 0; i < SM4_ROUNDS; i++) {
        drk[i] = ctx->rk[SM4_ROUNDS - 1 - i];
    }

    sm4_crypt_block_with_rk(drk, input, output);
}

void SM4_encrypt_ecb(const SM4_ctx *ctx,
                     const uint8_t *input,
                     uint8_t *output,
                     size_t length) {
    if (length % SM4_BLOCK_SIZE != 0) {
        return;
    }

    for (size_t i = 0; i < length; i += SM4_BLOCK_SIZE) {
        SM4_encrypt_block(ctx, input + i, output + i);
    }
}

void SM4_decrypt_ecb(const SM4_ctx *ctx,
                     const uint8_t *input,
                     uint8_t *output,
                     size_t length) {
    if (length % SM4_BLOCK_SIZE != 0) {
        return;
    }

    uint32_t drk[SM4_ROUNDS];

    for (int i = 0; i < SM4_ROUNDS; i++) {
        drk[i] = ctx->rk[SM4_ROUNDS - 1 - i];
    }

    for (size_t i = 0; i < length; i += SM4_BLOCK_SIZE) {
        sm4_crypt_block_with_rk(drk, input + i, output + i);
    }
}

static void print_block(const char *name, const uint8_t block[SM4_BLOCK_SIZE]) {
    printf("%s", name);
    for (int i = 0; i < SM4_BLOCK_SIZE; i++) {
        printf("%02x", block[i]);
    }
    printf("\n");
}

static uint32_t checksum32(const uint8_t *buf, size_t len) {
    uint32_t s = 0x12345678u;

    for (size_t i = 0; i < len; i++) {
        s = (s << 5) | (s >> 27);
        s ^= buf[i];
        s += 0x9e3779b9u;
    }

    return s;
}

static double now_seconds(void) {
    return (double)clock() / CLOCKS_PER_SEC;
}

static double benchmark_encrypt(const SM4_ctx *ctx,
                                uint8_t *buf_a,
                                uint8_t *buf_b,
                                size_t bytes,
                                int rounds,
                                uint32_t *out_sum) {
    double start = now_seconds();

    for (int r = 0; r < rounds; r++) {
        SM4_encrypt_ecb(ctx, buf_a, buf_b, bytes);

        uint8_t *tmp = buf_a;
        buf_a = buf_b;
        buf_b = tmp;

        /*
         * Change one byte each round so the compiler cannot safely treat
         * every round as identical repeated work.
         */
        buf_a[(size_t)r % bytes] ^= (uint8_t)(r + 1);
    }

    double end = now_seconds();
    *out_sum = checksum32(buf_a, bytes);
    return end - start;
}

static double benchmark_decrypt(const SM4_ctx *ctx,
                                uint8_t *buf_a,
                                uint8_t *buf_b,
                                size_t bytes,
                                int rounds,
                                uint32_t *out_sum) {
    double start = now_seconds();

    for (int r = 0; r < rounds; r++) {
        SM4_decrypt_ecb(ctx, buf_a, buf_b, bytes);

        uint8_t *tmp = buf_a;
        buf_a = buf_b;
        buf_b = tmp;

        buf_a[(size_t)r % bytes] ^= (uint8_t)(r + 1);
    }

    double end = now_seconds();
    *out_sum = checksum32(buf_a, bytes);
    return end - start;
}

int main(void) {
    SM4_ctx ctx;

    uint8_t key[SM4_KEY_SIZE] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
    };

    uint8_t plaintext[SM4_BLOCK_SIZE] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
    };

    uint8_t expected_cipher[SM4_BLOCK_SIZE] = {
        0x68,0x1e,0xdf,0x34,0xd2,0x06,0x96,0x5e,
        0x86,0xb3,0xe9,0x4f,0x53,0x6e,0x42,0x46
    };

    uint8_t ciphertext[SM4_BLOCK_SIZE];
    uint8_t decrypted[SM4_BLOCK_SIZE];

    SM4_init(&ctx, key);
    SM4_encrypt_block(&ctx, plaintext, ciphertext);
    SM4_decrypt_block(&ctx, ciphertext, decrypted);

    printf("=========== SM4 SOFTWARE TEST ===========\n");
    print_block("Plaintext : ", plaintext);
    print_block("Ciphertext: ", ciphertext);
    print_block("Decrypted : ", decrypted);
    printf("Correct   : %s\n", memcmp(plaintext, decrypted, SM4_BLOCK_SIZE) == 0 ? "PASS" : "FAIL");
    printf("Known test: %s\n", memcmp(ciphertext, expected_cipher, SM4_BLOCK_SIZE) == 0 ? "PASS" : "FAIL");

    /*
     * Speed test.
     * You can increase TEST_MB or ROUNDS to make timing more stable.
     */
    const size_t TEST_MB = 16;
    const int ROUNDS = 8;
    const size_t bytes = TEST_MB * 1024u * 1024u;

    uint8_t *buf_a = (uint8_t *)malloc(bytes);
    uint8_t *buf_b = (uint8_t *)malloc(bytes);

    if (buf_a == NULL || buf_b == NULL) {
        fprintf(stderr, "Memory allocation failed.\n");
        free(buf_a);
        free(buf_b);
        return 1;
    }

    for (size_t i = 0; i < bytes; i++) {
        buf_a[i] = (uint8_t)(i * 31u + 7u);
        buf_b[i] = 0;
    }

    uint32_t enc_sum = 0;
    uint32_t dec_sum = 0;

    double enc_time = benchmark_encrypt(&ctx, buf_a, buf_b, bytes, ROUNDS, &enc_sum);

    for (size_t i = 0; i < bytes; i++) {
        buf_a[i] = (uint8_t)(i * 31u + 7u);
        buf_b[i] = 0;
    }

    double dec_time = benchmark_decrypt(&ctx, buf_a, buf_b, bytes, ROUNDS, &dec_sum);

    double total_gbit = ((double)bytes * (double)ROUNDS * 8.0) / 1000000000.0;
    double enc_gbps = total_gbit / enc_time;
    double dec_gbps = total_gbit / dec_time;

    printf("\n=========== SPEED TEST ==================\n");
    printf("Buffer size : %zu MB\n", TEST_MB);
    printf("Rounds      : %d\n", ROUNDS);
    printf("Total data  : %.2f MB\n", ((double)bytes * ROUNDS) / (1024.0 * 1024.0));

    printf("\nEncryption:\n");
    printf("Time        : %.6f s\n", enc_time);
    printf("Throughput  : %.4f Gbps\n", enc_gbps);
    printf("Checksum    : %08x\n", enc_sum);

    printf("\nDecryption:\n");
    printf("Time        : %.6f s\n", dec_time);
    printf("Throughput  : %.4f Gbps\n", dec_gbps);
    printf("Checksum    : %08x\n", dec_sum);
    printf("=========================================\n");

    free(buf_a);
    free(buf_b);

    return 0;
}

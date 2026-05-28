#include "aes_faster.h"
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define AES_NB 4
#define AES_NK 4
#define AES_NR 10
#define TEST_MB 16
#define TEST_ROUNDS 6

static const uint8_t sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t inv_sbox[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

static const uint8_t rcon[11] = {
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
};

static uint8_t mul2[256], mul3[256], mul9[256], mul11[256], mul13[256], mul14[256];
static int table_ready = 0;

static inline uint8_t xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00));
}

static uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t r = 0;
    while (b) {
        if (b & 1) r ^= a;
        a = xtime(a);
        b >>= 1;
    }
    return r;
}

static void init_tables(void) {
    if (table_ready) return;
    for (int i = 0; i < 256; i++) {
        mul2[i]  = gf_mul((uint8_t)i, 2);
        mul3[i]  = gf_mul((uint8_t)i, 3);
        mul9[i]  = gf_mul((uint8_t)i, 9);
        mul11[i] = gf_mul((uint8_t)i, 11);
        mul13[i] = gf_mul((uint8_t)i, 13);
        mul14[i] = gf_mul((uint8_t)i, 14);
    }
    table_ready = 1;
}

static inline void add_round_key(uint8_t s[16], const uint8_t *rk) {
    s[0]^=rk[0];   s[1]^=rk[1];   s[2]^=rk[2];   s[3]^=rk[3];
    s[4]^=rk[4];   s[5]^=rk[5];   s[6]^=rk[6];   s[7]^=rk[7];
    s[8]^=rk[8];   s[9]^=rk[9];   s[10]^=rk[10]; s[11]^=rk[11];
    s[12]^=rk[12]; s[13]^=rk[13]; s[14]^=rk[14]; s[15]^=rk[15];
}

static inline void sub_bytes(uint8_t s[16]) {
    for (int i = 0; i < 16; i++) s[i] = sbox[s[i]];
}

static inline void inv_sub_bytes(uint8_t s[16]) {
    for (int i = 0; i < 16; i++) s[i] = inv_sbox[s[i]];
}

static inline void shift_rows(uint8_t s[16]) {
    uint8_t t;
    t=s[1];  s[1]=s[5];  s[5]=s[9];  s[9]=s[13]; s[13]=t;
    t=s[2];  s[2]=s[10]; s[10]=t;    t=s[6];    s[6]=s[14]; s[14]=t;
    t=s[15]; s[15]=s[11]; s[11]=s[7]; s[7]=s[3];  s[3]=t;
}

static inline void inv_shift_rows(uint8_t s[16]) {
    uint8_t t;
    t=s[13]; s[13]=s[9];  s[9]=s[5];  s[5]=s[1];  s[1]=t;
    t=s[2];  s[2]=s[10]; s[10]=t;    t=s[6];    s[6]=s[14]; s[14]=t;
    t=s[3];  s[3]=s[7];   s[7]=s[11]; s[11]=s[15]; s[15]=t;
}

static inline void mix_columns(uint8_t s[16]) {
    for (int c = 0; c < 16; c += 4) {
        uint8_t a0=s[c+0], a1=s[c+1], a2=s[c+2], a3=s[c+3];
        s[c+0] = (uint8_t)(mul2[a0] ^ mul3[a1] ^ a2 ^ a3);
        s[c+1] = (uint8_t)(a0 ^ mul2[a1] ^ mul3[a2] ^ a3);
        s[c+2] = (uint8_t)(a0 ^ a1 ^ mul2[a2] ^ mul3[a3]);
        s[c+3] = (uint8_t)(mul3[a0] ^ a1 ^ a2 ^ mul2[a3]);
    }
}

static inline void inv_mix_columns(uint8_t s[16]) {
    for (int c = 0; c < 16; c += 4) {
        uint8_t a0=s[c+0], a1=s[c+1], a2=s[c+2], a3=s[c+3];
        s[c+0] = (uint8_t)(mul14[a0] ^ mul11[a1] ^ mul13[a2] ^ mul9[a3]);
        s[c+1] = (uint8_t)(mul9[a0]  ^ mul14[a1] ^ mul11[a2] ^ mul13[a3]);
        s[c+2] = (uint8_t)(mul13[a0] ^ mul9[a1]  ^ mul14[a2] ^ mul11[a3]);
        s[c+3] = (uint8_t)(mul11[a0] ^ mul13[a1] ^ mul9[a2]  ^ mul14[a3]);
    }
}

void AES_init(AES_ctx *ctx, const uint8_t *key) {
    uint8_t temp[4];
    int i = 0;
    init_tables();

    while (i < AES_NK) {
        ctx->roundKey[i * 4 + 0] = key[i * 4 + 0];
        ctx->roundKey[i * 4 + 1] = key[i * 4 + 1];
        ctx->roundKey[i * 4 + 2] = key[i * 4 + 2];
        ctx->roundKey[i * 4 + 3] = key[i * 4 + 3];
        i++;
    }

    while (i < AES_NB * (AES_NR + 1)) {
        temp[0] = ctx->roundKey[(i - 1) * 4 + 0];
        temp[1] = ctx->roundKey[(i - 1) * 4 + 1];
        temp[2] = ctx->roundKey[(i - 1) * 4 + 2];
        temp[3] = ctx->roundKey[(i - 1) * 4 + 3];

        if (i % AES_NK == 0) {
            uint8_t k = temp[0];
            temp[0] = sbox[temp[1]];
            temp[1] = sbox[temp[2]];
            temp[2] = sbox[temp[3]];
            temp[3] = sbox[k];
            temp[0] ^= rcon[i / AES_NK];
        }

        ctx->roundKey[i * 4 + 0] = ctx->roundKey[(i - AES_NK) * 4 + 0] ^ temp[0];
        ctx->roundKey[i * 4 + 1] = ctx->roundKey[(i - AES_NK) * 4 + 1] ^ temp[1];
        ctx->roundKey[i * 4 + 2] = ctx->roundKey[(i - AES_NK) * 4 + 2] ^ temp[2];
        ctx->roundKey[i * 4 + 3] = ctx->roundKey[(i - AES_NK) * 4 + 3] ^ temp[3];
        i++;
    }
}

void AES_encrypt_block(const AES_ctx *ctx, const uint8_t *input, uint8_t *output) {
    uint8_t s[16];
    memcpy(s, input, 16);
    add_round_key(s, ctx->roundKey);
    for (int round = 1; round < AES_NR; round++) {
        sub_bytes(s);
        shift_rows(s);
        mix_columns(s);
        add_round_key(s, ctx->roundKey + round * 16);
    }
    sub_bytes(s);
    shift_rows(s);
    add_round_key(s, ctx->roundKey + AES_NR * 16);
    memcpy(output, s, 16);
}

void AES_decrypt_block(const AES_ctx *ctx, const uint8_t *input, uint8_t *output) {
    uint8_t s[16];
    memcpy(s, input, 16);
    add_round_key(s, ctx->roundKey + AES_NR * 16);
    for (int round = AES_NR - 1; round >= 1; round--) {
        inv_shift_rows(s);
        inv_sub_bytes(s);
        add_round_key(s, ctx->roundKey + round * 16);
        inv_mix_columns(s);
    }
    inv_shift_rows(s);
    inv_sub_bytes(s);
    add_round_key(s, ctx->roundKey);
    memcpy(output, s, 16);
}

int AES_encrypt_ecb(const AES_ctx *ctx, const uint8_t *input, uint8_t *output, size_t length) {
    if (length % AES_BLOCK_SIZE != 0) return 0;
    for (size_t i = 0; i < length; i += AES_BLOCK_SIZE) {
        AES_encrypt_block(ctx, input + i, output + i);
    }
    return 1;
}

int AES_decrypt_ecb(const AES_ctx *ctx, const uint8_t *input, uint8_t *output, size_t length) {
    if (length % AES_BLOCK_SIZE != 0) return 0;
    for (size_t i = 0; i < length; i += AES_BLOCK_SIZE) {
        AES_decrypt_block(ctx, input + i, output + i);
    }
    return 1;
}

static double now_seconds(void) { return (double)clock() / (double)CLOCKS_PER_SEC; }

static void print_block(const char *name, const uint8_t block[16]) {
    printf("%s", name);
    for (int i = 0; i < 16; i++) printf("%02x", block[i]);
    printf("\n");
}

static uint32_t checksum(const uint8_t *data, size_t len) {
    uint32_t s = 0;
    for (size_t i = 0; i < len; i++) {
        s = (s << 5) | (s >> 27);
        s ^= data[i];
    }
    return s;
}

int main(void) {
    AES_ctx ctx;
    uint8_t key[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    uint8_t plaintext[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    uint8_t ciphertext[16] = {0};
    uint8_t decrypted[16] = {0};
    const uint8_t expected[16] = {0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a};

    AES_init(&ctx, key);
    AES_encrypt_block(&ctx, plaintext, ciphertext);
    AES_decrypt_block(&ctx, ciphertext, decrypted);

    printf("=========== AES-128 SOFTWARE FASTER TEST ===========\n");
    print_block("Plaintext : ", plaintext);
    print_block("Ciphertext: ", ciphertext);
    print_block("Decrypted : ", decrypted);
    printf("Correct   : %s\n", memcmp(plaintext, decrypted, 16) == 0 ? "PASS" : "FAIL");
    printf("Known test: %s\n", memcmp(ciphertext, expected, 16) == 0 ? "PASS" : "FAIL");
    if (memcmp(plaintext, decrypted, 16) != 0 || memcmp(ciphertext, expected, 16) != 0) return 1;

    size_t data_size = (size_t)TEST_MB * 1024u * 1024u;
    uint8_t *plain = (uint8_t *)malloc(data_size);
    uint8_t *enc = (uint8_t *)malloc(data_size);
    uint8_t *dec = (uint8_t *)malloc(data_size);
    if (!plain || !enc || !dec) {
        printf("Memory allocation failed.\n");
        free(plain); free(enc); free(dec);
        return 1;
    }

    for (size_t i = 0; i < data_size; i++) plain[i] = (uint8_t)(i * 13u + 7u);

    volatile uint32_t guard = 0;
    double start = now_seconds();
    for (int r = 0; r < TEST_ROUNDS; r++) {
        AES_encrypt_ecb(&ctx, plain, enc, data_size);
        guard ^= enc[((size_t)r * 997u) & (data_size - 1)];
        plain[(size_t)r & (data_size - 1)] ^= (uint8_t)(guard + (uint32_t)r);
    }
    double enc_time = now_seconds() - start;
    uint32_t enc_sum = checksum(enc, data_size) ^ guard;

    start = now_seconds();
    for (int r = 0; r < TEST_ROUNDS; r++) {
        AES_decrypt_ecb(&ctx, enc, dec, data_size);
        guard ^= dec[((size_t)r * 991u) & (data_size - 1)];
        enc[(size_t)r & (data_size - 1)] ^= (uint8_t)(guard + (uint32_t)r);
    }
    double dec_time = now_seconds() - start;
    uint32_t dec_sum = checksum(dec, data_size) ^ guard;

    for (size_t i = 0; i < data_size; i++) plain[i] = (uint8_t)(i * 13u + 7u);
    AES_encrypt_ecb(&ctx, plain, enc, data_size);
    AES_decrypt_ecb(&ctx, enc, dec, data_size);
    int final_ok = (memcmp(plain, dec, data_size) == 0);

    double total_mb = (double)TEST_MB * (double)TEST_ROUNDS;
    double total_bits = total_mb * 1024.0 * 1024.0 * 8.0;

    printf("\n=========== SPEED TEST ===========\n");
    printf("Buffer size : %d MB\n", TEST_MB);
    printf("Rounds      : %d\n", TEST_ROUNDS);
    printf("Total data  : %.2f MB\n", total_mb);
    printf("Checksum E  : %08x\n", enc_sum);
    printf("Checksum D  : %08x\n", dec_sum);
    printf("Final check : %s\n", final_ok ? "PASS" : "FAIL");
    printf("\nEncryption:\n");
    printf("Time        : %.6f s\n", enc_time);
    printf("Throughput  : %.2f Mbps\n", total_bits / enc_time / 1000000.0);
    printf("\nDecryption:\n");
    printf("Time        : %.6f s\n", dec_time);
    printf("Throughput  : %.2f Mbps\n", total_bits / dec_time / 1000000.0);
    printf("==================================\n");

    free(plain); free(enc); free(dec);
    return final_ok ? 0 : 1;
}

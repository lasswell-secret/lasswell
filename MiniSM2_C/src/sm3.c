#include "sm3.h"
#include <stdlib.h>
#include <string.h>

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define P0(x) ((x) ^ ROTL32((x), 9) ^ ROTL32((x), 17))
#define P1(x) ((x) ^ ROTL32((x), 15) ^ ROTL32((x), 23))

static uint32_t load_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           (uint32_t)p[3];
}

static void store_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint32_t ff(uint32_t x, uint32_t y, uint32_t z, int j)
{
    return j <= 15 ? (x ^ y ^ z) : ((x & y) | (x & z) | (y & z));
}

static uint32_t gg(uint32_t x, uint32_t y, uint32_t z, int j)
{
    return j <= 15 ? (x ^ y ^ z) : ((x & y) | ((~x) & z));
}

static void sm3_compress(uint32_t v[8], const uint8_t block[64])
{
    uint32_t w[68];
    uint32_t w1[64];
    uint32_t a, b, c, d, e, f, g, h;
    int j;

    for (j = 0; j < 16; ++j) {
        w[j] = load_be32(block + j * 4);
    }
    for (j = 16; j < 68; ++j) {
        w[j] = P1(w[j - 16] ^ w[j - 9] ^ ROTL32(w[j - 3], 15)) ^
               ROTL32(w[j - 13], 7) ^ w[j - 6];
    }
    for (j = 0; j < 64; ++j) {
        w1[j] = w[j] ^ w[j + 4];
    }

    a = v[0]; b = v[1]; c = v[2]; d = v[3];
    e = v[4]; f = v[5]; g = v[6]; h = v[7];

    for (j = 0; j < 64; ++j) {
        uint32_t tj = (j <= 15) ? 0x79cc4519u : 0x7a879d8au;
        uint32_t ss1 = ROTL32((ROTL32(a, 12) + e + ROTL32(tj, j % 32)), 7);
        uint32_t ss2 = ss1 ^ ROTL32(a, 12);
        uint32_t tt1 = ff(a, b, c, j) + d + ss2 + w1[j];
        uint32_t tt2 = gg(e, f, g, j) + h + ss1 + w[j];

        d = c;
        c = ROTL32(b, 9);
        b = a;
        a = tt1;
        h = g;
        g = ROTL32(f, 19);
        f = e;
        e = P0(tt2);
    }

    v[0] ^= a; v[1] ^= b; v[2] ^= c; v[3] ^= d;
    v[4] ^= e; v[5] ^= f; v[6] ^= g; v[7] ^= h;
}

void sm3_hash(const uint8_t *msg, size_t len, uint8_t digest[SM3_DIGEST_SIZE])
{
    static const uint32_t iv[8] = {
        0x7380166fu, 0x4914b2b9u, 0x172442d7u, 0xda8a0600u,
        0xa96f30bcu, 0x163138aau, 0xe38dee4du, 0xb0fb0e4eu
    };
    uint32_t v[8];
    uint64_t bit_len = (uint64_t)len * 8u;
    size_t padded_len = ((len + 1 + 8 + 63) / 64) * 64;
    uint8_t *buf;
    size_t i;

    memcpy(v, iv, sizeof(v));
    buf = (uint8_t *)calloc(1, padded_len);
    if (!buf) {
        memset(digest, 0, SM3_DIGEST_SIZE);
        return;
    }

    if (len > 0 && msg) {
        memcpy(buf, msg, len);
    }
    buf[len] = 0x80u;
    for (i = 0; i < 8; ++i) {
        buf[padded_len - 1 - i] = (uint8_t)(bit_len >> (i * 8));
    }

    for (i = 0; i < padded_len; i += 64) {
        sm3_compress(v, buf + i);
    }

    for (i = 0; i < 8; ++i) {
        store_be32(digest + i * 4, v[i]);
    }

    free(buf);
}

void sm3_kdf(const uint8_t *z, size_t z_len, size_t out_len, uint8_t *out)
{
    uint32_t ct = 1;
    size_t done = 0;
    uint8_t *buf;
    uint8_t digest[SM3_DIGEST_SIZE];

    buf = (uint8_t *)malloc(z_len + 4);
    if (!buf) {
        memset(out, 0, out_len);
        return;
    }
    if (z_len > 0) {
        memcpy(buf, z, z_len);
    }

    while (done < out_len) {
        size_t take;
        buf[z_len] = (uint8_t)(ct >> 24);
        buf[z_len + 1] = (uint8_t)(ct >> 16);
        buf[z_len + 2] = (uint8_t)(ct >> 8);
        buf[z_len + 3] = (uint8_t)ct;

        sm3_hash(buf, z_len + 4, digest);
        take = out_len - done;
        if (take > SM3_DIGEST_SIZE) take = SM3_DIGEST_SIZE;
        memcpy(out + done, digest, take);
        done += take;
        ++ct;
    }

    free(buf);
}

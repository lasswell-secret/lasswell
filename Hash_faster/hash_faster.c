#include "hash_faster.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define TEST_TOTAL_GB 1u
#define TEST_TOTAL_BYTES ((uint64_t)TEST_TOTAL_GB * 1024ull * 1024ull * 1024ull)

static inline uint32_t rotl32(uint32_t x, unsigned int n) {
    n &= 31u;
    if (n == 0) {
        return x;
    }
    return (x << n) | (x >> (32u - n));
}

static inline uint32_t rotr32(uint32_t x, unsigned int n) {
    n &= 31u;
    if (n == 0) {
        return x;
    }
    return (x >> n) | (x << (32u - n));
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

static inline void store_be64(uint8_t *p, uint64_t x) {
    p[0] = (uint8_t)(x >> 56);
    p[1] = (uint8_t)(x >> 48);
    p[2] = (uint8_t)(x >> 40);
    p[3] = (uint8_t)(x >> 32);
    p[4] = (uint8_t)(x >> 24);
    p[5] = (uint8_t)(x >> 16);
    p[6] = (uint8_t)(x >>  8);
    p[7] = (uint8_t)(x);
}

static void print_digest(const char *name, const uint8_t *digest, size_t len) {
    printf("%s", name);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", digest[i]);
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

/* ============================== SM3 ============================== */

static const uint32_t sm3_iv[8] = {
    0x7380166fu, 0x4914b2b9u, 0x172442d7u, 0xda8a0600u,
    0xa96f30bcu, 0x163138aau, 0xe38dee4du, 0xb0fb0e4eu
};

static const uint32_t sm3_tj_rot[64] = {
    0x79cc4519u,0xf3988a32u,0xe7311465u,0xce6228cbu,
    0x9cc45197u,0x3988a32fu,0x7311465eu,0xe6228cbcu,
    0xcc451979u,0x988a32f3u,0x311465e7u,0x6228cbceu,
    0xc451979cu,0x88a32f39u,0x11465e73u,0x228cbce6u,
    0x9d8a7a87u,0x3b14f50fu,0x7629ea1eu,0xec53d43cu,
    0xd8a7a879u,0xb14f50f3u,0x629ea1e7u,0xc53d43ceu,
    0x8a7a879du,0x14f50f3bu,0x29ea1e76u,0x53d43cecu,
    0xa7a879d8u,0x4f50f3b1u,0x9ea1e762u,0x3d43cec5u,
    0x7a879d8au,0xf50f3b14u,0xea1e7629u,0xd43cec53u,
    0xa879d8a7u,0x50f3b14fu,0xa1e7629eu,0x43cec53du,
    0x879d8a7au,0x0f3b14f5u,0x1e7629eau,0x3cec53d4u,
    0x79d8a7a8u,0xf3b14f50u,0xe7629ea1u,0xcec53d43u,
    0x9d8a7a87u,0x3b14f50fu,0x7629ea1eu,0xec53d43cu,
    0xd8a7a879u,0xb14f50f3u,0x629ea1e7u,0xc53d43ceu,
    0x8a7a879du,0x14f50f3bu,0x29ea1e76u,0x53d43cecu,
    0xa7a879d8u,0x4f50f3b1u,0x9ea1e762u,0x3d43cec5u
};

static inline uint32_t sm3_p0(uint32_t x) {
    return x ^ rotl32(x, 9) ^ rotl32(x, 17);
}

static inline uint32_t sm3_p1(uint32_t x) {
    return x ^ rotl32(x, 15) ^ rotl32(x, 23);
}

static void sm3_transform(SM3_ctx *ctx, const uint8_t block[HASH_BLOCK_SIZE]) {
    uint32_t w[68];
    uint32_t w1[64];
    uint32_t a, b, c, d, e, f, g, h;

    for (int j = 0; j < 16; j++) {
        w[j] = load_be32(block + (size_t)j * 4u);
    }

    for (int j = 16; j < 68; j++) {
        w[j] = sm3_p1(w[j - 16] ^ w[j - 9] ^ rotl32(w[j - 3], 15)) ^
               rotl32(w[j - 13], 7) ^ w[j - 6];
    }

    for (int j = 0; j < 64; j++) {
        w1[j] = w[j] ^ w[j + 4];
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (int j = 0; j < 16; j++) {
        uint32_t ss1 = rotl32(rotl32(a, 12) + e + sm3_tj_rot[j], 7);
        uint32_t ss2 = ss1 ^ rotl32(a, 12);
        uint32_t tt1 = (a ^ b ^ c) + d + ss2 + w1[j];
        uint32_t tt2 = (e ^ f ^ g) + h + ss1 + w[j];

        d = c;
        c = rotl32(b, 9);
        b = a;
        a = tt1;
        h = g;
        g = rotl32(f, 19);
        f = e;
        e = sm3_p0(tt2);
    }

    for (int j = 16; j < 64; j++) {
        uint32_t ss1 = rotl32(rotl32(a, 12) + e + sm3_tj_rot[j], 7);
        uint32_t ss2 = ss1 ^ rotl32(a, 12);
        uint32_t tt1 = ((a & b) | (a & c) | (b & c)) + d + ss2 + w1[j];
        uint32_t tt2 = ((e & f) | ((~e) & g)) + h + ss1 + w[j];

        d = c;
        c = rotl32(b, 9);
        b = a;
        a = tt1;
        h = g;
        g = rotl32(f, 19);
        f = e;
        e = sm3_p0(tt2);
    }

    ctx->state[0] ^= a;
    ctx->state[1] ^= b;
    ctx->state[2] ^= c;
    ctx->state[3] ^= d;
    ctx->state[4] ^= e;
    ctx->state[5] ^= f;
    ctx->state[6] ^= g;
    ctx->state[7] ^= h;
}

void SM3_init(SM3_ctx *ctx) {
    memcpy(ctx->state, sm3_iv, sizeof(sm3_iv));
    ctx->bitlen = 0;
    ctx->buffer_len = 0;
}

void SM3_update(SM3_ctx *ctx, const uint8_t *data, size_t len) {
    ctx->bitlen += (uint64_t)len * 8u;

    if (ctx->buffer_len > 0) {
        size_t take = HASH_BLOCK_SIZE - ctx->buffer_len;
        if (take > len) {
            take = len;
        }

        memcpy(ctx->buffer + ctx->buffer_len, data, take);
        ctx->buffer_len += take;
        data += take;
        len -= take;

        if (ctx->buffer_len == HASH_BLOCK_SIZE) {
            sm3_transform(ctx, ctx->buffer);
            ctx->buffer_len = 0;
        }
    }

    while (len >= HASH_BLOCK_SIZE) {
        sm3_transform(ctx, data);
        data += HASH_BLOCK_SIZE;
        len -= HASH_BLOCK_SIZE;
    }

    if (len > 0) {
        memcpy(ctx->buffer, data, len);
        ctx->buffer_len = len;
    }
}

void SM3_final(SM3_ctx *ctx, uint8_t digest[SM3_DIGEST_SIZE]) {
    uint64_t bitlen = ctx->bitlen;

    ctx->buffer[ctx->buffer_len++] = 0x80;

    if (ctx->buffer_len > 56) {
        while (ctx->buffer_len < HASH_BLOCK_SIZE) {
            ctx->buffer[ctx->buffer_len++] = 0;
        }
        sm3_transform(ctx, ctx->buffer);
        ctx->buffer_len = 0;
    }

    while (ctx->buffer_len < 56) {
        ctx->buffer[ctx->buffer_len++] = 0;
    }

    store_be64(ctx->buffer + 56, bitlen);
    sm3_transform(ctx, ctx->buffer);

    for (int i = 0; i < 8; i++) {
        store_be32(digest + (size_t)i * 4u, ctx->state[i]);
    }
}

void SM3_hash(const uint8_t *data, size_t len, uint8_t digest[SM3_DIGEST_SIZE]) {
    SM3_ctx ctx;

    SM3_init(&ctx);
    SM3_update(&ctx, data, len);
    SM3_final(&ctx, digest);
}

/* ============================ SHA-256 ============================ */

static const uint32_t sha256_iv[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
};

static const uint32_t sha256_k[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,
    0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,
    0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,
    0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,
    0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,
    0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,
    0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,
    0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,
    0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

static inline uint32_t sha256_ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ ((~x) & z);
}

static inline uint32_t sha256_maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

static inline uint32_t sha256_big0(uint32_t x) {
    return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22);
}

static inline uint32_t sha256_big1(uint32_t x) {
    return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25);
}

static inline uint32_t sha256_small0(uint32_t x) {
    return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3);
}

static inline uint32_t sha256_small1(uint32_t x) {
    return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10);
}

static void sha256_transform(SHA256_ctx *ctx, const uint8_t block[HASH_BLOCK_SIZE]) {
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;

    for (int i = 0; i < 16; i++) {
        w[i] = load_be32(block + (size_t)i * 4u);
    }

    for (int i = 16; i < 64; i++) {
        w[i] = sha256_small1(w[i - 2]) + w[i - 7] +
               sha256_small0(w[i - 15]) + w[i - 16];
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + sha256_big1(e) + sha256_ch(e, f, g) + sha256_k[i] + w[i];
        uint32_t t2 = sha256_big0(a) + sha256_maj(a, b, c);

        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void SHA256_init(SHA256_ctx *ctx) {
    memcpy(ctx->state, sha256_iv, sizeof(sha256_iv));
    ctx->bitlen = 0;
    ctx->buffer_len = 0;
}

void SHA256_update(SHA256_ctx *ctx, const uint8_t *data, size_t len) {
    ctx->bitlen += (uint64_t)len * 8u;

    if (ctx->buffer_len > 0) {
        size_t take = HASH_BLOCK_SIZE - ctx->buffer_len;
        if (take > len) {
            take = len;
        }

        memcpy(ctx->buffer + ctx->buffer_len, data, take);
        ctx->buffer_len += take;
        data += take;
        len -= take;

        if (ctx->buffer_len == HASH_BLOCK_SIZE) {
            sha256_transform(ctx, ctx->buffer);
            ctx->buffer_len = 0;
        }
    }

    while (len >= HASH_BLOCK_SIZE) {
        sha256_transform(ctx, data);
        data += HASH_BLOCK_SIZE;
        len -= HASH_BLOCK_SIZE;
    }

    if (len > 0) {
        memcpy(ctx->buffer, data, len);
        ctx->buffer_len = len;
    }
}

void SHA256_final(SHA256_ctx *ctx, uint8_t digest[SHA256_DIGEST_SIZE]) {
    uint64_t bitlen = ctx->bitlen;

    ctx->buffer[ctx->buffer_len++] = 0x80;

    if (ctx->buffer_len > 56) {
        while (ctx->buffer_len < HASH_BLOCK_SIZE) {
            ctx->buffer[ctx->buffer_len++] = 0;
        }
        sha256_transform(ctx, ctx->buffer);
        ctx->buffer_len = 0;
    }

    while (ctx->buffer_len < 56) {
        ctx->buffer[ctx->buffer_len++] = 0;
    }

    store_be64(ctx->buffer + 56, bitlen);
    sha256_transform(ctx, ctx->buffer);

    for (int i = 0; i < 8; i++) {
        store_be32(digest + (size_t)i * 4u, ctx->state[i]);
    }
}

void SHA256_hash(const uint8_t *data, size_t len, uint8_t digest[SHA256_DIGEST_SIZE]) {
    SHA256_ctx ctx;

    SHA256_init(&ctx);
    SHA256_update(&ctx, data, len);
    SHA256_final(&ctx, digest);
}

/* ============================= Tests ============================= */

typedef void (*hash_once_fn)(const uint8_t *data, size_t len, uint8_t digest[32]);
typedef double (*stream_bench_fn)(uint8_t *buf, size_t packet_bytes, uint32_t *out_sum);

typedef struct {
    size_t packet_bytes;
    double mbps;
    double time;
    uint32_t checksum;
} LimitResult;

typedef struct {
    LimitResult independent;
    LimitResult stream;
} AlgorithmResult;

static void fill_test_data(uint8_t *buf, size_t bytes) {
    for (size_t i = 0; i < bytes; i++) {
        buf[i] = (uint8_t)(i * 31u + 7u);
    }
}

static void format_size(size_t bytes, char *out, size_t out_len) {
    if (bytes >= 1024u * 1024u && bytes % (1024u * 1024u) == 0) {
        snprintf(out, out_len, "%I64uMB",
                 (unsigned long long)(bytes / (1024u * 1024u)));
    } else if (bytes >= 1024u && bytes % 1024u == 0) {
        snprintf(out, out_len, "%I64uKB",
                 (unsigned long long)(bytes / 1024u));
    } else {
        snprintf(out, out_len, "%I64uB", (unsigned long long)bytes);
    }
}

static double benchmark_independent(hash_once_fn fn,
                                    uint8_t *buf,
                                    size_t packet_bytes,
                                    uint32_t *out_sum) {
    uint8_t digest[32];
    uint32_t sum = 0;
    size_t rounds = (size_t)(TEST_TOTAL_BYTES / packet_bytes);
    double start = now_seconds();

    for (size_t r = 0; r < rounds; r++) {
        fn(buf, packet_bytes, digest);
        sum ^= checksum32(digest, sizeof(digest)) + (uint32_t)r;
        buf[r % packet_bytes] ^= (uint8_t)(digest[r & 31u] + (uint8_t)r);
    }

    double end = now_seconds();
    *out_sum = sum;
    return end - start;
}

static double benchmark_sm3_stream(uint8_t *buf, size_t packet_bytes, uint32_t *out_sum) {
    SM3_ctx ctx;
    uint8_t digest[SM3_DIGEST_SIZE];
    size_t rounds = (size_t)(TEST_TOTAL_BYTES / packet_bytes);
    double start = now_seconds();

    SM3_init(&ctx);
    for (size_t r = 0; r < rounds; r++) {
        SM3_update(&ctx, buf, packet_bytes);
    }
    SM3_final(&ctx, digest);

    double end = now_seconds();
    *out_sum = checksum32(digest, sizeof(digest));
    return end - start;
}

static double benchmark_sha256_stream(uint8_t *buf, size_t packet_bytes, uint32_t *out_sum) {
    SHA256_ctx ctx;
    uint8_t digest[SHA256_DIGEST_SIZE];
    size_t rounds = (size_t)(TEST_TOTAL_BYTES / packet_bytes);
    double start = now_seconds();

    SHA256_init(&ctx);
    for (size_t r = 0; r < rounds; r++) {
        SHA256_update(&ctx, buf, packet_bytes);
    }
    SHA256_final(&ctx, digest);

    double end = now_seconds();
    *out_sum = checksum32(digest, sizeof(digest));
    return end - start;
}

static LimitResult empty_limit_result(void) {
    LimitResult result;

    result.packet_bytes = 0;
    result.mbps = 0.0;
    result.time = 0.0;
    result.checksum = 0;
    return result;
}

static void update_best(LimitResult *best,
                        size_t packet_bytes,
                        double mbps,
                        double time,
                        uint32_t checksum) {
    if (mbps > best->mbps) {
        best->packet_bytes = packet_bytes;
        best->mbps = mbps;
        best->time = time;
        best->checksum = checksum;
    }
}

static AlgorithmResult run_limit_sweep(const char *name,
                                       hash_once_fn one_shot,
                                       stream_bench_fn stream_bench,
                                       uint8_t *buf,
                                       const size_t *packet_sizes,
                                       size_t packet_count) {
    AlgorithmResult result;
    double total_bits = (double)TEST_TOTAL_BYTES * 8.0;

    result.independent = empty_limit_result();
    result.stream = empty_limit_result();

    printf("\n=========== %s HASH_FASTER LIMIT ==========\n", name);
    printf("Total per test : %u GB\n", TEST_TOTAL_GB);
    printf("Packet     Rounds       Independent Mbps   Stream Mbps\n");

    for (size_t i = 0; i < packet_count; i++) {
        size_t packet = packet_sizes[i];
        size_t rounds = (size_t)(TEST_TOTAL_BYTES / packet);
        uint32_t independent_sum = 0;
        uint32_t stream_sum = 0;
        char size_text[16];

        fill_test_data(buf, packet);
        double independent_time = benchmark_independent(one_shot, buf, packet, &independent_sum);
        double independent_mbps = total_bits / independent_time / 1000000.0;

        fill_test_data(buf, packet);
        double stream_time = stream_bench(buf, packet, &stream_sum);
        double stream_mbps = total_bits / stream_time / 1000000.0;

        update_best(&result.independent, packet, independent_mbps, independent_time, independent_sum);
        update_best(&result.stream, packet, stream_mbps, stream_time, stream_sum);

        format_size(packet, size_text, sizeof(size_text));
        printf("%-10s %-12I64u %16.2f %13.2f\n",
               size_text,
               (unsigned long long)rounds,
               independent_mbps,
               stream_mbps);
    }

    char independent_size[16];
    char stream_size[16];
    format_size(result.independent.packet_bytes, independent_size, sizeof(independent_size));
    format_size(result.stream.packet_bytes, stream_size, sizeof(stream_size));

    printf("\nBest independent packet: %s, %.2f Mbps, %.6f s, checksum %08x\n",
           independent_size,
           result.independent.mbps,
           result.independent.time,
           result.independent.checksum);
    printf("Best streaming limit   : %s, %.2f Mbps, %.6f s, checksum %08x\n",
           stream_size,
           result.stream.mbps,
           result.stream.time,
           result.stream.checksum);
    printf("===========================================\n");

    return result;
}

static int run_known_tests(void) {
    const uint8_t message[] = {'a', 'b', 'c'};

    const uint8_t sm3_expected[SM3_DIGEST_SIZE] = {
        0x66,0xc7,0xf0,0xf4,0x62,0xee,0xed,0xd9,
        0xd1,0xf2,0xd4,0x6b,0xdc,0x10,0xe4,0xe2,
        0x41,0x67,0xc4,0x87,0x5c,0xf2,0xf7,0xa2,
        0x29,0x7d,0xa0,0x2b,0x8f,0x4b,0xa8,0xe0
    };

    const uint8_t sha256_expected[SHA256_DIGEST_SIZE] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,
        0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,
        0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
    };

    uint8_t sm3_digest[SM3_DIGEST_SIZE];
    uint8_t sha256_digest[SHA256_DIGEST_SIZE];
    int sm3_ok;
    int sha256_ok;

    SM3_hash(message, sizeof(message), sm3_digest);
    SHA256_hash(message, sizeof(message), sha256_digest);

    sm3_ok = memcmp(sm3_digest, sm3_expected, SM3_DIGEST_SIZE) == 0;
    sha256_ok = memcmp(sha256_digest, sha256_expected, SHA256_DIGEST_SIZE) == 0;

    printf("=========== HASH_FASTER KNOWN TEST =======\n");
    printf("Message   : abc\n");
    print_digest("SM3       : ", sm3_digest, sizeof(sm3_digest));
    printf("SM3 test  : %s\n", sm3_ok ? "PASS" : "FAIL");
    print_digest("SHA-256   : ", sha256_digest, sizeof(sha256_digest));
    printf("SHA test  : %s\n", sha256_ok ? "PASS" : "FAIL");
    printf("==========================================\n");

    return sm3_ok && sha256_ok;
}

int main(void) {
    const size_t packet_sizes[] = {
        64u,
        256u,
        1024u,
        4u * 1024u,
        16u * 1024u,
        64u * 1024u,
        256u * 1024u,
        1024u * 1024u,
        8u * 1024u * 1024u
    };
    const size_t packet_count = sizeof(packet_sizes) / sizeof(packet_sizes[0]);
    const size_t max_packet = packet_sizes[packet_count - 1];
    uint8_t *buf;
    AlgorithmResult sm3_result;
    AlgorithmResult sha256_result;
    const LimitResult *sm3_observed;
    const LimitResult *sha256_observed;
    const char *sm3_mode;
    const char *sha256_mode;

    if (!run_known_tests()) {
        return 1;
    }

    buf = (uint8_t *)malloc(max_packet);
    if (buf == NULL) {
        fprintf(stderr, "Memory allocation failed.\n");
        return 1;
    }

    sm3_result = run_limit_sweep("SM3", SM3_hash, benchmark_sm3_stream,
                                 buf, packet_sizes, packet_count);
    sha256_result = run_limit_sweep("SHA-256", SHA256_hash, benchmark_sha256_stream,
                                    buf, packet_sizes, packet_count);

    sm3_observed = &sm3_result.stream;
    sm3_mode = "streaming";
    if (sm3_result.independent.mbps > sm3_observed->mbps) {
        sm3_observed = &sm3_result.independent;
        sm3_mode = "independent";
    }

    sha256_observed = &sha256_result.stream;
    sha256_mode = "streaming";
    if (sha256_result.independent.mbps > sha256_observed->mbps) {
        sha256_observed = &sha256_result.independent;
        sha256_mode = "independent";
    }

    printf("\n=========== HASH_FASTER SUMMARY ==========\n");
    char sm3_size[16];
    printf("SM3 stream limit     : %.2f Mbps at ", sm3_result.stream.mbps);
    format_size(sm3_result.stream.packet_bytes, sm3_size, sizeof(sm3_size));
    printf("%s streaming packets\n", sm3_size);
    format_size(sm3_observed->packet_bytes, sm3_size, sizeof(sm3_size));
    printf("SM3 observed max     : %.2f Mbps at %s %s packets\n",
           sm3_observed->mbps, sm3_size, sm3_mode);

    char sha_size[16];
    printf("SHA-256 stream limit : %.2f Mbps at ", sha256_result.stream.mbps);
    format_size(sha256_result.stream.packet_bytes, sha_size, sizeof(sha_size));
    printf("%s streaming packets\n", sha_size);
    format_size(sha256_observed->packet_bytes, sha_size, sizeof(sha_size));
    printf("SHA-256 observed max : %.2f Mbps at %s %s packets\n",
           sha256_observed->mbps, sha_size, sha256_mode);
    printf("==========================================\n");

    free(buf);
    return 0;
}

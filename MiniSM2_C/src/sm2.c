#include "sm2.h"
#include "sm3.h"
#include "util.h"
#include <stdlib.h>
#include <string.h>

static ECCurve g_curve;
static int g_initialized = 0;

static int parse_curve_param(U256 *x, const char *hex)
{
    return u256_from_hex(x, hex);
}

void sm2_init(void)
{
    if (g_initialized) return;

    parse_curve_param(&g_curve.p,
        "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF");
    parse_curve_param(&g_curve.a,
        "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC");
    parse_curve_param(&g_curve.b,
        "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93");
    parse_curve_param(&g_curve.n,
        "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123");
    parse_curve_param(&g_curve.G.x,
        "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7");
    parse_curve_param(&g_curve.G.y,
        "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0");
    g_curve.G.infinity = 0;

    g_initialized = 1;
}

const ECCurve *sm2_get_curve(void)
{
    sm2_init();
    return &g_curve;
}

static void random_scalar(U256 *k, const U256 *n)
{
    uint8_t buf[32];
    U256 n_minus_one;

    u256_sub_u32(&n_minus_one, n, 1);
    do {
        util_random_bytes(buf, sizeof(buf));
        u256_from_bytes(k, buf);
    } while (u256_is_zero(k) || u256_cmp(k, &n_minus_one) >= 0);
}

static void reduce_to_n(U256 *x, const U256 *n)
{
    u256_reduce_once(x, n);
}

static int is_all_zero(const uint8_t *buf, size_t len)
{
    size_t i;
    for (i = 0; i < len; ++i) {
        if (buf[i] != 0) return 0;
    }
    return 1;
}

int sm2_generate_keypair(SM2KeyPair *key)
{
    const ECCurve *curve = sm2_get_curve();

    do {
        random_scalar(&key->d, &curve->n);
        ecc_scalar_mul(curve, &key->public_key, &key->d, &curve->G);
    } while (key->public_key.infinity);

    return ecc_is_on_curve(curve, &key->public_key);
}

static int sm2_compute_c3(const uint8_t x2[32],
                          const uint8_t *msg, size_t msg_len,
                          const uint8_t y2[32],
                          uint8_t c3[32])
{
    uint8_t *buf = (uint8_t *)malloc(64 + msg_len);
    if (!buf) return SM2_ERR;

    memcpy(buf, x2, 32);
    if (msg_len > 0) {
        memcpy(buf + 32, msg, msg_len);
    }
    memcpy(buf + 32 + msg_len, y2, 32);
    sm3_hash(buf, 64 + msg_len, c3);
    free(buf);
    return SM2_OK;
}

int sm2_encrypt(const uint8_t *msg, size_t msg_len,
                const ECPoint *public_key,
                uint8_t *cipher, size_t *cipher_len)
{
    const ECCurve *curve = sm2_get_curve();
    size_t needed = SM2_C1_SIZE + SM2_C3_SIZE + msg_len;
    U256 k;
    ECPoint c1, s;
    uint8_t x2y2[64];
    uint8_t *t = NULL;
    size_t i;
    int have_kdf = 0;

    if (!cipher_len || !public_key || !msg) return SM2_ERR;
    if (*cipher_len < needed) {
        *cipher_len = needed;
        return SM2_ERR;
    }
    if (!ecc_is_on_curve(curve, public_key)) return SM2_ERR;

    t = (uint8_t *)malloc(msg_len == 0 ? 1 : msg_len);
    if (!t) return SM2_ERR;

    do {
        random_scalar(&k, &curve->n);
        ecc_scalar_mul(curve, &c1, &k, &curve->G);
        ecc_scalar_mul(curve, &s, &k, public_key);
        if (s.infinity) {
            continue;
        }

        u256_to_bytes(&s.x, x2y2);
        u256_to_bytes(&s.y, x2y2 + 32);
        sm3_kdf(x2y2, sizeof(x2y2), msg_len, t);
        have_kdf = 1;
    } while (!have_kdf || (msg_len > 0 && is_all_zero(t, msg_len)));

    ecc_point_to_bytes(&c1, cipher);
    for (i = 0; i < msg_len; ++i) {
        cipher[SM2_C1_SIZE + SM2_C3_SIZE + i] = msg[i] ^ t[i];
    }

    if (!sm2_compute_c3(x2y2, msg, msg_len, x2y2 + 32, cipher + SM2_C1_SIZE)) {
        free(t);
        return SM2_ERR;
    }

    *cipher_len = needed;
    free(t);
    return SM2_OK;
}

int sm2_decrypt(const uint8_t *cipher, size_t cipher_len,
                const U256 *private_key,
                uint8_t *msg, size_t *msg_len)
{
    const ECCurve *curve = sm2_get_curve();
    ECPoint c1, s;
    size_t c2_len;
    uint8_t x2y2[64];
    uint8_t c3_check[32];
    uint8_t *t = NULL;
    size_t i;

    if (!cipher || !private_key || !msg_len) return SM2_ERR;
    if (cipher_len < SM2_C1_SIZE + SM2_C3_SIZE) return SM2_ERR;

    c2_len = cipher_len - SM2_C1_SIZE - SM2_C3_SIZE;
    if (!msg || *msg_len < c2_len) {
        *msg_len = c2_len;
        return SM2_ERR;
    }

    if (!ecc_point_from_bytes(&c1, cipher)) return SM2_ERR;
    if (!ecc_is_on_curve(curve, &c1)) return SM2_ERR;

    ecc_scalar_mul(curve, &s, private_key, &c1);
    if (s.infinity) return SM2_ERR;

    u256_to_bytes(&s.x, x2y2);
    u256_to_bytes(&s.y, x2y2 + 32);

    t = (uint8_t *)malloc(c2_len == 0 ? 1 : c2_len);
    if (!t) return SM2_ERR;
    sm3_kdf(x2y2, sizeof(x2y2), c2_len, t);
    if (c2_len > 0 && is_all_zero(t, c2_len)) {
        free(t);
        return SM2_ERR;
    }

    for (i = 0; i < c2_len; ++i) {
        msg[i] = cipher[SM2_C1_SIZE + SM2_C3_SIZE + i] ^ t[i];
    }

    if (!sm2_compute_c3(x2y2, msg, c2_len, x2y2 + 32, c3_check)) {
        free(t);
        return SM2_ERR;
    }

    free(t);
    if (memcmp(c3_check, cipher + SM2_C1_SIZE, SM2_C3_SIZE) != 0) {
        return SM2_ERR;
    }

    *msg_len = c2_len;
    return SM2_OK;
}

static int compute_za(const uint8_t *id, size_t id_len,
                      const ECPoint *public_key,
                      uint8_t za[32])
{
    const ECCurve *curve = sm2_get_curve();
    size_t len = 2 + id_len + 32 * 6;
    uint8_t *buf = (uint8_t *)malloc(len);
    uint16_t entl = (uint16_t)(id_len * 8);
    size_t off = 0;

    if (!buf) return SM2_ERR;
    buf[off++] = (uint8_t)(entl >> 8);
    buf[off++] = (uint8_t)entl;
    if (id_len > 0) {
        memcpy(buf + off, id, id_len);
        off += id_len;
    }

    u256_to_bytes(&curve->a, buf + off); off += 32;
    u256_to_bytes(&curve->b, buf + off); off += 32;
    u256_to_bytes(&curve->G.x, buf + off); off += 32;
    u256_to_bytes(&curve->G.y, buf + off); off += 32;
    u256_to_bytes(&public_key->x, buf + off); off += 32;
    u256_to_bytes(&public_key->y, buf + off); off += 32;

    sm3_hash(buf, off, za);
    free(buf);
    return SM2_OK;
}

static int compute_e(const uint8_t *msg, size_t msg_len,
                     const uint8_t *id, size_t id_len,
                     const ECPoint *public_key,
                     U256 *e)
{
    const ECCurve *curve = sm2_get_curve();
    uint8_t za[32];
    uint8_t digest[32];
    uint8_t *buf;

    if (!compute_za(id, id_len, public_key, za)) return SM2_ERR;
    buf = (uint8_t *)malloc(32 + msg_len);
    if (!buf) return SM2_ERR;
    memcpy(buf, za, 32);
    if (msg_len > 0) {
        memcpy(buf + 32, msg, msg_len);
    }
    sm3_hash(buf, 32 + msg_len, digest);
    free(buf);

    u256_from_bytes(e, digest);
    reduce_to_n(e, &curve->n);
    return SM2_OK;
}

int sm2_sign(const uint8_t *msg, size_t msg_len,
             const uint8_t *id, size_t id_len,
             const SM2KeyPair *key,
             U256 *r, U256 *s)
{
    const ECCurve *curve = sm2_get_curve();
    U256 e, k, x1, r_plus_k;
    U256 one, one_plus_d, inv, rd, k_minus_rd;
    ECPoint p1;
    int retry;

    if (!msg || !key || !r || !s) return SM2_ERR;
    if (!compute_e(msg, msg_len, id, id_len, &key->public_key, &e)) return SM2_ERR;
    u256_set_u64(&one, 1);
    u256_mod_add(&one_plus_d, &key->d, &one, &curve->n);
    if (u256_is_zero(&one_plus_d)) return SM2_ERR;
    u256_mod_inv(&inv, &one_plus_d, &curve->n);

    for (retry = 0; retry < 128; ++retry) {
        random_scalar(&k, &curve->n);
        ecc_scalar_mul(curve, &p1, &k, &curve->G);
        x1 = p1.x;
        reduce_to_n(&x1, &curve->n);

        u256_mod_add(r, &e, &x1, &curve->n);
        u256_mod_add(&r_plus_k, r, &k, &curve->n);
        if (u256_is_zero(r) || u256_is_zero(&r_plus_k)) continue;

        u256_mod_mul(&rd, r, &key->d, &curve->n);
        u256_mod_sub(&k_minus_rd, &k, &rd, &curve->n);
        u256_mod_mul(s, &inv, &k_minus_rd, &curve->n);
        if (!u256_is_zero(s)) return SM2_OK;
    }

    return SM2_ERR;
}

int sm2_verify(const uint8_t *msg, size_t msg_len,
               const uint8_t *id, size_t id_len,
               const ECPoint *public_key,
               const U256 *r, const U256 *s)
{
    const ECCurve *curve = sm2_get_curve();
    U256 e, t, x1, rr;
    ECPoint p1, p2, sum;

    if (!msg || !public_key || !r || !s) return SM2_ERR;
    if (u256_is_zero(r) || u256_is_zero(s)) return SM2_ERR;
    if (u256_cmp(r, &curve->n) >= 0 || u256_cmp(s, &curve->n) >= 0) return SM2_ERR;
    if (!ecc_is_on_curve(curve, public_key)) return SM2_ERR;
    if (!compute_e(msg, msg_len, id, id_len, public_key, &e)) return SM2_ERR;

    u256_mod_add(&t, r, s, &curve->n);
    if (u256_is_zero(&t)) return SM2_ERR;

    ecc_scalar_mul(curve, &p1, s, &curve->G);
    ecc_scalar_mul(curve, &p2, &t, public_key);
    ecc_point_add(curve, &sum, &p1, &p2);
    if (sum.infinity) return SM2_ERR;

    x1 = sum.x;
    reduce_to_n(&x1, &curve->n);
    u256_mod_add(&rr, &e, &x1, &curve->n);

    return u256_is_equal(&rr, r) ? SM2_OK : SM2_ERR;
}

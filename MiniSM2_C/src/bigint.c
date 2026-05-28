#include "bigint.h"
#include <ctype.h>
#include <string.h>

void u256_zero(U256 *x)
{
    memset(x, 0, sizeof(*x));
}

void u256_set_u64(U256 *x, uint64_t v)
{
    u256_zero(x);
    x->limb[0] = v;
}

int u256_is_zero(const U256 *x)
{
    return x->limb[0] == 0 && x->limb[1] == 0 &&
           x->limb[2] == 0 && x->limb[3] == 0;
}

int u256_cmp(const U256 *a, const U256 *b)
{
    int i;
    for (i = 3; i >= 0; --i) {
        if (a->limb[i] > b->limb[i]) return 1;
        if (a->limb[i] < b->limb[i]) return -1;
    }
    return 0;
}

int u256_is_equal(const U256 *a, const U256 *b)
{
    return u256_cmp(a, b) == 0;
}

int u256_get_bit(const U256 *x, int bit)
{
    if (bit < 0 || bit >= 256) return 0;
    return (int)((x->limb[bit / 64] >> (bit % 64)) & 1u);
}

uint64_t u256_add_raw(U256 *r, const U256 *a, const U256 *b)
{
    __uint128_t carry = 0;
    int i;

    for (i = 0; i < 4; ++i) {
        __uint128_t sum = (__uint128_t)a->limb[i] + b->limb[i] + carry;
        r->limb[i] = (uint64_t)sum;
        carry = sum >> 64;
    }
    return (uint64_t)carry;
}

uint64_t u256_sub_raw(U256 *r, const U256 *a, const U256 *b)
{
    uint64_t borrow = 0;
    int i;

    for (i = 0; i < 4; ++i) {
        __uint128_t sub = (__uint128_t)b->limb[i] + borrow;
        if ((__uint128_t)a->limb[i] >= sub) {
            r->limb[i] = (uint64_t)((__uint128_t)a->limb[i] - sub);
            borrow = 0;
        } else {
            r->limb[i] = (uint64_t)((((__uint128_t)1) << 64) + a->limb[i] - sub);
            borrow = 1;
        }
    }
    return borrow;
}

void u256_sub_u32(U256 *r, const U256 *a, uint32_t v)
{
    U256 t;
    u256_set_u64(&t, v);
    u256_sub_raw(r, a, &t);
}

void u256_reduce_once(U256 *x, const U256 *mod)
{
    while (u256_cmp(x, mod) >= 0) {
        U256 t;
        u256_sub_raw(&t, x, mod);
        *x = t;
    }
}

void u256_mod_add(U256 *r, const U256 *a, const U256 *b, const U256 *mod)
{
    U256 mod_minus_b;

    if (u256_is_zero(b)) {
        *r = *a;
        return;
    }

    u256_sub_raw(&mod_minus_b, mod, b);
    if (u256_cmp(a, &mod_minus_b) >= 0) {
        u256_sub_raw(r, a, &mod_minus_b);
    } else {
        u256_add_raw(r, a, b);
    }
}

void u256_mod_sub(U256 *r, const U256 *a, const U256 *b, const U256 *mod)
{
    if (u256_cmp(a, b) >= 0) {
        u256_sub_raw(r, a, b);
    } else {
        U256 diff;
        u256_sub_raw(&diff, b, a);
        u256_sub_raw(r, mod, &diff);
    }
}

void u256_mod_mul(U256 *r, const U256 *a, const U256 *b, const U256 *mod)
{
    U256 result;
    U256 x;
    int i;

    u256_zero(&result);
    x = *a;
    u256_reduce_once(&x, mod);

    for (i = 0; i < 256; ++i) {
        if (u256_get_bit(b, i)) {
            U256 tmp;
            u256_mod_add(&tmp, &result, &x, mod);
            result = tmp;
        }
        if (i != 255) {
            U256 doubled;
            u256_mod_add(&doubled, &x, &x, mod);
            x = doubled;
        }
    }

    *r = result;
}

void u256_mod_exp(U256 *r, const U256 *a, const U256 *e, const U256 *mod)
{
    U256 result;
    U256 base;
    int i;

    u256_set_u64(&result, 1);
    base = *a;
    u256_reduce_once(&base, mod);

    for (i = 0; i < 256; ++i) {
        if (u256_get_bit(e, i)) {
            U256 tmp;
            u256_mod_mul(&tmp, &result, &base, mod);
            result = tmp;
        }
        if (i != 255) {
            U256 tmp;
            u256_mod_mul(&tmp, &base, &base, mod);
            base = tmp;
        }
    }

    *r = result;
}

void u256_mod_inv(U256 *r, const U256 *a, const U256 *prime_mod)
{
    U256 e;
    u256_sub_u32(&e, prime_mod, 2);
    u256_mod_exp(r, a, &e, prime_mod);
}

void u256_from_bytes(U256 *x, const uint8_t bytes[32])
{
    size_t i;
    u256_zero(x);
    for (i = 0; i < 32; ++i) {
        size_t rev = 31 - i;
        x->limb[rev / 8] |= ((uint64_t)bytes[i]) << ((rev % 8) * 8);
    }
}

void u256_to_bytes(const U256 *x, uint8_t bytes[32])
{
    size_t i;
    for (i = 0; i < 32; ++i) {
        size_t rev = 31 - i;
        bytes[i] = (uint8_t)(x->limb[rev / 8] >> ((rev % 8) * 8));
    }
}

static int hex_value(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int u256_from_hex(U256 *x, const char *hex)
{
    uint8_t bytes[32];
    char clean[65];
    size_t len = 0;
    size_t i;
    size_t pos;

    memset(bytes, 0, sizeof(bytes));
    if (hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
        hex += 2;
    }

    for (i = 0; hex[i] != '\0'; ++i) {
        if (isspace((unsigned char)hex[i])) continue;
        if (hex_value((unsigned char)hex[i]) < 0) return 0;
        if (len >= sizeof(clean) - 1) return 0;
        clean[len++] = hex[i];
    }

    clean[len] = '\0';
    if (len == 0 || len > 64) return 0;

    pos = 32;
    i = len;
    while (i > 0 && pos > 0) {
        int lo = hex_value((unsigned char)clean[--i]);
        int hi = 0;
        if (i > 0) {
            hi = hex_value((unsigned char)clean[--i]);
        }
        bytes[--pos] = (uint8_t)((hi << 4) | lo);
    }

    u256_from_bytes(x, bytes);
    return 1;
}

void u256_to_hex(const U256 *x, char out[65])
{
    static const char hex[] = "0123456789abcdef";
    uint8_t bytes[32];
    size_t i;

    u256_to_bytes(x, bytes);
    for (i = 0; i < 32; ++i) {
        out[i * 2] = hex[bytes[i] >> 4];
        out[i * 2 + 1] = hex[bytes[i] & 0x0f];
    }
    out[64] = '\0';
}

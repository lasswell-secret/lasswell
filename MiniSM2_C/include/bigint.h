#ifndef MINI_SM2_BIGINT_H
#define MINI_SM2_BIGINT_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint64_t limb[4]; /* little-endian: limb[0] is the least significant */
} U256;

void u256_zero(U256 *x);
void u256_set_u64(U256 *x, uint64_t v);
int u256_is_zero(const U256 *x);
int u256_cmp(const U256 *a, const U256 *b);
int u256_is_equal(const U256 *a, const U256 *b);
int u256_get_bit(const U256 *x, int bit);

uint64_t u256_add_raw(U256 *r, const U256 *a, const U256 *b);
uint64_t u256_sub_raw(U256 *r, const U256 *a, const U256 *b);
void u256_sub_u32(U256 *r, const U256 *a, uint32_t v);
void u256_reduce_once(U256 *x, const U256 *mod);

void u256_mod_add(U256 *r, const U256 *a, const U256 *b, const U256 *mod);
void u256_mod_sub(U256 *r, const U256 *a, const U256 *b, const U256 *mod);
void u256_mod_mul(U256 *r, const U256 *a, const U256 *b, const U256 *mod);
void u256_mod_exp(U256 *r, const U256 *a, const U256 *e, const U256 *mod);
void u256_mod_inv(U256 *r, const U256 *a, const U256 *prime_mod);

void u256_from_bytes(U256 *x, const uint8_t bytes[32]);
void u256_to_bytes(const U256 *x, uint8_t bytes[32]);
int u256_from_hex(U256 *x, const char *hex);
void u256_to_hex(const U256 *x, char out[65]);

#endif

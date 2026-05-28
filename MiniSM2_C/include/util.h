#ifndef MINI_SM2_UTIL_H
#define MINI_SM2_UTIL_H

#include <stddef.h>
#include <stdint.h>
#include "ecc.h"

void util_seed_random(void);
void util_random_bytes(uint8_t *out, size_t len);
void util_print_hex(const char *label, const uint8_t *buf, size_t len);
void util_print_u256(const char *label, const U256 *x);
void util_print_point(const char *label, const ECPoint *p);

#endif

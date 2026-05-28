#ifndef MINI_SM2_BENCHMARK_H
#define MINI_SM2_BENCHMARK_H

#include <stddef.h>
#include <stdint.h>
#include "ecc.h"

void benchmark_sm2_encrypt(const ECPoint *public_key,
                           const uint8_t *msg,
                           size_t msg_len,
                           int rounds);

#endif

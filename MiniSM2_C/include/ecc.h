#ifndef MINI_SM2_ECC_H
#define MINI_SM2_ECC_H

#include <stdint.h>
#include "bigint.h"

typedef struct {
    U256 x;
    U256 y;
    int infinity;
} ECPoint;

typedef struct {
    U256 p;
    U256 a;
    U256 b;
    U256 n;
    ECPoint G;
} ECCurve;

void ecc_point_set_infinity(ECPoint *p);
int ecc_point_is_infinity(const ECPoint *p);
int ecc_is_on_curve(const ECCurve *curve, const ECPoint *p);
void ecc_point_double(const ECCurve *curve, ECPoint *r, const ECPoint *p);
void ecc_point_add(const ECCurve *curve, ECPoint *r, const ECPoint *p, const ECPoint *q);
void ecc_scalar_mul(const ECCurve *curve, ECPoint *r, const U256 *k, const ECPoint *p);
void ecc_point_to_bytes(const ECPoint *p, uint8_t out[65]);
int ecc_point_from_bytes(ECPoint *p, const uint8_t in[65]);

#endif

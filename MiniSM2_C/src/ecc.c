#include "ecc.h"
#include <string.h>

void ecc_point_set_infinity(ECPoint *p)
{
    u256_zero(&p->x);
    u256_zero(&p->y);
    p->infinity = 1;
}

int ecc_point_is_infinity(const ECPoint *p)
{
    return p->infinity != 0;
}

int ecc_is_on_curve(const ECCurve *curve, const ECPoint *p)
{
    U256 y2, x2, x3, ax, rhs;

    if (p->infinity) return 1;
    if (u256_cmp(&p->x, &curve->p) >= 0 || u256_cmp(&p->y, &curve->p) >= 0) {
        return 0;
    }

    u256_mod_mul(&y2, &p->y, &p->y, &curve->p);
    u256_mod_mul(&x2, &p->x, &p->x, &curve->p);
    u256_mod_mul(&x3, &x2, &p->x, &curve->p);
    u256_mod_mul(&ax, &curve->a, &p->x, &curve->p);
    u256_mod_add(&rhs, &x3, &ax, &curve->p);
    u256_mod_add(&rhs, &rhs, &curve->b, &curve->p);

    return u256_is_equal(&y2, &rhs);
}

void ecc_point_double(const ECCurve *curve, ECPoint *r, const ECPoint *p)
{
    U256 x2, three_x2, num, den, inv, lambda;
    U256 lambda2, two_x, x3, x_minus_x3, y3, t;

    if (p->infinity || u256_is_zero(&p->y)) {
        ecc_point_set_infinity(r);
        return;
    }

    u256_mod_mul(&x2, &p->x, &p->x, &curve->p);
    u256_mod_add(&three_x2, &x2, &x2, &curve->p);
    u256_mod_add(&three_x2, &three_x2, &x2, &curve->p);
    u256_mod_add(&num, &three_x2, &curve->a, &curve->p);

    u256_mod_add(&den, &p->y, &p->y, &curve->p);
    u256_mod_inv(&inv, &den, &curve->p);
    u256_mod_mul(&lambda, &num, &inv, &curve->p);

    u256_mod_mul(&lambda2, &lambda, &lambda, &curve->p);
    u256_mod_add(&two_x, &p->x, &p->x, &curve->p);
    u256_mod_sub(&x3, &lambda2, &two_x, &curve->p);

    u256_mod_sub(&x_minus_x3, &p->x, &x3, &curve->p);
    u256_mod_mul(&t, &lambda, &x_minus_x3, &curve->p);
    u256_mod_sub(&y3, &t, &p->y, &curve->p);

    r->x = x3;
    r->y = y3;
    r->infinity = 0;
}

void ecc_point_add(const ECCurve *curve, ECPoint *r, const ECPoint *p, const ECPoint *q)
{
    U256 y_sum, num, den, inv, lambda;
    U256 lambda2, x_sum, x3, x_minus_x3, t, y3;

    if (p->infinity) {
        *r = *q;
        return;
    }
    if (q->infinity) {
        *r = *p;
        return;
    }

    if (u256_is_equal(&p->x, &q->x)) {
        u256_mod_add(&y_sum, &p->y, &q->y, &curve->p);
        if (u256_is_zero(&y_sum)) {
            ecc_point_set_infinity(r);
        } else {
            ecc_point_double(curve, r, p);
        }
        return;
    }

    u256_mod_sub(&num, &q->y, &p->y, &curve->p);
    u256_mod_sub(&den, &q->x, &p->x, &curve->p);
    u256_mod_inv(&inv, &den, &curve->p);
    u256_mod_mul(&lambda, &num, &inv, &curve->p);

    u256_mod_mul(&lambda2, &lambda, &lambda, &curve->p);
    u256_mod_add(&x_sum, &p->x, &q->x, &curve->p);
    u256_mod_sub(&x3, &lambda2, &x_sum, &curve->p);

    u256_mod_sub(&x_minus_x3, &p->x, &x3, &curve->p);
    u256_mod_mul(&t, &lambda, &x_minus_x3, &curve->p);
    u256_mod_sub(&y3, &t, &p->y, &curve->p);

    r->x = x3;
    r->y = y3;
    r->infinity = 0;
}

void ecc_scalar_mul(const ECCurve *curve, ECPoint *r, const U256 *k, const ECPoint *p)
{
    ECPoint acc;
    int i;

    ecc_point_set_infinity(&acc);

    for (i = 255; i >= 0; --i) {
        ECPoint doubled;
        ecc_point_double(curve, &doubled, &acc);
        acc = doubled;

        if (u256_get_bit(k, i)) {
            ECPoint added;
            ecc_point_add(curve, &added, &acc, p);
            acc = added;
        }
    }

    *r = acc;
}

void ecc_point_to_bytes(const ECPoint *p, uint8_t out[65])
{
    out[0] = 0x04u;
    u256_to_bytes(&p->x, out + 1);
    u256_to_bytes(&p->y, out + 33);
}

int ecc_point_from_bytes(ECPoint *p, const uint8_t in[65])
{
    if (in[0] != 0x04u) return 0;
    u256_from_bytes(&p->x, in + 1);
    u256_from_bytes(&p->y, in + 33);
    p->infinity = 0;
    return 1;
}

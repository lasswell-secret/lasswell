#include "util.h"
#include "bigint.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void util_seed_random(void)
{
    srand((unsigned int)time(NULL));
}

void util_random_bytes(uint8_t *out, size_t len)
{
    size_t i;
    for (i = 0; i < len; ++i) {
        out[i] = (uint8_t)(rand() & 0xff);
    }
}

void util_print_hex(const char *label, const uint8_t *buf, size_t len)
{
    size_t i;
    printf("%s", label);
    for (i = 0; i < len; ++i) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

void util_print_u256(const char *label, const U256 *x)
{
    char hex[65];
    u256_to_hex(x, hex);
    printf("%s%s\n", label, hex);
}

void util_print_point(const char *label, const ECPoint *p)
{
    printf("%s\n", label);
    if (p->infinity) {
        printf("  infinity\n");
        return;
    }
    util_print_u256("  x = ", &p->x);
    util_print_u256("  y = ", &p->y);
}

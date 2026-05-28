#include "benchmark.h"
#include "sm2.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void benchmark_sm2_encrypt(const ECPoint *public_key,
                           const uint8_t *msg,
                           size_t msg_len,
                           int rounds)
{
    uint8_t *cipher;
    size_t cipher_cap = SM2_C1_SIZE + SM2_C3_SIZE + msg_len;
    int i;
    clock_t begin;
    clock_t end;
    double seconds;
    double ops_per_sec;
    double kib_per_sec;

    if (rounds <= 0) rounds = 1;
    cipher = (uint8_t *)malloc(cipher_cap);
    if (!cipher) {
        printf("[bench] malloc failed\n");
        return;
    }

    begin = clock();
    for (i = 0; i < rounds; ++i) {
        size_t cipher_len = cipher_cap;
        if (!sm2_encrypt(msg, msg_len, public_key, cipher, &cipher_len)) {
            printf("[bench] encrypt failed at round %d\n", i + 1);
            free(cipher);
            return;
        }
    }
    end = clock();

    seconds = (double)(end - begin) / (double)CLOCKS_PER_SEC;
    if (seconds <= 0.0) seconds = 0.000001;

    ops_per_sec = (double)rounds / seconds;
    kib_per_sec = ((double)rounds * (double)msg_len / 1024.0) / seconds;

    printf("\n[Encryption speed]\n");
    printf("  rounds       : %d\n", rounds);
    printf("  message size : %lu bytes\n", (unsigned long)msg_len);
    printf("  total time   : %.3f s\n", seconds);
    printf("  rate         : %.2f encryptions/s\n", ops_per_sec);
    printf("  throughput   : %.2f KiB/s\n", kib_per_sec);

    free(cipher);
}

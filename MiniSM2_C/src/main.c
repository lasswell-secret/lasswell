#include "benchmark.h"
#include "sm2.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    SM2KeyPair key;
    const uint8_t id[] = "1234567812345678";
    const uint8_t plaintext[] = "Hello SM2 from MiniSM2_C";
    uint8_t cipher[SM2_C1_SIZE + SM2_C3_SIZE + sizeof(plaintext)];
    uint8_t decrypted[128];
    uint8_t bench_msg[1024];
    size_t cipher_len = sizeof(cipher);
    size_t decrypted_len = sizeof(decrypted);
    U256 r, s;
    int rounds = 2;
    size_t i;

    if (argc >= 2) {
        rounds = atoi(argv[1]);
        if (rounds <= 0) rounds = 2;
    }

    util_seed_random();
    sm2_init();

    printf("MiniSM2_C Demo\n");
    printf("==============\n\n");

    if (!sm2_generate_keypair(&key)) {
        printf("key generation failed\n");
        return 1;
    }

    printf("[1] key generation: success\n");
    util_print_u256("private key d = ", &key.d);
    util_print_point("public key P:", &key.public_key);

    printf("\n[2] plaintext: %s\n", plaintext);
    if (!sm2_encrypt(plaintext, sizeof(plaintext) - 1,
                     &key.public_key, cipher, &cipher_len)) {
        printf("encryption failed\n");
        return 1;
    }
    printf("[3] encryption: success\n");
    util_print_hex("cipher = ", cipher, cipher_len);

    if (!sm2_decrypt(cipher, cipher_len, &key.d, decrypted, &decrypted_len)) {
        printf("decryption failed\n");
        return 1;
    }
    decrypted[decrypted_len] = '\0';
    printf("[4] decryption: success\n");
    printf("decrypted = %s\n", decrypted);

    if (!sm2_sign(plaintext, sizeof(plaintext) - 1,
                  id, sizeof(id) - 1, &key, &r, &s)) {
        printf("signature failed\n");
        return 1;
    }
    printf("\n[5] signature: success\n");
    util_print_u256("r = ", &r);
    util_print_u256("s = ", &s);

    if (!sm2_verify(plaintext, sizeof(plaintext) - 1,
                    id, sizeof(id) - 1, &key.public_key, &r, &s)) {
        printf("verify failed\n");
        return 1;
    }
    printf("[6] verify: success\n");

    for (i = 0; i < sizeof(bench_msg); ++i) {
        bench_msg[i] = (uint8_t)('A' + (i % 26));
    }
    benchmark_sm2_encrypt(&key.public_key, bench_msg, sizeof(bench_msg), rounds);

    return 0;
}

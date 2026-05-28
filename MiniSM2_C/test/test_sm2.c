#include "sm2.h"
#include "util.h"
#include <stdio.h>
#include <string.h>

int main(void)
{
    SM2KeyPair key;
    const uint8_t msg[] = "SM2 unit test";
    uint8_t cipher[SM2_C1_SIZE + SM2_C3_SIZE + sizeof(msg)];
    uint8_t plain[64];
    size_t cipher_len = sizeof(cipher);
    size_t plain_len = sizeof(plain);

    util_seed_random();
    sm2_init();

    if (!sm2_generate_keypair(&key)) {
        printf("FAIL: keygen\n");
        return 1;
    }
    if (!sm2_encrypt(msg, sizeof(msg) - 1, &key.public_key, cipher, &cipher_len)) {
        printf("FAIL: encrypt\n");
        return 1;
    }
    if (!sm2_decrypt(cipher, cipher_len, &key.d, plain, &plain_len)) {
        printf("FAIL: decrypt\n");
        return 1;
    }
    if (plain_len != sizeof(msg) - 1 || memcmp(plain, msg, plain_len) != 0) {
        printf("FAIL: plaintext mismatch\n");
        return 1;
    }

    printf("PASS: SM2 encrypt/decrypt\n");
    return 0;
}

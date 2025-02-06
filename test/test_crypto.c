#include <stdio.h>
#include <string.h>

#include "../lib/crypto.h"

//#define BIG_ENDIAN 0
//#define LITTLE_ENDIAN 1

int main(int argc, char* argv[]) {

    int error = 0;

    fprintf(stdout, "\nAll the following tests must be OK:\n\n");

    // --------------------
    // Test exponentInteger

    unsigned long base = 2;

    error = exponentInteger(base, 1) != 2;
    error = error || exponentInteger(base, 2) != 4;
    error = error || exponentInteger(base, 3) != 8;
    error = error || exponentInteger(base, 4) != 16;
    error = error || exponentInteger(base, 32) != 4294967296;

    if (error) {
        fprintf(stdout, "Test 1 exponentInteger: \t\t\tKO\n");
    } else {
        fprintf(stdout, "Test 1 exponentInteger: \t\t\tOK\n");
    }

    // ----------------------------------
    // Test littleToBigEndian

    uint32_t from = 0x04030201;
    uint32_t to   = 0x01020304;

    error = littleToBigEndian(from) != to;
    error = error || littleToBigEndian(to) != from;
    error = error || littleToBigEndian(littleToBigEndian(from)) != from;
    error = error || littleToBigEndian(littleToBigEndian(to)) != to;

    error = error || littleToBigEndian(0x00000000) != 0x00000000;
    error = error || littleToBigEndian(0xFFFFFFFF) != 0xFFFFFFFF;

    if (error) {
        fprintf(stdout, "Test 2 littleToBigEndian: \t\t\tKO\n");
    } else {
        fprintf(stdout, "Test 2 littleToBigEndian: \t\t\tOK\n");
    } 

    // ----------------------------------
    // Test KDF_PBKDF2 with hmac_sha256

    // Password: "p@$Sw0rD~1"
    uint8_t pwd[] = { 0x70, 0x40, 0x24, 0x53, 0x77, 0x30, 0x72, 0x44, 0x7E, 0x31 };

    uint8_t salt[] = { 0xAA, 0xEF, 0x2D, 0x3F, 0x4D, 0x77, 0xAC, 0x66, 0xE9, 0xC5, 0xA6, 0xC3, 0xD8, 0xF9, 0x21, 0xD1 };
    uint8_t key[32];
    uint8_t good_key[32] = { 0x52, 0xc5, 0xef, 0xa1, 0x6e, 0x70, 0x22, 0x85, 0x90, 0x51, 0xb1, 0xde, 0xc2, 0x8b, 0xc6, 0x5d, 0x96, 0x96, 0xa3, 0x00, 0x5d, 0x0f, 0x97, 0xe5, 0x06, 0xc4, 0x28, 0x43, 0xbc, 0x3b, 0xdb, 0xc0 };

    error = KDF_PBKDF2((uint8_t *)pwd, sizeof(pwd), 
                       (uint8_t *)salt, sizeof(salt), 
                       50000, 32, key) == -1;

    error = error || memcmp(key, good_key, 32) != 0;

    if (error) {
        fprintf(stdout, "Test 3 KDF_PBKDF2 with HMAC_SHA256: \t\tKO\n");
    } else {
        fprintf(stdout, "Test 3 KDF_PBKDF2 with HMAC_SHA256: \t\tOK\n");
    }

    return 0;
}
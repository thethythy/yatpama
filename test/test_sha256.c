#include <stdio.h>
#include <memory.h>
#include <string.h>
#include "../lib/sha256.h"

void print_hash(const BYTE hash[])
{
   for (int idx=0; idx < 32; idx++)
      printf("%02x",hash[idx]);
   printf("\n");
}

int main() {

    int error = 0;

    fprintf(stdout, "\nAll the following tests must be OK:\n\n");

    // ----------------------------------
    // Test SHA256

	const BYTE text1[] = {"01234567879"},
               text2[] = {"0123456787901234567879012345678790123456787901234567879"},
			   good_hash1[] = {0x6e,0x27,0x82,0x94,0x57,0x6c,0x2f,0x66,0x76,0x67,0x61,0xd2,0x36,0x61,0xbe,0xa2,0xfc,0x16,0x00,0x7b,0x03,0xcd,0xa9,0x3f,0xc5,0xea,0x35,0x13,0x19,0x56,0x66,0x3b},
			   good_hash2[] = {0x00,0x53,0x99,0xdd,0x15,0xcd,0x5d,0xec,0x34,0x94,0xdf,0x7b,0x2e,0x13,0xe8,0x03,0xb4,0xbb,0x29,0xea,0xa0,0x24,0x46,0x9e,0x19,0x05,0xa6,0xa1,0x92,0x5a,0xc1,0x67};
    BYTE hash[32];

   	// Hash of text1 with subfunctions
	SHA256_CTX ctx;
	sha256_init(&ctx);
	sha256_compute(&ctx,text1,strlen((const char *)text1));
	sha256_final(&ctx);
	sha256_convert(&ctx,hash);

    error = error || memcmp(hash, good_hash1, 32) != 0;

    if (error) {
        fprintf(stdout, "Test 1 SHA256: \t\tKO\n");
    } else {
        fprintf(stdout, "Test 1 SHA256: \t\tOK\n");
    }

   	// Hash of text2 with main function
	sha256(text2, strlen((const char *)text2), hash);  	

    error = error || memcmp(hash, good_hash2, 32) != 0;

    if (error) {
        fprintf(stdout, "Test 2 SHA256: \t\tKO\n");
    } else {
        fprintf(stdout, "Test 2 SHA256: \t\tOK\n");
    }

   	return 0;
}

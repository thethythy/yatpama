#include <stdio.h>
#include <string.h>

#include "../lib/hmac_sha256.h"

void print_hash(const unsigned char hash[])
{
   for (int idx = 0; idx < 32; idx++)
      printf("%02x",hash[idx]);
   printf("\n");
}

int main() {

    int error = 0;

    fprintf(stdout, "\nAll the following tests must be OK:\n\n");

    // ----------------------------------
    // Test hmac_sha256

    BYTE text2[] = {"The quick brown fox jumps over the lazy dog"};
    BYTE hash[32];

	hmac_sha256(text2, (int) strlen((const char *)text2), (BYTE *)"key", 3, hash);

	BYTE good_hmac[] = { 0xf7, 0xbc, 0x83, 0xf4, 0x30, 0x53, 0x84, 0x24, 0xb1, 0x32, 0x98, 0xe6, 0xaa, 0x6f, 0xb1, 0x43, 0xef, 0x4d, 0x59, 0xa1, 0x49, 0x46, 0x17, 0x59, 0x97, 0x47, 0x9d, 0xbc, 0x2d, 0x1a, 0x3c, 0xd8 }; 

	error = memcmp(hash, good_hmac, 32);

	if (error) {
        fprintf(stdout, "Test 1 hmac_sha256: \t\tKO\n");
    } else {
        fprintf(stdout, "Test 1 hmac_sha256: \t\tOK\n");
    }

   	return 0;
}
 
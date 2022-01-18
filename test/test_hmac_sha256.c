#include <stdio.h>
#include <string.h>

#include "../lib/hmac_sha256.h"

void print_hash(unsigned char hash[])
{
   int idx;
   for (idx=0; idx < 32; idx++)
      printf("%02x",hash[idx]);
   printf("\n");
}

int main()
{
	BYTE text1[] = {""};
    BYTE text2[] = {"The quick brown fox jumps over the lazy dog"};
    BYTE hash[32];

   	// HMAC one
	hmac_sha256(text1, strlen((const char*)text1), (BYTE *)"", 0, hash);
   	print_hash(hash);
                 
   	// HMAC two
	hmac_sha256(text2, strlen((const char *)text2), (BYTE *)"key", 3, hash);
   	print_hash(hash);

   	return 0;
}
 
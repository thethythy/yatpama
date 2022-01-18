#include <stdio.h>
#include <memory.h>
#include <string.h>
#include "../lib/sha256.h"

void print_hash(BYTE hash[])
{
   int idx;
   for (idx=0; idx < 32; idx++)
      printf("%02x",hash[idx]);
   printf("\n");
}

int main()
{
	const BYTE text1[]={"01234567879"},
               text2[]={"0123456787901234567879012345678790123456787901234567879"};
    BYTE hash[32];

   	// Hash of text1 with subfunctions
	SHA256_CTX ctx;
	sha256_init(&ctx);
	sha256_compute(&ctx,text1,strlen((const char *)text1));
	sha256_final(&ctx);
	sha256_convert(&ctx,hash);	
   	print_hash(hash);

   	// Hash of text2 with main function
	sha256(text2, strlen((const char *)text2), hash);  	
   	print_hash(hash);

   	return 0;
}

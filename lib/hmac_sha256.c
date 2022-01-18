#include <string.h>
#include "hmac_sha256.h"

void hmac_sha256(BYTE text[], int text_len, BYTE key[], int key_len, BYTE hash[]) {
	SHA256_CTX ctx;
	
	BYTE k_ipad[64];
	BYTE k_opad[64];
	BYTE tk[32];
	
	int i;
	
	// Si la clé est plus grande que 64 octets alors key = SHA256(key)
	if (key_len > 64) {
		sha256(key, key_len, tk);
		key = tk;
		key_len = 32;
	}
	
	// Si la clé est plus petite elle est complétée avec des zéros
	// et copiées dans k_ipad et k_opad
	memset(k_ipad, 0, sizeof k_ipad);
	memset(k_opad, 0, sizeof k_opad);
	memcpy(k_ipad, key, key_len);
	memcpy(k_opad, key, key_len);
	
	for (i=0; i < 64; i++) {
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}
	
	// Empreinte sha256(k_ipad | text)
	sha256_init(&ctx);
	sha256_compute(&ctx, k_ipad, 64);
	sha256_compute(&ctx, text, text_len);
	sha256_final(&ctx);
	sha256_convert(&ctx, hash);
	
	// Empreinte sha256(k_opad | sha256(k_ipad | text))
	sha256_init(&ctx);
	sha256_compute(&ctx, k_opad, 64);
	sha256_compute(&ctx, hash, 32);
	sha256_final(&ctx);
	sha256_convert(&ctx,hash);
}
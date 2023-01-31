#include <string.h>
#include "hmac_sha256.h"

void hmac_sha256(const BYTE text[], int text_len, const BYTE key[], int key_len, BYTE hash[]) {
	SHA256_CTX ctx;
	
	BYTE k_ipad[64];
	BYTE k_opad[64];
	BYTE tk[32];
	
	// If the key length is more than 64 bytes then the key becomes SHA256(key)
	if (key_len > 64) {
		sha256(key, key_len, tk);
		key = tk;
		key_len = 32;
	}
	
	// If the key is smaller it is completed with zeros
	// and copied in k_ipad and k_opad
	memset(k_ipad, 0, sizeof k_ipad);
	memset(k_opad, 0, sizeof k_opad);
	memcpy(k_ipad, key, key_len);
	memcpy(k_opad, key, key_len);
	
	for (int i=0; i < 64; i++) {
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}
	
	// Footprint fp1: sha256(k_ipad | text)
	sha256_init(&ctx);
	sha256_compute(&ctx, k_ipad, 64);
	sha256_compute(&ctx, text, text_len);
	sha256_final(&ctx);
	sha256_convert(&ctx, hash);
	
	// Final footprint: sha256(k_opad | fp1)
	sha256_init(&ctx);
	sha256_compute(&ctx, k_opad, 64);
	sha256_compute(&ctx, hash, 32);
	sha256_final(&ctx);
	sha256_convert(&ctx,hash);
}
#ifndef _CRYPTO_H_
#define _CRYPTO_H_

#include <stdint.h>

#define MAX_ROUND_PWDTOKEY 10000

void rng(uint8_t *buf, int len);
void pwdtokey(uint8_t *pwd, int lenpwd, uint8_t *key);
int pwdConformity(const uint8_t pwd[], int pwdsize);
int compute_hash_executable(const char* filename, uint8_t hash[32]);
void xor_table(uint8_t *inout, const uint8_t* in, size_t len);

#endif
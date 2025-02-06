#ifndef _CRYPTO_H_
#define _CRYPTO_H_

#include <stdint.h>

#include "hmac_sha256.h"
#include "utilities.h"
#include "sha256.h"

#define MAX_ROUND_PBKDF2 500000
#define SALT_SIZE 64

void rng(uint8_t *buf, int len);
int KDF_PBKDF2(const uint8_t *pwd, int pwd_len, const uint8_t *salt, int salt_len, int count, long dklen, uint8_t * key);
int pwdConformity(const uint8_t pwd[], int pwdsize);
int compute_hash_executable(const char* filename, uint8_t hash[32]);
void xor_table(uint8_t *inout, const uint8_t* in, size_t len);

#endif
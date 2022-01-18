#ifndef _CRYPTO_H_
#define _CRYPTO_H_

#include <stdint.h>

#define MAX_ROUND_PWDTOKEY 10000

void rng(uint8_t *buf, int len);
void pwdtokey(uint8_t *pwd, int lenpwd, uint8_t *key);

void pwdConformity(uint8_t pwd[], int pwdsize);

#endif
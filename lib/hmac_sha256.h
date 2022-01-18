#ifndef HMAC_SHA256_H
#define HMAC_SHA256_H

#include "sha256.h"

void hmac_sha256(BYTE text[], int text_len, BYTE key[], int key_len, BYTE hash[]);

#endif
#ifndef HMAC_SHA256_H
#define HMAC_SHA256_H

#include "sha256.h"

void hmac_sha256(const BYTE text[], int text_len, const BYTE key[], int key_len, BYTE hash[]);

#endif
#ifndef _YATPAMA_H_
#define _YATPAMA_H_

#include <stdlib.h>
#include "lib/aes.h"

#define MAX_SIZE 16*AES_BLOCKLEN // Taille maximale des informations en octets
#define PWD_SIZE 12              // Taille minimale du mot de passe
#define HASH_SIZE 32             // Taille du HMAC (utilise SHA256)

typedef struct {
    uint8_t iv_info[AES_BLOCKLEN];
    uint8_t information[MAX_SIZE];
    uint8_t iv_sec[AES_BLOCKLEN];
    uint8_t secret[MAX_SIZE];
    uint8_t hash[HASH_SIZE];
} Entry;

#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>

#include "crypto.h"

/*
 *  Random Number Generator using /dev/urandom
 *  Set the buf parameter to a random number of size len
 */
void rng(uint8_t *buf, int len) {
  int randomDataSource = open("/dev/urandom", O_RDONLY);
  if (randomDataSource < 0) {
      fprintf(stderr, "Impossible to open entropic source\n");
      exit(1);
  }
  else {
      memset(buf, 0, len);
      ssize_t result = read(randomDataSource, buf, len);
      if (result < 0) {
        fprintf(stderr, "Impossible to read entropic source\n");
        close(randomDataSource);
        exit(1);
      }
      close(randomDataSource);
  }
}

/**
 * Key derivation function
 * Generate a key from a password and a salt according PBKDF2 algorithm
 * Parameter 1: the password is a string of byte terminated by '\0'
 * Parameter 2: the password length in byte
 * Parameter 3: the salt (must be >= 8 bytes)
 * Parameter 4: the salt length in byte
 * Parameter 5: the iteration count
 * Parameter 6: the length in byte of the generated key
 * Parameter 7: the generated key
 * Return value: -1 if KO, 0 if OK
 */
int KDF_PBKDF2(const uint8_t *pwd, int pwd_len, const uint8_t *salt, int salt_len, int count, long dkLen, uint8_t * key) {
    
    #define hLen 32 // Size of the SHA256 output hash function 

    // If dkLen is too long
    if (dkLen > (exponentInteger(2, 32) - 1) * hLen) {
        return -1;
    } else {
        int r = dkLen % hLen;   // Size of the last "block"
        int l;                  // Number of blocks

        l = (r > 0) ? 1 + (dkLen - r) / hLen : dkLen / hLen; 

        uint8_t hmac_j[hLen];
        uint8_t hmac_r[hLen];

        uint8_t * first_salt;

        first_salt = malloc(salt_len + 4);
        memcpy(first_salt, salt, salt_len);

        for (uint32_t i = 1; i <= l; i++) {

            #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
            uint32_t ibis = littleToBigEndian(i);
            #else
            uint32_t ibis = i;
            #endif
            memcpy(first_salt+salt_len, &ibis, 4);

            hmac_sha256(first_salt, salt_len + 4, pwd, pwd_len, hmac_j);
            memcpy(hmac_r, hmac_j, hLen);

            for (int j = 2; j <= count; j++) {
                hmac_sha256(hmac_j, hLen, pwd, pwd_len, hmac_j);
                xor_table(hmac_r, hmac_j, hLen);
            }

            if (i < l || r == 0) {
                memcpy(key, hmac_r, hLen);
                key += hLen;
            } else {
                memcpy(key, hmac_r, r);
            }
        }

        free(first_salt);
    }

    return 0;
}

/*
 * Control if the password is conformed to the policy : 
 *     length >= pwdsize, a capital letter at least, a lowercase letter at least and a digit at least
 * The password (pwd) is a string of characters terminated by the character '\0'
 * The min length of the password is given (pwdsize)
 * Return : 0 if OK
 */
int pwdConformity(const uint8_t pwd[], int pwdsize) {
    int i;
    int error = 0;
    int compteur = 0;

    for (i = 0, compteur = 0; pwd[i] != '\0'; i++, compteur++);
    error = compteur < pwdsize;

    if (!error) {
        for (i = 0, compteur = 0; pwd[i] != '\0'; i++)
            if (strchr("ABCDEFGHIJKLMNOPQRSTUVWXYZ", pwd[i])) compteur++;
        error = compteur <= 0;
    }

    if (!error) {
        for (i = 0, compteur = 0; pwd[i] != '\0'; i++)
            if (strchr("abcdefghijklmnopqrstuvwxyz", pwd[i])) compteur++;
        error = compteur <= 0;
    }

    if (!error) {
        for (i = 0, compteur = 0; pwd[i] != '\0'; i++)
            if (strchr("0123456789", pwd[i])) compteur++;
        error = compteur <= 0;
    }

    return error;
}

/*
 * Compute the SHA256 value of a file
 * Filename (first parameter) must be an absolute path
 * The result is stored in a hash value (second parameter) of 32 bytes length
 * Result : 0 if OK
 */
int compute_hash_executable(const char* filename, uint8_t hash[32]) {
    int fp = open(filename, O_RDONLY);

    if (fp != -1) {
        BYTE bin[256]; // Buffer of file content
        long nblus;
        
        // Initialization of SHA256
        SHA256_CTX ctx;
	    sha256_init(&ctx);

        // Read the file then hash its content
        do {
            nblus = read(fp, bin, 256);
            if (nblus != 0) sha256_compute(&ctx, bin, nblus);
        } while (nblus != 0);

        // Final hash value
	    sha256_final(&ctx);
	    sha256_convert(&ctx,hash);

        // Close the file
        close(fp);

    } else {
        return -1;
    }

    return 0;
}

/*
 * Do a xor binary operation byte per byte
 * inout = inout xor in
 * Parameter 1: inout
 * Parameter 2: in
 * Parameter 3 : length (we assume 'inout' and 'in' have same length)
 */
void xor_table(uint8_t *inout, const uint8_t* in, size_t len) {
    for (int i = 0; i < len; i++) inout[i] = inout[i] ^ in[i];
}

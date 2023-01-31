#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>

#include "crypto.h"
#include "aes.h"
#include "sha256.h"

/*
 *  Random Number Generator using /dev/urandom
 *  Set the buf parameter to a random number of size len
 */
void rng(uint8_t *buf, int len) {
  int randomDataSource = open("/dev/urandom", O_RDONLY);
  if (randomDataSource < 0) {
      fprintf(stderr, "Impossible to open entropic source\n");
      close(randomDataSource);
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

/*
 *  Generate a key from a password using AES as entropic generator
 *  AES256 must be defined
 *  Warning: length(pwd) >= length(key) 
 */
void pwdtokey(uint8_t *pwd, int lenpwd, uint8_t *key) {
    uint8_t iv[AES_BLOCKLEN] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    struct AES_ctx ctx;

    for (int j = 0; j < AES_KEYLEN; j++)
            key[j] = pwd[j];

    for (int i = 0; i < MAX_ROUND_PWDTOKEY; i++) {
        AES_init_ctx_iv(&ctx, key, iv);
        AES_CBC_encrypt_buffer(&ctx, pwd, lenpwd);

        iv[i % AES_BLOCKLEN]++; // New IV

        for (int j = 0; j < AES_KEYLEN; j++)
            key[j] = pwd[j];
    }

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
int compute_hash_executable(const char* filename, uint8_t hash[]) {
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

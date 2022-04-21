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
 * Contrôle de la conformité du mot de passe
 * Le mot de passe est stocké dans un tableau
 * Le mot de passe fini par le caractère '\0' 
 */
void pwdConformity(uint8_t pwd[], int pwdsize) {
    int i;
    int erreur = 0;
    int compteur = 0;
    char * existeMAJ = NULL;
    char * existeMIN = NULL;
    char * existeCHI = NULL;

    for (i = 0; pwd[i] != '\0'; i++, compteur++ );
    erreur = compteur < pwdsize;

    if (!erreur) {
        for (i = 0; pwd[i] != '\0' && !existeMAJ; i++)
            existeMAJ = strchr("ABCDEFGHIJKLMNOPQRSTUVWXYZ", pwd[i]);
        erreur = !existeMAJ;
    }

    if (!erreur) {
        for (i = 0; pwd[i] != '\0' && !existeMIN; i++)
            existeMIN = strchr("abcdefghijklmnopqrstuvwxyz", pwd[i]);
        erreur = !existeMIN;
    }

    if (!erreur) {
        for (i = 0; pwd[i] != '\0' && !existeCHI; i++)
            existeCHI = strchr("0123456789", pwd[i]);
        erreur = !existeCHI;
    }

    if (erreur) {
        fprintf(stderr, "Password does not conform to password policy!\n");
        exit(1);
    }
}

/*
 * Compute the SHA256 value of a file
 * Filename (first parameter) must be an absolute path
 * The result is stored in a hash value (second parameter) of 32 bytes length
 */
void compute_hash_executable(const char* filename, uint8_t hash[]) {
    int fp = open(filename, O_RDONLY);

    if (fp != -1) {
        BYTE bin[256]; // Stocke le contenu du fichier
        int nblus;
        
        // Initialiation de SHA256
        SHA256_CTX ctx;
	    sha256_init(&ctx);

        // Lecture du fichier puis hash du contenu
        do {
            nblus = read(fp, bin, 256);
            if (nblus != 0) sha256_compute(&ctx, bin, nblus);
        } while (nblus != 0);

        // Valeur de hash finale
	    sha256_final(&ctx);
	    sha256_convert(&ctx,hash);

    } else {
        fprintf(stderr, "\nImpossible to open file for computing its hash!");
        exit(1);
    }
}

/*
 * Do a xor binary operation byte per byte
 * inout = inout xor in
 * Parameter 1: intout
 * Parameter 2: in
 * Parameter 3 : length (we assume inout and in have same length)
 */
void xor_table(uint8_t *inout, uint8_t* in, size_t len) {
    for (int i = 0; i < len; i++) inout[i] = inout[i] ^ in[i];
}

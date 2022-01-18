#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <regex.h>

#include "lib/utilities.h"
#include "lib/crypto.h"
#include "lib/aes.h"
#include "lib/hmac_sha256.h"

#define IV_SIZE  16     // Taille de IV en octets 
#define KEY_SIZE 16     // Taille de la clé pour AES128 en octets
#define MAX_SIZE 256    // Taille maximale des informations en octets
#define PWD_SIZE 12     // Taille minimale du mot de passe
#define HASH_SIZE 32    // Taille du HMAC (utilise SHA256)

/*
 * Interface principale
 * Le programme attend que l'utilisateur utilise une commande connue
 */ 
char prompt() {
    char cmd;
    int again;

    do {
        printf("\n      yatpama : Yet Another Tiny Password Manager     ");
        printf("\n------------------------------------------------------");
        printf("\nCds:  k password | p print | s search | a add | q quit");
        printf("\n------------------------------------------------------");
        printf("\nChoose a command: ");
        cmd = getchar();
        again = cmd != 'k' && cmd != 'p' && cmd != 'a' && cmd != 'q' && cmd != 's'; 
    } while (again);

    getchar(); // Enlever la touche 'Enter' du buffer du clavier

    return cmd;
}

/*
 * Saisir le mot de passe pour générer une clé principale pour chiffrer / déchiffrer
 * La fonction génère la clé (paramètre)
 */
void do_command_key(uint8_t key[]) {
    uint8_t msecret[256];
    char enter;
    int nbChar;

    printf("Master password: ");
    nbChar = scanf("%s", msecret);

    if (nbChar != EOF) {
    	nbChar = scanf("%c", &enter); // Enlever la touche 'Enter' du buffer du clavier
    	pwdConformity(msecret, PWD_SIZE); // Contrôle de la conformité du mot de passe
        pwdtokey(msecret, 256, key); // Génére une clé à partir du mot de passe
    	memset(msecret, 0, 256); // On oublie le mot de passe
    } else {
        fprintf(stderr, "Impossible to read the password!\n");
        exit(1);
    }
}

/*
 * Affiche les informations secrètes actuellement connues en tenant compte d'un motif
 * Si le motif est NULL alors toutes les infos seront affichées
 * La fonction connaît la clé (1er paramètre)
 * La fonction connait le motif recherché (second paramètre)
 */
void search_and_print(uint8_t key[], char* pattern) {
    int fp;
    
    fp = open("./yatpama.data", O_RDONLY);

    if (fp != -1) {

        int nblus;
        int erreur = 0;

        int nbInfo = 0;

        uint8_t iv[IV_SIZE]; // Pour AES128, IV de 16 octets
        uint8_t information[MAX_SIZE];
        uint8_t secret[MAX_SIZE];
        uint8_t hash[HASH_SIZE];

        uint8_t hash2[HASH_SIZE];
        uint8_t text[MAX_SIZE * 2];

        struct AES_ctx ctx;

        // Compilation de l'expression régulière à partir du motif
        regex_t reg;
        if (pattern) {
            erreur = regcomp(&reg, pattern, REG_EXTENDED | REG_ICASE | REG_NOSUB);
            if (erreur) {
                fprintf(stderr, "Wrong search pattern!\n");
                close(fp);
                exit(1);
            }
        }

        do {
            // Lecture de IV pour déchiffrer information
            nblus = read(fp, iv, sizeof iv);
            erreur = nblus != sizeof iv;
                
            // Lecture de information chiffrée
            if (!erreur) {
                nblus = read(fp, information, sizeof information);
                erreur = nblus != sizeof information;
            }

            // Déchiffrement de information
            if (!erreur) {
                AES_init_ctx_iv(&ctx, key, iv);
                AES_CBC_decrypt_buffer(&ctx, information, sizeof information);
            }

            // Lecture de IV pour déchiffrer secret
            if (!erreur) {
                nblus = read(fp, iv, sizeof iv);
                erreur = nblus != sizeof iv;
            }

            // Lecture de secret chiffrée
            if (!erreur) {
                nblus = read(fp, secret, sizeof secret);
                erreur = nblus != sizeof secret;
            }

            // Déchiffrement de secret
            if (!erreur) {
                AES_init_ctx_iv(&ctx, key, iv);
                AES_CBC_decrypt_buffer(&ctx, secret, sizeof secret);
            }

            // Lecture du hash
            if (!erreur) {
                nblus = read(fp, hash, sizeof hash);
                erreur = nblus != sizeof hash;
            }

            // Contrôle du hash
            if (!erreur) {
                // Construction de text (avec concat)
                memset(text, 0, sizeof text);
                concat(text, information);
                concat(text, secret);

                // Calcul de hash2
                hmac_sha256(text, sizeof text, key, KEY_SIZE, hash2);
         
                // Comparaison de hash avec hash2 (fonction compare)
                if (-1 == compare(hash, sizeof hash, hash2, sizeof hash2)) {
                    fprintf(stderr, "\nWrong password or data file has been corrupted!\n");
                    close(fp);
                    exit(1);
                }
            }

            if (!erreur) {
                int match1 = 0;
                int match2 = 0;

                if (pattern) {
                    match1 = regexec(&reg, (char *)information, 0, NULL, 0);
                    match2 = regexec(&reg, (char *)secret, 0, NULL, 0);
                }

                if (!match1 || !match2) {
                    printf("\nInformation: ");
                    printf("%s", information);
                    printf("\nSecret: ");
                    printf("%s\n", secret);
                    nbInfo++;
                }
            }

        } while(!erreur);

        printf("\nNumber of information found: %i\n", nbInfo);
        close(fp);

    } else {
        fprintf(stderr, "Impossible to open data file!\n");
        exit(1);
    }
}

/*
 * Affiche toutes les informations secrètes actuellement connues
 * La fonction connaît la clé (paramètre)
 */
void do_command_print(uint8_t key[]) {
    search_and_print(key, NULL);
}

/*
 * Recherche les informations correspondant au motif puis les affiche
 * La fonction connaît la clé (paramètre)
 */
void do_command_search(uint8_t key[]) {
    uint8_t pattern[MAX_SIZE];

    /* Obtenir le pattern recherché */
    printf("Pattern: ");
    getsl((char*)pattern, MAX_SIZE);

    /* Lancer la recherche et l'affichage */
    search_and_print(key, (char*)pattern);
}

/*
 * Ajoute une nouvelle information secrète
 * La fonction connaît la clé (paramètre)
 * L'utilisateur saisie une information et le secret associé
 * Ces deux informations sont sauvegardées avec leur IV respectif une fois chiffré
 * On ajoute également une valeur hmac pour plus de sécurité
 */
void do_command_add(uint8_t key[]) {
    uint8_t information[MAX_SIZE];
    uint8_t secret[MAX_SIZE];

    printf("Information: ");
    getsl((char*)information, MAX_SIZE);

    printf("Secret: ");
    getsl((char*)secret, MAX_SIZE);

    // Construction de text en concaténant les deux chaines
    // text == information | secret
    uint8_t text[MAX_SIZE * 2];
    memset(text, 0, sizeof text); // Mise à zéro de la zone mémoire text
    concat(text, information);
    concat(text, secret);

    int fp;
    ssize_t nbBytes;
    int erreur = 0;
    
    fp = open("./yatpama.data", O_WRONLY);

    if (fp == -1)
        fp = creat("./yatpama.data", 0600);

    if (fp != -1) {
        uint8_t iv[IV_SIZE]; // Pour AES128, IV de 16 octets
        struct AES_ctx ctx;

        lseek(fp, 0L, SEEK_END); // Se placer à la fin du fichier

        rng(iv, IV_SIZE);
        nbBytes = write(fp, iv, IV_SIZE);
	    erreur = nbBytes != IV_SIZE;

	    if (!erreur) {
            AES_init_ctx_iv(&ctx, key, iv);
            AES_CBC_encrypt_buffer(&ctx, information, sizeof information);
            nbBytes = write(fp, information, sizeof information);
		    erreur = nbBytes != sizeof information;
	    }
	
        if (!erreur) {
            rng(iv, sizeof iv);
            nbBytes = write(fp, iv, sizeof iv);
	        erreur = nbBytes != sizeof iv;
        }

	    if (!erreur) {
            AES_init_ctx_iv(&ctx, key, iv);
            AES_CBC_encrypt_buffer(&ctx, secret, sizeof secret);
            nbBytes = write(fp, secret, sizeof secret);
            erreur = nbBytes != sizeof secret;
	    }

        if (!erreur) {
            BYTE hash[HASH_SIZE];

            // Calcul du HMAC sur la chaine text
            hmac_sha256(text, sizeof text, key, KEY_SIZE, hash);

            // Ecriture du hash dans le fichier
            nbBytes = write(fp, hash, sizeof hash);
            erreur = nbBytes != sizeof hash;
        }

        if (erreur) {
            fprintf(stderr, "Impossible to write in data file!\n");
            close(fp);
            exit(1);
        }

        close(fp);

    } else {
        fprintf(stderr, "Impossible to open data file!\n");
        exit(1);
    }
}

int main(int argc, char* argv[]) {
    char command; // La commande en cours
    uint8_t key[KEY_SIZE]; // Clé de chiffrement pour AES128
    int has_key = 0; // Flag pour indiquer si la clé est connue ou pas

    do {
        command = prompt();
        switch (command) {
            case 'k':
                printf("\nEnter password\n");
                if (!has_key) {
                    do_command_key(key);
                    has_key = 1;
                } else
                    printf("...but we have already a password!");
                break;
            case 'p':
                printf("\nPrint secret information\n");
                if (has_key)
                    do_command_print(key);
                else
                    printf("...but we don't have password!\n");
                break;
            case 's':
                printf("\nSearch a secret information\n");
                if (has_key)
                    do_command_search(key);
                else
                    printf("...but we don't have password!\n");
                break;
            case 'a':
                printf("\nAdd a new secret information\n");
                if (has_key)
                    do_command_add(key);
                else
                    printf("...but we don't have password!\n");
                break;
            case 'q':
                printf("\nGoodbye and good luck!\n");
                break;
        }
    } while (command != 'q');

    memset(key, 0, KEY_SIZE); // On oublie le master key
}

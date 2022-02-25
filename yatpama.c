#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <regex.h>

#include "lib/aes.h"
#include "lib/crypto.h"
#include "lib/dllist.h"
#include "lib/hmac_sha256.h"
#include "lib/utilities.h"

#include "yatpama.h"

/*
 * Interface principale
 * Le programme attend que l'utilisateur utilise une commande connue
 */ 
char prompt() {
    char cmd;
    int again;

    do {
        printf("\n----------------------------------------------------------");
        printf("\n        yatpama : Yet Another Tiny Password Manager       ");
        printf("\n----------------------------------------------------------");
        printf("\n k password | p print | s search | a add | d del | q quit ");
        printf("\n----------------------------------------------------------");
        printf("\nChoose a command: ");
        cmd = getchar();
        again = cmd != 'k' && cmd != 'p' && cmd != 'a' && cmd != 'q' && cmd != 's' && cmd != 'd'; 
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
 * Affiche les informations secrètes connues suivant un motif ou à une position
 * Si le motif est NULL alors toutes les entrées seront affichées
 * Si la position est donnée, seule l'entrée à cette position est affichée
 * 
 * La fonction connaît la clé (1er paramètre)
 * La fonction connaît la liste des entrées chiffrées (second paramètre)
 * La fonction connaît le motif recherché (troisième paramètre)
 * La fonction connaît la position recherchée (quatrième paramètre)
 */
void search_and_print(uint8_t key[], DLList list, char* pattern, int pos) {
    if (!isEmpty_DLList(list)) {

        int erreur = 0;
        int nbInfo = 0;
        int nbInfoMatch = 0;

        Entry * pentry; // Pointeur sur l'enregistrement

        uint8_t information[MAX_SIZE];
        uint8_t secret[MAX_SIZE];

        struct AES_ctx ctx;

        // Compilation de l'expression régulière à partir du motif
        regex_t reg;
        if (pattern) {
            erreur = regcomp(&reg, pattern, REG_EXTENDED | REG_ICASE | REG_NOSUB);
            if (erreur) {
                fprintf(stderr, "Wrong search pattern!\n");
                del_DLList(&list);
                exit(1);
            }
        }

        do {
            // Obtenir l'enregistrement courant de la liste
            pentry = list->entry;

            // Déchiffrement de information en mémoire
            memcpy(information, pentry->information, MAX_SIZE);
            AES_init_ctx_iv(&ctx, key, pentry->iv_info);
            AES_CBC_decrypt_buffer(&ctx, information, sizeof information);

            // Déchiffrement de secret en mémoire
            memcpy(secret, pentry->secret, MAX_SIZE);
            AES_init_ctx_iv(&ctx, key, pentry->iv_sec);
            AES_CBC_decrypt_buffer(&ctx, secret, sizeof secret);

            // Pattern matching
            int match1 = 0;
            int match2 = 0;

            if (pattern) {
                match1 = regexec(&reg, (char *)information, 0, NULL, 0);
                match2 = regexec(&reg, (char *)secret, 0, NULL, 0);
            }

            // Affichage des informations
            nbInfo++; // On incrèmente le numéro de l'entrée

            if ((!pos && (!match1 || !match2)) || (pos && pos == nbInfo)) {
                printf("\nEntry n°%i:", nbInfo);
                printf("\n\tInformation: ");
                printf("\t%s", information);
                printf("\n\tSecret: ");
                printf("\t%s\n", secret);
                nbInfoMatch++;
            }

            // Mise à zéro des zones mémoires utilisées
            memset(information, 0, sizeof information);
            memset(secret, 0, sizeof secret);

            list = next_DLList(list); // Noeud suivant

        } while(!isEmpty_DLList(list));

        if (!pos) printf("\nNumber of information found: %i\n", nbInfoMatch);

    } else {
        printf("\nThere is no entry yet!\n");
    }
}

/*
 * Affiche toutes les informations secrètes actuellement connues
 * La fonction connaît la clé (paramètre 1)
 * La fonction connaît la liste des entrées chiffrées (paramètre 2)
 */
void do_command_print(uint8_t key[], DLList list) {
    search_and_print(key, list, NULL, 0);
}

/*
 * Recherche les informations correspondant au motif puis les affiche
 * La fonction connaît la clé (paramètre 1)
 * La fonction connaît la liste des entrées chiffrées (paramètre 2)
 */
void do_command_search(uint8_t key[], DLList list) {
    uint8_t pattern[MAX_SIZE];

    /* Obtenir le pattern recherché */
    printf("Pattern: ");
    getsl((char*)pattern, MAX_SIZE);

    /* Lancer la recherche et l'affichage */
    search_and_print(key, list, (char*)pattern, 0);
}

/*
 * Ajoute une nouvelle information secrète
 * La fonction connaît la clé (paramètre 1)
 * La fonction connait la liste actuelle (paramètre 2)
 * La fonction retourne la liste modifiée
 * 
 * L'utilisateur saisie une information et le secret associé
 * Ces deux informations sont sauvegardées avec leur IV respectif une fois chiffré
 * On ajoute également une valeur hmac pour plus de sécurité
 */
DLList do_command_add(uint8_t key[], DLList list) {
    Entry * pentry = malloc(sizeof *pentry);

    printf("Information: ");
    getsl((char*)pentry->information, MAX_SIZE);

    printf("Secret: ");
    getsl((char*)pentry->secret, MAX_SIZE);

    // Construction de text en concaténant les deux chaines
    // text == information | secret
    uint8_t text[MAX_SIZE * 2];
    memset(text, 0, sizeof text); // Mise à zéro de la zone mémoire text
    concat(text, pentry->information);
    concat(text, pentry->secret);

    struct AES_ctx ctx;

    // Générer IV pour chiffrer information
    rng(pentry->iv_info, AES_BLOCKLEN);

    // Chiffrer information
    AES_init_ctx_iv(&ctx, key, pentry->iv_info);
    AES_CBC_encrypt_buffer(&ctx, pentry->information, sizeof pentry->information);

    // Générer IV pour secret
    rng(pentry->iv_sec, sizeof pentry->iv_sec);

    // Chiffrer secret
    AES_init_ctx_iv(&ctx, key, pentry->iv_sec);
    AES_CBC_encrypt_buffer(&ctx, pentry->secret, sizeof pentry->secret);

    // Calcul du HMAC sur la chaine text
    hmac_sha256(text, sizeof text, key, AES_KEYLEN, pentry->hash);

    // Ajouter de l'entrée dans la liste
    list = addAtLast_DLList(list, pentry);

    return list;
}

/**
 * Supprime une information secrète
 * La fontion connaît la clé (paramaètre 1)
 * La fonction connaît la liste des données (paramètre 2)
 * La fonction retourne la liste modifiée
 * 
 * L'utilisateur saisie le numéro de l'entrée à supprimer
 * L'entrée choisie est affichée pour confirmation
 * L'utilisateur confirme ou pas la suppression
 */ 
DLList do_command_delete(uint8_t key[], DLList list) {
    const int nbChiffre = 4; // 9999 maximum d'entrées
    int erreur; // Drapeau indicateur d'une erreur

    char cNbEntry[nbChiffre + 1]; // Numéro de l'entrée en chaine
    int nbEntry; // Numéro de l'entrée en entier
    
    // Obtenir et tester le numéro de l'entrée à supprimer
    printf("Give entry number: ");
    fgets(cNbEntry, nbChiffre + 1, stdin);

    nbEntry = atoi(cNbEntry);
    erreur = nbEntry <= 0 || nbEntry > size_DLList(list);

    if (!erreur) {
        char response[] = "n";

        // Afficher l'entrée à supprimer
        search_and_print(key, list, NULL, nbEntry);

        // Demander confirmation
        printf("\nPlease, confirm you want delete this entry [y/n]: ");
        fgets(response, 2, stdin);

        // Confirmation positive : supppresion de l'entrée de la liste
        if (response[0] == 'y') {
            list = del_Element_DLList(list, nbEntry);
            nbEntry = size_DLList(list);
            printf("Confirmation: one entry deleted, %d entries left.\n", nbEntry);
            if (nbEntry > 0)
                printf("Please take attention: entry numbers left could changed");
        }

    } else {
        printf("\nThis entry number does not exist\n");
    }

    fpurge(stdin);
    return list;
}

/*
 * Charge et contrôle les données depuis le fichier dans une liste
 * La fonction connaît la clé (paramètre 1)
 * La fonction connait le nom complet du fichier de données (paramètre 2)
 */
DLList load_data(uint8_t key[], const char *file_name) {
    DLList list = NULL;
    int fp;
    
    fp = open(file_name, O_RDONLY);

    if (fp != -1) {

        int nblus;
        int erreur = 0;

        Entry * pentry; // Pointeur sur l'enregistrement
        
        uint8_t information[MAX_SIZE];
        uint8_t secret[MAX_SIZE];
        uint8_t text[MAX_SIZE * 2];  // Texte à contrôler = information || secret
        uint8_t hash2[HASH_SIZE];  // Hash de contrôle

        struct AES_ctx ctx;

        do {
            // Lecture de l'enregistrement
            pentry = malloc(sizeof *pentry);
            nblus = read(fp, pentry, sizeof *pentry);
            erreur = nblus != sizeof *pentry;

            if (!erreur) {

                // Déchiffrement de information en mémoire
                memcpy(information, pentry->information, MAX_SIZE);
                AES_init_ctx_iv(&ctx, key, pentry->iv_info);
                AES_CBC_decrypt_buffer(&ctx, information, sizeof information);

                // Déchiffrement de secret en mémoire
                memcpy(secret, pentry->secret, MAX_SIZE);
                AES_init_ctx_iv(&ctx, key, pentry->iv_sec);
                AES_CBC_decrypt_buffer(&ctx, secret, sizeof secret);

                // Contrôle du hash

                // Construction de text (avec concat)
                memset(text, 0, sizeof text);
                concat(text, information);
                concat(text, secret);

                // Calcul de hash2
                hmac_sha256(text, sizeof text, key, AES_KEYLEN, hash2);

                // Comparaison de hash avec hash2 (fonction compare)
                if (-1 == compare(pentry->hash, sizeof pentry->hash, hash2, sizeof hash2)) {
                    fprintf(stderr, "\nWrong password or wrong file or data has been corrupted!\n");
                    close(fp);
                    exit(1);
                }

                // Mise à zéro des zones mémoires utilisées
                memset(text, 0, sizeof text);
                memset(information, 0, sizeof information);
                memset(secret, 0, sizeof secret);

                // Ajout des données chiffrées dans la liste
                list = addAtLast_DLList(list, pentry);
            }

        } while(!erreur);

        close(fp);
    } 

    return list;
}

/**
 * Sauvegarde une copie du fichier de données existant
 * Si une copie de sauvegarde existe déjà, elle est écrasée
 * La fonction connaît le nom complet du fichier de données existant (1er paramètre)
 */
void backup_data(const char *file_name) {
    int fp, bfp;
    char * backup_file_name;

    // Créer le nom du fichier de backup
    const char file_ext[] = ".old";
    backup_file_name = (char*) malloc(strlen(file_name) + strlen(file_ext) + 1);
    strcpy(backup_file_name, file_name);
    strcat(backup_file_name, file_ext);

    // Test si une copie existe déjà ou pas
    if (access(backup_file_name, F_OK) == -1) {
        // Création d'un nouveau fichier de sauvegarde
        bfp = creat(backup_file_name, 0600);
    } else {
        // Le fichier de sauvegarde existe déjà : on écrase son contenu
        bfp = open(backup_file_name, O_WRONLY | O_TRUNC);
    }

    // Copie enregistrement par enregistrement
    fp = open(file_name, O_RDONLY);
    if (fp != -1 && bfp != -1) {

        int nblus;
        int erreur = 0;

        Entry entry; // Un enregistrement

        do {
            // Lecture de l'enregistrement
            nblus = read(fp, &entry, sizeof entry);
            erreur = nblus != sizeof entry;

            if (!erreur) {

                // Ecriture de l'enregistrement dans le backup
                nblus = write(bfp, &entry, sizeof entry);
                erreur = nblus != sizeof entry;

                if (erreur) {
                    fprintf(stderr, "Impossible to write in backup file!\n");
                    close(fp);
                    close(bfp);
                    exit(1);
                }

            }

        } while(!erreur);

        close(fp);
        close(bfp);

    } else {
        fprintf(stderr, "Impossible to create a backup file!\n");
        if (fp != -1) close(fp);
        if (bfp != -1) close(fp);
        exit(1);
    }

}

/**
 * Enregistre les données chiffrées dans le fichier
 * La fonction connait la liste des données (premier paramètre)
 * La fonction connait le nom complet du fichier de données (second paramètre)
 * 
 * On consdidère que la liste n'est pas vide au départ !
 * Si ce fichier existe déjà, on fait une copie de sauvegarde avant de l'écraser
 */
void save_data(DLList list, const char *file_name){
    int fp;
    
    // Test de l'existence du fichier
    if (access(file_name, F_OK) == -1) {
        // Création d'un nouveau fichier
        fp = creat(file_name, 0600);
    } else {
        // Faire une copie de sauvegarde si un fichier existe déjà
        backup_data(file_name);

        // Ouverture en écriture du fichier existant en mode écrasement
        fp = open(file_name, O_WRONLY | O_TRUNC);
    }

    // Si un fichier existe on écrit dedans
    if (fp != -1) {

        do {
            
            ssize_t nbBytes;
            int erreur = 0;
            Entry * pentry;

            // On prend l'enrée en tête de liste
            pentry = list->entry;

            // Ecriture de la structure dans le fichier
            nbBytes = write(fp, pentry, sizeof *pentry);
            erreur = nbBytes != sizeof *pentry;

            if (erreur) {
                fprintf(stderr, "Impossible to write in data file!\n");
                del_DLList(&list);
                close(fp);
                exit(1);
            }

            // Next entry
            list = next_DLList(list);

        } while(!isEmpty_DLList(list));

        close(fp);

    } else {
        fprintf(stderr, "Impossible to create or open data file!\n");
        del_DLList(&list);
        exit(1);
    }
}

int main(int argc, char* argv[]) {
    char command; // La commande en cours

    int has_key = 0; // Flag pour indiquer si la clé est connue ou pas
    uint8_t key[AES_KEYLEN]; // Clé de chiffrement

    DLList list = NULL; // La liste contenant les données chiffrées

    const char file_name[] = "./yatpama.data"; // Le nom et chemin du fichier 

    do {
        command = prompt();
        switch (command) {
            case 'k':
                printf("\nEnter password\n");
                if (!has_key) {
                    do_command_key(key); // Saisie le mdp et génère la clé
                    list = load_data(key, file_name); // Charge et contrôle les données
                    int nbEntries = size_DLList(list);
                    if (nbEntries) printf("\nEntries found in a local data file: %i", nbEntries);
                    has_key = 1;
                } else
                    printf("...but we have already a password!");
                break;
            case 'p':
                printf("\nPrint secret information\n");
                if (has_key)
                    do_command_print(key, list);
                else
                    printf("...but we don't have password!\n");
                break;
            case 's':
                printf("\nSearch a secret information\n");
                if (has_key)
                    do_command_search(key, list);
                else
                    printf("...but we don't have password!\n");
                break;
            case 'a':
                printf("\nAdd a new secret information\n");
                if (has_key) {
                    list = do_command_add(key, list);
                    save_data(list, file_name);
                }
                else
                    printf("...but we don't have password!\n");
                break;
            case 'q':
                printf("\nGoodbye and good luck!\n");
                break;
            case 'd':
                printf("\nDelete an entry\n");
                if (has_key) {
                    int nbEntries = size_DLList(list);
                    list = do_command_delete(key, list);
                    if (size_DLList(list) == nbEntries - 1)
                        save_data(list, file_name);
                }
                else
                    printf("...but we don't have password!\n");
                break;
        }
    } while (command != 'q');

    del_DLList(&list); // On supprime la liste et son contenu
    memset(key, 0, AES_KEYLEN); // On oublie le master key
}

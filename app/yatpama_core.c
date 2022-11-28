#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <regex.h>
#include <sys/param.h>
#include <sys/time.h>

#include "../lib/crypto.h"
#include "../lib/hmac_sha256.h"
#include "../lib/utilities.h"

#include "yatpama_shared.h"

/*
 * Calculer la valeur de hachage du fichier exécuté
 * On prends le chemin absolu pour accéder au fichier exécuté
 * Paramètre n°1 : le nom du fichier de la ligne de commande
 * Paramètre n°2 : la valeur de hachage calculée
 */
void get_hash_executable(char* argv0, uint8_t hash[]) {
    // Mise à zéro du hash
    memset(hash, 0, 32);

    // Récupérer le chemin absolu complet de l'executable
    char path[MAXPATHLEN*2];
    *path = '\0';
    getAbsolutePath("yatpama", argv0, path, sizeof(path));

    if (*path != '\0') {
        char * canonical_path = realpath(path, NULL);
        printf("\nReference used: %s\n", canonical_path);
        compute_hash_executable(path, hash);
        free(canonical_path);
    } else {
        fprintf(stderr, "Impossible to get access to the executable file!\n");
        exit(1);
    }
}

/*
 * Saisir le mot de passe pour générer une clé principale pour chiffrer / déchiffrer
 * La fonction génère la clé (2ème paramètre) de 32 octets soit 256 bits
 */
void do_command_key(char * argv0, uint8_t key[]) {
    uint8_t msecret[256];
    char enter;
    int nbChar;

    memset(msecret, 0, 256);
    printf("Master password: ");
    nbChar = scanf("%s", msecret);

    if (nbChar != EOF) {
    	nbChar = scanf("%c", &enter); // Enlever la touche 'Enter' du buffer du clavier
    	pwdConformity(msecret, PWD_SIZE); // Contrôle de la conformité du mot de passe
        pwdtokey(msecret, 256, key); // Génére une clé à partir du mot de passe
    	memset(msecret, 0, 256); // On oublie le mot de passe

        // Génère la clé finale = key_from_pwd xor hash_from_executable
        BYTE hash[AES_KEYLEN];
        get_hash_executable(argv0, hash);
        xor_table(key, hash, AES_KEYLEN);
    } else {
        fprintf(stderr, "Impossible to read the password!\n");
        exit(1);
    }
}

/*
 * Calcul du hmac d'une entrée (couple de chaîne de caractère)
 * Paramètre 1 : la clé de chiffrement
 * Paramètre 2 : la première chaine du couple
 * Paramètre 3 : la seconde chaine du couple
 * Paramètre 4 : un pointeur sur une zone pour stocker le hash calculé
 */
void hmac_data(uint8_t key[], char * information, char * secret, uint8_t * hash) {
    // Construction de text en concaténant les deux chaines
    // text == information | secret
    uint8_t text[MAX_SIZE * 2];
    memset(text, 0, sizeof text); // Mise à zéro de la zone mémoire text
    strcat((char*)text, information);
    strcat((char*)text, secret);

    // Calcul du HMAC sur la chaine text
    hmac_sha256(text, sizeof text, key, AES_KEYLEN, hash);

    // Mise à zéro de la zone mémoire text
    memset(text, 0, sizeof text);
}

/*
 * Chiffrement d'une entrée
 * Paramètre 1 : la clé de chiffrement
 * Paramètre 2 : l'entrée contenant les deux chaines claires puis chiffrées
 */
void cypher_data(uint8_t key[], Entry * pentry) {
    struct AES_ctx ctx;

    // Calcul du HMAC de l'entrée
    hmac_data(key, (char*)pentry->information, (char*)pentry->secret, pentry->hash);

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
}

/*
 * Déchiffrement en mémoire d'une entrée 
 * Paramètre 1 : la clé de déchiffrement
 * Paramètre 2 : l'entrée contenant les 2 données chiffrées
 * Paramètre 3 : pointeur sur l'information déchiffrée
 * Paramètre 4 : pointeur sur le secret déchiffré
 */
void uncypher_data(uint8_t key[], Entry * pentry, uint8_t * pinformation, uint8_t * psecret) {
    struct AES_ctx ctx;

    // Déchiffrement de information en mémoire
    memcpy(pinformation, pentry->information, MAX_SIZE);
    AES_init_ctx_iv(&ctx, key, pentry->iv_info);
    AES_CBC_decrypt_buffer(&ctx, pinformation, MAX_SIZE);

    // Déchiffrement de secret en mémoire
    memcpy(psecret, pentry->secret, MAX_SIZE);
    AES_init_ctx_iv(&ctx, key, pentry->iv_sec);
    AES_CBC_decrypt_buffer(&ctx, psecret, MAX_SIZE);
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

        uint8_t information[MAX_SIZE];
        uint8_t secret[MAX_SIZE];

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
            // Déchiffrement en mémoire
            uncypher_data(key, list->pdata, information, secret);

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

    // Chiffrement de l'entrée
    cypher_data(key, pentry);

    // Ajout de l'entrée dans la liste
    list = addAtLast_DLList(list, pentry);

    printf("\nOne entry added\n");

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
    char * pret; // Pointeur sur valeur retournée par fgets

    char cNbEntry[nbChiffre + 1]; // Numéro de l'entrée en chaine
    int nbEntry; // Numéro de l'entrée en entier
    
    // Obtenir et tester le numéro de l'entrée à supprimer
    printf("Give entry number: ");
    pret = fgets(cNbEntry, nbChiffre + 1, stdin);
    erreur = pret == NULL;

    if (!erreur) {
        nbEntry = atoi(cNbEntry);
        erreur = nbEntry <= 0 || nbEntry > size_DLList(list);
    }

    if (!erreur) {
        char response[] = "n";

        // Afficher l'entrée à supprimer
        search_and_print(key, list, NULL, nbEntry);

        // Demander confirmation
        printf("\nPlease, confirm you want delete this entry [y/n]: ");
        pret = fgets(response, 2, stdin);

        // Confirmation positive : supppresion de l'entrée de la liste
        if (pret != NULL && response[0] == 'y') {
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
 * Chargement et contrôle de l'enregistrement spécial de contrôle de version
 * Paramètre 1 : le numéro de fichier data ouvert
 * Paramètre 2 : la clé principale pour le contrôle du hmac
 */
void load_special_entry(int fp, uint8_t key[]) {
    int nblus;
    int erreur = 0;
    Entry entry;

    memset(&entry, 0, sizeof entry);

    // ---------------------------
    // Lecture de l'enregistrement
    nblus = read(fp, &entry, sizeof entry);
    erreur = nblus != sizeof entry;

    if (erreur) {
        fprintf(stderr, "Impossible to read the special entry from data file!\n");
        close(fp);
        exit(1);
    }

    // ----------------
    // Contrôle du hash

    uint8_t hash2[HASH_SIZE];  // Hash de contrôle
    
    // Calcul du hash de contrôle
    hmac_data(key, (char*)entry.information, (char*)entry.secret, hash2);

    // Comparaison du hash
    int erreurHash = 0 != memcmp((const void *)&entry.hash, (const void *)&hash2, sizeof hash2);

    // ------------------------------------
    // Prise en compte du numéro de version
    int erreurVersion = 0 != memcmp((const void*)EXEC_VERSION, (const void *)& entry.information, sizeof EXEC_VERSION);

    // -------------------------
    // Gestion des cas d'erreurs
    if (erreurHash && erreurVersion) {
        printf("\nA previous version (%s) has been detected for the data file", entry.information);
        printf("\nThe current version used is %s", EXEC_VERSION);
        printf("\nSee the procedure at https://github.com/thethythy/yatpama to retrieve data safely\n\n");
        close(fp);
        exit(1);
    }
    else if (erreurHash && !erreurVersion) {
        fprintf(stderr, "\nWrong password or data file has been corrupted!\n");
        close(fp);
        exit(1);
    }

    // -------------------------------------
    // Bouclier anti attaque par force brute
    // TODO

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

        // Lecture et contrôle de l'enregistrement spécial
        load_special_entry(fp, key);

        int nblus;
        int erreur = 0;

        Entry * pentry; // Pointeur sur l'enregistrement
        
        uint8_t information[MAX_SIZE];
        uint8_t secret[MAX_SIZE];
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

                // Calcul de hash2
                hmac_data(key, (char*)information, (char*)secret, hash2);

                // Comparaison de hash avec hash2 (fonction compare)
                if (-1 == compare(pentry->hash, sizeof pentry->hash, hash2, sizeof hash2)) {
                    fprintf(stderr, "\nWrong password or data file has been corrupted!\n");
                    close(fp);
                    exit(1);
                }

                // Mise à zéro des zones mémoires utilisées
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
    backup_file_name = (char*) malloc(strlen(file_name) + strlen(FILE_BACKUP_EXT) + 1);
    strcpy(backup_file_name, file_name);
    strcat(backup_file_name, FILE_BACKUP_EXT);

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
 * Construction de l'enregistrement spécial de contrôle de version
 * Paramètre n°1 : fp est le numéro du fichier data ouvert en écriture
 * Paramètre n°2 : la clé pour le calcul du hmac
 */
void save_special_entry(int fp, uint8_t key[]) {
    ssize_t nbBytes;
    int erreur = 0; 
    Entry entry;
    
    // Mise à zéro
    memset(&entry, 0, sizeof entry);

    // Numéro de version
    memcpy((void *)entry.information, (const void *)EXEC_VERSION, sizeof EXEC_VERSION);

    // Date en secondes
    struct timeval time;
    gettimeofday(&time, NULL);
    erreur = sizeof time.tv_sec >= sizeof entry.secret;

    if (!erreur) {
        memcpy((void *)entry.secret, (const void*)& (time.tv_sec), sizeof time.tv_sec);
    }

    // Calcul d'un HMAC
    if (!erreur) {
        hmac_data(key, (char*)entry.information, (char*)entry.secret, entry.hash);
    }

    // Ecriture de l'enregistrement spéciale
    if (!erreur) {
        nbBytes = write(fp, &entry, sizeof entry);
        erreur = nbBytes != sizeof entry;
    }

    if (erreur) {
        fprintf(stderr, "Impossible to create the special entry in data file!\n");
        close(fp);
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
void save_data(DLList list, const char *file_name, uint8_t key[]){
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

        // Construction de l'enregistrement spéciale
        save_special_entry(fp, key);

        // Ecriture des entrées de la liste
        do {

            ssize_t nbBytes;
            int erreur = 0;          
            Entry * pentry;

            if (!isEmpty_DLList(list)) {
                // On prend l'entrée en tête de liste
                pentry = list->pdata;

                // Ecriture de la structure dans le fichier
                nbBytes = write(fp, pentry, sizeof *pentry);
                erreur = nbBytes != sizeof *pentry;
            }

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

/*
 * Exporte les données en clair dans un fichier texte
 * La fonction connait la clé de déchiffrement (premier paramètre)
 * La fonction connait la liste des données chiffrées (second paramètre)
 * La fonction connait le nom du fichier d'exportation (troisième paramètre)
 */
void do_command_export(uint8_t key[], DLList list, const char *file_export) {
    if (!isEmpty_DLList(list)) {

        int fp;

        // Création ou ouverture en mode écrasement
        if (access(file_export, F_OK) == -1)
            fp = creat(file_export, 0600);
        else
            fp = open(file_export, O_WRONLY | O_TRUNC);

        if (fp != -1) {

            int nbEntries = 0;

            uint8_t information[MAX_SIZE];
            uint8_t secret[MAX_SIZE];

            char * fin; // Position de la fin de chaine
            int nbBytes, nbWrote, error;

            do {
                // Déchiffrement en mémoire
                uncypher_data(key, list->pdata, information, secret);

                // Ecriture dans le fichier d'exportation de "information"
                fin = index((const char *)information, '\0');
                nbBytes = fin - (char *)information;
                nbWrote = write(fp, information, nbBytes);
                error = nbBytes != nbWrote;

                if (!error) {
                    nbWrote = write(fp, "\n", 1);
                    error = 1 != nbWrote;
                }

                // Ecriture dans le fichier d'exportation de "secret"
                if (!error) {
                    fin = index((const char *)secret, '\0');
                    nbBytes = fin - (char *)secret;
                    nbWrote = write(fp, secret, nbBytes);
                    error = nbBytes != nbWrote;
                }

                if (!error) {
                    nbWrote = write(fp, "\n", 1);
                    error = 1 != nbWrote;
                }
                
                if (error) {
                    fprintf(stderr, "\nImpossible to write to the exportation file (%s)\n", file_export);
                    close(fp);
                    exit(1);
                }

                nbEntries++;

                // Mise à zéro des zones mémoires utilisées
                memset(information, 0, sizeof information);
                memset(secret, 0, sizeof secret);

                list = next_DLList(list); // Noeud suivant

            } while(!isEmpty_DLList(list));

            printf("\n%d entries has been exported in %s\n", nbEntries, file_export);
            close(fp);

        } else {
            fprintf(stderr, "\nImpossible to create or open to the exportation file!\n");
            exit(1);
        }

    } else
        printf("\nThere is no entry yet!\n");
}

/*
 * Importe des données depuis un fichier texte
 * La fonction connait la clé de chiffrement (premier paramètre)
 * La fonction connait la liste des données chiffrées (second paramètre)
 * La liste (éventuellement modifiée) est retournée
 */
DLList do_command_import(uint8_t key[], DLList list) {
    char file_import[MAXPATHLEN];
    char * pret; // Pointeur sur la valeur de retour de fgets
    FILE * pf;

    // Obtenir le nom du fichier texte à importer
    printf("\nGive the complete name of the text file to import: ");
    pret = fgets(file_import, MAXPATHLEN, stdin);

    if (pret == NULL) {
        fprintf(stderr, "\nImpossible do read standard input stream\n");
        exit(1);
    }

    * index(file_import, '\n') = '\0'; // Supprime le '\n'

    // Ouverture de l'import en mode lecture
    pf = fopen(file_import, "r");

    if (pf) {
        Entry * pentry;
        int nbEntries = 0;
        char * data;

        do {
            pentry = malloc(sizeof *pentry); // Allocation de l'entrée

            // Lecture de "information" et suppression de '\n'
            data = fgets((char *)(pentry->information), MAX_SIZE, pf);
            if (data) * index((char *)(pentry->information), '\n') = '\0';

            if (data) {
                 // Lecture de "secret" et suppression de '\n'
                data = fgets((char *)(pentry->secret), MAX_SIZE, pf);
                if (data) * index((char *)(pentry->secret), '\n') = '\0';

                if (data) {
                    // Chiffre l'entrée en mémoire
                    cypher_data(key, pentry);

                    // Ajout de l'entrée dans la liste
                    list = addAtLast_DLList(list, pentry);

                    nbEntries++;
                }
            }

        } while(data);

        printf("\n%d entries imported from %s\n", nbEntries, file_import);
        fclose(pf);

    } else {
        fprintf(stderr, "\nImpossible do open the importation file (%s)\n", file_import);
        exit(1);
    }

    return list;
}

/*
 * Thread de gestion des commandes "métier"
 * Paramètre 1 : une donnée utilisable par le thread
 */
void * thread_core(void * t_arg) {
    T_Core * pt_core = t_arg;           // L'argument est une structure T_Core
    T_Shared * pt_sh = pt_core->t_sh;   // Accès à la structure partagée

    int has_key = 0; // Flag pour indiquer si la clé est connue ou pas
    uint8_t key[AES_KEYLEN]; // Clé de chiffrement

    DLList list = NULL; // La liste contenant les données chiffrées

    int loop_again = 1;
    while(loop_again) {
    
        int core_cmd = 0;

        // Lecture d'une commande éventuelle
        core_cmd = get_shared_cmd(pt_sh);
    
        switch (core_cmd) {
            case CORE_CMD_KEY:
                if (!has_key) {
                    do_command_key(pt_core->exec_name, key); // Saisie le mdp et génère la clé
                    list = load_data(key, FILE_DATA_NAME); // Charge et contrôle les données
                    int nbEntries = size_DLList(list);
                    if (nbEntries) printf("\nEntries found in a local data file: %i", nbEntries);
                    has_key = 1;
                } else
                    printf("...but we have already a password!");
                delete_shared_cmd_0arg(pt_sh); // Suppression de la commande
                add_shared_cmd_0arg(pt_sh, HMI_CMD_LOOP_INTER); // On revient en mode interaction
                break;

            case CORE_CMD_PRINT:
                if (has_key)
                    do_command_print(key, list);
                else
                    printf("...but we don't have password!\n");
                delete_shared_cmd_0arg(pt_sh); // Suppression de la commande
                add_shared_cmd_0arg(pt_sh, HMI_CMD_LOOP_INTER); // On revient en mode interaction
                break;

            case CORE_CMD_ADD:
                if (has_key) {
                    list = do_command_add(key, list);
                    save_data(list, FILE_DATA_NAME, key);
                }
                else
                    printf("...but we don't have password!\n");
                delete_shared_cmd_0arg(pt_sh); // Suppression de la commande
                add_shared_cmd_0arg(pt_sh, HMI_CMD_LOOP_INTER); // On revient en mode interaction
                break;

            case CORE_CMD_SEARCH:
                if (has_key)
                    do_command_search(key, list);
                else
                    printf("...but we don't have password!\n");
                delete_shared_cmd_0arg(pt_sh); // Suppression de la commande
                add_shared_cmd_0arg(pt_sh, HMI_CMD_LOOP_INTER); // On revient en mode interaction
                break;

            case CORE_CMD_DEL:
                if (has_key) {
                    int nbEntries = size_DLList(list);
                    list = do_command_delete(key, list);
                    if (size_DLList(list) == nbEntries - 1)
                        save_data(list, FILE_DATA_NAME, key);
                }
                else
                    printf("...but we don't have password!\n");
                delete_shared_cmd_0arg(pt_sh); // Suppression de la commande
                add_shared_cmd_0arg(pt_sh, HMI_CMD_LOOP_INTER); // On revient en mode interaction
                break;

            case CORE_CMD_EXP:
                if (has_key)
                    do_command_export(key, list, FILE_EXPORT_NAME);
                else
                    printf("...but we don't have password!\n");
                delete_shared_cmd_0arg(pt_sh); // Suppression de la commande
                add_shared_cmd_0arg(pt_sh, HMI_CMD_LOOP_INTER); // On revient en mode interaction                
                break;

            case CORE_CMD_IMP:
                if (has_key) {
                    int nbEntries = size_DLList(list);
                    list = do_command_import(key, list);
                    if (size_DLList(list) != nbEntries)
                        save_data(list, FILE_DATA_NAME, key);
                }
                else
                    printf("...but we don't have password!\n");
                delete_shared_cmd_0arg(pt_sh); // Suppression de la commande
                add_shared_cmd_0arg(pt_sh, HMI_CMD_LOOP_INTER); // On revient en mode interaction                
                break;                

            case CORE_CMD_EXIT:
                delete_shared_cmd_0arg(pt_sh); // Suppression de la commande
                loop_again = 0; // Fin du thread
                break;

            default:
                break;
        }
    }

    del_DLList(&list); // On supprime la liste et son contenu
    memset(key, 0, AES_KEYLEN); // On oublie le master key

    return NULL;
}
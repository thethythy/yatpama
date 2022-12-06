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
 * 
 * Paramètre 1 : la structure partagée
 * Paramètre 2 : le nom du fichier de la ligne de commande
 * Paramètre 3 : la valeur de hachage calculée
 */
void get_hash_executable(T_Shared * pt_sh, char * argv0, uint8_t * hash) {
    // Mise à zéro du hash
    memset(hash, 0, AES_KEYLEN);

    // Récupérer le chemin absolu complet de l'executable
    char path[MAXPATHLEN*2];
    *path = '\0';
    getAbsolutePath(FILE_EXEC_NAME, argv0, path, sizeof(path));

    if (*path != '\0') {
        char * canonical_path = realpath(path, NULL);
        char message[MAXPATHLEN*2 + 20];
        sprintf(message, "\nReference used: %s\n", canonical_path);       
        add_shared_cmd_1arg(pt_sh, HMI_CMD_ALERT, message);
        compute_hash_executable(path, hash);
        free(canonical_path);
    } else {
        add_shared_cmd_1arg(pt_sh, HMI_CMD_ERROR, "Impossible to get access to the executable file!\n");
    }
}

/*
 * Générer une clé principale pour chiffrer / déchiffrer
 * La fonction génère la clé (2ème paramètre) de 32 octets soit 256 bits
 * 
 * Paramètre 1 : la structure partagée
 * Paramètre 2 : le nom de l'exécutable pour lier la clé avec l'exécutable
 * Paramètre 3 : la clé générée
 * Paramètre 4 : le mot de passe
 */
void generate_key(T_Shared * pt_sh, char * argv0, uint8_t * key, uint8_t * msecret) {
    pwdConformity(msecret, PWD_SIZE);       // Contrôle de la conformité du mot de passe
    pwdtokey(msecret, PWD_MAX_SIZE, key);   // Génére une clé à partir du mot de passe

    // Génère la clé finale = key_from_pwd xor hash_from_executable
    BYTE hash[AES_KEYLEN];
    get_hash_executable(pt_sh, argv0, hash);
    xor_table(key, hash, AES_KEYLEN);
}

/*
 * Calcul du hmac d'une entrée (couple de chaîne de caractère)
 * Paramètre 1 : la clé de chiffrement
 * Paramètre 2 : la première chaine du couple
 * Paramètre 3 : la seconde chaine du couple
 * Paramètre 4 : un pointeur sur une zone pour stocker le hash calculé
 */
void hmac_data(uint8_t * key, char * information, char * secret, uint8_t * hash) {
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
void cypher_data(uint8_t * key, Entry * pentry) {
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
void uncypher_data(uint8_t * key, Entry * pentry, uint8_t * pinformation, uint8_t * psecret) {
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
 * Demande d'afficher les informations secrètes connues suivant un motif ou à une position
 * Si le motif est NULL alors toutes les entrées seront affichées
 * Si la position est donnée, seule l'entrée à cette position est affichée
 * 
 * Paramètre 1 : la structure partagée
 * Paramètre 2 : la clé
 * Paramètre 3 : la liste des entrées chiffrées
 * Paramètre 4 : le motif recherché
 * Paramètre 5 : la position recherchée
 */
void search_and_print(T_Shared * pt_sh, uint8_t * key, DLList list, char * pattern, int pos) {
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
                add_shared_cmd_1arg(pt_sh, HMI_CMD_ALERT, "Wrong search pattern!\n");
                return;
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
                char strNbInfo[5];
                sprintf(strNbInfo, "%d", nbInfo);
                add_shared_cmd_3arg(pt_sh, HMI_CMD_SHOW_ENTRY, strNbInfo, (char *)information, (char *)secret);
                nbInfoMatch++;
            }

            // Mise à zéro des zones mémoires utilisées
            memset(information, 0, sizeof information);
            memset(secret, 0, sizeof secret);

            list = next_DLList(list); // Noeud suivant

        } while(!isEmpty_DLList(list));

        if (!pos) {
            char message[40];
            sprintf(message, "\nNumber of information found: %i\n", nbInfoMatch);
            add_shared_cmd_1arg(pt_sh, HMI_CMD_ALERT, message);
        }

    } else {
        add_shared_cmd_1arg(pt_sh, HMI_CMD_ALERT, "\nThere is no entry yet!\n");
    }
}

/*
 * Demande d'afficher toutes les informations secrètes actuellement connues
 * Paramètre 1 : la structure partagée 
 * Paramètre 2 : la clé
 * Paramètre 3 : la liste des entrées chiffrées
 */
void do_command_print(T_Shared * pt_sh, uint8_t * key, DLList list) {
    search_and_print(pt_sh, key, list, NULL, 0);
}

/*
 * Recherche les informations correspondant au motif puis les affiche
 * Paramètre 1 : la structure partagée 
 * Paramètre 2 : la clé
 * Paramètre 3 : la liste des entrées chiffrées
 */
void do_command_search(T_Shared * pt_sh, uint8_t * key, DLList list) {
    char pattern[MAX_SIZE];

    // Obtenir le pattern recherché
    get_shared_cmd_1arg(pt_sh, pattern);

    // Lancer la recherche et l'affichage
    search_and_print(pt_sh, key, list, pattern, 0);
}

/*
 * Ajoute une nouvelle information secrète

 * L'utilisateur a saisi une information et le secret associé
 * Ces deux informations sont sauvegardées avec leur IV respectif une fois chiffré
 * On ajoute également une valeur hmac pour plus de sécurité
 * 
 * Paramètre 1 : la structure partagée 
 * Paramètre 2 : la clé (paramètre 1)
 * Paramètre 3 : la liste actuelle (paramètre 2)
 * Paramètre 4 : la liste initiale
 * Retour : la liste modifiée
 */
DLList do_command_add(T_Shared * pt_sh, uint8_t * key, DLList list) {
    Entry * pentry = malloc(sizeof *pentry);

    get_shared_cmd_1arg(pt_sh, (char *) pentry->information);
    get_shared_cmd_1arg(pt_sh, (char *) pentry->secret);

    // Chiffrement de l'entrée
    cypher_data(key, pentry);

    // Ajout de l'entrée dans la liste
    list = addAtLast_DLList(list, pentry);

    add_shared_cmd_1arg(pt_sh, HMI_CMD_ALERT, "\nOne entry added\n");

    return list;
}

/**
 * Affiche l'entrée à supprimer 
 * 
 * Paramètre 1 : la structure partagée 
 * Paramètre 2 : la clé
 * Paramètre 3 : la liste des données
 * Retour : le numéro de l'entrée à supprimer (ou -1)
 */ 
int do_command_delete_get_entry(T_Shared * pt_sh, uint8_t * key, DLList list) {
    int erreur; // Drapeau indicateur d'une erreur

    char cNbEntry[ENTRY_NB_MAX_NB + 1]; // Numéro de l'entrée en chaine
    int nbEntry = - 1; // Numéro de l'entrée en entier
    
    get_shared_cmd_1arg(pt_sh, cNbEntry);

    nbEntry = atoi(cNbEntry);
    erreur = nbEntry <= 0 || nbEntry > size_DLList(list);
 
    if (!erreur) {
        // Afficher l'entrée à supprimer
        search_and_print(pt_sh, key, list, NULL, nbEntry);
    } else {
        add_shared_cmd_1arg(pt_sh, HMI_CMD_ALERT, "\nThis entry number does not exist\n");
        return -1;
    }

    return nbEntry;
}

/*
 * Supprimer une entrée si confirmation positive
 *
 * Paramètre 1 : la structure partagée 
 * Paramètre 2 : la liste des données chiffrées
 * Paramètre 3 : le numéro de l'entrée à supprimer
 * Retour : la liste éventuellement modifiée
 */
DLList do_command_delete_exec(T_Shared * pt_sh, DLList list, int nbEntry) {
    char reponse[2] = "n";

    get_shared_cmd_1arg(pt_sh, reponse);
    if (reponse[0] == 'y') {
        list = del_Element_DLList(list, nbEntry);
        nbEntry = size_DLList(list);

        char message[ALERT_MAX_SIZE];
        sprintf(message, "Confirmation: one entry deleted, %d entries left.\n", nbEntry);
        if (nbEntry > 0)
            strcat(message, "Please take attention: entry numbers left could changed");
        add_shared_cmd_1arg(pt_sh, HMI_CMD_ALERT, message);
    }

    return list;
}

/*
 * Chargement et contrôle de l'enregistrement spécial de contrôle de version
 *
 * Paramètre 1 : la structure partagée 
 * Paramètre 2 : le numéro de fichier data ouvert
 * Paramètre 3 : la clé principale pour le contrôle du hmac
 * Retour : code d'erreur (0 = pas de soucis)
 */
int load_special_entry(T_Shared * pt_sh, int fp, uint8_t * key) {
    int nblus;
    int erreur = 0;
    Entry entry;

    memset(&entry, 0, sizeof entry);

    // ---------------------------
    // Lecture de l'enregistrement
    nblus = read(fp, &entry, sizeof entry);
    erreur = nblus != sizeof entry;

    if (erreur) {
        add_shared_cmd_1arg(pt_sh, HMI_CMD_ERROR, "Impossible to read the special entry from data file!\n");
        close(fp);
        return 1;
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
        char message[ALERT_MAX_SIZE];
        sprintf(message, "\nA previous version (%s) has been detected for the data file\
                          \nThe current version used is %s\
                          \nSee the procedure at https://github.com/thethythy/yatpama to retrieve data safely\n\n", 
                          entry.information, EXEC_VERSION);
        add_shared_cmd_1arg(pt_sh, HMI_CMD_ERROR, message);
        close(fp);
        return 1;
    }
    else if (erreurHash && !erreurVersion) {
        add_shared_cmd_1arg(pt_sh, HMI_CMD_ERROR, "\nWrong password or data file has been corrupted!\n");
        close(fp);
        return 1;
    }

    // -------------------------------------
    // Bouclier anti attaque par force brute
    // TODO

    return 0;
}

/*
 * Charge et contrôle les données depuis le fichier dans une liste
 *
 * Paramètre 1 : la structure partagée 
 * Paramètre 2 : la clé
 * Paramètre 3 : le nom complet du fichier de données
 * Retour : la liste des données chiffrées
 */
DLList load_data(T_Shared * pt_sh, uint8_t * key, const char * file_name) {
    DLList list = NULL;
    int fp;
    int erreur = 0;
    
    fp = open(file_name, O_RDONLY);

    if (fp != -1) {

        // Lecture et contrôle de l'enregistrement spécial
        erreur = load_special_entry(pt_sh, fp, key);

        int nblus;

        Entry * pentry; // Pointeur sur l'enregistrement
        
        uint8_t information[MAX_SIZE];
        uint8_t secret[MAX_SIZE];
        uint8_t hash2[HASH_SIZE];  // Hash de contrôle

        struct AES_ctx ctx;

        if (!erreur)
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
                        add_shared_cmd_1arg(pt_sh, HMI_CMD_ERROR, "\nWrong password or data file has been corrupted!\n");
                        close(fp);
                        return list;
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
 *
 * Paramètre 1 : la structure partagée 
 * Paramètre 2 : le nom complet du fichier de données existant
 * Retour : code d'erreur (0 = pas d'erreur)
 */
int backup_data(T_Shared * pt_sh, const char * file_name) {
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
                    add_shared_cmd_1arg(pt_sh, HMI_CMD_ERROR, "Impossible to write in backup file!\n");
                    close(fp);
                    close(bfp);
                    return 1;
                }

            }

        } while(!erreur);

        close(fp);
        close(bfp);

    } else {
        add_shared_cmd_1arg(pt_sh, HMI_CMD_ERROR, "Impossible to create a backup file!\n");
        if (fp != -1) close(fp);
        if (bfp != -1) close(fp);
        return 1;
    }

    return 0;

}

/**
 * Construction de l'enregistrement spécial de contrôle de version
 * 
 * Paramètre 1 : la structure partagée 
 * Paramètre 2 : fp est le numéro du fichier data ouvert en écriture
 * Paramètre 3 : la clé pour le calcul du hmac
 * Retour : code d'erreur (O = pas d'erreur)
 */
int save_special_entry(T_Shared * pt_sh, int fp, uint8_t * key) {
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
        add_shared_cmd_1arg(pt_sh, HMI_CMD_ERROR, "Impossible to create the special entry in data file!\n");
        close(fp);
        return 1;
    }

    return 0;
}

/**
 * Enregistre les données chiffrées dans le fichier
 * On consdidère que la liste n'est pas vide au départ !
 * Si ce fichier existe déjà, on fait une copie de sauvegarde avant de l'écraser
 * 
 * Paramètre 1 : la structure partagée 
 * Paramètre 2 : la liste des données
 * Paramètre 3 : le nom complet du fichier de données (second paramètre)
 * Paramètre 4 : la clé de chiffrement
 */
void save_data(T_Shared * pt_sh, DLList list, const char * file_name, uint8_t * key){
    int fp = -1;
    int erreur = 0;
    
    // Test de l'existence du fichier
    if (access(file_name, F_OK) == -1) {
        // Création d'un nouveau fichier
        fp = creat(file_name, 0600);
    } else {
        // Faire une copie de sauvegarde si un fichier existe déjà
        erreur = backup_data(pt_sh, file_name);

        // Ouverture en écriture du fichier existant en mode écrasement
        if (!erreur) fp = open(file_name, O_WRONLY | O_TRUNC);
    }

    // Si un fichier existe on écrit dedans
    if (fp != -1 && !erreur) {

        // Construction de l'enregistrement spéciale
        erreur = save_special_entry(pt_sh, fp, key);

        // Ecriture des entrées de la liste
        if (!erreur)
            do {

                ssize_t nbBytes;         
                Entry * pentry;

                if (!isEmpty_DLList(list)) {
                    // On prend l'entrée en tête de liste
                    pentry = list->pdata;

                    // Ecriture de la structure dans le fichier
                    nbBytes = write(fp, pentry, sizeof *pentry);
                    erreur = nbBytes != sizeof *pentry;
                }

                if (erreur) {
                    add_shared_cmd_1arg(pt_sh, HMI_CMD_ERROR, "Impossible to write in data file!\n");
                    break;
                }

                // Next entry
                list = next_DLList(list);

            } while(!isEmpty_DLList(list));

        close(fp);

    } else {
        add_shared_cmd_1arg(pt_sh, HMI_CMD_ERROR, "Impossible to create or open data file!\n");
    }
}

/*
 * Exporte les données en clair dans un fichier texte
 *
 * Paramètre 1 : la structure partagée 
 * Paramètre 2 : la clé de déchiffrement
 * Paramètre 3 : la liste des données chiffrées
 */
void do_command_export(T_Shared * pt_sh, uint8_t * key, DLList list) {
    if (!isEmpty_DLList(list)) {

        char file_export[MAXPATHLEN];
        int fp;

        // Obtenir le nom du fichier d'exportation
        get_shared_cmd_1arg(pt_sh, file_export);

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
                    char message[MAXPATHLEN + 50];
                    sprintf(message, "\nImpossible to write to the exportation file (%s)\n", file_export);
                    add_shared_cmd_1arg(pt_sh, HMI_CMD_ALERT, message);
                    close(fp);
                    break;
                }

                nbEntries++;

                // Mise à zéro des zones mémoires utilisées
                memset(information, 0, sizeof information);
                memset(secret, 0, sizeof secret);

                list = next_DLList(list); // Noeud suivant

            } while(!isEmpty_DLList(list));

            if (!error) {
                char message[MAXPATHLEN + 50];
                sprintf(message, "\n%d entries has been exported in %s\n", nbEntries, file_export);
                add_shared_cmd_1arg(pt_sh, HMI_CMD_ALERT, message);
                close(fp);
            }

        } else {
            add_shared_cmd_1arg(pt_sh, HMI_CMD_ALERT, "\nImpossible to create or open the exportation file!\n");
        }

    } else
        add_shared_cmd_1arg(pt_sh, HMI_CMD_ALERT, "\nThere is no entry yet!\n");
}

/*
 * Importe des données depuis un fichier texte
 *
 * Paramètre 1 : la structure partagée 
 * Paramètre 2 : la clé de chiffrement
 * Paramètre 3 : la liste des données chiffrées
 * Retour : la liste éventuellement modifiée
 */
DLList do_command_import(T_Shared * pt_sh, uint8_t * key, DLList list) {
    char file_import[MAXPATHLEN];
    char message[MAXPATHLEN + 50];
    FILE * pf;

    // Obtenir le nom du fichier texte à importer
    get_shared_cmd_1arg(pt_sh, file_import);

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

        sprintf(message, "\n%d entries imported from %s\n", nbEntries, file_import);
        add_shared_cmd_1arg(pt_sh, HMI_CMD_ALERT, message);
        fclose(pf);

    } else {
        sprintf(message, "\nImpossible do open the importation file (%s)\n", file_import);
        add_shared_cmd_1arg(pt_sh, HMI_CMD_ALERT, message);
    }

    return list;
}

/*
 * Génére la clé puis charge les données existantes en les vérifiant
 *
 * Paramètre 1 : la structure partagée
 * Paramètre 2 : le nom du fichier exécutable
 * Paramètre 3 : la clé générée
 * Paramètre 4 : la liste des entrées qui vont être chargées
 * Retour : la liste des entrées éventuellement modifiées
 */
DLList do_command_key(T_Shared * pt_sh, char * exec_name, uint8_t * key, DLList list) {
    char passwd[PWD_MAX_SIZE];

    get_shared_cmd_1arg(pt_sh, passwd); // Récupère le mdp
    generate_key(pt_sh, exec_name, key, (uint8_t *)passwd); // Génère la clé
    memset(passwd, 0, PWD_MAX_SIZE);
    
    list = load_data(pt_sh, key, FILE_DATA_NAME); // Charge et contrôle les données
    
    // Demande pour afficher un message
    int nbEntries = size_DLList(list);
    if (nbEntries) {
        char message[ALERT_MAX_SIZE];
        sprintf(message, "\nEntries found in a local data file: %i", nbEntries);
        add_shared_cmd_1arg(pt_sh, HMI_CMD_ALERT, message);
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
    int nbEntries; // Mémorise la taille de la liste
    int nbEntry; // Mémorise un numéro d'entrée de la liste

    int loop_again = 1;
    while(loop_again) {
    
        int core_cmd = 0;

        // Attente d'une commande
        core_cmd = get_shared_cmd(pt_sh);
    
        switch (core_cmd) {

            // Calcul de la clé et chargement des données existantes
            case CORE_CMD_KEY:
                if (!has_key) {
                    list = do_command_key(pt_sh, pt_core->exec_name, key, list);
                    has_key = 1;
                } else
                    add_shared_cmd_1arg(pt_sh, HMI_CMD_ALERT, "...but we have already a password!");
                delete_shared_cmd(pt_sh, 1); // Suppression de la commande
                add_shared_cmd_0arg(pt_sh, HMI_CMD_LOOP_INTER); // On revient en mode interaction
                break;

            // Déchiffrement et demande affichage côté HMI
            case CORE_CMD_PRINT:
                if (has_key)
                    do_command_print(pt_sh, key, list);
                else
                    add_shared_cmd_1arg(pt_sh, HMI_CMD_ALERT, "...but we don't have password!\n");
                delete_shared_cmd(pt_sh, 0); // Suppression de la commande
                add_shared_cmd_0arg(pt_sh, HMI_CMD_LOOP_INTER); // On revient en mode interaction
                break;

            // Ajout d'une nouvelle entrée
            case CORE_CMD_ADD:
                if (has_key) {
                    list = do_command_add(pt_sh, key, list);
                    save_data(pt_sh, list, FILE_DATA_NAME, key);
                }
                else
                    add_shared_cmd_1arg(pt_sh, HMI_CMD_ALERT, "...but we don't have password!\n");
                delete_shared_cmd(pt_sh, 2); // Suppression de la commande
                add_shared_cmd_0arg(pt_sh, HMI_CMD_LOOP_INTER); // On revient en mode interaction
                break;

            // Filtrage des entrées selon un pattern
            case CORE_CMD_SEARCH:
                if (has_key)
                    do_command_search(pt_sh, key, list);
                else
                    add_shared_cmd_1arg(pt_sh, HMI_CMD_ALERT, "...but we don't have password!\n");
                delete_shared_cmd(pt_sh, 1); // Suppression de la commande
                add_shared_cmd_0arg(pt_sh, HMI_CMD_LOOP_INTER); // On revient en mode interaction
                break;

            // Demande de retourner l'entrée à supprimer
            case CORE_CMD_DEL_P1:
                if (has_key)
                    nbEntry = do_command_delete_get_entry(pt_sh, key, list); // On mémorise le numéro
                else
                    add_shared_cmd_1arg(pt_sh, HMI_CMD_ALERT, "...but we don't have password!\n");
                
                delete_shared_cmd(pt_sh, 1); // Suppression de la commande
                
                if (has_key && nbEntry > 0)
                    add_shared_cmd_0arg(pt_sh, HMI_CMD_ASK_YN); // On demande confirmation
                else
                    add_shared_cmd_0arg(pt_sh, HMI_CMD_LOOP_INTER); // On revient en mode interaction
                break;

            // Suppression d'une entrée
            case CORE_CMD_DEL_P2:
                nbEntries = size_DLList(list);
                list = do_command_delete_exec(pt_sh, list, nbEntry);
                if (size_DLList(list) == nbEntries - 1)
                    save_data(pt_sh, list, FILE_DATA_NAME, key);
                
                delete_shared_cmd(pt_sh, 1); // Suppression de la commande
                add_shared_cmd_0arg(pt_sh, HMI_CMD_LOOP_INTER); // On revient en mode interaction
                break;

            // Demande d'exportation vers un fichier texte
            case CORE_CMD_EXP:
                if (has_key)                
                    do_command_export(pt_sh, key, list);
                else
                    printf("...but we don't have password!\n");
                delete_shared_cmd(pt_sh, 1); // Suppression de la commande
                add_shared_cmd_0arg(pt_sh, HMI_CMD_LOOP_INTER); // On revient en mode interaction                
                break;

            // Demande d'importation depuis un fichier texte
            case CORE_CMD_IMP:
                if (has_key) {
                    int nbEntries = size_DLList(list);
                    list = do_command_import(pt_sh, key, list);
                    if (size_DLList(list) != nbEntries)
                        save_data(pt_sh, list, FILE_DATA_NAME, key);
                }
                else
                    printf("...but we don't have password!\n");
                delete_shared_cmd(pt_sh, 1); // Suppression de la commande
                add_shared_cmd_0arg(pt_sh, HMI_CMD_LOOP_INTER); // On revient en mode interaction
                break;

            // Arrêt du thread
            case CORE_CMD_EXIT:
                delete_shared_cmd(pt_sh, 0); // Suppression de la commande
                loop_again = 0; // Fin de la boucle et donc du thread
                break;

            default:
                break;
        }
    }

    del_DLList(&list); // On supprime la liste et son contenu
    memset(key, 0, AES_KEYLEN); // On oublie le master key

    return NULL;
}
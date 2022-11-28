#ifndef _YATPAMA_SHARED_H_
#define _YATPAMA_SHARED_H_

#include <stdlib.h>
#include <pthread.h>

#include "../lib/aes.h"
#include "../lib/dllist.h"

#define EXEC_VERSION "v1.4.0" // La version de l'exécutable

#define FILE_DATA_NAME "./yatpama.data" // Le nom et chemin du fichier
#define FILE_EXPORT_NAME "./yatpama_export.txt" // Nom du fichier d'exportation
#define FILE_BACKUP_EXT ".old" // Extension du fichier de sauvegarde

#define MAX_SIZE 16*AES_BLOCKLEN // Taille maximale des informations en octets
#define PWD_SIZE 12              // Taille minimale du mot de passe
#define HASH_SIZE 32             // Taille du HMAC (utilise SHA256)

// ---------------------------------------------------------------------------
// Enregistrement représentant une entrée :
// - un couple d'informations (champs information et secret)
// - deux vecteurs d'initialisation pour le couple
// - un valeur hmac du couple

typedef struct Entry {
    uint8_t iv_info[AES_BLOCKLEN];
    uint8_t information[MAX_SIZE];
    uint8_t iv_sec[AES_BLOCKLEN];
    uint8_t secret[MAX_SIZE];
    uint8_t hash[HASH_SIZE];
} Entry;

// ---------------------------------------------------------------------------
// Structure de données partagées entre les deux threads

typedef struct T_Shared {
    DLList cmd_list;            // La liste contenant les commandes
    pthread_mutex_t mut_list;   // Un sémaphore pour accéder à la liste
    pthread_cond_t synchro;     // Une synchro pour éviter de boucler à vide
} T_Shared;

// ---------------------------------------------------------------------------
// Structure de données propre au thread CORE

typedef struct T_Core {
    T_Shared * t_sh;            // La structure partagée
    char * exec_name;           // Le nom de l'exécutable
} T_Core;

// ---------------------------------------------------------------------------
// Liste des identifiants de commande

#define HMI_CMD_LOOP_INTER  1
#define HMI_CMD_EXIT        2

#define CORE_CMD_KEY        100
#define CORE_CMD_PRINT      101
#define CORE_CMD_ADD        102
#define CORE_CMD_SEARCH     103
#define CORE_CMD_DEL        104
#define CORE_CMD_EXP        105
#define CORE_CMD_IMP        106
#define CORE_CMD_EXIT       107

// ---------------------------------------------------------------------------
// Liste des fonctions communes liées à T_Shared

int get_shared_cmd(T_Shared * pt_sh);
void get_shared_cmd_1arg(T_Shared *  pt_sh, char ** arg);

void add_shared_cmd_0arg(T_Shared * pt_sh, int cmd_value);
void delete_shared_cmd_0arg(T_Shared * pt_sh);

void add_shared_cmd_1arg(T_Shared * pt_sh, int cmd_value, char * arg_value);
void delete_shared_cmd_1arg(T_Shared * pt_sh);

#endif
#ifndef _YATPAMA_SHARED_H_
#define _YATPAMA_SHARED_H_

#include <stdlib.h>
#include <pthread.h>

#include "../lib/aes.h"
#include "../lib/dllist.h"

#define EXEC_VERSION "v1.7.3" // The version of the executable

#define TIMEOUT_LOCK 60 // Timeout in seconds before locking the terminal
#define EXEC_INTERVAL_TIME 60 // Time interval in seconds between two execution

#define FILE_EXEC_NAME "yatpama" // The name of the executable file
#define FILE_DATA_NAME "./yatpama.data" // The name and path of the data file
#define FILE_BACKUP_EXT ".old" // Backup File Extension

#define MAX_SIZE 16*AES_BLOCKLEN    // Maximum size of information in bytes
#define PWD_SIZE 12                 // Minimum password size
#define PWD_MAX_SIZE 256            // Maximum password size
#define PROMPT_MAX_SIZE 70          // Maximum prompt size
#define ALERT_MAX_SIZE 1024         // Maximum size of alert and error messages
#define INFO_MAX_SIZE 256           // Maximum size of information entered
#define ENTRY_NB_MAX_NB 10          // Maximum number of digit size of the entry number      
#define HASH_SIZE 32                // HMAC size (uses SHA256)
#define CMD_NB_MAX_NB 5             // Maximum size of the number of digits in a command

// ---------------------------------------------------------------------------
// Record representing an entry :
// - a couple of information (information and secret fields)
// - two initialization vectors for the couple
// - a HMAC value of the couple

typedef struct Entry {
    uint8_t iv_info[AES_BLOCKLEN];
    uint8_t information[MAX_SIZE];
    uint8_t iv_sec[AES_BLOCKLEN];
    uint8_t secret[MAX_SIZE];
    uint8_t hash[HASH_SIZE];
} Entry;

// ---------------------------------------------------------------------------
// Structure of data shared between the two threads

typedef struct T_Shared {
    DLList cmd_list;            // The list containing the commands
    pthread_mutex_t mut_list;   // A semaphore to access the list
    pthread_cond_t synchro;     // A synchro to avoid looping empty
} T_Shared;

// ---------------------------------------------------------------------------
// CORE thread-specific data structure

typedef struct T_Core {
    T_Shared * t_sh;            // The shared structure of data
    char * exec_name;           // The name of the executable file
} T_Core;

// ---------------------------------------------------------------------------
// List of command identifiers

#define HMI_CMD_LOOP_INTER      1
#define HMI_CMD_SHOW_ENTRY      2
#define HMI_CMD_CLEAR_WINDOW    3
#define HMI_CMD_ASK_YN          4
#define HMI_CMD_SIGNEDIN        5
#define HMI_CMD_ALERT           6
#define HMI_CMD_EXIT            7
#define HMI_CMD_ERROR           8
#define HMI_CMD_EDIT_ENTRY      9

#define CORE_CMD_KEY        100
#define CORE_CMD_PRINT      101
#define CORE_CMD_ADD        102
#define CORE_CMD_SEARCH     103
#define CORE_CMD_DEL_P1     104
#define CORE_CMD_DEL_P2     105
#define CORE_CMD_EXP        106
#define CORE_CMD_IMP        107
#define CORE_CMD_EXIT       108
#define CORE_CMD_EDT_P1     109
#define CORE_CMD_EDT_P2     110

// ---------------------------------------------------------------------------
// List of common functions related to T_Shared

int get_shared_cmd(T_Shared * pt_sh);
void get_shared_cmd_1arg(T_Shared *  pt_sh, char * arg, int arg_size);
void get_shared_cmd_2arg(T_Shared *  pt_sh, char * arg, int arg_size);
void get_shared_cmd_3arg(T_Shared *  pt_sh, char * arg, int arg_size);

void add_shared_cmd_hpriority(T_Shared * pt_sh, int cmd_value);
void add_shared_cmd_0arg(T_Shared * pt_sh, int cmd_value);
void add_shared_cmd_1arg(T_Shared * pt_sh, int cmd_value, const char * arg_value);
void add_shared_cmd_2arg(T_Shared * pt_sh, int cmd_value, const char * arg1_value, const char * arg2_value);
void add_shared_cmd_3arg(T_Shared * pt_sh, int cmd_value, const char * arg1_value, const char * arg2_value, const char * arg3_value);

void delete_shared_cmd(T_Shared * pt_sh, int nb_arg);

#endif
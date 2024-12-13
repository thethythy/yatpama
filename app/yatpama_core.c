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
 * Calculate the hash value of the executed file
 * We take the absolute path to access the executed file
 * 
 * Parameter 1: The shared structure
 * Parameter 2: The name of the command-line file
 * Parameter 3: The calculated hash value
 * Return value: 0 if OK
 */
int get_hash_executable(T_Shared * pt_sh, char * argv0, uint8_t * hash) {
    // Reset of the hash
    memset(hash, 0, AES_KEYLEN);

    // Retrieve the full absolute path of the executable
    char path[MAXPATHLEN*2];
    *path = '\0';
    getAbsolutePath(FILE_EXEC_NAME, argv0, path, sizeof(path));

    if (*path != '\0') {
        char * canonical_path = realpath(path, NULL);
        char message[MAXPATHLEN*2 + 20];
        sprintf(message, "Reference used: %s", canonical_path);       
        add_shared_cmd_1arg(pt_sh, HMI_CMD_ALERT, message);
        free(canonical_path);
        int error = compute_hash_executable(path, hash);
        if (error) {
            add_shared_cmd_1arg(pt_sh, HMI_CMD_ERROR, "Impossible to open the executable file for computing its hash!");
            return -1;
        }
    } else {
        add_shared_cmd_1arg(pt_sh, HMI_CMD_ERROR, "Impossible to get access to the executable file!");
        return -1;
    }

    return 0;
}

/*
 * Generate a master key to encrypt/decrypt
 * The function generates the key (2nd parameter) of 32 bytes or 256 bits
 * 
 * Parameter 1: The shared structure
 * Parameter 2: The name of the executable to bind the key with the executable
 * Parameter 3: The generated key
 * Parameter 4: The mask of the key
 * Parameter 5: The password
 * Return value: 0 if OK
 */
int generate_key(T_Shared * pt_sh, char * argv0, uint8_t * key_m, uint8_t * mask, uint8_t * msecret) {
    int error = 0; 
    error = pwdConformity(msecret, PWD_SIZE);  // Password compliance check

    if (error)
        add_shared_cmd_1arg(pt_sh, HMI_CMD_ALERT, "Password does not conform to password policy!");
    else {
        // Generates a key from the password
        pwdtokey(msecret, PWD_MAX_SIZE, key_m);

        // Generates final key = key_from_pwd xor hash_from_executable
        BYTE hash[AES_KEYLEN];
        error = get_hash_executable(pt_sh, argv0, hash);
        if (!error) xor_table(key_m, hash, AES_KEYLEN);

        // Mask the final key with a random string
        rng(mask, AES_KEYLEN);
        xor_table(key_m, mask, AES_KEYLEN);
    }

    return error;
}

/*
 * Compute the HMAC of an entry (string pair)
 * Parameter 1: the encryption key
 * Parameter 2: the first string of the couple
 * Parameter 3: the second string of the couple
 * Parameter 4: a pointer to an area to store the calculated hash
 */
void hmac_data(const uint8_t * key, const char * information, const char * secret, uint8_t * hash) {
    // Text construction by concatenating the two strings
    // text == information | secret
    uint8_t text[MAX_SIZE * 2];
    memset(text, 0, sizeof text); // Zeroing the text memory area
    strcat((char*)text, information);
    strcat((char*)text, secret);

    // HMAC calculation on the text string
    hmac_sha256(text, sizeof text, key, AES_KEYLEN, hash);

    // Zeroing the text memory area
    memset(text, 0, sizeof text);
}

/*
 * Encrypting an entry
 * Parameter 1: the encryption key masked
 * Parameter 2: the mask of the key
 * Parameter 2: the entry containing the two clear strings then encrypted
 */
void cypher_data(const uint8_t * key_m, const uint8_t * mask, Entry * pentry) {
    struct AES_ctx ctx;

    // Unmask to get the real key
    uint8_t key[AES_KEYLEN];
    memcpy(key, key_m, AES_KEYLEN);
    xor_table(key, mask, AES_KEYLEN);

    // Calculation of the HMAC of the input
    hmac_data(key, (char*)pentry->information, (char*)pentry->secret, pentry->hash);

    // Generate IV to encrypt information
    rng(pentry->iv_info, AES_BLOCKLEN);

    // Encrypt information
    AES_init_ctx_iv(&ctx, key, pentry->iv_info);
    AES_CBC_encrypt_buffer(&ctx, pentry->information, sizeof pentry->information);

    // Generate IV to encrypt secret
    rng(pentry->iv_sec, sizeof pentry->iv_sec);

    // Encrypt secret
    AES_init_ctx_iv(&ctx, key, pentry->iv_sec);
    AES_CBC_encrypt_buffer(&ctx, pentry->secret, sizeof pentry->secret);

    memset(key, 0, sizeof key); // Zeroing the key
}

/*
 * In-memory decryption of an entry 
 * Parameter 1: the encryption key masked
 * Parameter 2: the mask of the key
 * Parameter 3: the entry containing the two encrypted strings
 * Parameter 4: pointer on clear information
 * Parameter 5: pointer on clear secret
 */
void uncypher_data(const uint8_t * key_m,  const uint8_t * mask, const Entry * pentry, uint8_t * pinformation, uint8_t * psecret) {
    struct AES_ctx ctx;

    // Unmask the key
    uint8_t key[AES_KEYLEN];
    memcpy(key, key_m, AES_KEYLEN);
    xor_table(key, mask, AES_KEYLEN);

    // In-memory decryption of information field
    memcpy(pinformation, pentry->information, MAX_SIZE);
    AES_init_ctx_iv(&ctx, key, pentry->iv_info);
    AES_CBC_decrypt_buffer(&ctx, pinformation, MAX_SIZE);

    // In-memory decryption of secret field
    memcpy(psecret, pentry->secret, MAX_SIZE);
    AES_init_ctx_iv(&ctx, key, pentry->iv_sec);
    AES_CBC_decrypt_buffer(&ctx, psecret, MAX_SIZE);

    memset(key, 0, sizeof key); // Zeroing the key
}

/*
 * Obtain known secret information by pattern or position
 * If the pattern is NULL then all entries will be displayed
 * If the position is given, only the entry at that position is displayed
 * 
 * Parameter 1: the shared structure
 * Parameter 2: the encryption key masked
 * Parameter 3: the mask of the key
 * Parameter 4: the list of the entries
 * Parameter 5: the pattern
 * Parameter 6: the position 
 */
void search_and_print(T_Shared * pt_sh, const uint8_t * key_m, const uint8_t * mask, DLList list, const char * pattern, int pos) {
    if (!isEmpty_DLList(list)) {

        int error = 0;
        int nbInfo = 0;
        int nbInfoMatch = 0;

        uint8_t information[MAX_SIZE];
        uint8_t secret[MAX_SIZE];

        // Compiling the regular expression from the pattern
        regex_t reg;
        if (pattern) {
            error = regcomp(&reg, pattern, REG_EXTENDED | REG_ICASE | REG_NOSUB);
            if (error) {
                add_shared_cmd_1arg(pt_sh, HMI_CMD_ALERT, "Wrong search pattern!");
                return;
            }
        }

        do {
            // In-memory decryption
            uncypher_data(key_m, mask, list->pdata, information, secret);

            // Pattern matching
            int match1 = 0;
            int match2 = 0;

            if (pattern) {
                match1 = regexec(&reg, (char *)information, 0, NULL, 0);
                match2 = regexec(&reg, (char *)secret, 0, NULL, 0);
            }

            // Sends couple of data
            nbInfo++; // A new entry has been find

            if ((!pos && (!match1 || !match2)) || (pos && pos == nbInfo)) {
                char strNbInfo[ENTRY_NB_MAX_NB+1];
                sprintf(strNbInfo, "%d", nbInfo);
                add_shared_cmd_3arg(pt_sh, HMI_CMD_SHOW_ENTRY, strNbInfo, (char *)information, (char *)secret);
                nbInfoMatch++;
            }

            // Zeroing temporary variables
            memset(information, 0, sizeof information);
            memset(secret, 0, sizeof secret);

            list = next_DLList(list); // Next node

        } while(!isEmpty_DLList(list));

        if (!pos) {
            char message[ALERT_MAX_SIZE];
            sprintf(message, "Number of entries found: %i", nbInfoMatch);
            add_shared_cmd_1arg(pt_sh, HMI_CMD_ALERT, message);
        }

    } else {
        add_shared_cmd_1arg(pt_sh, HMI_CMD_ALERT, "There is no entry yet!");
    }
}

/*
 * Obtain the entire list of entries
 * Parameter 1: the shared structure
 * Parameter 2: the encryption key masked
 * Parameter 3: the mask of the key 
 * Parameter 4: the list of the entries
 */
void do_command_print(T_Shared * pt_sh, const uint8_t * key_m, const uint8_t * mask, DLList list) {
    search_and_print(pt_sh, key_m, mask, list, NULL, 0);
}

/*
 * Finds and sends the entries matching the pattern
 * Parameter 1: the shared structure
 * Parameter 2: the encryption key masked
 * Parameter 3: the mask of the key
 * Parameter 4: the list of the entries
 */
void do_command_search(T_Shared * pt_sh, const uint8_t * key_m, const uint8_t * mask, DLList list) {
    char pattern[MAX_SIZE];

    // Retrieve the pattern
    get_shared_cmd_1arg(pt_sh, pattern, MAX_SIZE);

    // Search according the pattern
    search_and_print(pt_sh, key_m, mask, list, pattern, 0);
}

/*
 * Add a new entry

 * The user has entered information and the associated secret
 * These two pieces of information are saved with their respective IV once encrypted
 * We also add a hmac value for more security
 * 
 * Parameter 1: the shared structure
 * Parameter 2: the encryption key masked
 * Parameter 3: the mask of the key
 * Parameter 4: the list of the entries
 * Return value: the modified list
 */
DLList do_command_add(T_Shared * pt_sh, const uint8_t * key_m, const uint8_t * mask, DLList list) {
    Entry * pentry = malloc(sizeof *pentry);

    get_shared_cmd_1arg(pt_sh, (char *) pentry->information, MAX_SIZE);
    get_shared_cmd_2arg(pt_sh, (char *) pentry->secret, MAX_SIZE);

    // Encryt the entry
    cypher_data(key_m, mask, pentry);

    // Add to the list
    list = addAtLast_DLList(list, pentry);

    // Alert the user
    add_shared_cmd_1arg(pt_sh, HMI_CMD_ALERT, "One entry added");

    return list;
}

/**
 * Edit an existing entry
 * Parameter 1: the shared structure
 * Parameter 2: the encryption key masked
 * Parameter 3: the mask of the key
 * Parameter 4: the position of the entry to edit
 * Parameter 5: the list of the entries
 * Return value: the modified list
 */
DLList do_command_edit(T_Shared *pt_sh, const uint8_t * key_m, const uint8_t * mask, int nbEntry, DLList list) {
    Entry * pentry = malloc(sizeof *pentry);

    get_shared_cmd_1arg(pt_sh, (char *) pentry->information, MAX_SIZE);
    get_shared_cmd_2arg(pt_sh, (char *) pentry->secret, MAX_SIZE);

    // Encryt the entry
    cypher_data(key_m, mask, pentry);

    // Modify the list
    list = mod_Element_DLList(list, nbEntry, pentry);

    // Alert the user
    char message[ALERT_MAX_SIZE];
    sprintf(message, "Entry number %i edited", nbEntry);
    add_shared_cmd_1arg(pt_sh, HMI_CMD_ALERT, message);

    return list;
}

/**
 * Send the entry to delete or edit 
 * 
 * Parameter 1: the shared structure
 * Parameter 2: the encryption key masked
 * Parameter 3: the mask of the key
 * Parameter 4: the list of the entries
 * Return value: the number of the entry (or -1)
 */ 
int do_command_get_entry_from_number(T_Shared * pt_sh, const uint8_t * key_m, const uint8_t * mask, DLList list) {
    int error; // Indicator flag

    char cNbEntry[ENTRY_NB_MAX_NB + 1]; // Entry number as a string
    int nbEntry = - 1; // Entry number as an integer
    
    get_shared_cmd_1arg(pt_sh, cNbEntry, ENTRY_NB_MAX_NB + 1);

    nbEntry = atoi(cNbEntry);
    error = nbEntry <= 0 || nbEntry > size_DLList(list);
 
    if (!error) {
        // Send the entry to delete or edit
        search_and_print(pt_sh, key_m, mask, list, NULL, nbEntry);
    } else {
        add_shared_cmd_1arg(pt_sh, HMI_CMD_ALERT, "This entry number does not exist");
        return -1;
    }

    return nbEntry;
}

/*
 * Delete an entry
 *
 * Parameter 1: the shared structure
 * Parameter 2: the list of the entries
 * Parameter 3: the number of the entry to remove
 * Return value: the possibly modified list
 */
DLList do_command_delete_exec(T_Shared * pt_sh, DLList list, int nbEntry) {
    list = del_Element_DLList(list, nbEntry);

    int nbEntries = size_DLList(list);
    char message[ALERT_MAX_SIZE];
    
    sprintf(message, "Confirmation: one entry deleted, %d entries left.", nbEntries);
    add_shared_cmd_1arg(pt_sh, HMI_CMD_ALERT, message);

    return list;
}

/*
 * Loading and controlling the special version control record
 *
 * Parameter 1: the shared structure
 * Parameter 2: the open data file number
 * Parameter 3: the master key
 * Return value: error value (0 = OK)
 */
int load_special_entry(T_Shared * pt_sh, int fp, const uint8_t * key) {
    long nblus;
    int error = 0;
    Entry entry;

    memset(&entry, 0, sizeof entry);

    // ---------------------------
    // Read the special record
    nblus = read(fp, &entry, sizeof entry);
    error = nblus != sizeof entry;

    if (error) {
        add_shared_cmd_1arg(pt_sh, HMI_CMD_ERROR, "Impossible to read the special entry from data file!");
        close(fp);
        return 1;
    }

    // ----------------------
    // Control the hash value

    uint8_t hash2[HASH_SIZE];  // Hash value
    
    // Compute the hash value
    hmac_data(key, (char*)entry.information, (char*)entry.secret, hash2);

    // Compare the two hash values
    int erreurHash = 0 != memcmp((const void *)&entry.hash, (const void *)&hash2, sizeof hash2);

    // ------------------------------------
    // Take into account of version number
    int erreurVersion = 0 != memcmp((const void*)EXEC_VERSION, (const void *)& entry.information, sizeof EXEC_VERSION);

    // -------------------------
    // Handle the error cases
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

    return 0;
}

/*
 * Loads and controls data from the file into a list
 *
 * Parameter 1: the shared structure
 * Parameter 2: the master key masked
 * Parameter 3: the mask of the key
 * Parameter 4: fullpath name of the data file
 * Return value: the list of the entries
 */
DLList load_data(T_Shared * pt_sh, const uint8_t * key_m, const uint8_t * mask, const char * file_name) {
    DLList list = NULL;
    int fp;
    int error = 0;
    
    fp = open(file_name, O_RDONLY);

    if (fp != -1) {

        // Unmask to get the real key
        uint8_t key[AES_KEYLEN];
        memcpy(key, key_m, AES_KEYLEN);
        xor_table(key, mask, AES_KEYLEN);

        // Reads and controls the special record
        error = load_special_entry(pt_sh, fp, key);

        long nblus;

        Entry * pentry; // Pointer on an entry

        uint8_t information[MAX_SIZE];
        uint8_t secret[MAX_SIZE];
        uint8_t hash2[HASH_SIZE];  // Hash of control

        if (!error)
            do {
                // Read a record
                pentry = malloc(sizeof *pentry);
                nblus = read(fp, pentry, sizeof *pentry);
                error = nblus != sizeof *pentry;

                if (!error) {

                    // In-memory decryption
                    uncypher_data(key_m, mask, pentry, information, secret);

                    // Control the hash value

                    // Compute hash2
                    hmac_data(key, (char*)information, (char*)secret, hash2);

                    // Compare the two hash values
                    if (-1 == compare(pentry->hash, sizeof pentry->hash, hash2, sizeof hash2)) {
                        add_shared_cmd_1arg(pt_sh, HMI_CMD_ERROR, "Wrong password or data file has been corrupted!");
                        close(fp);
                        free(pentry);
                        return list;
                    }

                    // Zeroing memory areas used
                    memset(information, 0, sizeof information);
                    memset(secret, 0, sizeof secret);

                    // Add the entry into the list
                    list = addAtLast_DLList(list, pentry);
                } else {
                    free(pentry);  // TODO
                }

            } while(!error);

        close(fp);
        memset(key, 0, sizeof key); // Zeroing the key
    }

    return list;
}

/**
 * Backs up a copy of the existing data file
 * If a backup copy already exists, it is overwritten
 *
 * Parameter 1: the shared structure
 * Parameter 2: fullpath name of the data file
 * Return value: error value (0 = OK)
 */
int backup_data(T_Shared * pt_sh, const char * file_name) {
    int fp, bfp;
    char * backup_file_name;

    // Create the backup file name
    backup_file_name = (char*) malloc(strlen(file_name) + strlen(FILE_BACKUP_EXT) + 1);
    strcpy(backup_file_name, file_name);
    strcat(backup_file_name, FILE_BACKUP_EXT);

    // Try to create a new backup file
    bfp = open(backup_file_name, O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (bfp == -1) {
        // A backup file already exists: it is overwritten
        bfp = open(backup_file_name, O_WRONLY | O_TRUNC);
    }

    // Copy record by record
    fp = open(file_name, O_RDONLY);
    if (fp != -1 && bfp != -1) {

        long nblus;
        int error = 0;

        Entry entry; // A record
        do {
            // Read from the original file
            nblus = read(fp, &entry, sizeof entry);
            error = nblus != sizeof entry;

            if (!error) {

                // Write to the backup file
                nblus = write(bfp, &entry, sizeof entry);
                error = nblus != sizeof entry;

                if (error) {
                    add_shared_cmd_1arg(pt_sh, HMI_CMD_ERROR, "Impossible to write in backup file!");
                    close(fp);
                    close(bfp);
                    free(backup_file_name);
                    return 1;
                }

            }

        } while(!error);

        close(fp);
        close(bfp);

    } else {
        add_shared_cmd_1arg(pt_sh, HMI_CMD_ERROR, "Impossible to create a backup file!\n");
        if (fp != -1) close(fp);
        if (bfp != -1) close(fp);
        free(backup_file_name);
        return 1;
    }

    free(backup_file_name);
    return 0;
}

/**
 * Save the special version control record
 * 
 * Parameter 1: the shared structure
 * Parameter 2: fp is the number of the data file already opened
 * Parameter 3: the master key
 * Return value : error value (0 = OK)
 */
int save_special_entry(T_Shared * pt_sh, int fp, const uint8_t * key) {
    ssize_t nbBytes;
    int error = 0; 
    Entry entry;
    
    // Zeroing
    memset(&entry, 0, sizeof entry);

    // Version number
    memcpy((void *)entry.information, (const void *)EXEC_VERSION, sizeof EXEC_VERSION);

    // Date in seconds
    struct timeval time;
    gettimeofday(&time, NULL);
    error = sizeof time.tv_sec >= sizeof entry.secret;

    if (!error) {
        memcpy((void *)entry.secret, (const void*)& (time.tv_sec), sizeof time.tv_sec);
    }

    // HMAC calculation
    if (!error) {
        hmac_data(key, (char*)entry.information, (char*)entry.secret, entry.hash);
    }

    // Write the special record
    if (!error) {
        nbBytes = write(fp, &entry, sizeof entry);
        error = nbBytes != sizeof entry;
    }

    if (error) {
        add_shared_cmd_1arg(pt_sh, HMI_CMD_ERROR, "Impossible to create the special entry in data file!");
        close(fp);
        return 1;
    }

    return 0;
}

/**
 * Save encrypted data to the file
 * We consider that the list is not empty at first!
 * If this file already exists, we make a backup copy before overwriting it
 * 
 * Parameter 1: the shared structure
 * Parameter 2: the list of the entries
 * Parameter 3: the fullpath name the data file
 * Parameter 4: the master key masked
 * Parameter 5: the mask of the key
 */
void save_data(T_Shared * pt_sh, DLList list, const char * file_name, const uint8_t * key_m, const uint8_t * mask) {
    int fp = -1;
    int error = 0;
    
    // Try to create a new data file
    fp = open(file_name, O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (fp == -1) {
        // A data file already exists: do a backup copy
        error = backup_data(pt_sh, file_name);

        // Open the existing file in overwrite mode
        if (!error) fp = open(file_name, O_WRONLY | O_TRUNC);
    }

    // If a file has been opened we can continue
    if (fp != -1 && !error) {

        // Umask to get the real key
        uint8_t key[AES_KEYLEN];
        memcpy(key, key_m, AES_KEYLEN);
        xor_table(key, mask, AES_KEYLEN);

        // Create the special record
        error = save_special_entry(pt_sh, fp, key);

        // Write entries to the list
        if (!error)
            do {

                ssize_t nbBytes;         
                const Entry * pentry;

                if (!isEmpty_DLList(list)) {
                    // We get the entry at the head of the list
                    pentry = list->pdata;

                    // Write the record to the file
                    nbBytes = write(fp, pentry, sizeof *pentry);
                    error = nbBytes != sizeof *pentry;
                }

                if (error) {
                    add_shared_cmd_1arg(pt_sh, HMI_CMD_ERROR, "Impossible to write in data file!");
                    break;
                }

                list = next_DLList(list); // Next entry

            } while(!isEmpty_DLList(list));

        close(fp);
        memset(key, 0, sizeof key); // Zeroing the key

    } else {
        add_shared_cmd_1arg(pt_sh, HMI_CMD_ERROR, "Impossible to create or open data file!");
    }
}

/*
 * Exports plaintext data to a text file
 *
 * Parameter 1: the shared structure
 * Parameter 2: the master key masked
 * Parameter 3: the mask of the key 
 * Parameter 4: the list of the entries
 */
void do_command_export(T_Shared * pt_sh, const uint8_t * key_m, const uint8_t * mask, DLList list) {
    if (!isEmpty_DLList(list)) {

        char file_export[MAXPATHLEN];
        int fp;

        // Get the name of the export file
        get_shared_cmd_1arg(pt_sh, file_export, MAXPATHLEN);

        // Try to create or open in overwrite mode
        fp = open(file_export, O_CREAT | O_EXCL | O_WRONLY, 0600);
        if (fp == -1) fp = open(file_export, O_WRONLY | O_TRUNC);

        if (fp != -1) {

            int nbEntries = 0;

            uint8_t information[MAX_SIZE];
            uint8_t secret[MAX_SIZE];

            const char * fin; // Position of the end of the string
            long nbBytes, nbWrote, error;

            do {
                // In-memory decryption
                uncypher_data(key_m, mask, list->pdata, information, secret);

                // Writing information field to the export file
                fin = index((const char *)information, '\0');
                nbBytes = fin - (char *)information;
                nbWrote = write(fp, information, nbBytes);
                error = nbBytes != nbWrote;

                if (!error) {
                    nbWrote = write(fp, "\n", 1);
                    error = 1 != nbWrote;
                }

                // Writing secret field to the export file
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
                    sprintf(message, "Impossible to write to the exportation file (%s)", file_export);
                    add_shared_cmd_1arg(pt_sh, HMI_CMD_ALERT, message);
                    close(fp);
                    break;
                }

                nbEntries++;

                // Zeroing temporary variables
                memset(information, 0, sizeof information);
                memset(secret, 0, sizeof secret);

                list = next_DLList(list); // Next node

            } while(!isEmpty_DLList(list));

            if (!error) {
                char message[MAXPATHLEN + 50];
                sprintf(message, "%d entries has been exported in %s", nbEntries, file_export);
                add_shared_cmd_1arg(pt_sh, HMI_CMD_ALERT, message);
                close(fp);
            }

        } else {
            add_shared_cmd_1arg(pt_sh, HMI_CMD_ALERT, "Impossible to create or open the exportation file!");
        }

    } else
        add_shared_cmd_1arg(pt_sh, HMI_CMD_ALERT, "There is no entry yet!");
}

/*
 * Imports data from a text file
 *
 * Parameter 1: the shared structure
 * Parameter 2: the master key masked
 * Parameter 3: the mask of the key
 * Parameter 4: the list of the entries
 * Return value: the list modified
 */
DLList do_command_import(T_Shared * pt_sh, const uint8_t * key_m, const uint8_t * mask, DLList list) {
    char file_import[MAXPATHLEN];
    char message[MAXPATHLEN + 50];
    FILE * pf;

    // Get the name of the text file to import
    get_shared_cmd_1arg(pt_sh, file_import, MAXPATHLEN);

    // Opening the import file in read mode
    pf = fopen(file_import, "r");

    if (pf) {
        Entry * pentry;
        int nbEntries = 0;
        const char * data;

        do {
            pentry = malloc(sizeof *pentry); // Allocation of the structure

            // Reading "information" and deleting '\n'
            data = fgets((char *)(pentry->information), MAX_SIZE, pf);
            if (data) * index((char *)(pentry->information), '\n') = '\0';

            if (data) {
                 // Reading "secret" and deleting '\n'
                data = fgets((char *)(pentry->secret), MAX_SIZE, pf);
                if (data) * index((char *)(pentry->secret), '\n') = '\0';

                if (data) {
                    // In-memory encryption
                    cypher_data(key_m, mask, pentry);

                    // Add into the list
                    list = addAtLast_DLList(list, pentry);

                    nbEntries++;
                }
            }

        } while(data);

        sprintf(message, "%d entries imported from %s", nbEntries, file_import);
        add_shared_cmd_1arg(pt_sh, HMI_CMD_ALERT, message);
        fclose(pf);

    } else {
        sprintf(message, "Impossible do open the importation file (%s)", file_import);
        add_shared_cmd_1arg(pt_sh, HMI_CMD_ALERT, message);
    }

    return list;
}

/*
 * Generates the key and then loads the existing data by checking it
 *
 * Parameter 1: the shared structure
 * Parameter 2: the executable name file
 * Parameter 3: the generated key
 * Parameter 4: the mask of the key
 * Parameter 5: the list of the entries
 * Return value: 0 if OK
 */
int do_command_key(T_Shared * pt_sh, char * exec_name, uint8_t * key_m, uint8_t * mask, DLList * list) {
    char passwd[PWD_MAX_SIZE];

    get_shared_cmd_1arg(pt_sh, passwd, PWD_MAX_SIZE); // Get the password
    int error = generate_key(pt_sh, exec_name, key_m, mask, (uint8_t *)passwd); // Generate the key

    if (!error) {
        memset(passwd, 0, PWD_MAX_SIZE);
        *list = load_data(pt_sh, key_m, mask, FILE_DATA_NAME); // Load and control data
                            
        // Request to display a message about the number of entries loaded
        int nbEntries = size_DLList(*list);
        if (nbEntries) {
            char message[ALERT_MAX_SIZE];
            sprintf(message, "Entries found in a local data file: %i", nbEntries);
            add_shared_cmd_1arg(pt_sh, HMI_CMD_ALERT, message);
        }
    
    }

    return error;
}

/*
 * A thread handler of business commands
 * Parameter 1: a useful data for the thread containing the shared structure and the name of the executable
 */
void * thread_core(void * t_arg) {
    T_Core * pt_core = t_arg;           // The argument is a structure T_Core
    T_Shared * pt_sh = pt_core->t_sh;   // Access to the shared structure

    int has_key = 0; // Flag to indicate whether the key is known or not
    uint8_t key_m[AES_KEYLEN]; // Encryption key masked
    uint8_t mask[AES_KEYLEN]; // Mask of the key

    DLList list = NULL; // The list containing the encrypted data
    int nbEntries; // Store the size of the list
    int nbEntry = 0; // Store an entry number of the list

    char response[2] = "n";
    int core_cmd;
    int loop_again = 1;

    while(loop_again) {
    
        // Wait a business command
        core_cmd = get_shared_cmd(pt_sh);
    
        switch (core_cmd) {

            // Compute the key then load data
            case CORE_CMD_KEY:
                if (!has_key) {
                    int error = do_command_key(pt_sh, pt_core->exec_name, key_m, mask, & list);
                    if (!error) {
                        has_key = 1;
                        add_shared_cmd_0arg(pt_sh, HMI_CMD_SIGNEDIN); // We inform the user is signed in
                    }
                } else
                    add_shared_cmd_1arg(pt_sh, HMI_CMD_ALERT, "...but we have already a password!");
                delete_shared_cmd(pt_sh, 1); // Delete the command
                add_shared_cmd_0arg(pt_sh, HMI_CMD_LOOP_INTER); // We return to interaction mode
                break;

            // Decryption then request display on the HMI side
            case CORE_CMD_PRINT:
                if (has_key)
                    do_command_print(pt_sh, key_m, mask, list);
                else
                    add_shared_cmd_1arg(pt_sh, HMI_CMD_ALERT, "...but we don't have password!");
                delete_shared_cmd(pt_sh, 0); // Delete the command
                add_shared_cmd_0arg(pt_sh, HMI_CMD_LOOP_INTER); // We return to interaction mode
                break;

            // Add a new entry
            case CORE_CMD_ADD:
                if (has_key) {
                    list = do_command_add(pt_sh, key_m, mask, list);
                    save_data(pt_sh, list, FILE_DATA_NAME, key_m, mask);
                }
                else
                    add_shared_cmd_1arg(pt_sh, HMI_CMD_ALERT, "...but we don't have password!");
                delete_shared_cmd(pt_sh, 2); // Delete the command
                add_shared_cmd_0arg(pt_sh, HMI_CMD_LOOP_INTER); // We return to interaction mode
                break;

            // Filtering entries according to a pattern
            case CORE_CMD_SEARCH:
                if (has_key)
                    do_command_search(pt_sh, key_m, mask, list);
                else
                    add_shared_cmd_1arg(pt_sh, HMI_CMD_ALERT, "...but we don't have password!");
                delete_shared_cmd(pt_sh, 1); // Delete the command
                add_shared_cmd_0arg(pt_sh, HMI_CMD_LOOP_INTER); // We return to interaction mode
                break;

            // Request to return the entry to be deleted
            case CORE_CMD_DEL_P1:
                if (has_key)
                    nbEntry = do_command_get_entry_from_number(pt_sh, key_m, mask, list); // We store the entry number to be deleted
                else
                    add_shared_cmd_1arg(pt_sh, HMI_CMD_ALERT, "...but we don't have password!");
                
                delete_shared_cmd(pt_sh, 1); // Delete the command
                
                if (has_key && nbEntry > 0) {
                    char next_command[5];
                    sprintf(next_command, "%i", CORE_CMD_DEL_P2);
                    // We ask for confirmation and we give the next command to execute in return
                    add_shared_cmd_2arg(pt_sh, HMI_CMD_ASK_YN, next_command, "Please, confirm you want delete this entry [y/n]: ");
                }
                else
                    add_shared_cmd_0arg(pt_sh, HMI_CMD_LOOP_INTER); // We return to interaction mode
                break;

            // Remove an entry
            case CORE_CMD_DEL_P2:
                get_shared_cmd_1arg(pt_sh, response, 2);
                if (response[0] == 'y') {
                    list = do_command_delete_exec(pt_sh, list, nbEntry);
                    save_data(pt_sh, list, FILE_DATA_NAME, key_m, mask);
                    add_shared_cmd_0arg(pt_sh, HMI_CMD_CLEAR_WINDOW); // We ask to clear the window
                }
                delete_shared_cmd(pt_sh, 1); // Delete the command
                add_shared_cmd_0arg(pt_sh, HMI_CMD_LOOP_INTER); // We return to interaction mode
                break;

            // Request to export to a text file
            case CORE_CMD_EXP:
                if (has_key)                
                    do_command_export(pt_sh, key_m, mask, list);
                else
                    add_shared_cmd_1arg(pt_sh, HMI_CMD_ALERT, "...but we don't have password!");
                delete_shared_cmd(pt_sh, 1); // Delete the command
                add_shared_cmd_0arg(pt_sh, HMI_CMD_LOOP_INTER); // We return to interaction mode
                break;

            // Request to import from a text file
            case CORE_CMD_IMP:
                if (has_key) {
                    nbEntries = size_DLList(list);
                    list = do_command_import(pt_sh, key_m, mask, list);
                    if (size_DLList(list) != nbEntries)
                        save_data(pt_sh, list, FILE_DATA_NAME, key_m, mask);
                }
                else
                    add_shared_cmd_1arg(pt_sh, HMI_CMD_ALERT, "...but we don't have password!");
                delete_shared_cmd(pt_sh, 1); // Delete the command
                add_shared_cmd_0arg(pt_sh, HMI_CMD_LOOP_INTER); // We return to interaction mode
                break;

            // Stop the thread
            case CORE_CMD_EXIT:
                delete_shared_cmd(pt_sh, 0); // Delete the command
                loop_again = 0; // End of the loop and therefore of the thread
                break;

            // Request to return the entry to edit
            case CORE_CMD_EDT_P1:
                if (has_key)
                    // We store the entry number to edit
                    nbEntry = do_command_get_entry_from_number(pt_sh, key_m, mask, list);
                else
                    add_shared_cmd_1arg(pt_sh, HMI_CMD_ALERT, "...but we don't have password!");
                
                delete_shared_cmd(pt_sh, 1); // Delete the command
                
                if (has_key && nbEntry > 0) {
                    // We ask to start editing
                    add_shared_cmd_0arg(pt_sh, HMI_CMD_EDIT_ENTRY);
                }
                else
                    // We return to interaction mode
                    add_shared_cmd_0arg(pt_sh, HMI_CMD_LOOP_INTER);
                break;

            // Save the entry that has been edited
            case CORE_CMD_EDT_P2:
                list = do_command_edit(pt_sh, key_m, mask, nbEntry, list);
                save_data(pt_sh, list, FILE_DATA_NAME, key_m, mask);
                delete_shared_cmd(pt_sh, 2); // Delete the command
                
                // Request to print the modified entry
                add_shared_cmd_0arg(pt_sh, HMI_CMD_CLEAR_WINDOW);
                search_and_print(pt_sh, key_m, mask, list, NULL, nbEntry);
                
                // Finally, request to return to the interaction mode
                add_shared_cmd_0arg(pt_sh, HMI_CMD_LOOP_INTER);
                break;

            default:
                break;
        }
    }

    del_DLList(&list); // We delete the list and its contents
    memset(key_m, 0, AES_KEYLEN); // We forget the masked key
    memset(mask, 0, AES_KEYLEN); // We forget the mask

    return NULL;
}
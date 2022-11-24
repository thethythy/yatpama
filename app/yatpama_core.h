#ifndef _YATPAMA_CORE_H_
#define _YATPAMA_CORE_H_

#include "yatpama.h"
#include "../lib/dllist.h"

void get_hash_executable(char* argv0, uint8_t hash[]);

void hmac_data(uint8_t key[], char * information, char * secret, uint8_t * hash);
void cypher_data(uint8_t key[], Entry * pentry);
void uncypher_data(uint8_t key[], Entry * pentry, uint8_t * pinformation, uint8_t * psecret);

void search_and_print(uint8_t key[], DLList list, char* pattern, int pos);

void save_data(DLList list, const char *file_name, uint8_t key[]);
DLList load_data(uint8_t key[], const char *file_name);
void backup_data(const char *file_name);

void save_special_entry(int fp, uint8_t key[]);
void load_special_entry(int fp, uint8_t key[]);

void do_command_key(char * argv0, uint8_t key[]);

void do_command_print(uint8_t key[], DLList list);
void do_command_search(uint8_t key[], DLList list);

DLList do_command_add(uint8_t key[], DLList list);
DLList do_command_delete(uint8_t key[], DLList list);

void do_command_export(uint8_t key[], DLList list, const char *file_export);
DLList do_command_import(uint8_t key[], DLList list);

#endif
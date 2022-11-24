#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <regex.h>
#include <sys/param.h>
#include <sys/time.h>

#include "../lib/aes.h"
#include "../lib/dllist.h"
#include "yatpama_core.h"
#include "yatpama_hmi.h"

int main(int argc, char* argv[]) {
    char command; // La commande en cours

    int has_key = 0; // Flag pour indiquer si la clé est connue ou pas
    uint8_t key[AES_KEYLEN]; // Clé de chiffrement

    DLList list = NULL; // La liste contenant les données chiffrées

    const char file_name[] = "./yatpama.data"; // Le nom et chemin du fichier
    const char file_export[] = "./yatpama_export.txt"; // Nom du fichier d'exportation

    do {
        command = prompt();
        switch (command) {
            case 'k':
                printf("\nEnter password\n");
                if (!has_key) {
                    do_command_key(argv[0], key); // Saisie le mdp et génère la clé
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
                    save_data(list, file_name, key);
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
                        save_data(list, file_name, key);
                }
                else
                    printf("...but we don't have password!\n");
                break;
            case 'e':
                printf("\nExport entries\n");
                if (has_key) {
                    do_command_export(key, list, file_export);
                }
                else
                    printf("...but we don't have password!\n");
                break;
            case 'i':
                printf("\nImport entries\n");
                if (has_key) {
                    int nbEntries = size_DLList(list);
                    list = do_command_import(key, list);
                    if (size_DLList(list) != nbEntries)
                        save_data(list, file_name, key);
                }
                else
                    printf("...but we don't have password!\n");
                break;
        }
    } while (command != 'q');

    del_DLList(&list); // On supprime la liste et son contenu
    memset(key, 0, AES_KEYLEN); // On oublie le master key
}

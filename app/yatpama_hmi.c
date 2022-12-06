#include <stdio.h>
#include <string.h>
#include <sys/param.h>

#include "yatpama_shared.h"
#include "../lib/utilities.h"

/*
 * Interface principale
 * Le programme attend que l'utilisateur utilise une commande connue
 */ 
char prompt() {
    char cmd;
    int again;

    do {
        printf("\n---------------------------------------------------------------------------");
        printf("\n                yatpama : Yet Another Tiny Password Manager                ");
        printf("\n---------------------------------------------------------------------------");
        printf("\n k pwd | p print | s search | a add | d del | e export | i import | q quit ");
        printf("\n---------------------------------------------------------------------------");
        printf("\nChoose a command: ");
        cmd = getchar();
        again = cmd != 'k' && cmd != 'p' && cmd != 'a' && cmd != 'q' &&
                cmd != 's' && cmd != 'd' && cmd != 'e' && cmd != 'i'; 
    } while (again);

    fpurge(stdin); // Enlever la touche 'Enter' du buffer du clavier

    return cmd;
}

/*
 * Saisir une chaine de caractère en claire
 * Paramètre 1 : le message d'attente
 * Paramètre 2 : la chaine saisie
 * Paramètre 3 : la taille maximale de la chaine
 */
void getAPublicString(char * prompt, char * chaine, int size_max) {
    memset(chaine, 0, INFO_MAX_SIZE);
    printf("%s", prompt);
    getsl(chaine, size_max);
    fpurge(stdin);
}

/*
 * Affiche un message d'alerte ou une information utile
 * Paramètre 1 : le message à afficher
 */
void putAnAlertMessage(char * chaine) {
    printf("%s", chaine);
}

/*
 * Affiche une entrée en claire
 * Paramètre 1 : le numéro de l'entrée
 * Paramètre 2 : l'information
 * Paramètre 3 : le secret 
 */
void putAnEntry(int nbInfo, char * information, char * secret) {
    printf("\nEntry n°%i:", nbInfo);
    printf("\n\tInformation: ");
    printf("\t%s", information);
    printf("\n\tSecret: ");
    printf("\t%s\n", secret);
}

/*
 * Boucle d'interaction principale
 * Paramètre 1 : la structure de donnée partagée
 */
void interaction_loop(T_Shared * pt_sh) {
    char command; // La commande en cours

    command = prompt(); // Saisie d'une commande

    switch (command) {

        // Saisie du mot de passe et génération de la clé
        case 'k':
            printf("\nEnter password\n");
            char msecret[PWD_MAX_SIZE]; // Le mot de passe
            getAPublicString("Master password: ", msecret, PWD_MAX_SIZE);
            add_shared_cmd_1arg(pt_sh, CORE_CMD_KEY, msecret); // Demande création de la clé
            memset(msecret, 0, PWD_MAX_SIZE);
            break;

        // Affichage des entrées
        case 'p':
            printf("\nPrint secret information\n");
            add_shared_cmd_0arg(pt_sh, CORE_CMD_PRINT); // Demande d'exécution de l'affichage
            break;

        // Filtrage des entrées
        case 's':
            printf("\nSearch a secret information\n");
            char pattern[MAX_SIZE]; // Le pattern de filtrage
            getAPublicString("Pattern: ", pattern, MAX_SIZE);
            add_shared_cmd_1arg(pt_sh, CORE_CMD_SEARCH, pattern); // Demande d'exéction d'une recherche
            break;

        // Ajout d'une nouvelle entrée
        case 'a':
            printf("\nAdd a new secret information\n");

            char information[MAX_SIZE];
            getAPublicString("Information: ", information, MAX_SIZE);
            
            char secret[MAX_SIZE];
            getAPublicString("Secret: ", secret, MAX_SIZE);
            
            add_shared_cmd_2arg(pt_sh, CORE_CMD_ADD, information, secret); // Demande d'exécution d'un ajout

            memset(information, 0, MAX_SIZE);
            memset(secret, 0, MAX_SIZE);

            break;

        // Arrêt normal
        case 'q':
            printf("\nGoodbye and good luck!\n");
            add_shared_cmd_0arg(pt_sh, HMI_CMD_EXIT); // Fin de l'interface
            break;
        
        // Suppression d'une entrée
        case 'd':
            printf("\nDelete an entry\n");
            char cNbEntry[ENTRY_NB_MAX_NB + 1]; // Numéro de l'entrée en chaine
            getAPublicString("Give entry number: ", cNbEntry, ENTRY_NB_MAX_NB + 1); // Obtenir le numéro de l'entrée à supprimer
            add_shared_cmd_1arg(pt_sh, CORE_CMD_DEL_P1, cNbEntry); // Demande pour obtenir l'entrée concernée
            break;

        // Exportation des entrées
        case 'e':
            printf("\nExport entries\n");
            char file_export[MAXPATHLEN];
            getAPublicString("\nGive the name of the file to export to: ", file_export, MAXPATHLEN);
            add_shared_cmd_1arg(pt_sh, CORE_CMD_EXP, file_export); // Demande d'exécution d'une exportation
            break;

        // Importation des entrées
        case 'i':
            printf("\nImport entries\n");
            char file_import[MAXPATHLEN];
            getAPublicString("\nGive the name of the file to import from: ", file_import, MAXPATHLEN);
            add_shared_cmd_1arg(pt_sh, CORE_CMD_IMP, file_import); // Demande d'exécution d'une importation
            break;
    }
}

/*
 * Thread de gestion des commandes HMI
 * Paramètre 1 : une donnée utilisable par le thread
 */
void * thread_hmi(void * t_arg) {
    T_Shared * pt_sh = t_arg; // L'argument est une structure T_Shared

    char message[ALERT_MAX_SIZE]; // Pour stocker les messages d'alerte et d'erreur

    char nbInfo[ENTRY_NB_MAX_NB];   // Numéro de l'entrée
    char information[MAX_SIZE];     // Champs information de l'entrée
    char secret[MAX_SIZE];          // Champs secret de l'entrée

    int loop_again = 1;
    while(loop_again == 1) {
    
        int hmi_cmd = 0;

        // Lecture d'une commande éventuelle
        hmi_cmd = get_shared_cmd(pt_sh);
    
        switch (hmi_cmd) {

            // Attente d'une commande
            case HMI_CMD_LOOP_INTER:
                delete_shared_cmd(pt_sh, 0);                // Supprime la commande
                interaction_loop(pt_sh);                    // Interagit avec l'utilisateur
                break;

            // Affichage d'une entrée
            case HMI_CMD_SHOW_ENTRY:
                get_shared_cmd_1arg(pt_sh, nbInfo);         // Récupère le numéro de l'entrée
                get_shared_cmd_2arg(pt_sh, information);    // Récupère l'info
                get_shared_cmd_3arg(pt_sh, secret);         // Récupère le secret
                putAnEntry(atoi(nbInfo), information, secret);    // Affiche l'entrée
                delete_shared_cmd(pt_sh, 3);                // Supprime la commande
                break;

            // Demande confirmation
            case HMI_CMD_ASK_YN:
                delete_shared_cmd(pt_sh, 0);                // Supprime la commande
                char reponse;
                getAPublicString("\nPlease, confirm you want delete this entry [y/n]: ", &reponse, 2);
                add_shared_cmd_1arg(pt_sh, CORE_CMD_DEL_P2, &reponse);
                break;

            // Affichage d'un message d'alerte
            case HMI_CMD_ALERT:
                get_shared_cmd_1arg(pt_sh, message);        // Récupère le message
                putAnAlertMessage(message);                 // Affiche le message d'alerte
                delete_shared_cmd(pt_sh, 1);                // Supprime la commande
                break;
        
            // Arrêt (normal) de l'interface
            case HMI_CMD_EXIT:
                delete_shared_cmd(pt_sh, 0);                // Supprime la commande
                add_shared_cmd_0arg(pt_sh, CORE_CMD_EXIT);  // Demande d'arrêt du thread CORE
                loop_again = 0;                             // Fin du thread HMI
                break;

            // Arrêt de l'application sur erreur
            case HMI_CMD_ERROR:
                get_shared_cmd_1arg(pt_sh, message);        // Récupère le message
                printf("%s", message);                      // Affiche le message
                delete_shared_cmd(pt_sh, 1);                // Supprime la commande
                add_shared_cmd_hpriority(pt_sh, CORE_CMD_EXIT);  // Demande prioritaire d'arrêt du thread CORE
                loop_again = 0;                             // Fin du thread HMI
                break;

            default:
                break;
        }

    }

    return NULL;
}
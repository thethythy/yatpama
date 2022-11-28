#include <stdio.h>
#include <string.h>

#include "yatpama_shared.h"

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

    getchar(); // Enlever la touche 'Enter' du buffer du clavier

    return cmd;
}

/*
 * Boucle d'interaction principale
 * Paramètre 1 : la structure de donnée partagée
 */
void interaction_loop(T_Shared * pt_sh) {
    char command; // La commande en cours

    command = prompt();
    switch (command) {
        case 'k':
            printf("\nEnter password\n");
            add_shared_cmd_0arg(pt_sh, CORE_CMD_KEY); // Demande d'exécution de saisie du mdp
            break;
        case 'p':
            printf("\nPrint secret information\n");
            add_shared_cmd_0arg(pt_sh, CORE_CMD_PRINT); // Demande d'exécution de l'affichage
            break;
        case 's':
            printf("\nSearch a secret information\n");
            add_shared_cmd_0arg(pt_sh, CORE_CMD_SEARCH); // Demande d'exéction d'une recherche
            break;
        case 'a':
            printf("\nAdd a new secret information\n");
            add_shared_cmd_0arg(pt_sh, CORE_CMD_ADD); // Demande d'exécution d'un ajout
            break;
        case 'q':
            printf("\nGoodbye and good luck!\n");
            add_shared_cmd_0arg(pt_sh, HMI_CMD_EXIT); // Fin de l'interface
            break;
        case 'd':
            printf("\nDelete an entry\n");
            add_shared_cmd_0arg(pt_sh, CORE_CMD_DEL); // Demande d'exécution d'une suppression
            break;
        case 'e':
            printf("\nExport entries\n");
            add_shared_cmd_0arg(pt_sh, CORE_CMD_EXP); // Demande d'exécution d'une exportation
            break;
        case 'i':
            printf("\nImport entries\n");
            add_shared_cmd_0arg(pt_sh, CORE_CMD_IMP); // Demande d'exéction d'une importation
            break;
    }
}

/*
 * Thread de gestion des commandes HMI
 * Paramètre 1 : une donnée utilisable par le thread
 */
void * thread_hmi(void * t_arg) {
    T_Shared * pt_sh = t_arg; // L'argument est une structure T_Shared

    int loop_again = 1;
    while(loop_again == 1) {
    
        int hmi_cmd = 0;

        // Lecture d'une commande éventuelle
        hmi_cmd = get_shared_cmd(pt_sh);
    
        switch (hmi_cmd) {
            case HMI_CMD_LOOP_INTER:
                delete_shared_cmd_0arg(pt_sh);              // Supprime la commande
                interaction_loop(pt_sh);                    // Interagit avec l'utilisateur
                break;
        
            case HMI_CMD_EXIT:
                delete_shared_cmd_0arg(pt_sh);              // Supprime la commande
                add_shared_cmd_0arg(pt_sh, CORE_CMD_EXIT);  // Ajout de la commande d'arrêt de l'interface
                loop_again = 0;                             // Fin du thread HMI
                break;

            default:
                break;
        }

    }

    return NULL;
}
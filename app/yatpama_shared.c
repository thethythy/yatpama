#include "string.h"

#include "yatpama_shared.h"

/*
 * Récupérer la commande actuelle (sans modifier la liste partagée)
 * Paramètre 1 : la structure de donnée partagée
 * Retour : la valeur de la commande et 0 si pas de commande
 */
int get_shared_cmd(T_Shared * pt_sh) {
    int cmd = 0;

    pthread_mutex_lock(& pt_sh->mut_list);
    while(isEmpty_DLList(pt_sh->cmd_list) == 1)
        pthread_cond_wait (&pt_sh->synchro, &pt_sh->mut_list);
    if (isEmpty_DLList(pt_sh->cmd_list) == 0)
        cmd = * ((int *) pt_sh->cmd_list->pdata);
    pthread_mutex_unlock(& pt_sh->mut_list);

    return cmd;
}

/*
 * Récupérer le premier argument de la commande actuelle (sans modifier la liste partagée)
 * Paramètre 1 : la structure de donnée partagée
 * Paramètre 2 : le 1er argument
 */
void get_shared_cmd_1arg(T_Shared *  pt_sh, char * arg) {
    *arg = '\0';
    pthread_mutex_lock(& pt_sh->mut_list);
    while(isEmpty_DLList(pt_sh->cmd_list) == 1)
        pthread_cond_wait(&pt_sh->synchro, &pt_sh->mut_list);
    if (isEmpty_DLList(pt_sh->cmd_list) == 0) {
        DLList list = next_DLList(pt_sh->cmd_list);
        if (list != NULL) {
            strcpy(arg, (char *) list->pdata);
        }
    }
    pthread_mutex_unlock(& pt_sh->mut_list);
}

/*
 * Récupérer le second argument de la commande actuelle (sans modifier la liste partagée)
 * Paramètre 1 : la structure de donnée partagée
 * Paramètre 2 : le second argument
 */
void get_shared_cmd_2arg(T_Shared *  pt_sh, char * arg) {
    *arg = '\0';
    pthread_mutex_lock(& pt_sh->mut_list);
    while(isEmpty_DLList(pt_sh->cmd_list) == 1)
        pthread_cond_wait(&pt_sh->synchro, &pt_sh->mut_list);
    if (isEmpty_DLList(pt_sh->cmd_list) == 0) {
        DLList list = next_DLList(pt_sh->cmd_list); // On passe la commande
        if (list != NULL) {
            list = next_DLList(list);    // On passe le premier argument
            if (list != NULL)
                strcpy(arg, (char *) list->pdata);  // On récupère le second argument
        }
    }
    pthread_mutex_unlock(& pt_sh->mut_list);
}

/*
 * Récupérer le troisième argument de la commande actuelle (sans modifier la liste partagée)
 * Paramètre 1 : la structure de donnée partagée
 * Paramètre 2 : le troisème argument
 */
void get_shared_cmd_3arg(T_Shared *  pt_sh, char * arg) {
    *arg = '\0';
    pthread_mutex_lock(& pt_sh->mut_list);
    while(isEmpty_DLList(pt_sh->cmd_list) == 1)
        pthread_cond_wait(&pt_sh->synchro, &pt_sh->mut_list);
    if (isEmpty_DLList(pt_sh->cmd_list) == 0) {
        DLList list = next_DLList(pt_sh->cmd_list); // On passe la commande
        if (list != NULL) {
            list = next_DLList(list);    // On passe le premier argument
            if (list != NULL) {
                list = next_DLList(list); // On passe le second argument
                if (list != NULL)
                    strcpy(arg, (char *) list->pdata);  // On récupère le troisieme argument
            }
        }
    }
    pthread_mutex_unlock(& pt_sh->mut_list);
}

/*
 * Ajouter une commande (sans argument) au début de la liste de commande partagée
 * Paramètre 1 : la structure de donnée partagée
 * Paramètre 2 : le numéro de la nouvelle commande
 */
void add_shared_cmd_hpriority(T_Shared * pt_sh, int cmd_value) {
    int * cmd = malloc(sizeof(int));
    *cmd = cmd_value;

    pthread_mutex_lock(& pt_sh->mut_list);
    pt_sh->cmd_list = addAtFirst_DLList(pt_sh->cmd_list, cmd);
    pthread_cond_signal(&pt_sh->synchro);
    pthread_mutex_unlock(& pt_sh->mut_list);
}

/*
 * Ajouter une commande (sans argument) à la fin de la liste de commande partagée
 * Paramètre 1 : la structure de donnée partagée
 * Paramètre 2 : le numéro de la nouvelle commande
 */
void add_shared_cmd_0arg(T_Shared * pt_sh, int cmd_value) {
    int * cmd = malloc(sizeof(int));
    *cmd = cmd_value;

    pthread_mutex_lock(& pt_sh->mut_list);
    pt_sh->cmd_list = addAtLast_DLList(pt_sh->cmd_list, cmd);
    pthread_cond_signal(&pt_sh->synchro);
    pthread_mutex_unlock(& pt_sh->mut_list);
}

/*
 * Ajouter une commande (à 1 argument) à la fin de la liste partagée
 * Paramètre 1 : la structure de donnée partagée
 * Paramètre 2 : le numéro de la nouvelle commande
 * Paramètre 3 : l'argument de la commande
 */
void add_shared_cmd_1arg(T_Shared * pt_sh, int cmd_value, char * arg_value) {
    int * cmd = malloc(sizeof(int));
    *cmd = cmd_value;

    char * arg = malloc(strlen(arg_value) + 1);
    strcpy(arg, arg_value);

    pthread_mutex_lock(& pt_sh->mut_list);
    pt_sh->cmd_list = addAtLast_DLList(pt_sh->cmd_list, cmd);
    pt_sh->cmd_list = addAtLast_DLList(pt_sh->cmd_list, arg);
    pthread_cond_signal(&pt_sh->synchro);      
    pthread_mutex_unlock(& pt_sh->mut_list);    
}

/*
 * Ajouter une commande (à 2 arguments) à la fin de la liste partagée
 * Paramètre 1 : la structure de donnée partagée
 * Paramètre 2 : le numéro de la nouvelle commande
 * Paramètre 3 : l'argument n°1 de la commande
 * Paramètre 4 : l'argument n°2 de la commande
 */
void add_shared_cmd_2arg(T_Shared * pt_sh, int cmd_value, char * arg1_value, char * arg2_value) {
    int * cmd = malloc(sizeof(int));
    *cmd = cmd_value;

    char * arg1 = malloc(strlen(arg1_value) + 1);
    strcpy(arg1, arg1_value);

    char * arg2 = malloc(strlen(arg2_value) + 1);
    strcpy(arg2, arg2_value);

    pthread_mutex_lock(& pt_sh->mut_list);
    pt_sh->cmd_list = addAtLast_DLList(pt_sh->cmd_list, cmd);
    pt_sh->cmd_list = addAtLast_DLList(pt_sh->cmd_list, arg1);
    pt_sh->cmd_list = addAtLast_DLList(pt_sh->cmd_list, arg2);
    pthread_cond_signal(&pt_sh->synchro);      
    pthread_mutex_unlock(& pt_sh->mut_list);  
}

/*
 * Ajouter une commande (à 3 arguments) à la fin de la liste partagée
 * Paramètre 1 : la structure de donnée partagée
 * Paramètre 2 : le numéro de la nouvelle commande
 * Paramètre 3 : l'argument n°1 de la commande
 * Paramètre 4 : l'argument n°2 de la commande
 * Paramètre 5 : l'argument n°3 de la commande
 */
void add_shared_cmd_3arg(T_Shared * pt_sh, int cmd_value, char * arg1_value, char * arg2_value, char * arg3_value) {
    int * cmd = malloc(sizeof(int));
    *cmd = cmd_value;

    char * arg1 = malloc(strlen(arg1_value) + 1);
    strcpy(arg1, arg1_value);

    char * arg2 = malloc(strlen(arg2_value) + 1);
    strcpy(arg2, arg2_value);

    char * arg3 = malloc(strlen(arg3_value) + 1);
    strcpy(arg3, arg3_value);

    pthread_mutex_lock(& pt_sh->mut_list);
    pt_sh->cmd_list = addAtLast_DLList(pt_sh->cmd_list, cmd);
    pt_sh->cmd_list = addAtLast_DLList(pt_sh->cmd_list, arg1);
    pt_sh->cmd_list = addAtLast_DLList(pt_sh->cmd_list, arg2);
    pt_sh->cmd_list = addAtLast_DLList(pt_sh->cmd_list, arg3);
    pthread_cond_signal(&pt_sh->synchro);      
    pthread_mutex_unlock(& pt_sh->mut_list);   
}

/*
 * Suppression d'une commande du début de la liste partagée
 * Paramètre 1 : la structure de donnée partagée
 * Paramètre 2 : le nombre d'argument de la commande
 */
void delete_shared_cmd(T_Shared * pt_sh, int nb_arg) {
    nb_arg++; // Incrément pour prendre en compte le numéro de la commande

    pthread_mutex_lock(& pt_sh->mut_list);
    for (int i = 1; i <= nb_arg; i++)
        pt_sh->cmd_list = del_Element_DLList(pt_sh->cmd_list, 1);
    pthread_mutex_unlock(& pt_sh->mut_list);
}


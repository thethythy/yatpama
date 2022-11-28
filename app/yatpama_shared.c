#include "string.h"

#include "yatpama_shared.h"

/*
 * Récupérer la commande sans modifier la liste partagée
 * Paramètre 1 : la structure de donnée partagée
 * Retour : la valeur de la commande et 0 si pas de commande
 */
int get_shared_cmd(T_Shared * pt_sh) {
    int cmd = 0;

    pthread_mutex_lock(& pt_sh->mut_list);
    while (isEmpty_DLList(pt_sh->cmd_list) == 1)
        pthread_cond_wait (&pt_sh->synchro, &pt_sh->mut_list);
    if (isEmpty_DLList(pt_sh->cmd_list) == 0)
        cmd = * ((int *) pt_sh->cmd_list->pdata);
    pthread_mutex_unlock(& pt_sh->mut_list);

    return cmd;
}

/*
 * Récupérer le premier argument de la commande actuelle (sans modifier la liste partagée)
 * Paramètre 1 : la structure de donnée partagée
 * Paramètre 2 : le 1er argument ou NULL
 */
void get_shared_cmd_1arg(T_Shared *  pt_sh, char ** arg) {
    *arg = NULL;
    pthread_mutex_lock(& pt_sh->mut_list);
    while (isEmpty_DLList(pt_sh->cmd_list) == 1)
        pthread_cond_wait(&pt_sh->synchro, &pt_sh->mut_list);
    if (isEmpty_DLList(pt_sh->cmd_list) == 0) {
        DLList list = next_DLList(pt_sh->cmd_list);
        if (list != NULL)
            *arg = (char *) list->pdata;
    }
    pthread_mutex_unlock(& pt_sh->mut_list);
}

/*
 * Ajouter une commande (sans argument) à la liste de commande partagée
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
 * Suppression d'une commande (sans argument) de la liste partagée
 * Paramètre 1 : la structure de donnée partagée
 */
void delete_shared_cmd_0arg(T_Shared * pt_sh) {
    pthread_mutex_lock(& pt_sh->mut_list);
    pt_sh->cmd_list = del_Element_DLList(pt_sh->cmd_list, 1);
    pthread_mutex_unlock(& pt_sh->mut_list);
}

/*
 * Ajouter une commande (à 1 argument) à la liste de commande partagée
 * Paramètre 1 : la structure de donnée partagée
 * Paramètre 2 : le numéro de la nouvelle commande
 * Paramètre 3 : l'argument de la commande
 */
void add_shared_cmd_1arg(T_Shared * pt_sh, int cmd_value, char * arg_value) {
    int * cmd = malloc(sizeof(int));
    *cmd = cmd_value;

    char * arg = malloc(strlen(arg_value));
    strcpy(arg, arg_value);

    pthread_mutex_lock(& pt_sh->mut_list);
    pt_sh->cmd_list = addAtLast_DLList(pt_sh->cmd_list, cmd);
    pt_sh->cmd_list = addAtLast_DLList(pt_sh->cmd_list, arg);
    pthread_cond_signal(&pt_sh->synchro);      
    pthread_mutex_unlock(& pt_sh->mut_list);    
}

/*
 * Suppression d'une commande (à 1 argument) de la liste partagée
 * Paramètre 1 : la structure de donnée partagée
 */
void delete_shared_cmd_1arg(T_Shared * pt_sh) {
    pthread_mutex_lock(& pt_sh->mut_list);
    pt_sh->cmd_list = del_Element_DLList(pt_sh->cmd_list, 1);
    pt_sh->cmd_list = del_Element_DLList(pt_sh->cmd_list, 1);    
    pthread_mutex_unlock(& pt_sh->mut_list);
}

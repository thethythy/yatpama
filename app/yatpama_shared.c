#include "string.h"

#include "yatpama_shared.h"

/*
 * Retrieve the current command (without modifying the shared list)
 * Parameter 1: the shared data structure
 * Return value: the value of the command and 0 if no command
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
 * Retrieve the first argument of the current command (without modifying the shared list)
 * Parameter 1: the shared data structure
 * Parameter 2: the 1st argument
 * Parameter 3 : the length of the 1st argument
 */
void get_shared_cmd_1arg(T_Shared *  pt_sh, char * arg, int arg_size) {
    *arg = '\0';
    pthread_mutex_lock(& pt_sh->mut_list);
    while(isEmpty_DLList(pt_sh->cmd_list) == 1)
        pthread_cond_wait(&pt_sh->synchro, &pt_sh->mut_list);
    if (isEmpty_DLList(pt_sh->cmd_list) == 0) {
        DLList list = next_DLList(pt_sh->cmd_list);
        if (list != NULL) {
            strncpy(arg, (char *) list->pdata, arg_size - 1);
            arg[arg_size - 1] = '\0';
        }
    }
    pthread_mutex_unlock(& pt_sh->mut_list);
}

/*
 * Retrieve the second argument of the current command (without modifying the shared list)
 * Parameter 1: the shared data structure
 * Parameter 2: the 2nd argument
 * Parameter 3 : the length of the 2nd argument
 */
void get_shared_cmd_2arg(T_Shared *  pt_sh, char * arg, int arg_size) {
    *arg = '\0';
    pthread_mutex_lock(& pt_sh->mut_list);
    while(isEmpty_DLList(pt_sh->cmd_list) == 1)
        pthread_cond_wait(&pt_sh->synchro, &pt_sh->mut_list);
    if (isEmpty_DLList(pt_sh->cmd_list) == 0) {
        DLList list = next_DLList(pt_sh->cmd_list); // The command
        if (list != NULL) {
            list = next_DLList(list);    // The 1st argument
            if (list != NULL) {
                strncpy(arg, (char *) list->pdata, arg_size - 1);  // We get the 2nd argument
                arg[arg_size - 1] = '\0';
            }
        }
    }
    pthread_mutex_unlock(& pt_sh->mut_list);
}

/*
 * Retrieve the third argument of the current command (without modifying the shared list)
 * Parameter 1: the shared data structure
 * Parameter 2 : the 3rd argument of the command
 * Parameter 3 : the length of the 3rd argument
 */
void get_shared_cmd_3arg(T_Shared *  pt_sh, char * arg, int arg_size) {
    *arg = '\0';
    pthread_mutex_lock(& pt_sh->mut_list);
    while(isEmpty_DLList(pt_sh->cmd_list) == 1)
        pthread_cond_wait(&pt_sh->synchro, &pt_sh->mut_list);
    if (isEmpty_DLList(pt_sh->cmd_list) == 0) {
        DLList list = next_DLList(pt_sh->cmd_list); // The command
        if (list != NULL) {
            list = next_DLList(list);    // The 1st argument
            if (list != NULL) {
                list = next_DLList(list); // The 2nd argument
                if (list != NULL) {
                    strncpy(arg, (char *) list->pdata, arg_size - 1);  // We get the 3rd argument
                    arg[arg_size - 1] = '\0';
                }
            }
        }
    }
    pthread_mutex_unlock(& pt_sh->mut_list);
}

/*
 * Add a command (without arguments) to the beginning of the shared command list
 * Parameter 1: the shared data structure
 * Parameter 2: the number of the new command
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
 * Add a command (without arguments) to the end of the shared command list
 * Parameter 1: the shared data structure
 * Parameter 2: the number of the new command
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
 * Add a command (with 1 argument) to the end of the shared list
 * Parameter 1: the shared data structure
 * Parameter 2: the number of the new command
 * Parameter 3: the command argument
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
 * Add a command (with 2 arguments) to the end of the shared list
 * Parameter 1: the shared data structure
 * Parameter 2: the number of the new command
 * Parameter 3: the 1st command argument
 * Parameter 4: the 2nd command argument
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
 * Add a command (with 3 arguments) to the end of the shared list
 * Parameter 1: the shared data structure
 * Paramètre 2 : the number of the new command
 * Paramètre 3 : the 1st command argument
 * Paramètre 4 : the 2nd command argument
 * Paramètre 5 : the 3rd command argument
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
 * Remove a command from the beginning of the shared list
 * Parameter 1: the shared data structure
 * Parameter 2: the number of arguments of the command
 */
void delete_shared_cmd(T_Shared * pt_sh, int nb_arg) {
    nb_arg++; // Increment to take into account the command number

    pthread_mutex_lock(& pt_sh->mut_list);
    for (int i = 1; i <= nb_arg; i++)
        pt_sh->cmd_list = del_Element_DLList(pt_sh->cmd_list, 1);
    pthread_mutex_unlock(& pt_sh->mut_list);
}


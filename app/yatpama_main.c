#include <string.h>

#include "yatpama_shared.h"
#include "yatpama_hmi.h"
#include "yatpama_core.h"

int main(int argc, char * argv[]) {
  pthread_t t_core;
  pthread_t t_hmi;

  // Shared data structure between the two threads
  T_Shared sh = {
    .cmd_list = NULL,                       // List of commands
    .mut_list = PTHREAD_MUTEX_INITIALIZER,  // Semaphore for access to the list
    .synchro = PTHREAD_COND_INITIALIZER     // Sync to avoid looping on an empty list
  };

  // CORE thread-specific data structure
  T_Core core = {
    .t_sh = &sh,          // The shared structure of data
    .exec_name = argv[0]  // The name of the executable entered on the command line
  };

  // The first command: launch an interaction loop on the HMI side
  add_shared_cmd_0arg(&sh, HMI_CMD_LOOP_INTER);

  // Launching threads
  pthread_create(&t_core, NULL, thread_core, &core);
  pthread_create(&t_hmi, NULL, thread_hmi, &sh);

  // Waiting for threads to end
  pthread_join(t_hmi, NULL);
  pthread_join(t_core, NULL);

  del_DLList(& sh.cmd_list); // Suppresion de la liste des commandes

  return 0;
}
